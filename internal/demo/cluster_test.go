package demo

import (
	"context"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Every combination the gate will meet: the newest protocol (stateless,
// server/discover) and the last session-based one, each with JSON and with
// SSE responses.
var transports = []struct {
	name     string
	version  string // "" = the SDK's latest
	jsonResp bool
}{
	{"latest+sse", "", false},
	{"latest+json", "", true},
	{"2025-11-25+sse", "2025-11-25", false},
	{"2025-11-25+json", "2025-11-25", true},
}

func connect(t *testing.T, url, version string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestDemoServerOverHTTP(t *testing.T) {
	for _, tc := range transports {
		t.Run(tc.name, func(t *testing.T) {
			cluster := NewCluster()
			srv := httptest.NewServer(Handler(NewServer(cluster), tc.jsonResp))
			// Cleanups run last-in first-out: the session (and its open SSE
			// stream) closes before the server, or srv.Close waits forever.
			t.Cleanup(srv.Close)
			cs := connect(t, srv.URL, tc.version)
			ctx := context.Background()

			tools, err := cs.ListTools(ctx, nil)
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			var names []string
			for _, tool := range tools.Tools {
				names = append(names, tool.Name)
			}
			slices.Sort(names)
			if !slices.Equal(names, ToolNames) {
				t.Fatalf("tools = %v, want %v", names, ToolNames)
			}

			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "scale_deployment",
				Arguments: map[string]any{"namespace": "staging-payments", "deployment": "api", "replicas": 3}})
			if err != nil || res.IsError {
				t.Fatalf("scale: err=%v result=%+v", err, res)
			}
			if got := cluster.Replicas("staging-payments", "api"); got != 3 {
				t.Fatalf("replicas = %d, want 3", got)
			}

			// A tool error (unknown namespace) comes back as a result with
			// isError set, not as a protocol error: the model gets to read it.
			res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_pods",
				Arguments: map[string]any{"namespace": "nope"}})
			if err != nil {
				t.Fatalf("list_pods on a missing namespace: protocol error %v", err)
			}
			if !res.IsError {
				t.Fatalf("expected a tool error, got %+v", res)
			}
		})
	}
}
