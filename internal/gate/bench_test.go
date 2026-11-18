package gate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/builtbyshailendra/mcp-gate/internal/authz"
	"github.com/builtbyshailendra/mcp-gate/internal/demo"
)

// BenchmarkToolCall measures one allowed tools/call end to end over local
// HTTP, straight to the server and through the gate. The difference is what
// the gate adds: parsing, the Cedar decision, the audit line and the extra hop.
func BenchmarkToolCall(b *testing.B) {
	for _, jsonResp := range []bool{true, false} {
		mode := "sse"
		if jsonResp {
			mode = "json"
		}
		up := httptest.NewServer(demo.Handler(demo.NewServer(demo.NewCluster()), jsonResp))
		engine, err := authz.LoadDir("../../policies", agents, "k8s")
		if err != nil {
			b.Fatal(err)
		}
		u, _ := url.Parse(up.URL)
		g, _ := New(Options{Upstream: u, Engine: func() *authz.Engine { return engine }, Tokens: hashTokens(),
			Audit: nil, Location: ist, Now: func() time.Time { return weekday }})
		gs := httptest.NewServer(g)

		for _, target := range []struct{ name, url string }{{"direct", up.URL}, {"via-gate", gs.URL}} {
			b.Run(mode+"/"+target.name, func(b *testing.B) {
				ctx := context.Background()
				client := mcp.NewClient(&mcp.Implementation{Name: "bench", Version: "0"}, nil)
				cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: target.url, MaxRetries: -1,
					HTTPClient: &http.Client{Transport: bearer{"tok-docs", http.DefaultTransport}}}, nil)
				if err != nil {
					b.Fatal(err)
				}
				defer cs.Close()
				params := &mcp.CallToolParams{Name: "list_pods", Arguments: map[string]any{"namespace": "prod-payments"}}
				for b.Loop() {
					res, err := cs.CallTool(ctx, params)
					if err != nil || res.IsError {
						b.Fatalf("call failed: %v %+v", err, res)
					}
				}
			})
		}
		gs.Close()
		up.Close()
	}
}
