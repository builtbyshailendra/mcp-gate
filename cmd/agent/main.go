// Command agent is a tiny MCP client for trying the gate by hand. It plays
// the part of an AI agent: list the tools it can see, or call one.
//
//	agent -token demo-docs-token tools
//	agent -token demo-oncall-token call scale_deployment '{"namespace":"prod-payments","deployment":"api","replicas":5}'
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func main() {
	url := flag.String("url", "http://127.0.0.1:8081/mcp", "gate (or server) endpoint")
	token := flag.String("token", "", "bearer token")
	version := flag.String("protocol", "", "MCP protocol version (default: the SDK's latest)")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agent -token T tools | call <tool> '<json args>'")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "try-agent", Version: "0.1.0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: *url, MaxRetries: -1,
		HTTPClient: &http.Client{Transport: bearer{*token}}}, &mcp.ClientSessionOptions{ProtocolVersion: *version})
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer cs.Close()

	switch flag.Arg(0) {
	case "tools":
		res, err := cs.ListTools(ctx, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tools/list:", err)
			os.Exit(1)
		}
		for _, t := range res.Tools {
			fmt.Printf("%-20s %s\n", t.Name, t.Description)
		}
	case "call":
		if flag.NArg() != 3 {
			fmt.Fprintln(os.Stderr, "usage: agent call <tool> '<json args>'")
			os.Exit(2)
		}
		var args map[string]any
		if err := json.Unmarshal([]byte(flag.Arg(2)), &args); err != nil {
			fmt.Fprintln(os.Stderr, "args:", err)
			os.Exit(2)
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: flag.Arg(1), Arguments: args})
		if err != nil {
			fmt.Fprintln(os.Stderr, "tools/call:", err)
			os.Exit(1)
		}
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				fmt.Println(tc.Text)
			}
		}
		if res.IsError {
			os.Exit(3)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", flag.Arg(0))
		os.Exit(2)
	}
}
