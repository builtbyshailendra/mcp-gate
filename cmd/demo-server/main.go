// Command demo-server runs the fake-cluster MCP server on a local port.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/builtbyshailendra/mcp-gate/internal/demo"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8090", "address to listen on")
	jsonResp := flag.Bool("json", false, "reply with application/json instead of text/event-stream")
	flag.Parse()

	h := demo.Handler(demo.NewServer(demo.NewCluster()), *jsonResp)
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	log.Printf("demo MCP server on http://%s/mcp (%s)", *addr, demo.Describe())
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
