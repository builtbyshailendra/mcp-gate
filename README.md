# mcp-gate

A policy gate for AI agents' tool calls. Agents connect to `mcp-gate` instead of straight to an MCP server; every `tools/call` is checked against policies written in [Cedar](https://www.cedarpolicy.com/) before it reaches the tool.

Status: being built step by step, locally. Not published.

## Build log

### Step 1: a demo MCP server to protect

`internal/demo` is a fake Kubernetes cluster behind five MCP tools, built on the official Go SDK (`github.com/modelcontextprotocol/go-sdk` v1.8.0): `list_pods`, `get_logs`, `restart_deployment`, `scale_deployment`, `delete_namespace`. It runs in memory and touches no real cluster.

The test connects a real SDK client four ways: the newest protocol (2026-07-28, stateless, `server/discover`) and the last session-based one (2025-11-25), each with JSON replies and with SSE replies. The gate has to handle all four, so it needs a server that can produce all four.

What broke: the first run hung for 10 minutes. The test closed the HTTP test server while the client's standalone SSE stream (a long-lived GET) was still open, and `httptest.Server.Close` waits for every connection. Fixed by registering cleanups so the session closes first.
