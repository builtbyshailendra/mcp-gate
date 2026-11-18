# mcp-gate

A policy gate for AI agents' tool calls. Agents connect to `mcp-gate` instead of straight to an MCP server; every `tools/call` is checked against policies written in [Cedar](https://www.cedarpolicy.com/) before it reaches the tool.

Status: being built step by step, locally. Not published.

## Build log

### Step 1: a demo MCP server to protect

`internal/demo` is a fake Kubernetes cluster behind five MCP tools, built on the official Go SDK (`github.com/modelcontextprotocol/go-sdk` v1.8.0): `list_pods`, `get_logs`, `restart_deployment`, `scale_deployment`, `delete_namespace`. It runs in memory and touches no real cluster.

The test connects a real SDK client four ways: the newest protocol (2026-07-28, stateless, `server/discover`) and the last session-based one (2025-11-25), each with JSON replies and with SSE replies. The gate has to handle all four, so it needs a server that can produce all four.

What broke: the first run hung for 10 minutes. The test closed the HTTP test server while the client's standalone SSE stream (a long-lived GET) was still open, and `httptest.Server.Close` waits for every connection. Fixed by registering cleanups so the session closes first.

### Step 2: Cedar policies and the decision engine

`internal/authz` turns a tool call into a Cedar request and decides it, using `github.com/cedar-policy/cedar-go` v1.9.2:

| Cedar part | What it is here |
|---|---|
| principal | `Agent::"oncall-bot"`, a member of `Team::"sre"`, with an `on_call` attribute |
| action | one per tool (`Action::"scale_deployment"`), each in a risk group: `read`, `write`, `destructive` |
| resource | the upstream server, `Server::"k8s"` |
| context | the call's arguments as `context.args`, plus `context.clock` (hour and weekday in the gate's time zone) |

The policies live in `policies/`: every agent may read; SRE agents may change things outside prod; in prod only an on-call agent may; never scale prod to zero; never above 20 replicas; no prod changes at weekends; destructive tools never. Each policy has an `@id` and a `@reason`, and a denied agent is told the reason.

Choices worth explaining:
- **Risk groups come from the gate's schema, not the server.** MCP tools can describe themselves as read-only or destructive, but those are hints from the server being protected. The gate ignores them.
- **Everything is type-checked against `policies/schema.cedarschema`.** A policy that reads `context.args.namespce` (typo) fails to load. A call whose arguments don't match the tool's declaration (an extra `force: true`, `replicas: "3"` as a string, a missing argument) is denied before any policy runs.
- **Fail closed on evaluation errors.** Cedar skips a policy that errors. If that policy were a forbid, the call could get through, so the gate denies any call where a policy errored.
- **`tools/list` visibility** uses a second, scope-only copy of the policies: permits with their conditions removed, and only the forbids that have no conditions. A tool is listed if some permit could ever apply. It's a convenience for the model; the real check runs on every call.
- **No argument values in reasons.** Cedar's validation error quotes the arguments. Those could hold secrets, so the gate's reason says what the schema expects instead.

Tests: 20 decision cases (each checks allow/deny and *which* policies decided), visibility per agent, and five ways a bad policy file must fail to load (typo, an attribute some tools in a group lack, an unknown action, a syntax error, a duplicate ID).
