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

### Step 3: the gate

`internal/gate` is an `http.Handler` in front of the upstream MCP server (Streamable HTTP). For every request it:

1. **Authenticates the agent** from `Authorization: Bearer …`. The config stores only SHA-256 hashes of tokens. The agent's token is removed before forwarding, so the tool server never sees it.
2. **Parses the JSON-RPC message strictly** (Go 1.27's `encoding/json/v2` and `jsontext`) and refuses anything two parsers could read differently:

   | Trick | Why it matters | Gate's answer |
   |---|---|---|
   | `"name"` twice in one object | gate reads one, server reads the other | 400 (RFC 7493: names must be unique) |
   | `"Method"` or `"Name"` instead of the lowercase key | Go's `encoding/json` v1 matches keys case-insensitively | 400 |
   | `"argumentſ"` (long s) | v1's case folding turns ſ into s | 400 |
   | `Mcp-Name: list_pods` header, `delete_namespace` in the body | MCP 2026-07-28 copies method and tool name into headers so proxies can route on them | 400 if they disagree |
   | JSON-RPC batch | every element would need its own decision; MCP dropped batches in 2025-06-18 | 400 |
   | invalid UTF-8, oversized body | | 400, 413 |

   The upstream then receives exactly the bytes the gate checked.
3. **Decides `tools/call`** with the Step 2 engine. A denial goes back to the agent as a normal tool result with `isError: true`, e.g. `Denied by mcp-gate (policy never-scale-prod-to-zero): Scaling a prod deployment to zero replicas takes the service down.` That's how MCP reports tool failures, so the model can read it and change course.
4. **Refuses methods it can't check**: `resources/*`, `prompts/*` and `tasks/*` are refused unless the operator lists them. Lifecycle methods, `tools/list` and notifications pass through.
5. **Filters `tools/list` replies**, both plain JSON and SSE streams, and also GET streams, because a client resuming a dropped stream can get an old `tools/list` reply replayed there. The SSE filter rewrites one event at a time, so long-lived streams aren't held back.
6. **Audits and counts**: one JSON line per decision (agent, tool, decision, deciding policies, argument *names* only), plus Prometheus counters with label values taken only from the config and schema.

Tests (24, all on real SDK clients or raw HTTP, no mocks of the gate):
- three agents through the gate in all four protocol/transport combinations: what each sees in `tools/list`, which calls pass, and that denied calls leave the fake cluster unchanged
- each trick in the table above, plus the check that it never reached the upstream
- an unknown token, the upstream being down (502, audited), the filter on edge cases, and the SSE filter's streaming behaviour

What broke: nothing in the tests on the first full run. `go vet` first failed because `go mod tidy` in Step 1 had dropped modules that later code needed.
