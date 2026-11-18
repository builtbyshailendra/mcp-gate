# Learning notes: mcp-gate

What this project teaches, in plain words, and how to check you can explain it yourself. Read it with the code open.

## 1. The problem

An AI agent with tools can do real things: restart services, move money, delete data. The model decides which tool to call, and models can be wrong, confused, or manipulated by text they read (prompt injection). So something outside the model has to decide what it's allowed to do.

`mcp-gate` is that something: a proxy between agents and a tool server. The agent can ask for anything; the gate checks each request against written rules before it reaches the tool.

## 2. MCP in five minutes

The Model Context Protocol is how AI applications talk to tool servers.

- **Messages are JSON-RPC 2.0**: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scale_deployment","arguments":{...}}}`. A request has an `id` and expects a reply; a notification has no `id`.
- **Two methods matter here**: `tools/list` (what tools exist, with JSON Schemas for their arguments) and `tools/call` (run one).
- **Streamable HTTP transport**: the client POSTs each message. The server replies with plain JSON *or* opens a Server-Sent Events stream on that POST and sends the reply (plus any progress or requests back to the client) as events.
- **Two generations are live at once**, and the gate handles both:
  - up to 2025-11-25: an `initialize` handshake creates a session (`Mcp-Session-Id` header); a GET opens a long-lived stream for server messages.
  - 2026-07-28: stateless. `server/discover` replaces the handshake, and clients copy the method and tool name into `Mcp-Method` / `Mcp-Name` headers so proxies can route without reading the body.
- **Tool errors vs protocol errors**: a tool that fails returns a normal result with `isError: true`, so the model can read what went wrong. Protocol errors (unknown method, bad JSON) are JSON-RPC `error` replies. The gate sends denials as tool errors on purpose.

Where it is in the code: `internal/demo` (a server built with the official Go SDK), `internal/gate/message.go` (parsing), `internal/gate/stream.go` (SSE).

## 3. Cedar in five minutes

Cedar is a policy language (made by AWS, open source, used by Amazon Verified Permissions). A request has four parts, PARC:

| Part | Here |
|---|---|
| **P**rincipal: who | `Agent::"oncall-bot"`, in `Team::"sre"` |
| **A**ction: what | `Action::"scale_deployment"`, in the group `Action::"write"` |
| **R**esource: on what | `Server::"k8s"` |
| **C**ontext: everything else | `context.args.replicas`, `context.clock.weekday` |

Rules that make Cedar easy to reason about:
1. **Default deny.** No matching `permit` means no.
2. **Forbid wins.** One matching `forbid` beats any number of permits. Guardrails are forbids.
3. **Order doesn't matter.** Policies are a set, not a list of if-statements.
4. **A schema makes it type-checked.** `policies/schema.cedarschema` says which actions exist, what context each one gets, and which attributes agents have. Policies are checked against it when they load, and requests before they're decided.

Features used: `in` (group membership, for teams and action groups), `like "prod-*"` (wildcard match), `&&`, `!`, `@id` and `@reason` annotations.

Why not just `if` statements in Go? Policies can be read, reviewed and tested by people who don't read Go; they change without a rebuild (hot reload); the engine can tell you *which* rule decided; and the language is deliberately limited (no loops, no I/O), so rules always finish fast and can be analysed.

Alternatives: OPA/Rego (more general, harder to analyse), OpenFGA/Zanzibar (relationship-based: "who can see this document"). Cedar suits "who may do what, under which conditions".

## 4. Go things this project uses

| Thing | Where | One-line idea |
|---|---|---|
| `http.Handler` | `gate.Gate.ServeHTTP` | anything with `ServeHTTP` can serve HTTP; the gate is one |
| `httputil.ReverseProxy` | `gate.New` | forwarding with hooks: `Rewrite` (outgoing request), `ModifyResponse`, `ErrorHandler` |
| goroutine + `io.Pipe` | `stream.go` | a background goroutine rewrites the SSE stream while the proxy reads from the pipe |
| `context.Context` | everywhere | carries cancellation and request-scoped values (`reqInfo`) |
| `atomic.Pointer[T]` | `authz.Store` | swap the whole rule set in one step; readers never see half a reload |
| generics | `mcp.AddTool[In, Out]` | the SDK builds each tool's JSON Schema from a Go struct |
| `encoding/json/v2`, `jsontext` | `message.go` | Go 1.27's strict JSON: case-sensitive, rejects duplicate keys |
| table-driven tests, `t.Run` | all tests | one loop, many cases, each named |
| `t.Cleanup` order | `demo/cluster_test.go` | cleanups run last-in first-out, which is why Step 1's hang was fixed by order |
| native fuzzing | `fuzz_test.go` | `go test -fuzz` mutates inputs to break a property you state |
| `b.Loop()` benchmarks | `bench_test.go` | the Go 1.24+ way to write a benchmark loop |

## 5. Security ideas worth being able to explain

- **Parser differentials.** If the gate and the server read the same bytes differently, an attacker shows the gate one call and runs another: duplicate keys, `Method` vs `method`, `ſ` folding to `s`. The fix is to refuse ambiguity, not to guess, and the fuzz test checks that whatever the gate accepts, a lenient parser reads the same way.
- **Fail closed.** A policy that errors, a policy file that won't load, a reply the gate can't parse: each ends in "no", never in "probably fine".
- **Don't trust the thing you're protecting.** MCP tools describe themselves (`readOnlyHint`, `destructiveHint`), but a compromised server can lie. Risk groups live in the gate's schema.
- **Hiding isn't enforcing.** Filtering `tools/list` helps the model and reveals less, but an agent can still call a hidden tool by name. Every call is checked regardless.
- **Token passthrough.** The agent's token stops at the gate; forwarding it would let the tool server act as the agent elsewhere (a "confused deputy").
- **Audit without secrets.** The log records argument *names*, never values.
- **The gate can be bypassed by the network.** If agents can reach the tool server directly, policies don't matter. The demo showed it; production needs network isolation.

## 6. Explain it without notes

Answer out loud, then check against the code.

1. Walk through what happens, step by step, when docs-bot calls `scale_deployment`.
2. Why does a denial come back as a tool result with `isError` instead of a JSON-RPC error?
3. What's the difference between `permit ... when {...}` and `forbid ... when {...}`, and why are the guardrails forbids?
4. The weekend-freeze case at "Friday 23:30 in India" passes, though it's Friday 18:00 UTC. Why does the time zone matter, and where is it set?
5. How does `tools/list` filtering decide what an agent sees? Why is it allowed to be approximate?
6. Give three ways to make two JSON parsers disagree, and say what the gate does about each.
7. What did the two fuzz failures in Step 5 find, and why was each original behaviour unsafe?
8. A policy file with a typo is saved while the gate is running. What happens, and how would you notice?
9. Why does the gate strip the agent's `Authorization` header before forwarding?
10. What can't the gate protect against? (Name at least two.)
11. Why is the SSE filter written with a goroutine and a pipe, not by reading the whole body first?
12. What do the benchmark numbers in the README mean, and what don't they tell you?

## 7. Your turn (exercises)

Each one is small and has a test you can add next to the existing ones.

1. **New guardrail:** helper-bot may scale only up to 5 replicas. Write it as a forbid, add two cases to `policies/tests.yaml`, run `mcp-gate test`.
2. **New tool:** add `rollback_deployment` to the demo server, declare it in the schema in the `write` group, and show that SRE agents see it and support agents don't.
3. **Rate limit:** no agent may make more than 5 write calls a minute. Where does that belong: Cedar or Go? (Hint: Cedar has no state.) Build it in Go and pass the result into `context`.
4. **Approval:** prod restarts need a human's OK. Sketch how the gate could hold the call and ask, and what the agent sees while it waits.
