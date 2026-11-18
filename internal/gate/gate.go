// Package gate is the HTTP side of mcp-gate: it sits between agents and an
// MCP server speaking Streamable HTTP, authenticates each agent, checks every
// tools/call with the authz engine, and hides tools an agent can't use.
package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/builtbyshailendra/mcp-gate/internal/audit"
	"github.com/builtbyshailendra/mcp-gate/internal/authz"
)

// Options configure a Gate. Upstream, Engine and Tokens are required.
type Options struct {
	Upstream      *url.URL
	UpstreamToken string               // optional bearer token the gate itself presents upstream
	Engine        func() *authz.Engine // the current rules; read once per request
	Tokens        map[string]string    // hex sha256 of a bearer token -> agent ID

	Audit    *audit.Log
	Metrics  *Metrics
	Logger   *slog.Logger
	Location *time.Location   // for context.clock; default UTC
	Now      func() time.Time // default time.Now

	MaxBodyBytes     int64    // per request; default 1 MiB
	MaxResponseBytes int64    // per buffered reply or SSE event; default 8 MiB
	ExtraMethods     []string // other JSON-RPC methods to pass through unchecked
	Transport        http.RoundTripper
}

// The methods every MCP client needs. tools/call is checked; the rest carry
// no tool execution. Anything else (resources/*, prompts/*, tasks/*) is
// refused unless the operator lists it in ExtraMethods.
var baseMethods = []string{"initialize", "ping", "server/discover", "subscriptions/listen", "tools/list", "tools/call", "logging/setLevel"}

// Gate is an http.Handler.
type Gate struct {
	opts    Options
	allowed map[string]bool
	proxy   *httputil.ReverseProxy
}

type infoKey struct{}

// reqInfo travels in the request context from ServeHTTP to ModifyResponse.
type reqInfo struct {
	agent  string
	method string // JSON-RPC method, or "GET"/"DELETE"
	rpcID  string
}

// New builds a Gate.
func New(opts Options) (*Gate, error) {
	if opts.Upstream == nil || opts.Engine == nil || opts.Tokens == nil {
		return nil, errors.New("gate: Upstream, Engine and Tokens are required")
	}
	if opts.Metrics == nil {
		opts.Metrics = NewMetrics()
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Location == nil {
		opts.Location = time.UTC
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 1 << 20
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = 8 << 20
	}
	if opts.Transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConnsPerHost = 64
		t.ResponseHeaderTimeout = 5 * time.Minute // a tool may take a while before replying
		opts.Transport = t
	}
	g := &Gate{opts: opts, allowed: map[string]bool{}}
	for _, m := range append(baseMethods, opts.ExtraMethods...) {
		g.allowed[m] = true
	}
	up := *opts.Upstream
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The gate's endpoint maps to exactly the upstream URL.
			pr.Out.URL.Scheme, pr.Out.URL.Host = up.Scheme, up.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath, pr.Out.URL.RawQuery = up.Path, up.RawPath, up.RawQuery
			pr.Out.Host = ""
			// The agent's token is for the gate only. The upstream sees the
			// gate's own credential, if any.
			pr.Out.Header.Del("Authorization")
			if opts.UpstreamToken != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+opts.UpstreamToken)
			}
		},
		Transport:      opts.Transport,
		FlushInterval:  -1, // flush every write: SSE must not sit in a buffer
		ModifyResponse: g.modifyResponse,
		ErrorHandler:   g.upstreamError,
	}
	return g, nil
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agent, ok := g.authenticate(r)
	if !ok {
		g.opts.Metrics.Rejected.WithLabelValues("unauthenticated").Inc()
		g.opts.Audit.Write(audit.Event{Kind: "reject", Reason: "missing or unknown bearer token"})
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gate"`)
		http.Error(w, "missing or unknown bearer token", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		g.post(w, r, agent)
	case http.MethodGet, http.MethodDelete:
		// GET opens a server-to-client stream (older protocol versions);
		// DELETE ends a session. Neither runs a tool.
		g.opts.Metrics.Requests.WithLabelValues(r.Method).Inc()
		g.forward(w, r, &reqInfo{agent: agent, method: r.Method}, nil)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gate) authenticate(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(h[len(prefix):])))
	agent, ok := g.opts.Tokens[hex.EncodeToString(sum[:])]
	return agent, ok
}

func (g *Gate) post(w http.ResponseWriter, r *http.Request, agent string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.opts.MaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			g.refuse(w, agent, nil, refuse("too_large", http.StatusRequestEntityTooLarge, "request body is over %d bytes", g.opts.MaxBodyBytes))
			return
		}
		g.refuse(w, agent, nil, refuse("unreadable", http.StatusBadRequest, "could not read the request body"))
		return
	}
	msg, rf := parseMessage(body)
	if rf != nil {
		g.refuse(w, agent, nil, rf)
		return
	}
	var call *callParams
	if msg.Method == "tools/call" {
		if call, rf = parseCallParams(msg); rf != nil {
			g.refuse(w, agent, msg, rf)
			return
		}
	}
	tool := ""
	if call != nil {
		tool = call.Name
	}
	if rf := checkHeaders(r.Header, msg, tool); rf != nil {
		g.refuse(w, agent, msg, rf)
		return
	}

	info := &reqInfo{agent: agent, method: msg.Method, rpcID: idString(msg.ID)}
	switch {
	case msg.Method == "":
		// The agent answering a server request (sampling, elicitation).
		g.opts.Metrics.Requests.WithLabelValues("response").Inc()
		g.forward(w, r, info, body)
	case strings.HasPrefix(msg.Method, "notifications/"):
		g.opts.Metrics.Requests.WithLabelValues("notification").Inc()
		g.forward(w, r, info, body)
	case msg.Method == "tools/call":
		g.opts.Metrics.Requests.WithLabelValues(msg.Method).Inc()
		g.call(w, r, info, msg, call, body)
	case g.allowed[msg.Method]:
		g.opts.Metrics.Requests.WithLabelValues(msg.Method).Inc()
		g.forward(w, r, info, body)
	default:
		g.opts.Metrics.Requests.WithLabelValues("blocked").Inc()
		g.opts.Metrics.Rejected.WithLabelValues("blocked_method").Inc()
		g.opts.Audit.Write(audit.Event{Kind: "reject", Agent: agent, Method: msg.Method, RPCID: info.rpcID,
			Reason: "method is not allowed through the gate"})
		if msg.ID == nil {
			w.WriteHeader(http.StatusAccepted) // a notification gets no reply
			return
		}
		writeJSON(w, http.StatusOK, rpcError(msg.ID, codeMethodNotFound,
			fmt.Sprintf("method %q is not allowed through mcp-gate", msg.Method)))
	}
}

func (g *Gate) call(w http.ResponseWriter, r *http.Request, info *reqInfo, msg *message, call *callParams, body []byte) {
	engine := g.opts.Engine()
	start := time.Now()
	d := engine.AuthorizeCall(info.agent, call.Name, call.Arguments, g.opts.Now(), g.opts.Location)
	took := time.Since(start)

	decision, toolLabel := "deny", call.Name
	if d.Allow {
		decision = "allow"
	}
	if !engine.Declared(toolLabel) {
		toolLabel = "undeclared" // keep metric labels to names from the schema
	}
	g.opts.Metrics.DecisionTime.Observe(took.Seconds())
	g.opts.Metrics.Decisions.WithLabelValues(info.agent, toolLabel, decision).Inc()
	g.opts.Audit.Write(audit.Event{Kind: "call", Agent: info.agent, Method: "tools/call", Tool: call.Name,
		RPCID: info.rpcID, Decision: decision, Policies: d.Policies, Reason: d.Reason,
		ArgNames: argNames(call.Arguments), EvalUS: took.Microseconds()})
	if !d.Allow {
		writeJSON(w, http.StatusOK, denial(msg.ID, d.Policies, d.Reason))
		return
	}
	g.forward(w, r, info, body)
}

func (g *Gate) refuse(w http.ResponseWriter, agent string, msg *message, rf *refusal) {
	g.opts.Metrics.Rejected.WithLabelValues(rf.label).Inc()
	ev := audit.Event{Kind: "reject", Agent: agent, Reason: rf.text}
	var id jsontext.Value
	if msg != nil {
		ev.Method, ev.RPCID, id = msg.Method, idString(msg.ID), msg.ID
	}
	g.opts.Audit.Write(ev)
	writeJSON(w, rf.status, rpcError(id, codeInvalidRequest, rf.text))
}

// forward sends the request upstream. body, if not nil, is the exact bytes
// the gate checked; it's what the upstream receives.
func (g *Gate) forward(w http.ResponseWriter, r *http.Request, info *reqInfo, body []byte) {
	r = r.WithContext(context.WithValue(r.Context(), infoKey{}, info))
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	g.proxy.ServeHTTP(w, r)
}

// modifyResponse filters tools/list replies. A POST for tools/list may come
// back as JSON or as an SSE stream. A GET stream is filtered too: a client
// resuming a dropped stream gets earlier replies replayed on a GET, and one
// of those could be a tools/list reply.
func (g *Gate) modifyResponse(resp *http.Response) error {
	info, _ := resp.Request.Context().Value(infoKey{}).(*reqInfo)
	if info == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	if info.method != "tools/list" && info.method != http.MethodGet {
		return nil
	}
	engine := g.opts.Engine()
	filter := func(data []byte) []byte { return g.filterTools(engine, info.agent, data) }
	switch mediaType(resp.Header.Get("Content-Type")) {
	case "application/json":
		body, err := io.ReadAll(io.LimitReader(resp.Body, g.opts.MaxResponseBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if int64(len(body)) > g.opts.MaxResponseBytes {
			return fmt.Errorf("tools/list reply is over %d bytes", g.opts.MaxResponseBytes)
		}
		out := filter(body)
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	case "text/event-stream":
		resp.Body = newSSEFilter(resp.Body, g.opts.MaxResponseBytes, filter)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	}
	return nil
}

// filterTools removes, from a tools/list result, every tool the agent could
// never call. Anything that isn't a tools/list result passes unchanged.
func (g *Gate) filterTools(e *authz.Engine, agent string, data []byte) []byte {
	if !bytes.Contains(data, []byte(`"tools"`)) {
		return data
	}
	var msg map[string]jsontext.Value
	if jsonv2.Unmarshal(data, &msg) != nil {
		if bytes.Contains(data, []byte(`"result"`)) {
			// It might be a tools/list reply the gate can't read. Don't
			// pass on what it can't check.
			return rpcError(nil, -32603, "mcp-gate could not check the upstream server's reply")
		}
		return data
	}
	var result map[string]jsontext.Value
	if raw, ok := msg["result"]; !ok || jsonv2.Unmarshal(raw, &result) != nil {
		return data
	}
	var tools []jsontext.Value
	if raw, ok := result["tools"]; !ok || jsonv2.Unmarshal(raw, &tools) != nil {
		return data
	}
	kept := make([]jsontext.Value, 0, len(tools))
	var hidden []string
	for _, t := range tools {
		var head struct {
			Name string `json:"name"`
		}
		if jsonv2.Unmarshal(t, &head) == nil && e.Visible(agent, head.Name) {
			kept = append(kept, t)
		} else {
			hidden = append(hidden, head.Name)
		}
	}
	if len(hidden) == 0 {
		return data
	}
	var err error
	if result["tools"], err = jsonv2.Marshal(kept); err != nil {
		return rpcError(nil, -32603, "mcp-gate could not filter the tool list")
	}
	if msg["result"], err = jsonv2.Marshal(result); err != nil {
		return rpcError(nil, -32603, "mcp-gate could not filter the tool list")
	}
	out, err := jsonv2.Marshal(msg)
	if err != nil {
		return rpcError(nil, -32603, "mcp-gate could not filter the tool list")
	}
	g.opts.Metrics.ToolsHidden.WithLabelValues(agent).Add(float64(len(hidden)))
	g.opts.Audit.Write(audit.Event{Kind: "list", Agent: agent, Method: "tools/list", Hidden: hidden})
	return out
}

func (g *Gate) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return // the agent hung up; nothing to tell anyone
	}
	g.opts.Metrics.UpstreamErrors.Inc()
	ev := audit.Event{Kind: "upstream_error", Reason: err.Error()}
	if info, _ := r.Context().Value(infoKey{}).(*reqInfo); info != nil {
		ev.Agent, ev.Method, ev.RPCID = info.agent, info.method, info.rpcID
	}
	g.opts.Audit.Write(ev)
	g.opts.Logger.Warn("upstream request failed", "error", err)
	http.Error(w, "upstream MCP server unavailable", http.StatusBadGateway)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func mediaType(ct string) string {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return mt
}
