package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/builtbyshailendra/mcp-gate/internal/audit"
	"github.com/builtbyshailendra/mcp-gate/internal/authz"
	"github.com/builtbyshailendra/mcp-gate/internal/demo"
)

var (
	ist     = time.FixedZone("IST", 5*3600+1800)
	weekday = time.Date(2026, 11, 18, 11, 0, 0, 0, ist) // a Wednesday

	agents = []authz.Agent{
		{ID: "oncall-bot", Teams: []string{"sre"}, OnCall: true},
		{ID: "helper-bot", Teams: []string{"sre"}},
		{ID: "docs-bot", Teams: []string{"support"}},
	}
	tokenOf = map[string]string{"oncall-bot": "tok-oncall", "helper-bot": "tok-helper", "docs-bot": "tok-docs"}
)

func hashTokens() map[string]string {
	out := map[string]string{}
	for agent, tok := range tokenOf {
		sum := sha256.Sum256([]byte(tok))
		out[hex.EncodeToString(sum[:])] = agent
	}
	return out
}

// syncBuffer collects audit lines from concurrent requests.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) events(t *testing.T) []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

type env struct {
	cluster  *demo.Cluster
	gateURL  string
	audit    *syncBuffer
	metrics  *Metrics
	upPosts  *atomic.Int64 // POSTs that reached the upstream
	lastBody *atomic.Value // the last POST body the upstream received
}

func newEnv(t *testing.T, jsonResp bool) *env {
	t.Helper()
	e := &env{cluster: demo.NewCluster(), audit: &syncBuffer{}, metrics: NewMetrics(),
		upPosts: &atomic.Int64{}, lastBody: &atomic.Value{}}
	h := demo.Handler(demo.NewServer(e.cluster), jsonResp)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			e.upPosts.Add(1)
			b, _ := io.ReadAll(r.Body)
			e.lastBody.Store(b)
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(up.Close)
	engine, err := authz.LoadDir("../../policies", agents, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(up.URL)
	g, err := New(Options{Upstream: u, Engine: func() *authz.Engine { return engine }, Tokens: hashTokens(),
		Audit: audit.New(e.audit), Metrics: e.metrics, Location: ist, Now: func() time.Time { return weekday }})
	if err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(g)
	t.Cleanup(gs.Close)
	e.gateURL = gs.URL
	return e
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func connect(t *testing.T, url, token, version string) (*mcp.ClientSession, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, MaxRetries: -1,
		HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}}},
		&mcp.ClientSessionOptions{ProtocolVersion: version})
	if err == nil {
		t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, err
}

func mustConnect(t *testing.T, url, agent, version string) *mcp.ClientSession {
	t.Helper()
	cs, err := connect(t, url, tokenOf[agent], version)
	if err != nil {
		t.Fatalf("%s connect: %v", agent, err)
	}
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (bool, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", tool, err)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	return !res.IsError, text
}

var transports = []struct {
	name     string
	version  string
	jsonResp bool
}{
	{"latest+sse", "", false},
	{"latest+json", "", true},
	{"2025-11-25+sse", "2025-11-25", false},
	{"2025-11-25+json", "2025-11-25", true},
}

func TestThroughTheGate(t *testing.T) {
	for _, tc := range transports {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.jsonResp)

			docs := mustConnect(t, e.gateURL, "docs-bot", tc.version)
			if got, want := toolNames(t, docs), []string{"get_logs", "list_pods"}; !slices.Equal(got, want) {
				t.Fatalf("docs-bot sees %v, want %v", got, want)
			}
			if ok, text := call(t, docs, "list_pods", map[string]any{"namespace": "prod-payments"}); !ok {
				t.Fatalf("docs-bot list_pods denied: %s", text)
			}
			// A hidden tool is still enforced if the agent calls it anyway.
			ok, text := call(t, docs, "scale_deployment", map[string]any{"namespace": "staging-payments", "deployment": "api", "replicas": 2})
			if ok || !strings.Contains(text, "Denied by mcp-gate") || !strings.Contains(text, "default deny") {
				t.Fatalf("docs-bot scale: ok=%v text=%q", ok, text)
			}
			if r := e.cluster.Replicas("staging-payments", "api"); r != 1 {
				t.Fatalf("a denied call changed the cluster: replicas=%d", r)
			}

			oncall := mustConnect(t, e.gateURL, "oncall-bot", tc.version)
			if got, want := toolNames(t, oncall), []string{"get_logs", "list_pods", "restart_deployment", "scale_deployment"}; !slices.Equal(got, want) {
				t.Fatalf("oncall-bot sees %v, want %v", got, want)
			}
			if ok, text := call(t, oncall, "scale_deployment", map[string]any{"namespace": "prod-payments", "deployment": "api", "replicas": 5}); !ok {
				t.Fatalf("on-call scale in prod denied: %s", text)
			}
			if r := e.cluster.Replicas("prod-payments", "api"); r != 5 {
				t.Fatalf("replicas = %d, want 5", r)
			}
			ok, text = call(t, oncall, "scale_deployment", map[string]any{"namespace": "prod-payments", "deployment": "api", "replicas": 0})
			if ok || !strings.Contains(text, "never-scale-prod-to-zero") {
				t.Fatalf("scale prod to zero: ok=%v text=%q", ok, text)
			}
			if r := e.cluster.Replicas("prod-payments", "api"); r != 5 {
				t.Fatalf("a denied call changed the cluster: replicas=%d", r)
			}
			if ok, _ := call(t, oncall, "delete_namespace", map[string]any{"namespace": "dev-sandbox"}); ok || !e.cluster.HasNamespace("dev-sandbox") {
				t.Fatal("delete_namespace got through")
			}

			helper := mustConnect(t, e.gateURL, "helper-bot", tc.version)
			if ok, _ := call(t, helper, "restart_deployment", map[string]any{"namespace": "prod-checkout", "deployment": "web"}); ok {
				t.Fatal("helper-bot (not on call) restarted prod")
			}

			// Every decision is in the audit log with the policy that made it,
			// and argument names but never values.
			var calls []audit.Event
			for _, ev := range e.audit.events(t) {
				if ev.Kind == "call" {
					calls = append(calls, ev)
				}
			}
			if len(calls) != 6 {
				t.Fatalf("audit has %d call events, want 6: %+v", len(calls), calls)
			}
			zero := calls[3]
			if zero.Decision != "deny" || !slices.Equal(zero.Policies, []string{"never-scale-prod-to-zero"}) ||
				!slices.Equal(zero.ArgNames, []string{"deployment", "namespace", "replicas"}) {
				t.Fatalf("audit for scale-to-zero: %+v", zero)
			}
			if got := testutil.ToFloat64(e.metrics.Decisions.WithLabelValues("oncall-bot", "delete_namespace", "deny")); got != 1 {
				t.Fatalf("deny metric = %v, want 1", got)
			}
			if got := testutil.ToFloat64(e.metrics.ToolsHidden.WithLabelValues("docs-bot")); got != 3 {
				t.Fatalf("hidden-tools metric for docs-bot = %v, want 3", got)
			}
		})
	}
}

func TestUnknownTokenCannotConnect(t *testing.T) {
	e := newEnv(t, true)
	if _, err := connect(t, e.gateURL, "not-a-real-token", ""); err == nil {
		t.Fatal("connected with a bad token")
	}
	resp, err := http.Post(e.gateURL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("status %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if e.upPosts.Load() != 0 {
		t.Fatal("an unauthenticated request reached the upstream")
	}
}

func post(t *testing.T, url, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-oncall")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Each of these is a way to make the gate and the server read different
// things into the same request. None may reach the upstream.
func TestAmbiguousRequestsAreRefused(t *testing.T) {
	e := newEnv(t, true)
	cases := []struct {
		name    string
		body    string
		headers map[string]string
		status  int
		want    string
	}{
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","arguments":{"namespace":"dev-sandbox"}}}]`,
			nil, 400, "batches"},
		{"duplicate tool name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","name":"delete_namespace","arguments":{"namespace":"dev-sandbox"}}}`,
			nil, 400, "repeats a member"},
		{"duplicate argument", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scale_deployment","arguments":{"namespace":"staging-payments","namespace":"prod-payments","deployment":"api","replicas":0}}}`,
			nil, 400, "repeats a member"},
		{"Method in another case", `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"delete_namespace","arguments":{"namespace":"dev-sandbox"}}}`,
			nil, 400, "unexpected top-level member"},
		{"Name in another case", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","Name":"delete_namespace","arguments":{"namespace":"dev-sandbox"}}}`,
			nil, 400, "only by case"},
		{"long s folds to s", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","arguments":{"namespace":"dev-sandbox"},"argumentſ":{"namespace":"prod-payments"}}}`,
			nil, 400, "only by case"},
		{"invalid UTF-8", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"list_pods\xff\",\"arguments\":{}}}",
			nil, 400, "not valid JSON"},
		{"Mcp-Name header disagrees", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_namespace","arguments":{"namespace":"dev-sandbox"}}}`,
			map[string]string{"Mcp-Name": "list_pods"}, 400, "Mcp-Name"},
		{"Mcp-Method header disagrees", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_namespace","arguments":{"namespace":"dev-sandbox"}}}`,
			map[string]string{"Mcp-Method": "tools/list"}, 400, "Mcp-Method"},
		{"tools/call without an id", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_pods","arguments":{"namespace":"dev-sandbox"}}}`,
			nil, 400, "with an id"},
		{"too large", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", 2<<20) + `"}}`,
			nil, 413, "over"},
		{"method the gate doesn't know how to check", `{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`,
			nil, 200, "not allowed through mcp-gate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := e.upPosts.Load()
			status, body := post(t, e.gateURL, tc.body, tc.headers)
			if status != tc.status || !strings.Contains(body, tc.want) {
				t.Fatalf("status %d body %q; want %d containing %q", status, body, tc.status, tc.want)
			}
			if e.upPosts.Load() != before {
				t.Fatal("the request reached the upstream")
			}
		})
	}
}

func TestUpstreamGetsTheCheckedBytes(t *testing.T) {
	e := newEnv(t, true)
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_pods","arguments":{"namespace":"dev-sandbox"}}}`
	post(t, e.gateURL, body, nil)
	got, _ := e.lastBody.Load().([]byte)
	if string(got) != body {
		t.Fatalf("upstream got %q, want the exact bytes the gate checked", got)
	}
}

func TestUpstreamDown(t *testing.T) {
	engine, err := authz.LoadDir("../../policies", agents, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(dead.URL)
	dead.Close()
	buf := &syncBuffer{}
	m := NewMetrics()
	g, _ := New(Options{Upstream: u, Engine: func() *authz.Engine { return engine }, Tokens: hashTokens(), Audit: audit.New(buf), Metrics: m})
	gs := httptest.NewServer(g)
	defer gs.Close()
	status, _ := post(t, gs.URL, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", status)
	}
	if testutil.ToFloat64(m.UpstreamErrors) != 1 {
		t.Fatal("upstream error not counted")
	}
	evs := buf.events(t)
	if len(evs) != 1 || evs[0].Kind != "upstream_error" || evs[0].Agent != "oncall-bot" {
		t.Fatalf("audit: %+v", evs)
	}
}

func TestFilterTools(t *testing.T) {
	engine, err := authz.LoadDir("../../policies", agents, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	g, _ := New(Options{Upstream: &url.URL{}, Engine: func() *authz.Engine { return engine }, Tokens: map[string]string{}})
	list := `{"jsonrpc":"2.0","id":2,"result":{"nextCursor":"abc","tools":[{"name":"list_pods","inputSchema":{}},{"name":"delete_namespace","inputSchema":{}},{"name":"exec_shell","inputSchema":{}},{"inputSchema":{}}]}}`
	out := string(g.filterTools(engine, "oncall-bot", []byte(list)))
	if !strings.Contains(out, `"list_pods"`) || strings.Contains(out, "delete_namespace") || strings.Contains(out, "exec_shell") ||
		strings.Count(out, "inputSchema") != 1 || !strings.Contains(out, `"nextCursor":"abc"`) {
		t.Fatalf("filtered: %s", out)
	}
	for _, unchanged := range []string{
		`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`,
		`{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{"tools":[{"name":"x"}]}}`,
	} {
		if got := string(g.filterTools(engine, "docs-bot", []byte(unchanged))); got != unchanged {
			t.Errorf("changed %s into %s", unchanged, got)
		}
	}
	broken := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"delete_namespace"}],"tools":[]}}`
	if got := string(g.filterTools(engine, "docs-bot", []byte(broken))); strings.Contains(got, "delete_namespace") {
		t.Fatalf("an unreadable tools/list reply was passed on: %s", got)
	}
}
