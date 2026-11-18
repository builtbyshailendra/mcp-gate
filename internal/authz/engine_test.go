package authz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	ist     = time.FixedZone("IST", 5*3600+1800)
	weekday = time.Date(2026, 11, 18, 11, 0, 0, 0, ist) // a Wednesday
	weekend = time.Date(2026, 11, 21, 11, 0, 0, 0, ist) // a Saturday
)

var testAgents = []Agent{
	{ID: "oncall-bot", Teams: []string{"sre"}, OnCall: true},
	{ID: "helper-bot", Teams: []string{"sre"}},
	{ID: "docs-bot", Teams: []string{"support"}},
}

func load(t *testing.T) *Engine {
	t.Helper()
	e, err := LoadDir("../../policies", testAgents, "k8s")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return e
}

func TestDecisions(t *testing.T) {
	e := load(t)
	cases := []struct {
		name     string
		agent    string
		tool     string
		args     string
		at       time.Time
		allow    bool
		policies []string // the deciding policies; nil means a default deny
		reason   string   // substring of the reason
	}{
		{"anyone can read", "docs-bot", "list_pods", `{"namespace":"prod-payments"}`, weekday, true,
			[]string{"read-tools-for-every-agent"}, ""},
		{"support can't change anything", "docs-bot", "restart_deployment", `{"namespace":"staging-payments","deployment":"api"}`, weekday, false,
			nil, "default deny"},
		{"SRE changes outside prod", "helper-bot", "restart_deployment", `{"namespace":"staging-payments","deployment":"api"}`, weekday, true,
			[]string{"sre-changes-outside-prod"}, ""},
		{"prod needs on-call", "helper-bot", "restart_deployment", `{"namespace":"prod-payments","deployment":"api"}`, weekday, false,
			nil, "default deny"},
		{"on-call restarts prod", "oncall-bot", "restart_deployment", `{"namespace":"prod-payments","deployment":"api"}`, weekday, true,
			[]string{"prod-changes-need-on-call"}, ""},
		{"weekend freeze beats on-call", "oncall-bot", "restart_deployment", `{"namespace":"prod-payments","deployment":"api"}`, weekend, false,
			[]string{"weekend-prod-freeze"}, "frozen"},
		{"weekend is fine outside prod", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api","replicas":2}`, weekend, true,
			[]string{"sre-changes-outside-prod"}, ""},
		{"never scale prod to zero", "oncall-bot", "scale_deployment", `{"namespace":"prod-payments","deployment":"api","replicas":0}`, weekday, false,
			[]string{"never-scale-prod-to-zero"}, "takes the service down"},
		{"replica cap", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api","replicas":25}`, weekday, false,
			[]string{"replica-cap"}, "above 20"},
		{"two forbids both reported", "oncall-bot", "scale_deployment", `{"namespace":"prod-payments","deployment":"api","replicas":0}`, weekend, false,
			[]string{"never-scale-prod-to-zero", "weekend-prod-freeze"}, ""},
		{"3.0 is read as the integer 3", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api","replicas":3.0}`, weekday, true,
			[]string{"sre-changes-outside-prod"}, ""},
		{"destructive is never allowed", "oncall-bot", "delete_namespace", `{"namespace":"dev-sandbox"}`, weekday, false,
			[]string{"no-destructive-tools"}, "never go through the gate"},
		{"undeclared tool", "oncall-bot", "exec_shell", `{"cmd":"rm -rf /"}`, weekday, false,
			nil, "not declared"},
		{"unknown agent", "intruder", "list_pods", `{"namespace":"dev-sandbox"}`, weekday, false,
			nil, "not registered"},
		{"extra argument", "oncall-bot", "restart_deployment", `{"namespace":"staging-payments","deployment":"api","force":true}`, weekday, false,
			nil, "don't match"},
		{"wrong type", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api","replicas":"3"}`, weekday, false,
			nil, "don't match"},
		{"missing argument", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api"}`, weekday, false,
			nil, "don't match"},
		{"arguments not an object", "oncall-bot", "list_pods", `["prod-payments"]`, weekday, false,
			nil, "JSON object"},
		{"optional argument given", "docs-bot", "get_logs", `{"namespace":"dev-sandbox","pod":"scratch-0","tail":3}`, weekday, true,
			[]string{"read-tools-for-every-agent"}, ""},
		{"optional argument as null", "docs-bot", "get_logs", `{"namespace":"dev-sandbox","pod":"scratch-0","tail":null}`, weekday, true,
			[]string{"read-tools-for-every-agent"}, ""},
		{"undeclared argument as null", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api","replicas":3,"extra":null}`, weekday, false,
			nil, "doesn't declare it as optional"},
		{"required argument as null", "oncall-bot", "scale_deployment", `{"namespace":"staging-payments","deployment":"api","replicas":null}`, weekday, false,
			nil, "doesn't declare it as optional"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.AuthorizeCall(tc.agent, tc.tool, json.RawMessage(tc.args), tc.at, ist)
			t.Logf("allow=%v policies=%v reason=%s", d.Allow, d.Policies, d.Reason)
			if d.Allow != tc.allow {
				t.Fatalf("allow = %v, want %v (reason: %s)", d.Allow, tc.allow, d.Reason)
			}
			if !slices.Equal(d.Policies, tc.policies) {
				t.Fatalf("policies = %v, want %v", d.Policies, tc.policies)
			}
			if tc.reason != "" && !strings.Contains(d.Reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", d.Reason, tc.reason)
			}
		})
	}
}

func TestVisibility(t *testing.T) {
	e := load(t)
	want := map[string][]string{
		"docs-bot":   {"get_logs", "list_pods"},
		"helper-bot": {"get_logs", "list_pods", "restart_deployment", "scale_deployment"},
		"oncall-bot": {"get_logs", "list_pods", "restart_deployment", "scale_deployment"},
		"intruder":   nil,
	}
	all := append(e.Tools(), "exec_shell")
	for agent, tools := range want {
		var got []string
		for _, tool := range all {
			if e.Visible(agent, tool) {
				got = append(got, tool)
			}
		}
		if !slices.Equal(got, tools) {
			t.Errorf("%s sees %v, want %v", agent, got, tools)
		}
	}
}

// writePolicies copies the real schema plus one extra policy file into a
// temp dir, so each test can break one thing.
func writePolicies(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"schema.cedarschema", "baseline.cedar"} {
		b, err := os.ReadFile(filepath.Join("../../policies", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.cedar"), []byte(extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadRejectsBadPolicies(t *testing.T) {
	cases := map[string]struct{ policy, want string }{
		"typo in an attribute": {`@id("typo") permit (principal, action == Action::"restart_deployment", resource) when { context.args.namespce == "x" };`,
			"doesn't fit the schema"},
		"attribute another tool lacks": {`@id("bad-group") permit (principal, action in Action::"read", resource) when { context.args.replicas > 1 };`,
			"doesn't fit the schema"},
		"unknown action": {`@id("ghost") permit (principal, action == Action::"exec_shell", resource);`,
			"doesn't fit the schema"},
		"syntax error":     {`permit (principal, action, resource) when { context.args.namespace == };`, "extra.cedar"},
		"duplicate policy": {`@id("read-tools-for-every-agent") permit (principal, action, resource);`, "used in"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadDir(writePolicies(t, tc.policy), testAgents, "k8s")
			if err == nil {
				t.Fatal("expected the load to fail")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsDuplicateAgents(t *testing.T) {
	agents := append(slices.Clone(testAgents), Agent{ID: "docs-bot"})
	if _, err := LoadDir("../../policies", agents, "k8s"); err == nil {
		t.Fatal("expected duplicate agent IDs to fail")
	}
}
