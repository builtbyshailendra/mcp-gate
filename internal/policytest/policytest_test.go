package policytest

import (
	"strings"
	"testing"
	"time"

	"github.com/builtbyshailendra/mcp-gate/internal/authz"
)

var agents = []authz.Agent{
	{ID: "oncall-bot", Teams: []string{"sre"}, OnCall: true},
	{ID: "helper-bot", Teams: []string{"sre"}},
	{ID: "docs-bot", Teams: []string{"support"}},
}

func TestShippedCasesPass(t *testing.T) {
	e, err := authz.LoadDir("../../policies", agents, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load("../../policies/tests.yaml")
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Kolkata")
	for _, r := range Run(e, cases, loc) {
		if !r.Pass() {
			t.Errorf("%s: %s", r.Case.Name, strings.Join(r.Problems, "; "))
		}
	}
}

func TestWrongExpectationsAreCaught(t *testing.T) {
	e, err := authz.LoadDir("../../policies", agents, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	no := false
	cases := []Case{
		{Name: "wrong decision", Agent: "docs-bot", Tool: "list_pods", Args: map[string]any{"namespace": "x"},
			At: "2026-11-18T11:00:00+05:30", Expect: "deny"},
		{Name: "wrong policy", Agent: "docs-bot", Tool: "list_pods", Args: map[string]any{"namespace": "x"},
			At: "2026-11-18T11:00:00+05:30", Expect: "allow", Policies: []string{"sre-changes-outside-prod"}},
		{Name: "wrong visibility", Agent: "docs-bot", Tool: "list_pods", Args: map[string]any{"namespace": "x"},
			At: "2026-11-18T11:00:00+05:30", Expect: "allow", Visible: &no},
		{Name: "bad time", Agent: "docs-bot", Tool: "list_pods", At: "Wednesday", Expect: "allow"},
	}
	for _, r := range Run(e, cases, time.UTC) {
		if r.Pass() {
			t.Errorf("%s: should have failed", r.Case.Name)
		}
	}
}
