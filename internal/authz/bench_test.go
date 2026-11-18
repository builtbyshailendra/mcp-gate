package authz

import (
	"encoding/json"
	"testing"
)

func BenchmarkAuthorizeCall(b *testing.B) {
	e, err := LoadDir("../../policies", testAgents, "k8s")
	if err != nil {
		b.Fatal(err)
	}
	for _, bc := range []struct {
		name, agent, tool, args string
	}{
		{"allow-read", "docs-bot", "list_pods", `{"namespace":"prod-payments"}`},
		{"allow-write", "oncall-bot", "scale_deployment", `{"namespace":"prod-payments","deployment":"api","replicas":5}`},
		{"deny-forbid", "oncall-bot", "scale_deployment", `{"namespace":"prod-payments","deployment":"api","replicas":0}`},
		{"deny-schema", "oncall-bot", "scale_deployment", `{"namespace":"prod-payments","deployment":"api","replicas":"5"}`},
	} {
		args := json.RawMessage(bc.args)
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				e.AuthorizeCall(bc.agent, bc.tool, args, weekday, ist)
			}
		})
	}
}

func BenchmarkVisible(b *testing.B) {
	e, err := LoadDir("../../policies", testAgents, "k8s")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		e.Visible("helper-bot", "scale_deployment")
	}
}
