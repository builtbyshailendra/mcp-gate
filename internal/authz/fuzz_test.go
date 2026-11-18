package authz

import (
	"encoding/json"
	"testing"
)

// FuzzAuthorizeCall throws arbitrary argument JSON at the engine. It must
// never panic, and anything the schema doesn't describe must be denied.
func FuzzAuthorizeCall(f *testing.F) {
	e, err := LoadDir("../../policies", testAgents, "k8s")
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		`{"namespace":"staging-payments","deployment":"api","replicas":3}`,
		`{"namespace":"prod-payments","deployment":"api","replicas":0}`,
		`{"namespace":"staging-payments","deployment":"api","replicas":1e400}`,
		`{"namespace":["a"],"deployment":{"x":1},"replicas":3.5}`,
		`{"namespace":"staging-payments","deployment":"api","replicas":3,"extra":null}`,
		`null`, `[]`, `"x"`, `{}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		d := e.AuthorizeCall("oncall-bot", "scale_deployment", json.RawMessage(args), weekday, ist)
		if !d.Allow {
			return
		}
		// If it was allowed, the arguments must be exactly the declared
		// shape with an in-range replica count.
		var a struct {
			Namespace  *string `json:"namespace"`
			Deployment *string `json:"deployment"`
			Replicas   *json.Number
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal([]byte(args), &raw) != nil || len(raw) != 3 {
			t.Fatalf("allowed with arguments outside the schema: %s", args)
		}
		if json.Unmarshal([]byte(args), &a) != nil || a.Namespace == nil || a.Deployment == nil || a.Replicas == nil {
			t.Fatalf("allowed with arguments outside the schema: %s", args)
		}
		n, err := a.Replicas.Float64()
		if err != nil || n < 0 || n > 20 {
			t.Fatalf("allowed replicas %s", *a.Replicas)
		}
	})
}
