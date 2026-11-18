package authz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreKeepsLastGoodPolicies(t *testing.T) {
	dir := writePolicies(t, `@id("extra") permit (principal in Team::"support", action == Action::"restart_deployment", resource) when { context.args.namespace like "dev-*" };`)
	s, err := NewStore(dir, testAgents, "k8s")
	if err != nil {
		t.Fatal(err)
	}
	var reloads []error
	s.OnReload = func(_ *Engine, err error) { reloads = append(reloads, err) }
	args := json.RawMessage(`{"namespace":"dev-sandbox","deployment":"scratch"}`)
	allowed := func() bool {
		return s.Engine().AuthorizeCall("docs-bot", "restart_deployment", args, weekday, ist).Allow
	}

	if !allowed() {
		t.Fatal("the extra policy should allow docs-bot to restart in dev")
	}
	if tried, err := s.Check(); tried || err != nil {
		t.Fatalf("nothing changed, yet Check tried=%v err=%v", tried, err)
	}

	// A broken edit: the old rules stay in force.
	write(t, dir, "extra.cedar", `@id("extra") permit (principal, action, resource) when { context.args.namespce == "x" };`)
	if tried, err := s.Check(); !tried || err == nil {
		t.Fatalf("broken policy: tried=%v err=%v", tried, err)
	}
	if !allowed() {
		t.Fatal("a broken edit changed the active rules")
	}
	if tried, _ := s.Check(); tried {
		t.Fatal("the same broken file was reloaded twice")
	}

	// A good edit that removes the permission takes effect.
	write(t, dir, "extra.cedar", `// nothing extra any more`)
	if tried, err := s.Check(); !tried || err != nil {
		t.Fatalf("good edit: tried=%v err=%v", tried, err)
	}
	if allowed() {
		t.Fatal("the reload did not take effect")
	}
	if len(reloads) != 2 || reloads[0] == nil || reloads[1] != nil {
		t.Fatalf("OnReload saw %v", reloads)
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
