// Package authz decides, with Cedar, whether an agent may call a tool.
//
// An Engine is an immutable snapshot of one schema, one policy set and the
// known agents. Reloading builds a new Engine and swaps it in whole, so a
// request is always judged by one consistent set of rules.
package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

// Agent is a caller the gate knows, with the attributes policies can use.
type Agent struct {
	ID     string   `yaml:"id"`
	Teams  []string `yaml:"teams"`
	OnCall bool     `yaml:"on_call"`
}

// File is one named policy document.
type File struct {
	Name string
	Body []byte
}

// Decision is the outcome of one authorization check.
type Decision struct {
	Allow bool
	// Policies are the IDs of the policies that decided it: the permits that
	// matched for an allow, the forbids that matched for a deny. Empty for a
	// default deny.
	Policies []string
	// Reason is a sentence for the agent and the audit log.
	Reason string
	// Errors are policy evaluation errors. Any error means deny (fail closed).
	Errors []string
}

// Engine holds one consistent set of rules. Safe for concurrent use.
type Engine struct {
	policies  *cedar.PolicySet
	scopeOnly *cedar.PolicySet // permits without conditions, unconditional forbids
	reasons   map[cedar.PolicyID]string
	entities  cedar.EntityMap
	validator *validate.Validator
	tools     map[string]bool   // actions that apply to a request (not groups)
	expected  map[string]string // tool -> its declared arguments, for error messages
	server    cedar.EntityUID
	ids       []string
}

const (
	agentType  = cedar.EntityType("Agent")
	teamType   = cedar.EntityType("Team")
	serverType = cedar.EntityType("Server")
	actionType = cedar.EntityType("Action")
)

// LoadDir reads schema.cedarschema and every *.cedar file in dir.
func LoadDir(dir string, agents []Agent, server string) (*Engine, error) {
	schemaBody, err := os.ReadFile(filepath.Join(dir, "schema.cedarschema"))
	if err != nil {
		return nil, err
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.cedar"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var files []File
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: filepath.Base(n), Body: b})
	}
	return Load(schemaBody, files, agents, server)
}

// Load builds an Engine. It fails, rather than guessing, if the schema doesn't
// parse, any policy doesn't parse or type-check, two policies share an ID, or
// an agent doesn't fit the schema.
func Load(schemaBody []byte, files []File, agents []Agent, server string) (*Engine, error) {
	if len(files) == 0 {
		return nil, errors.New("no policy files: with nothing permitted every call would be denied")
	}
	var s schema.Schema
	s.SetFilename("schema.cedarschema")
	if err := s.UnmarshalCedar(schemaBody); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	resolved, err := s.Resolve()
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	v := validate.New(resolved)

	e := &Engine{
		policies:  cedar.NewPolicySet(),
		scopeOnly: cedar.NewPolicySet(),
		reasons:   map[cedar.PolicyID]string{},
		entities:  cedar.EntityMap{},
		validator: v,
		tools:     map[string]bool{},
		expected:  map[string]string{},
		server:    cedar.NewEntityUID(serverType, cedar.String(server)),
	}

	// Agents, their teams and the server are entities the policies can refer to.
	e.entities[e.server] = cedar.Entity{UID: e.server}
	for _, a := range agents {
		uid := cedar.NewEntityUID(agentType, cedar.String(a.ID))
		if _, dup := e.entities[uid]; dup {
			return nil, fmt.Errorf("agent %q is listed twice", a.ID)
		}
		var parents []cedar.EntityUID
		for _, t := range a.Teams {
			team := cedar.NewEntityUID(teamType, cedar.String(t))
			parents = append(parents, team)
			e.entities[team] = cedar.Entity{UID: team}
		}
		e.entities[uid] = cedar.Entity{
			UID:        uid,
			Parents:    cedar.NewEntityUIDSet(parents...),
			Attributes: cedar.NewRecord(cedar.RecordMap{"on_call": cedar.Boolean(a.OnCall)}),
		}
	}
	if err := v.Entities(e.entities); err != nil {
		return nil, fmt.Errorf("agents don't fit the schema: %w", err)
	}

	// Actions and their groups come from the schema, so `action in
	// Action::"write"` works without listing the hierarchy twice.
	for uid, act := range resolved.Actions {
		e.entities[uid] = act.Entity
		if act.AppliesTo != nil {
			e.tools[string(uid.ID)] = true
			if args, ok := act.AppliesTo.Context["args"]; ok {
				e.expected[string(uid.ID)] = describe(args.Type)
			}
		}
	}

	seen := map[cedar.PolicyID]string{}
	for _, f := range files {
		list, err := cedar.NewPolicyListFromBytes(f.Name, f.Body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		for i, p := range list {
			id := cedar.PolicyID(fmt.Sprintf("%s#%d", f.Name, i))
			if named, ok := p.Annotations()["id"]; ok && named != "" {
				id = cedar.PolicyID(named)
			}
			if where, dup := seen[id]; dup {
				return nil, fmt.Errorf("policy ID %q is used in %s and %s", id, where, f.Name)
			}
			seen[id] = f.Name
			if err := v.Policy(string(id), (*xast.Policy)(p.AST())); err != nil {
				return nil, fmt.Errorf("%s: policy %q doesn't fit the schema: %w", f.Name, id, err)
			}
			e.policies.Add(id, p)
			e.reasons[id] = string(p.Annotations()["reason"])
			e.ids = append(e.ids, string(id))

			// The scope-only copy answers "could this agent ever call this
			// tool?" for tools/list: a permit counts if its scope matches,
			// whatever its conditions; a forbid counts only if it has none.
			scoped := *(*xast.Policy)(p.AST())
			if scoped.Effect == xast.EffectPermit {
				scoped.Conditions = nil
				e.scopeOnly.Add(id, cedar.NewPolicyFromAST((*ast.Policy)(&scoped)))
			} else if len(scoped.Conditions) == 0 {
				e.scopeOnly.Add(id, p)
			}
		}
	}
	return e, nil
}

// PolicyIDs lists the loaded policies.
func (e *Engine) PolicyIDs() []string { return slices.Clone(e.ids) }

// Tools lists the tools the schema declares, sorted.
func (e *Engine) Tools() []string {
	out := make([]string, 0, len(e.tools))
	for t := range e.tools {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Declared reports whether the schema declares a tool.
func (e *Engine) Declared(tool string) bool { return e.tools[tool] }

// KnownAgent reports whether an agent ID is in the entity set.
func (e *Engine) KnownAgent(id string) bool {
	_, ok := e.entities[cedar.NewEntityUID(agentType, cedar.String(id))]
	return ok
}

// Visible reports whether an agent could ever be allowed to call a tool, so
// tools/list can hide the rest. It's a filter for the model's benefit; the
// real check is AuthorizeCall on every call.
func (e *Engine) Visible(agent, tool string) bool {
	if !e.tools[tool] || !e.KnownAgent(agent) {
		return false
	}
	d, _ := e.scopeOnly.IsAuthorized(e.entities, cedar.Request{
		Principal: cedar.NewEntityUID(agentType, cedar.String(agent)),
		Action:    cedar.NewEntityUID(actionType, cedar.String(tool)),
		Resource:  e.server,
		Context:   cedar.NewRecord(nil),
	})
	return d == cedar.Allow
}

// AuthorizeCall decides one tools/call. args is the call's raw "arguments"
// JSON (may be empty); now sets context.clock in loc.
func (e *Engine) AuthorizeCall(agent, tool string, args json.RawMessage, now time.Time, loc *time.Location) Decision {
	if !e.KnownAgent(agent) {
		return Decision{Reason: fmt.Sprintf("agent %q is not registered with the gate", agent)}
	}
	if !e.tools[tool] {
		return Decision{Reason: fmt.Sprintf("tool %q is not declared in the gate's schema, so it is denied by default", tool)}
	}
	argRec, err := argsRecord(args)
	if err != nil {
		return Decision{Reason: fmt.Sprintf("arguments for %s: %v", tool, err)}
	}
	local := now.In(loc)
	req := cedar.Request{
		Principal: cedar.NewEntityUID(agentType, cedar.String(agent)),
		Action:    cedar.NewEntityUID(actionType, cedar.String(tool)),
		Resource:  e.server,
		Context: cedar.NewRecord(cedar.RecordMap{
			"clock": cedar.NewRecord(cedar.RecordMap{
				"hour":    cedar.Long(local.Hour()),
				"weekday": cedar.Long(local.Weekday()),
			}),
			"args": argRec,
		}),
	}
	if err := e.validator.Request(req); err != nil {
		// The validator's message quotes the argument values. Those must not
		// reach the audit log, so say what was expected instead.
		return Decision{Reason: fmt.Sprintf("arguments for %s don't match the gate's schema, which expects %s", tool, e.expected[tool])}
	}

	decision, diag := e.policies.IsAuthorized(e.entities, req)
	d := Decision{Allow: decision == cedar.Allow}
	for _, r := range diag.Reasons {
		d.Policies = append(d.Policies, string(r.PolicyID))
	}
	sort.Strings(d.Policies)
	for _, er := range diag.Errors {
		d.Errors = append(d.Errors, er.String())
	}
	switch {
	case len(d.Errors) > 0:
		// Cedar skips a policy that errors. If that policy was a forbid, the
		// call could slip through, so the gate denies instead.
		d.Allow = false
		d.Reason = "a policy failed to evaluate, so the gate denied the call: " + strings.Join(d.Errors, "; ")
	case d.Allow:
		d.Reason = "permitted by " + strings.Join(d.Policies, ", ")
	case len(d.Policies) > 0:
		var why []string
		for _, id := range d.Policies {
			if r := e.reasons[cedar.PolicyID(id)]; r != "" {
				why = append(why, r)
			} else {
				why = append(why, "forbidden by "+id)
			}
		}
		d.Reason = strings.Join(why, " ")
	default:
		d.Reason = fmt.Sprintf("no policy permits agent %q to call %s with these arguments (default deny)", agent, tool)
	}
	return d
}

// argsRecord turns a JSON object into a Cedar record. JSON null means "not
// given" and is dropped, since Cedar has no null.
func argsRecord(raw json.RawMessage) (cedar.Record, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return cedar.NewRecord(nil), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return cedar.Record{}, errors.New("arguments must be a JSON object")
	}
	v, err := toCedar(obj, 0)
	if err != nil {
		return cedar.Record{}, err
	}
	return v.(cedar.Record), nil
}

const maxDepth = 32

func toCedar(v any, depth int) (cedar.Value, error) {
	if depth > maxDepth {
		return nil, errors.New("arguments are nested too deeply")
	}
	switch x := v.(type) {
	case string:
		return cedar.String(x), nil
	case bool:
		return cedar.Boolean(x), nil
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return cedar.Long(i), nil
		}
		f, err := x.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, fmt.Errorf("number %s is out of range", x)
		}
		if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return cedar.Long(int64(f)), nil // 3.0 from a client is still 3
		}
		d, err := cedar.NewDecimalFromFloat(f)
		if err != nil {
			return nil, fmt.Errorf("number %s: %w", x, err)
		}
		return d, nil
	case map[string]any:
		rm := cedar.RecordMap{}
		for k, val := range x {
			if val == nil {
				continue
			}
			cv, err := toCedar(val, depth+1)
			if err != nil {
				return nil, err
			}
			rm[cedar.String(k)] = cv
		}
		return cedar.NewRecord(rm), nil
	case []any:
		vals := make([]cedar.Value, 0, len(x))
		for _, val := range x {
			if val == nil {
				return nil, errors.New("null inside a list is not supported")
			}
			cv, err := toCedar(val, depth+1)
			if err != nil {
				return nil, err
			}
			vals = append(vals, cv)
		}
		return cedar.NewSet(vals...), nil
	default:
		return nil, fmt.Errorf("unsupported JSON value %T", v)
	}
}

// describe renders a schema type the way the schema file writes it.
func describe(t resolved.IsType) string {
	switch x := t.(type) {
	case resolved.StringType:
		return "String"
	case resolved.LongType:
		return "Long"
	case resolved.BoolType:
		return "Bool"
	case resolved.SetType:
		return "Set<" + describe(x.Element) + ">"
	case resolved.EntityType:
		return string(x)
	case resolved.ExtensionType:
		return string(x)
	case resolved.RecordType:
		names := make([]string, 0, len(x))
		for n := range x {
			names = append(names, string(n))
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			a := x[cedar.String(n)]
			opt := ""
			if a.Optional {
				opt = "?"
			}
			parts = append(parts, n+opt+": "+describe(a.Type))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprintf("%T", t)
	}
}
