// Package policytest runs policy test cases: "this agent, calling this tool
// with these arguments at this time, is allowed (or denied) by these
// policies". It's how a policy change gets reviewed in CI like code.
package policytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/builtbyshailendra/mcp-gate/internal/authz"
)

// Case is one expectation.
type Case struct {
	Name     string         `yaml:"name"`
	Agent    string         `yaml:"agent"`
	Tool     string         `yaml:"tool"`
	Args     map[string]any `yaml:"args"`
	At       string         `yaml:"at"`       // RFC 3339 time; the weekday and hour matter
	Expect   string         `yaml:"expect"`   // allow or deny
	Policies []string       `yaml:"policies"` // optional: exactly these policies decide
	Visible  *bool          `yaml:"visible"`  // optional: is the tool in this agent's tools/list
}

// Result is one case's outcome.
type Result struct {
	Case     Case
	Decision authz.Decision
	Problems []string
}

// Pass reports whether every expectation held.
func (r Result) Pass() bool { return len(r.Problems) == 0 }

// Load reads a YAML file of cases.
func Load(path string) ([]Case, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Cases []Case `yaml:"cases"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(f.Cases) == 0 {
		return nil, fmt.Errorf("%s: no cases", path)
	}
	return f.Cases, nil
}

// Run checks every case against e. loc is the gate's time zone.
func Run(e *authz.Engine, cases []Case, loc *time.Location) []Result {
	out := make([]Result, 0, len(cases))
	for _, c := range cases {
		r := Result{Case: c}
		at, err := time.Parse(time.RFC3339, c.At)
		if err != nil {
			r.Problems = append(r.Problems, fmt.Sprintf("bad 'at' time %q: want RFC 3339, e.g. 2026-11-18T11:00:00+05:30", c.At))
		}
		if c.Expect != "allow" && c.Expect != "deny" {
			r.Problems = append(r.Problems, fmt.Sprintf("expect must be allow or deny, not %q", c.Expect))
		}
		args, err := json.Marshal(c.Args)
		if err != nil {
			r.Problems = append(r.Problems, "args: "+err.Error())
		}
		if len(r.Problems) > 0 {
			out = append(out, r)
			continue
		}
		r.Decision = e.AuthorizeCall(c.Agent, c.Tool, args, at, loc)
		if got := map[bool]string{true: "allow", false: "deny"}[r.Decision.Allow]; got != c.Expect {
			r.Problems = append(r.Problems, fmt.Sprintf("got %s, want %s (%s)", got, c.Expect, r.Decision.Reason))
		}
		if c.Policies != nil {
			want := slices.Clone(c.Policies)
			sort.Strings(want)
			if !slices.Equal(r.Decision.Policies, want) {
				r.Problems = append(r.Problems, fmt.Sprintf("decided by [%s], want [%s]",
					strings.Join(r.Decision.Policies, ", "), strings.Join(want, ", ")))
			}
		}
		if c.Visible != nil {
			if got := e.Visible(c.Agent, c.Tool); got != *c.Visible {
				r.Problems = append(r.Problems, fmt.Sprintf("visible in tools/list = %v, want %v", got, *c.Visible))
			}
		}
		out = append(out, r)
	}
	return out
}
