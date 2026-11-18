package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// A message is one JSON-RPC message from an agent, parsed strictly.
//
// Strict matters because the gate and the upstream server each parse the same
// bytes. If they could disagree (one takes the first of two "name" keys, the
// other the last; one matches "Method" to "method", the other doesn't), an
// agent could show the gate one tool and run another. So the gate refuses
// anything ambiguous instead of guessing which reading the server will pick.
type message struct {
	ID     jsontext.Value // nil for a notification
	Method string         // empty for a response to a server-initiated request
	Params jsontext.Value
}

// refusal is a request the gate won't forward, with a fixed metric label.
type refusal struct {
	label  string // bounded set, used as a Prometheus label
	status int
	text   string
}

func (r *refusal) Error() string { return r.text }

func refuse(label string, status int, format string, args ...any) *refusal {
	return &refusal{label: label, status: status, text: fmt.Sprintf(format, args...)}
}

var topLevelMembers = map[string]bool{"jsonrpc": true, "id": true, "method": true, "params": true, "result": true, "error": true}

func parseMessage(body []byte) (*message, *refusal) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, refuse("bad_json", http.StatusBadRequest, "empty request body")
	}
	if trimmed[0] == '[' {
		// Batches were removed from MCP in 2025-06-18. Accepting them would
		// mean authorizing every element; refusing is simpler and safe.
		return nil, refuse("batch", http.StatusBadRequest, "JSON-RPC batches are not accepted; send one message per request")
	}
	// RFC 7493 (I-JSON): valid UTF-8 and no repeated names in any object.
	if !jsontext.Value(trimmed).IsValid() {
		return nil, refuse("bad_json", http.StatusBadRequest, "body is not valid JSON, or an object repeats a member name")
	}
	var top map[string]jsontext.Value
	if err := jsonv2.Unmarshal(trimmed, &top); err != nil {
		return nil, refuse("bad_json", http.StatusBadRequest, "body must be a JSON-RPC message object")
	}
	for k := range top {
		if !topLevelMembers[k] {
			// Catches "Method" and friends, which a case-insensitive parser
			// upstream would read as "method".
			return nil, refuse("unknown_member", http.StatusBadRequest, "unexpected top-level member %q", k)
		}
	}
	var version string
	if err := jsonv2.Unmarshal(top["jsonrpc"], &version); err != nil || version != "2.0" {
		return nil, refuse("bad_json", http.StatusBadRequest, `"jsonrpc" must be "2.0"`)
	}
	m := &message{ID: top["id"], Params: top["params"]}
	if raw, ok := top["method"]; ok {
		if err := jsonv2.Unmarshal(raw, &m.Method); err != nil || m.Method == "" {
			return nil, refuse("bad_json", http.StatusBadRequest, `"method" must be a non-empty string`)
		}
	}
	_, hasResult := top["result"]
	_, hasError := top["error"]
	switch {
	case m.Method == "" && !hasResult && !hasError:
		return nil, refuse("bad_json", http.StatusBadRequest, "message has no method, result or error")
	case m.Method != "" && (hasResult || hasError):
		return nil, refuse("bad_json", http.StatusBadRequest, "a request can't also carry a result or an error")
	}
	return m, nil
}

// callParams are the parts of tools/call params the gate decides on.
type callParams struct {
	Name      string
	Arguments jsontext.Value
}

var callMembers = []string{"name", "arguments", "_meta"}

func parseCallParams(m *message) (*callParams, *refusal) {
	if m.ID == nil {
		return nil, refuse("bad_json", http.StatusBadRequest, "tools/call must be a request with an id")
	}
	var p map[string]jsontext.Value
	if len(m.Params) == 0 || jsonv2.Unmarshal(m.Params, &p) != nil {
		return nil, refuse("bad_json", http.StatusBadRequest, "tools/call params must be an object")
	}
	for k := range p {
		for _, known := range callMembers {
			// EqualFold also folds "ſ" to "s" and "K" (Kelvin) to "k", which
			// Go's encoding/json v1 matches too.
			if k != known && strings.EqualFold(k, known) {
				return nil, refuse("unknown_member", http.StatusBadRequest, "params member %q differs from %q only by case", k, known)
			}
		}
	}
	var name string
	if err := jsonv2.Unmarshal(p["name"], &name); err != nil || name == "" {
		return nil, refuse("bad_json", http.StatusBadRequest, "tools/call needs a tool name")
	}
	return &callParams{Name: name, Arguments: p["arguments"]}, nil
}

// checkHeaders compares the headers MCP 2026-07-28 clients copy from the body
// (Mcp-Method, Mcp-Name) with the body. Servers and gateways may route on the
// headers, so a mismatch is refused rather than forwarded.
func checkHeaders(h http.Header, m *message, tool string) *refusal {
	if v := h.Get("Mcp-Method"); v != "" && v != m.Method {
		return refuse("header_mismatch", http.StatusBadRequest, "Mcp-Method header %q does not match the body's method %q", v, m.Method)
	}
	if v := h.Get("Mcp-Name"); v != "" && m.Method == "tools/call" {
		name, ok := decodeHeaderValue(v)
		if !ok || name != tool {
			return refuse("header_mismatch", http.StatusBadRequest, "Mcp-Name header does not match the tool being called")
		}
	}
	return nil
}

// decodeHeaderValue undoes the "=?base64?...?=" wrapping MCP uses for header
// values that aren't plain ASCII.
func decodeHeaderValue(v string) (string, bool) {
	if inner, ok := strings.CutPrefix(v, "=?base64?"); ok {
		if inner, ok = strings.CutSuffix(inner, "?="); ok {
			b, err := base64.StdEncoding.DecodeString(inner)
			return string(b), err == nil
		}
	}
	return v, true
}

// argNames lists an arguments object's member names, sorted. Values are left
// out on purpose: the audit log must not collect secrets.
func argNames(args jsontext.Value) []string {
	var obj map[string]jsontext.Value
	if len(args) == 0 || jsonv2.Unmarshal(args, &obj) != nil {
		return nil
	}
	names := make([]string, 0, len(obj))
	for k := range obj {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func idString(id jsontext.Value) string {
	if id == nil {
		return ""
	}
	return string(bytes.TrimSpace(id))
}

// rpcError is a JSON-RPC error reply.
func rpcError(id jsontext.Value, code int, text string) []byte {
	if id == nil {
		id = jsontext.Value("null")
	}
	b, _ := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": text},
	})
	return b
}

// denial is the reply to a refused tools/call: a normal result with isError
// set, which is how MCP reports tool failures. The model reads it and can
// change course; a protocol error would look like the gate itself broke.
func denial(id jsontext.Value, policies []string, reason string) []byte {
	text := "Denied by mcp-gate: " + reason
	if len(policies) > 0 {
		text = fmt.Sprintf("Denied by mcp-gate (policy %s): %s", strings.Join(policies, ", "), reason)
	}
	b, _ := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": text}},
			"isError": true,
		},
	})
	return b
}

const (
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
)
