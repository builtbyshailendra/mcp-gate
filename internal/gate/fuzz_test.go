package gate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

var messageSeeds = []string{
	`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","arguments":{"namespace":"dev-sandbox"}}}`,
	`{"jsonrpc":"2.0","id":"a","method":"tools/list"}`,
	`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	`{"jsonrpc":"2.0","id":4,"result":{"action":"accept"}}`,
	`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","name":"delete_namespace"}}`,
	`{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"delete_namespace"}}`,
	`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","Name":"delete_namespace"}}`,
	`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","arguments":{}}}`,
	`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pods","argumentſ":{}}}`,
	`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
}

// FuzzParseAgreesWithLenientParser is the gate's core safety property: if the
// gate accepts a message, a lenient parser on the server side (Go's
// encoding/json v1: case-insensitive keys, last duplicate wins) must read the
// same method, tool name and arguments. If it ever didn't, an agent could show
// the gate one call and run another.
func FuzzParseAgreesWithLenientParser(f *testing.F) {
	for _, s := range messageSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		msg, rf := parseMessage(body)
		if rf != nil {
			return
		}
		var lenient struct {
			Method string `json:"method"`
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &lenient); err != nil {
			// v1 couldn't read something the gate accepted. That's only safe
			// if the server would refuse it too; flag it so a person looks.
			if msg.Method == "tools/call" {
				t.Fatalf("gate accepted a tools/call that encoding/json rejects: %v", err)
			}
			return
		}
		if lenient.Method != msg.Method {
			t.Fatalf("gate read method %q, lenient parser %q", msg.Method, lenient.Method)
		}
		if msg.Method != "tools/call" {
			return
		}
		call, rf := parseCallParams(msg)
		if rf != nil {
			return
		}
		if lenient.Params.Name != call.Name {
			t.Fatalf("gate read tool %q, lenient parser %q", call.Name, lenient.Params.Name)
		}
		if !bytes.Equal(bytes.TrimSpace(lenient.Params.Arguments), bytes.TrimSpace(call.Arguments)) {
			t.Fatalf("gate read arguments %s, lenient parser %s", call.Arguments, lenient.Params.Arguments)
		}
	})
}

// parseEvents is a reference SSE parser written from the spec: lines end at
// CRLF, LF or a lone CR; a blank line dispatches the event if it had any
// data; an unterminated last line is dropped. It returns each event's data.
func parseEvents(s string) []string {
	var out, data []string
	have := false
	for {
		i := strings.IndexAny(s, "\r\n")
		if i < 0 {
			return out // whatever is left has no line end yet
		}
		line := s[:i]
		if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
			s = s[i+2:]
		} else {
			s = s[i+1:]
		}
		switch {
		case line == "":
			if have {
				out = append(out, strings.Join(data, "\n"))
			}
			data, have = nil, false
		case line == "data" || strings.HasPrefix(line, "data:"):
			v := strings.TrimPrefix(strings.TrimPrefix(line, "data"), ":")
			data, have = append(data, strings.TrimPrefix(v, " ")), true
		}
	}
}

// FuzzSSEPassthrough: with an identity rewrite, the filter must not change
// what a client reads from the stream.
func FuzzSSEPassthrough(f *testing.F) {
	for _, s := range []string{
		"data: {\"a\":1}\n\n",
		"id: 1\nevent: message\ndata: x\ndata: y\n\n: comment\n\ndata: z\n\n",
		"data:no-space\r\n\r\ndata: tail",
		"\n\n\ndata: after blanks\n\n",
		"data:\r\r\n\n", // found by the fuzzer: a lone CR ends a line
		"data\n\n",      // a field with no colon has an empty value
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		var out bytes.Buffer
		if err := filterEvents(strings.NewReader(in), &out, 1<<20, func(b []byte) []byte { return b }); err != nil {
			t.Fatal(err)
		}
		want, got := parseEvents(in), parseEvents(out.String())
		if strings.Join(want, "\x00") != strings.Join(got, "\x00") || len(want) != len(got) {
			t.Fatalf("events changed:\n in %q -> %q\nout %q -> %q", in, want, out.String(), got)
		}
	})
}
