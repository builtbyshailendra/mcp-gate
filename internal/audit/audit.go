// Package audit writes one JSON line per gate decision.
//
// Argument values are never written, only their names: tool arguments can
// hold anything, including secrets an agent pasted in.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event is one line of the audit log.
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"` // call, list, reject, reload, upstream_error
	Agent    string    `json:"agent,omitempty"`
	Method   string    `json:"method,omitempty"`
	Tool     string    `json:"tool,omitempty"`
	RPCID    string    `json:"rpc_id,omitempty"`
	Decision string    `json:"decision,omitempty"` // allow or deny
	Policies []string  `json:"policies,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	ArgNames []string  `json:"arg_names,omitempty"`
	Hidden   []string  `json:"hidden,omitempty"` // tools removed from a tools/list reply
	EvalUS   int64     `json:"eval_us,omitempty"`
}

// Log is safe for concurrent use. A nil *Log discards events.
type Log struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() time.Time
}

// New writes events to w.
func New(w io.Writer) *Log {
	return &Log{enc: json.NewEncoder(w), now: time.Now}
}

// Write records one event, stamping the time if it's unset.
func (l *Log) Write(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e) // a failed audit write must not take the gate down
}
