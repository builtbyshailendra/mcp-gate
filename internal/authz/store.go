package authz

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"
)

// Store holds the active Engine and swaps in a new one when the policy files
// change. A change that doesn't load (syntax error, type error) is reported
// and ignored: the gate keeps enforcing the last good set rather than
// failing open or going down.
type Store struct {
	dir    string
	agents []Agent
	server string
	cur    atomic.Pointer[Engine]
	sum    [32]byte

	// OnReload, if set, hears about every reload attempt.
	OnReload func(e *Engine, err error)
}

// NewStore loads dir once. The first load must succeed.
func NewStore(dir string, agents []Agent, server string) (*Store, error) {
	s := &Store{dir: dir, agents: agents, server: server}
	sum, err := s.fingerprint()
	if err != nil {
		return nil, err
	}
	e, err := LoadDir(dir, agents, server)
	if err != nil {
		return nil, err
	}
	s.cur.Store(e)
	s.sum = sum
	return s, nil
}

// Engine returns the active rules.
func (s *Store) Engine() *Engine { return s.cur.Load() }

// Check reloads if any policy file changed. It reports whether it tried.
// Not safe to call from two goroutines at once; Watch is the only caller in
// the gate.
func (s *Store) Check() (bool, error) {
	sum, err := s.fingerprint()
	if err != nil {
		return false, err
	}
	if sum == s.sum {
		return false, nil
	}
	// Remember this version even if it fails, so a broken file is reported
	// once, not every poll. Fixing the file changes the sum again.
	s.sum = sum
	e, err := LoadDir(s.dir, s.agents, s.server)
	if err == nil {
		s.cur.Store(e)
	}
	if s.OnReload != nil {
		s.OnReload(e, err)
	}
	return true, err
}

// Watch polls for changes until ctx ends. Polling works the same on Windows,
// Linux and a Kubernetes ConfigMap mount, where file events are unreliable.
func (s *Store) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.Check()
		}
	}
}

// fingerprint hashes the names and contents of the schema and policy files.
func (s *Store) fingerprint() ([32]byte, error) {
	names, err := filepath.Glob(filepath.Join(s.dir, "*.cedar"))
	if err != nil {
		return [32]byte{}, err
	}
	names = append(names, filepath.Join(s.dir, "schema.cedarschema"))
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return [32]byte{}, err
		}
		h.Write([]byte(filepath.Base(n)))
		h.Write([]byte{0})
		h.Write(b)
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
