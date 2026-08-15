// Package audit is the append-only record of who did what.
//
// The rule, and it is non-negotiable here: every
// entry carries the authenticated user AND the role they acted under, as two
// separate fields. Roles are shared — several people hold `operator` — so a
// record with only the role cannot answer "which of them?", and one with only
// the user cannot answer "under what privilege?". The pair is what makes the
// trail forensically useful.
package audit

import (
	"encoding/json"
	"github.com/jchirayath/secscan/internal/clock"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audited action.
type Entry struct {
	At       time.Time `json:"at"`
	Caller   string    `json:"caller"` // the authenticated principal
	Role     string    `json:"role"`   // the privilege exercised — never merged with Caller
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	Result   string    `json:"result"` // allowed | denied | error
	Detail   string    `json:"detail,omitempty"`
	RemoteIP string    `json:"remote_ip,omitempty"`
}

// Log is an append-only audit sink.
type Log struct {
	mu   sync.Mutex
	path string
}

// Open prepares the audit log under dir.
func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Log{path: filepath.Join(dir, "audit.jsonl")}, nil
}

// Write appends an entry. Audit failures are logged but never block the action
// being audited from returning — except for denials, which are already the
// safe outcome.
func (l *Log) Write(e Entry) {
	if e.At.IsZero() {
		e.At = clock.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("audit write failed", slog.String("err", err.Error()))
		return
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		slog.Error("audit marshal failed", slog.String("err", err.Error()))
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		slog.Error("audit append failed", slog.String("err", err.Error()))
	}
}

// Tail returns the most recent n entries, newest last.
func (l *Log) Tail(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, err := os.ReadFile(l.path)
	if err != nil {
		return nil
	}
	var all []Entry
	start := 0
	for i, c := range b {
		if c != '\n' {
			continue
		}
		if i > start {
			var e Entry
			if json.Unmarshal(b[start:i], &e) == nil {
				all = append(all, e)
			}
		}
		start = i + 1
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}
