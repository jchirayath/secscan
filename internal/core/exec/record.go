package exec

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
)

// Recording a transcript of every command a collector ran is how an operator
// checks the scanner's work rather than taking it on faith. "OS packages: 2
// findings" is a claim; the apt-get output that produced it is evidence.
//
// The hazard is obvious once stated: some of those commands read secrets. The
// accounts collector reads /etc/shadow; a secret scanner reads credentials by
// definition. Persisting raw transcripts would have this tool create the
// exposure it exists to find — password hashes sitting in a world-readable
// state file is strictly worse than the finding it supports.
//
// So redaction is not a later refinement here, it is a precondition of the
// feature existing at all.

// Step is one recorded command.
type Step struct {
	Command  string        `json:"command"`
	Stdout   string        `json:"stdout,omitempty"`
	Stderr   string        `json:"stderr,omitempty"`
	ExitCode int           `json:"exit_code"`
	Took     time.Duration `json:"-"`
	TookMS   int64         `json:"took_ms"`
	// Redacted marks a step whose output was deliberately withheld, so the
	// reader sees that something was read rather than assuming nothing was.
	Redacted bool `json:"redacted,omitempty"`
}

// sensitiveTargets are reads whose CONTENT must never be persisted. The command
// itself is recorded — knowing the scanner read /etc/shadow is useful and not
// sensitive; the hashes are.
var sensitiveTargets = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
	".pem", ".key",
	"authorized_keys",
	"secrets", "credentials", ".env",
}

// maxOutput bounds a single recorded output. A transcript is for reading, and
// a scan that captured a 40MB package list would be unreadable and would bloat
// the state file for no benefit.
const maxOutput = 4000

// maxSteps bounds how many commands one collector contributes.
const maxSteps = 80

// Recorder wraps a Runner and captures everything it executes.
type Recorder struct {
	Runner
	mu    sync.Mutex
	steps []Step
}

// NewRecorder wraps r.
func NewRecorder(r Runner) *Recorder { return &Recorder{Runner: r} }

// Steps returns what was recorded.
func (rec *Recorder) Steps() []Step {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]Step(nil), rec.steps...)
}

func (rec *Recorder) record(cmd string, res Result, took time.Duration) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.steps) >= maxSteps {
		return
	}
	s := Step{
		Command: cmd, ExitCode: res.ExitCode,
		Took: took, TookMS: took.Milliseconds(),
	}
	if isSensitive(cmd) {
		s.Redacted = true
		s.Stdout = "(output withheld — this command reads secret material, and " +
			"persisting it would make the scanner's own state file a disclosure risk)"
	} else {
		s.Stdout = truncate(res.Stdout)
		s.Stderr = truncate(res.Stderr)
	}
	rec.steps = append(rec.steps, s)
}

// contentReaders are the commands that return a file's CONTENTS. Metadata
// commands (stat, find, ls, test) touch the same paths but return only a mode
// or a name — and that metadata is usually the very evidence a permissions
// finding rests on. Redacting it would hide the proof while protecting nothing.
var contentReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"grep": true, "awk": true, "sed": true, "strings": true, "xxd": true,
}

// isSensitive reports whether a command's OUTPUT must be withheld: it must both
// read content and touch something secret.
func isSensitive(cmd string) bool {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	// Skip a sudo prefix to find the real command.
	i := 0
	for i < len(fields) && (fields[i] == "sudo" || strings.HasPrefix(fields[i], "-")) {
		i++
	}
	if i >= len(fields) {
		return false
	}
	base := fields[i]
	if j := strings.LastIndex(base, "/"); j >= 0 {
		base = base[j+1:]
	}
	if !contentReaders[base] {
		return false
	}
	low := strings.ToLower(cmd)
	for _, t := range sensitiveTargets {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

func truncate(s string) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= maxOutput {
		return s
	}
	return s[:maxOutput] + "\n… (truncated)"
}

// Run records the command and its result.
func (rec *Recorder) Run(ctx context.Context, argv ...string) Result {
	start := clock.Now()
	res := rec.Runner.Run(ctx, argv...)
	rec.record(strings.Join(argv, " "), res, clock.Now().Sub(start))
	return res
}

// Has records the probe too — "is trivy installed?" is part of the story of why
// a check did or did not run.
func (rec *Recorder) Has(ctx context.Context, cmd string) bool {
	start := clock.Now()
	ok := rec.Runner.Has(ctx, cmd)
	status := "not found"
	code := 1
	if ok {
		status, code = "found", 0
	}
	rec.record("command -v "+cmd, Result{Stdout: status, ExitCode: code}, clock.Now().Sub(start))
	return ok
}

// ReadFile records the read, withholding content for sensitive paths.
func (rec *Recorder) ReadFile(ctx context.Context, path string) (string, bool) {
	start := clock.Now()
	body, ok := rec.Runner.ReadFile(ctx, path)
	res := Result{Stdout: body}
	if !ok {
		res = Result{ExitCode: 1, Stderr: "not readable"}
	}
	rec.record("cat "+path, res, clock.Now().Sub(start))
	return body, ok
}
