package exec

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestShellQuoteBlocksInjection: remote commands are assembled into a string
// the login shell interprets, so quoting is the only thing between a hostile
// path and command execution on the target. A scanner that can be turned into
// a remote-execution primitive by a filename is worse than no scanner.
func TestShellQuoteBlocksInjection(t *testing.T) {
	hostile := []string{
		"; rm -rf /",
		"$(whoami)",
		"`id`",
		"a b; touch /tmp/pwned",
		"'; echo pwned; '",
		"foo\nbar",
		"--flag=$(id)",
		"",
	}
	for _, h := range hostile {
		q := shellQuote(h)
		if h == "" {
			if q != "''" {
				t.Errorf("empty string quoted as %q, want ''", q)
			}
			continue
		}
		// Anything dangerous must end up inside single quotes, and the only
		// way out of single quotes is the '\'' sequence we generate.
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") {
			t.Errorf("shellQuote(%q) = %q — dangerous input was not quoted", h, q)
		}
		stripped := strings.TrimSuffix(strings.TrimPrefix(q, "'"), "'")
		for _, bare := range []string{";", "$(", "`", "\n"} {
			if strings.Contains(stripped, bare) && !strings.Contains(q, `'\''`) {
				// Inside single quotes these are literal, which is fine; this
				// check exists to catch a future change that drops the quoting.
				if !strings.HasPrefix(q, "'") {
					t.Errorf("shellQuote(%q) left %q unquoted", h, bare)
				}
			}
		}
	}

	// Safe words stay unquoted so commands remain readable in evidence output.
	for _, safe := range []string{"ls", "/etc/passwd", "-tulpnH", "a-b_c.d"} {
		if q := shellQuote(safe); q != safe {
			t.Errorf("shellQuote(%q) = %q — safe input should pass through", safe, q)
		}
	}
}

func TestSanitizeForPath(t *testing.T) {
	// A target name is operator-supplied and lands in a filesystem path for
	// the SSH control socket; it must not be able to escape the directory.
	cases := map[string]string{
		"web01":            "web01",
		"../../etc/passwd": "______etc_passwd",
		"a/b":              "a_b",
		"with space":       "with_space",
	}
	for in, want := range cases {
		if got := sanitizeForPath(in); got != want {
			t.Errorf("sanitizeForPath(%q) = %q, want %q", in, got, want)
		}
	}
	// Long names are truncated so the sockaddr_un limit cannot be exceeded.
	if got := sanitizeForPath(strings.Repeat("x", 200)); len(got) > 32 {
		t.Errorf("long name produced a %d-char path component", len(got))
	}
}

// TestNeedsPrivilege pins the explicit privilege list. Prepending sudo
// speculatively would make the scanner run as root far more than necessary.
func TestNeedsPrivilege(t *testing.T) {
	yes := [][]string{
		{"cat", "/etc/shadow"},
		{"cat", "/etc/ssh/sshd_config"},
		{"docker", "ps"},
		{"ss", "-tulpnH"},
	}
	no := [][]string{
		{"cat", "/etc/passwd"},
		{"uname", "-r"},
		{"apt-get", "-s", "upgrade"},
		{"sysctl", "-n", "kernel.randomize_va_space"},
	}
	for _, c := range yes {
		if !needsPrivilege(c) {
			t.Errorf("%v should need privilege", c)
		}
	}
	for _, c := range no {
		if needsPrivilege(c) {
			t.Errorf("%v should NOT need privilege — sudo must not be speculative", c)
		}
	}
}

// TestLocalRunnerExitCodeIsNotAnError: probes rely on "command not found"
// being information, not a transport failure.
func TestLocalRunnerExitCodeIsNotAnError(t *testing.T) {
	r := New(Target{Name: "t"}, 5*time.Second)
	res := r.Run(context.Background(), "false")
	if res.Err != nil {
		t.Errorf("non-zero exit surfaced as Err: %v", res.Err)
	}
	if res.OK() {
		t.Error("OK() true for a non-zero exit")
	}

	ok := r.Run(context.Background(), "echo", "hello")
	if !ok.OK() || !strings.Contains(ok.Stdout, "hello") {
		t.Errorf("echo failed: %+v", ok)
	}
}

func TestHasUsesLookPath(t *testing.T) {
	r := New(Target{Name: "t"}, 5*time.Second)
	ctx := context.Background()
	// `command` is a shell builtin with no binary — the local runner must not
	// try to exec it.
	if !r.Has(ctx, "echo") {
		t.Error("echo should be found on PATH")
	}
	if r.Has(ctx, "definitely-not-a-real-binary-xyz") {
		t.Error("nonexistent binary reported as present")
	}
}
