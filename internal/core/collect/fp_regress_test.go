package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Both of these were false positives on betty (2026-11-25); each test pins the
// fix so the scanner cannot quietly go back to being confidently wrong.

// TestDNSHygieneSkipsIPTargets: a target addressed by IP has no domain. The
// old code took the "parent domain" of 10.30.0.4 to be "0.4" and reported
// missing SPF and DMARC for it.
func TestDNSHygieneSkipsIPTargets(t *testing.T) {
	for _, host := range []string{"10.30.0.4", "2001:db8::1", "[2001:db8::1]"} {
		fs, note := DNSHygiene{}.Check(context.Background(), host, &finding.Asset{ID: "a"})
		if len(fs) != 0 {
			t.Errorf("%s: %d findings, want none — an IP has no SPF/DMARC to check", host, len(fs))
		}
		if !strings.Contains(note.Skipped, "addressed by IP") {
			t.Errorf("%s: skip note %q does not say why", host, note.Skipped)
		}
	}
}

// listRunner answers `ls -1 <dir>` from a map; a missing key fails like an
// unreadable directory.
type listRunner map[string]string

func (l listRunner) Run(_ context.Context, argv ...string) exec.Result {
	out, ok := l[argv[len(argv)-1]]
	if !ok {
		return exec.Result{Command: strings.Join(argv, " "), ExitCode: 2, Stderr: "Permission denied"}
	}
	return exec.Result{Command: strings.Join(argv, " "), Stdout: out}
}
func (listRunner) Has(context.Context, string) bool                { return true }
func (listRunner) ReadFile(context.Context, string) (string, bool) { return "", false }
func (listRunner) Target() exec.Target                             { return exec.Target{Name: "t"} }

// TestUserCrontabsIgnoresSpoolDirs: on Debian, /var/spool/cron holds the
// crontabs/ directory. When crontabs/ itself was unreadable, the fallback
// listing reported a user named "crontabs".
func TestUserCrontabsIgnoresSpoolDirs(t *testing.T) {
	a := &finding.Asset{ID: "a"}
	if fs := (Hygiene{}).userCrontabs(context.Background(), listRunner{"/var/spool/cron": "crontabs\natjobs\natspool\n"}, a); len(fs) != 0 {
		t.Errorf("spool directories reported as users: %s", fs[0].Title)
	}
	fs := (Hygiene{}).userCrontabs(context.Background(), listRunner{"/var/spool/cron": "crontabs\nalice\n"}, a)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Title, "1 per-user") {
		t.Errorf("RHEL-style user file not counted: %+v", fs)
	}
}

// fileRunner serves commands (keyed by the full command line) and files.
type fileRunner struct {
	cmds  map[string]string
	files map[string]string
}

func (f fileRunner) Run(_ context.Context, argv ...string) exec.Result {
	c := strings.Join(argv, " ")
	out, ok := f.cmds[c]
	if !ok {
		return exec.Result{Command: c, ExitCode: 1}
	}
	return exec.Result{Command: c, Stdout: out}
}
func (fileRunner) Has(context.Context, string) bool { return true }
func (f fileRunner) ReadFile(_ context.Context, p string) (string, bool) {
	s, ok := f.files[p]
	return s, ok
}
func (fileRunner) Target() exec.Target { return exec.Target{Name: "t"} }

// TestSSHDUsesEffectiveConfig: on betty a drop-in set X11Forwarding no, which
// sshd honours, but the collector kept reporting the stock "yes" from the main
// file. When sshd -T is available its answer is the truth.
func TestSSHDUsesEffectiveConfig(t *testing.T) {
	main := "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nX11Forwarding yes\n"
	r := fileRunner{
		cmds:  map[string]string{"sshd -T": "x11forwarding no\npasswordauthentication no\npermitrootlogin without-password\n"},
		files: map[string]string{"/etc/ssh/sshd_config": main},
	}
	fs, _ := SSHD{}.Collect(context.Background(), r, &finding.Asset{ID: "a"})
	for _, f := range fs {
		if f.RuleID == "identity.ssh-x11-forwarding" {
			t.Fatalf("X11 reported from the file although sshd -T says no: %s", f.Evidence[0].Output)
		}
	}

	// And the effective "yes" is still reported, with sshd -T as the source.
	r.cmds["sshd -T"] = "x11forwarding yes\npasswordauthentication no\n"
	fs, _ = SSHD{}.Collect(context.Background(), r, &finding.Asset{ID: "a"})
	found := false
	for _, f := range fs {
		if f.RuleID == "identity.ssh-x11-forwarding" {
			found = true
			if !strings.Contains(f.Evidence[0].Path+f.Evidence[0].Output, "sshd -T") {
				t.Errorf("evidence does not name sshd -T as its source: %+v", f.Evidence[0])
			}
		}
	}
	if !found {
		t.Error("effective X11Forwarding yes not reported")
	}
}
