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
