package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// stubRunner answers from fixed tables: a command line (argv joined by spaces)
// either has an entry, which succeeds with that stdout, or fails.
type stubRunner struct {
	ok    map[string]string
	has   map[string]bool
	files map[string]string
}

func (s stubRunner) Run(_ context.Context, argv ...string) exec.Result {
	cmd := strings.Join(argv, " ")
	if out, ok := s.ok[cmd]; ok {
		return exec.Result{Command: cmd, Stdout: out}
	}
	return exec.Result{Command: cmd, ExitCode: 1}
}
func (s stubRunner) Has(_ context.Context, c string) bool { return s.has[c] }
func (s stubRunner) ReadFile(_ context.Context, p string) (string, bool) {
	v, ok := s.files[p]
	return v, ok
}
func (s stubRunner) Target() exec.Target { return exec.Target{Name: "stub"} }

func TestAptUnattendedEnabled(t *testing.T) {
	for cfg, want := range map[string]bool{
		`APT::Periodic::Update-Package-Lists "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "1";`: true,
		`APT::Periodic::Unattended-Upgrade "7";`:                                                     true,
		`APT::Periodic::Unattended-Upgrade "0";`:                                                     false,
		// The old check matched any "1", including the package-lists line.
		`APT::Periodic::Update-Package-Lists "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "0";`: false,
		`// APT::Periodic::Unattended-Upgrade "1";`:                                                  false,
		`APT::Periodic::Unattended-Upgrade "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "0";`:   false,
		``: false,
	} {
		if got := aptUnattendedEnabled(cfg); got != want {
			t.Errorf("aptUnattendedEnabled(%q) = %v, want %v", cfg, got, want)
		}
	}
}

const aptDumpOn = `APT::Periodic::Unattended-Upgrade "1";` + "\n"

func TestDetectAutoUpdates(t *testing.T) {
	ctx := context.Background()
	dump := "apt-config dump APT::Periodic::Unattended-Upgrade"
	timer := "systemctl is-active --quiet apt-daily-upgrade.timer"
	cases := []struct {
		name string
		r    stubRunner
		want bool
	}{
		{"apt enabled, installed, timer active",
			stubRunner{ok: map[string]string{dump: aptDumpOn, timer: ""},
				has: map[string]bool{"unattended-upgrade": true, "systemctl": true}}, true},
		{"apt enabled but package missing",
			stubRunner{ok: map[string]string{dump: aptDumpOn, timer: ""},
				has: map[string]bool{"systemctl": true}}, false},
		{"apt enabled but timer inactive",
			stubRunner{ok: map[string]string{dump: aptDumpOn},
				has: map[string]bool{"unattended-upgrade": true, "systemctl": true}}, false},
		{"no systemd: config and binary suffice",
			stubRunner{ok: map[string]string{dump: aptDumpOn},
				has: map[string]bool{"unattended-upgrade": true}}, true},
		{"no apt-config: falls back to the file",
			stubRunner{files: map[string]string{aptAutoUpgradesFile: aptDumpOn},
				has: map[string]bool{"unattended-upgrade": true}}, true},
		{"apt disabled",
			stubRunner{ok: map[string]string{dump: `APT::Periodic::Unattended-Upgrade "0";`},
				has: map[string]bool{"unattended-upgrade": true}}, false},
		{"dnf-automatic-install timer",
			stubRunner{ok: map[string]string{"systemctl is-active --quiet dnf-automatic-install.timer": ""},
				has: map[string]bool{"systemctl": true}}, true},
		{"dnf-automatic download-only",
			stubRunner{ok: map[string]string{"systemctl is-active --quiet dnf-automatic.timer": ""},
				has:   map[string]bool{"systemctl": true},
				files: map[string]string{"/etc/dnf/automatic.conf": "[commands]\napply_updates = no\n"}}, false},
		{"dnf-automatic applying",
			stubRunner{ok: map[string]string{"systemctl is-active --quiet dnf-automatic.timer": ""},
				has:   map[string]bool{"systemctl": true},
				files: map[string]string{"/etc/dnf/automatic.conf": "[commands]\napply_updates = yes\n"}}, true},
		{"nothing", stubRunner{}, false},
	}
	for _, c := range cases {
		ctl, ok := detectAutoUpdates(ctx, c.r)
		if ok != c.want {
			t.Errorf("%s: detected = %v, want %v", c.name, ok, c.want)
		}
		if ok && (ctl.ID != "auto-updates" || ctl.Limits == "") {
			t.Errorf("%s: control %q must use the catalogue ID and state its limits", c.name, ctl.ID)
		}
	}
}

// TestActiveAutoUpdatesIsNotRecommended is the bug this file exists for: with
// the control detected, Recommend must not tell the operator to enable it.
func TestActiveAutoUpdatesIsNotRecommended(t *testing.T) {
	f := finding.Finding{RuleID: "patch.updates-pending", Severity: finding.SevMedium}
	has := func(ms []finding.Mitigation) bool {
		for _, m := range ms {
			if strings.Contains(strings.ToLower(m.Name), "unattended") {
				return true
			}
		}
		return false
	}
	if !has(Recommend(f, nil)) {
		t.Fatal("precondition: with no active controls, auto-updates should be recommended")
	}
	ctl, ok := detectAutoUpdates(context.Background(), stubRunner{
		ok:  map[string]string{"apt-config dump APT::Periodic::Unattended-Upgrade": aptDumpOn},
		has: map[string]bool{"unattended-upgrade": true}})
	if !ok {
		t.Fatal("detector did not fire")
	}
	if has(Recommend(f, []Control{ctl})) {
		t.Error("auto-updates recommended although it is active")
	}
}
