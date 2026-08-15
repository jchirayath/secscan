package remediate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
	osexec "os/exec"
)

// These tests guard the invariants that make this component safe to ship. If
// one of them fails, the right response is to stop, not to adjust the test.

// TestNothingTouchingAccessPathIsGreen is the central one. A fix that can
// interfere with SSH, authentication, firewalling or boot must never be
// executable, because if it goes wrong the tool has destroyed the means of
// repairing what it broke.
func TestNothingTouchingAccessPathIsGreen(t *testing.T) {
	for _, p := range catalogue {
		n := normalise(p)
		if p.TouchesAccessPath && n.Risk != RiskRed {
			t.Errorf("%s touches the access path but is %s", p.RuleID, n.Risk)
		}
		if p.TouchesAccessPath && n.Executable() {
			t.Errorf("%s touches the access path and is EXECUTABLE — this could lock the "+
				"operator out of the host being fixed", p.RuleID)
		}
	}
}

// TestGreenPlaybooksAreComplete: green means we can prove it worked and undo it.
func TestGreenPlaybooksAreComplete(t *testing.T) {
	for _, p := range catalogue {
		n := normalise(p)
		if n.Risk != RiskGreen {
			continue
		}
		if len(n.Apply) == 0 {
			t.Errorf("%s is green with nothing to apply", p.RuleID)
		}
		if len(n.Verify) == 0 {
			t.Errorf("%s is green with no verification — a fix we cannot prove worked "+
				"must not run unattended", p.RuleID)
		}
		if len(n.Backup) == 0 {
			t.Errorf("%s is green with no backup — rollback would be a guess", p.RuleID)
		}
		if n.NeedsRestart != "" {
			t.Errorf("%s is green but restarts %q", p.RuleID, n.NeedsRestart)
		}
	}
}

// TestRestartsAreNeverGreen
func TestRestartsAreNeverGreen(t *testing.T) {
	p := normalise(Playbook{
		RuleID: "x", Risk: RiskGreen, NeedsRestart: "nginx",
		Apply: [][]string{{"true"}}, Verify: []string{"true"}, Backup: [][]string{{"true"}},
	})
	if p.Risk == RiskGreen {
		t.Error("a playbook that restarts a service stayed green")
	}
}

// TestUnknownFindingsAreNotExecutable: the catalogue is an allow-list. A
// finding with no reviewed playbook must never fall back to running whatever
// command string a collector happened to emit.
func TestUnknownFindingsAreNotExecutable(t *testing.T) {
	f := finding.Finding{
		RuleID: "some.rule.nobody.reviewed",
		Remediation: finding.Remediation{
			Op: "change_config", Command: "rm -rf / --no-preserve-root",
		},
	}
	if _, ok := Lookup(f); ok {
		t.Fatal("an unreviewed rule resolved to a playbook")
	}
	plan := PlanFor(f)
	if plan.Executable {
		t.Error("an unreviewed finding is executable")
	}
	if len(plan.Apply) > 0 {
		t.Errorf("a plan was generated from the finding's own command: %v", plan.Apply)
	}

	res := Apply(context.Background(), &stubRunner{}, f, Options{})
	if res.Applied {
		t.Fatal("Apply executed an unreviewed finding — the allow-list was bypassed")
	}
}

// TestAmberAndRedRefuseToRun
func TestAmberAndRedRefuseToRun(t *testing.T) {
	for _, rule := range []string{"identity.ssh-password-auth", "patch.updates-pending", "hardening.no-firewall"} {
		f := finding.Finding{RuleID: rule}
		res := Apply(context.Background(), &stubRunner{}, f, Options{})
		if res.Applied {
			t.Errorf("%s was applied despite not being green", rule)
		}
		if res.Error == "" {
			t.Errorf("%s produced no explanation for the refusal", rule)
		}
	}
}

// TestVerifyFailureTriggersRollback: a fix that did not take must not be left
// in place and reported as done.
func TestVerifyFailureTriggersRollback(t *testing.T) {
	r := &stubRunner{failVerify: true}
	f := finding.Finding{RuleID: "hygiene.log-dir-world-readable"}

	res := Apply(context.Background(), r, f, Options{})
	if res.Verified {
		t.Fatal("reported verified when verification failed")
	}
	if !res.RolledBack {
		t.Error("verification failed but no rollback ran")
	}
	var phases []string
	for _, s := range res.Steps {
		phases = append(phases, s.Phase)
	}
	joined := strings.Join(phases, ",")
	for _, want := range []string{"canary", "backup", "apply", "verify", "rollback"} {
		if !strings.Contains(joined, want) {
			t.Errorf("phase %q missing from %s", want, joined)
		}
	}
}

// TestDryRunChangesNothing
func TestDryRunChangesNothing(t *testing.T) {
	r := &stubRunner{}
	f := finding.Finding{RuleID: "hygiene.log-dir-world-readable"}

	res := Apply(context.Background(), r, f, Options{DryRun: true})
	if res.Applied {
		t.Error("dry run reported applying the change")
	}
	for _, c := range r.ran {
		if strings.HasPrefix(c, "chmod") {
			t.Errorf("dry run executed a mutating command: %q", c)
		}
	}
}

// TestCanaryRunsBeforeAnyChange: if the host is unreachable we must fail
// before touching it, not after.
func TestCanaryRunsBeforeAnyChange(t *testing.T) {
	r := &stubRunner{failAll: true}
	f := finding.Finding{RuleID: "hygiene.log-dir-world-readable"}

	res := Apply(context.Background(), r, f, Options{})
	if res.Applied {
		t.Fatal("applied a change to a host that never answered")
	}
	if len(r.ran) != 1 || !strings.HasPrefix(r.ran[0], "echo") {
		t.Errorf("expected only the canary to have run, got %v", r.ran)
	}
}

// ---- stub ----------------------------------------------------------------

type stubRunner struct {
	ran        []string
	failVerify bool
	failAll    bool
}

func (s *stubRunner) Run(_ context.Context, argv ...string) exec.Result {
	cmd := strings.Join(argv, " ")
	s.ran = append(s.ran, cmd)
	switch {
	case s.failAll:
		return exec.Result{Command: cmd, ExitCode: 1}
	case s.failVerify && strings.Contains(cmd, "test "):
		return exec.Result{Command: cmd, ExitCode: 1}
	}
	return exec.Result{Command: cmd, Stdout: "ok", ExitCode: 0}
}

func (s *stubRunner) Has(context.Context, string) bool                { return true }
func (s *stubRunner) ReadFile(context.Context, string) (string, bool) { return "", false }
func (s *stubRunner) Target() exec.Target                             { return exec.Target{Name: "stub"} }

var _ = time.Second

// TestShellSnippetsParse runs every embedded shell fragment through `sh -n`.
//
// A syntax error in a Verify script is uniquely nasty: sh exits non-zero, the
// executor reads that as "the weakness is still present", and every apply
// rolls itself back forever with no indication that the script — not the host
// — is the problem. Catching it at build time costs nothing.
func TestShellSnippetsParse(t *testing.T) {
	check := func(t *testing.T, what string, argv []string) {
		t.Helper()
		if len(argv) < 3 || argv[0] != "sh" || argv[1] != "-c" {
			return // not a shell fragment
		}
		cmd := osexec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(argv[2])
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: shell snippet does not parse: %v\n%s\n%s",
				what, err, argv[2], out)
		}
	}
	for _, p := range catalogue {
		for _, c := range p.Backup {
			check(t, p.RuleID+" backup", c)
		}
		for _, c := range p.Apply {
			check(t, p.RuleID+" apply", c)
		}
		for _, c := range p.Rollback {
			check(t, p.RuleID+" rollback", c)
		}
		check(t, p.RuleID+" verify", p.Verify)
	}
}
