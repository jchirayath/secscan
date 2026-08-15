package remediate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Step is one recorded action in a remediation run.
type Step struct {
	Phase   string `json:"phase"` // canary | backup | apply | verify | rollback
	Command string `json:"command"`
	Output  string `json:"output,omitempty"`
	Exit    int    `json:"exit"`
	OK      bool   `json:"ok"`
}

// Result is the full record of one attempt.
type Result struct {
	FindingID string     `json:"finding_id"`
	Rule      string     `json:"rule"`
	Title     string     `json:"title"`
	Risk      ChangeRisk `json:"risk"`
	At        time.Time  `json:"at"`

	Applied    bool   `json:"applied"`
	Verified   bool   `json:"verified"`
	RolledBack bool   `json:"rolled_back"`
	Steps      []Step `json:"steps"`
	Error      string `json:"error,omitempty"`
	// PriorState is whatever Backup captured, kept so a human can restore by
	// hand even if automated rollback was not possible.
	PriorState []string `json:"prior_state,omitempty"`
}

// Options control an attempt.
type Options struct {
	// DryRun runs the canary and the backup, prints what would be applied, and
	// stops. This is the default everywhere it can be.
	DryRun bool
	// Timeout bounds each command.
	Timeout time.Duration
}

// Apply executes a fix, verifies it, and rolls back if verification fails.
//
// The order is deliberate and each step earns its place:
//
//  1. canary   — prove we can reach and command the host BEFORE changing it,
//     so a failure here is "could not start" rather than "changed
//     something and then lost contact"
//  2. backup   — capture prior state; without it rollback is a guess
//  3. apply    — the change
//  4. canary   — prove we STILL have the host. This is the step that matters:
//     if a fix cost us access, we want to know now, while the
//     operator is watching, not at the next scan
//  5. verify   — prove the weakness is actually gone, by testing the condition
//     rather than trusting that the command exited zero
//  6. rollback — only if verify failed
func Apply(ctx context.Context, r exec.Runner, f finding.Finding, opts Options) Result {
	res := Result{
		FindingID: f.ID, Rule: f.RuleID, Title: f.Title, At: clock.Now(),
	}
	if opts.Timeout == 0 {
		opts.Timeout = 60 * time.Second
	}

	p, ok := Lookup(f)
	if !ok {
		res.Error = "no reviewed fix exists for " + f.RuleID + "; it must be applied by hand"
		return res
	}
	res.Risk = p.Risk

	// The refusal is here, not in the caller, so no future caller can route
	// around it by forgetting to check.
	if !p.Executable() {
		res.Error = fmt.Sprintf("fix for %s is %s, not green — %s", f.RuleID, p.Risk, p.Why)
		return res
	}

	// sudo is added here, explicitly, for the phases that change the host.
	// Relying on the transport's needs-privilege heuristic would mean a fix
	// silently ran unprivileged, failed to take effect, and got reported as
	// "verification failed" instead of "we were not allowed to do this".
	priv := func(argv []string) []string {
		if !p.Privileged || len(argv) == 0 || argv[0] == "sudo" || r.Target().IsLocal() && isRoot() {
			return argv
		}
		return append([]string{"sudo", "-n"}, argv...)
	}

	run := func(phase string, argv []string) Step {
		if phase == "apply" || phase == "rollback" {
			argv = priv(argv)
		}
		out := r.Run(ctx, argv...)
		text := strings.TrimSpace(out.Stdout)
		if e := strings.TrimSpace(out.Stderr); e != "" {
			text = strings.TrimSpace(text + "\n" + e)
		}
		if !out.OK() && strings.Contains(text, "sudo:") {
			text += "\n(the scanning account is not permitted to run this; " +
				"grant it in sudoers or apply the fix by hand)"
		}
		st := Step{
			Phase: phase, Command: strings.Join(argv, " "),
			Output: text, Exit: out.ExitCode, OK: out.OK(),
		}
		res.Steps = append(res.Steps, st)
		return st
	}

	// 1. Canary before.
	if st := run("canary", []string{"echo", "secscan-canary"}); !st.OK {
		res.Error = "host did not respond before any change was attempted; nothing was done"
		return res
	}

	// 2. Backup.
	for _, cmd := range p.Backup {
		st := run("backup", cmd)
		if st.OK {
			res.PriorState = append(res.PriorState, st.Command+" → "+st.Output)
		}
	}

	if opts.DryRun {
		for _, cmd := range p.Apply {
			res.Steps = append(res.Steps, Step{
				Phase: "apply", Command: strings.Join(priv(cmd), " "),
				Output: "(dry run — not executed)", OK: true,
			})
		}
		return res
	}

	// 3. Apply.
	for _, cmd := range p.Apply {
		if st := run("apply", cmd); !st.OK {
			res.Error = "apply failed: " + st.Output
			// A partial apply is why backup exists; try to undo it.
			res.RolledBack = rollback(run, p)
			return res
		}
	}
	res.Applied = true

	// 4. Canary after — the step that catches a fix which cost us the host.
	if st := run("canary", []string{"echo", "secscan-canary"}); !st.OK {
		res.Error = "the host stopped responding after the change was applied — " +
			"attempting rollback, but you should check this host directly now"
		res.RolledBack = rollback(run, p)
		return res
	}

	// 5. Verify the condition, not the exit code of the fix.
	st := run("verify", p.Verify)
	res.Verified = st.OK
	if !res.Verified {
		res.Error = "the fix ran but verification says the weakness is still present; rolling back"
		res.RolledBack = rollback(run, p)
	}
	return res
}

func isRoot() bool { return os.Geteuid() == 0 }

func rollback(run func(string, []string) Step, p Playbook) bool {
	if len(p.Rollback) == 0 {
		return false
	}
	ok := true
	for _, cmd := range p.Rollback {
		if st := run("rollback", cmd); !st.OK {
			ok = false
		}
	}
	return ok
}

// Plan describes what would happen, without doing it.
type Plan struct {
	FindingID string `json:"finding_id"`
	Rule      string `json:"rule"`
	// Playbook is the catalogue entry that matched. Families like
	// container.image-cve.<cve> all share one entry, so this is what to group
	// by — grouping by Rule instead prints the same advice 871 times.
	Playbook   string     `json:"playbook,omitempty"`
	Title      string     `json:"title"`
	Risk       ChangeRisk `json:"risk"`
	Why        string     `json:"why"`
	Executable bool       `json:"executable"`
	Backup     []string   `json:"backup,omitempty"`
	Apply      []string   `json:"apply,omitempty"`
	Verify     []string   `json:"verify,omitempty"`
	Rollback   []string   `json:"rollback,omitempty"`
	// Blocked explains, when Executable is false, why the tool will not do it.
	Blocked string `json:"blocked,omitempty"`
}

// PlanFor builds the plan shown before anything runs.
func PlanFor(f finding.Finding) Plan {
	pl := Plan{FindingID: f.ID, Rule: f.RuleID, Title: f.Title}
	p, ok := Lookup(f)
	if !ok {
		pl.Blocked = "No reviewed fix exists for this finding. The remediation text describes " +
			"what to do by hand; nothing is generated from it, because running generated shell " +
			"as root is how a scanner becomes the incident."
		return pl
	}
	pl.Playbook = p.RuleID
	pl.Risk, pl.Why = p.Risk, p.Why
	pl.Backup, pl.Apply = joinAll(p.Backup), joinAll(p.Apply)
	pl.Rollback = joinAll(p.Rollback)
	if len(p.Verify) > 0 {
		pl.Verify = []string{strings.Join(p.Verify, " ")}
	}
	pl.Executable = p.Executable()

	if !pl.Executable {
		switch {
		case p.Risk == RiskRed:
			pl.Blocked = "Red: this tool will not apply it. " + p.Why
		case p.Risk == RiskAmber:
			pl.Blocked = "Amber: needs a human and a maintenance window. " + p.Why
		default:
			pl.Blocked = "No apply or verify step is defined, so the result could not be proven."
		}
	}
	return pl
}

// joinAll renders each argv as one displayable line.
func joinAll(cmds [][]string) []string {
	var out []string
	for _, c := range cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}
