// Package scan orchestrates a run: build a runner for the target, execute every
// collector, run whichever optional engines are installed, weight risk, and
// summarise — including an honest account of what did not run.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/collect"
	"github.com/jchirayath/secscan/internal/core/engine"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/feature"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/core/risk"
	"github.com/jchirayath/secscan/internal/store"
)

// Result is one target's scan outcome.
type Result struct {
	Asset      finding.Asset        `json:"asset"`
	Findings   []finding.Finding    `json:"findings"`
	Collectors []store.CollectorRun `json:"collectors"`
	Engines    []engine.Status      `json:"engines"`
	Duration   time.Duration        `json:"-"`
	Provenance finding.Provenance   `json:"provenance"`
	Probed     int                  `json:"probed"`    // ports verified from outside
	Controls   []collect.Control    `json:"controls"`  // compensating controls detected
	Mitigated  int                  `json:"mitigated"` // findings with residual < inherent
	Validated  int                  `json:"validated"` // findings proven or refuted by a live test
	// Transcript is what each check actually ran, so an operator can check the
	// scanner's work rather than take the conclusions on faith.
	Transcript map[string][]exec.Step `json:"transcript,omitempty"`
}

// Options control a run.
type Options struct {
	Timeout time.Duration
	// SkipEngines runs native collectors only. Useful for a fast pass and for
	// deterministic tests.
	SkipEngines bool
	// Features carries the operator's enable/disable choices. The zero value
	// enables everything, so a caller that does not care gets full coverage.
	Features feature.State
	// SkipValidation turns off live proof-of-exploitability tests. Those tests
	// write and remove uniquely-named temp files on the target; a scan of a
	// system under change freeze may want them off.
	SkipValidation bool
	// SkipReachability turns off the external exposure probe. Tests set this;
	// so does anyone scanning a host with no public address.
	SkipReachability bool
}

// Run scans one target.
func Run(ctx context.Context, t exec.Target, opts Options) (Result, error) {
	start := clock.Now()
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	r := exec.New(t, opts.Timeout)

	asset := finding.Asset{
		ID:       t.Name,
		Name:     t.Name,
		Kind:     "host",
		Address:  t.Host,
		Critical: t.Critical,
		LastScan: start,
	}
	if asset.Address == "" {
		asset.Address = "localhost"
	}

	res := Result{Asset: asset, Provenance: finding.ProvLive,
		Transcript: map[string][]exec.Step{}}
	var all []finding.Finding

	// Preflight. Without this, an unreachable or unauthenticated target makes
	// every single collector report "not present" — "/etc/passwd unreadable
	// (non-POSIX host?)" when the truth is "SSH refused the key". That is a
	// confidently wrong scan, which is worse than no scan, so fail loudly here
	// instead of returning a clean-looking empty result.
	if err := preflight(ctx, r); err != nil {
		res.Provenance = finding.ProvUnavailable
		return res, fmt.Errorf("target %s unreachable: %w", t.Name, err)
	}

	for _, c := range collect.All() {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		// A disabled collector is reported as disabled, never omitted. The
		// coverage view must always account for every check that exists.
		if !opts.Features.IsEnabled(c.ID()) {
			res.Collectors = append(res.Collectors, store.CollectorRun{
				ID: c.ID(), Ran: false, Skipped: "disabled by operator",
			})
			continue
		}
		cStart := clock.Now()
		// One recorder per collector: a shared one would attribute every
		// command to whichever check happened to run last.
		rec := exec.NewRecorder(r)
		fs, note := c.Collect(ctx, rec, &res.Asset)
		all = append(all, fs...)
		res.Collectors = append(res.Collectors, store.CollectorRun{
			ID: note.Collector, Ran: note.Ran, Skipped: note.Skipped,
			Checks: note.Checks, Found: len(fs),
		})
		res.Transcript[c.ID()] = rec.Steps()
		slog.Debug("collector complete",
			slog.String("collector", c.ID()), slog.Bool("ran", note.Ran),
			slog.Int("found", len(fs)), slog.Duration("took", time.Since(cStart)))
	}

	// If a collector could not determine the OS, everything downstream is
	// guesswork. Say the result is partial rather than presenting it as whole.
	if res.Asset.OS == "" {
		res.Provenance = finding.ProvPartial
	}

	if !opts.SkipEngines {
		erec := exec.NewRecorder(r)
		fs, statuses := engine.RunAll(ctx, erec, &res.Asset, engineGate{opts.Features})
		all = append(all, fs...)
		res.Engines = statuses
		for _, st := range statuses {
			res.Transcript[st.ID] = filterSteps(erec.Steps(), st.ID)
		}
	} else {
		for _, e := range engine.All() {
			res.Engines = append(res.Engines, engine.Status{
				ID: e.ID(), Installed: false, Reason: "engines skipped by request",
			})
		}
	}

	// Asset criticality is a property of the target, not of any collector, so
	// it is stamped here rather than asked of every collector — otherwise the
	// ×1.3 multiplier silently never fires.
	for i := range all {
		all[i].AssetCritical = res.Asset.Critical
	}

	// Exposure is applied after collection, not during: only the Listeners
	// collector knows what is reachable, and its answer must weight findings
	// that other collectors produced.
	applyExposure(all)

	// WebHeaders reaches out to the sites this host serves, so it is gated the
	// same way as the other outbound checks rather than sitting in collect.All()
	// — a scan told not to touch the network must not quietly make requests.
	if opts.Features.IsEnabled("web-headers") && !opts.SkipReachability {
		wrec := exec.NewRecorder(r)
		fs, note := collect.WebHeaders{}.Collect(ctx, wrec, &res.Asset)
		all = append(all, fs...)
		res.Transcript["web-headers"] = wrec.Steps()
		res.Collectors = append(res.Collectors, store.CollectorRun{
			ID: note.Collector, Ran: note.Ran, Skipped: note.Skipped,
			Checks: note.Checks, Found: len(fs),
		})
	}

	// DNS/mail hygiene is a public-record lookup rather than a host probe, so
	// it runs off the target's public name rather than through the runner.
	if opts.Features.IsEnabled("dns-hygiene") && t.Host != "" && !opts.SkipReachability {
		fs, note := collect.DNSHygiene{}.Check(ctx, t.Host, &res.Asset)
		all = append(all, fs...)
		res.Collectors = append(res.Collectors, store.CollectorRun{
			ID: note.Collector, Ran: note.Ran, Skipped: note.Skipped,
			Checks: note.Checks, Found: len(fs),
		})
	}

	// Validate before scoring: proving or refuting a finding changes its
	// weight, and a refuted finding must not be ranked as if it were real.
	if opts.Features.IsEnabled("validate") && !opts.SkipValidation {
		vrec := exec.NewRecorder(r)
		res.Validated = collect.Validator{}.Validate(ctx, vrec, all)
		res.Transcript["validate"] = vrec.Steps()
		res.Collectors = append(res.Collectors, store.CollectorRun{
			ID: "validate", Ran: true, Checks: len(all), Found: res.Validated,
		})
	} else {
		res.Collectors = append(res.Collectors, store.CollectorRun{
			ID: "validate", Ran: false, Skipped: "disabled by operator",
		})
	}

	// Detect compensating controls and attach them BEFORE scoring, so residual
	// risk is what the dashboard ranks on. The order matters: exposure raises
	// inherent risk, controls reduce it, and residual is what is left.
	if opts.Features.IsEnabled("controls") {
		crec := exec.NewRecorder(r)
		ctrls, note := collect.ControlsCollector{}.Detect(ctx, crec, &res.Asset)
		res.Transcript["controls"] = crec.Steps()
		res.Controls = ctrls
		res.Collectors = append(res.Collectors, store.CollectorRun{
			ID: note.Collector, Ran: note.Ran, Skipped: note.Skipped,
			Checks: note.Checks, Found: len(ctrls),
		})
		res.Mitigated = collect.ApplyControls(all, ctrls)
		// Where nothing is protecting a finding, say what would.
		collect.ApplyRecommendations(all, ctrls)
	}

	// Verify exposure from outside rather than inferring it from the bind
	// address. A socket on 0.0.0.0 behind a cloud security group is not
	// exposed, and one behind an authenticating proxy is exposed differently —
	// scoring both as "internet-facing" over-ranks them and erodes trust in the
	// whole ordering.
	if !opts.SkipReachability && t.Host != "" {
		res.Probed = collect.Reachability{}.Apply(ctx, all, t.Host, t.VirtualHosts...)
	}

	risk.Apply(all)
	finding.Sort(all)

	res.Findings = all
	res.Duration = time.Since(start)
	return res, nil
}

// engineGate routes the enable decision through feature.ShouldRun, so an
// expensive engine's opt-in requirement is honoured identically by the scanner
// and the UI. Two places deciding "does this run?" is how they drift.
type engineGate struct{ st feature.State }

func (g engineGate) IsEnabled(id string) bool { return feature.ShouldRun(g.st, id) }

// filterSteps narrows a shared engine transcript to the steps belonging to one
// engine, matched on its binary name appearing in the command.
func filterSteps(steps []exec.Step, engineID string) []exec.Step {
	var out []exec.Step
	for _, st := range steps {
		if strings.Contains(st.Command, engineID) {
			out = append(out, st)
		}
	}
	return out
}

// preflight proves we can actually execute on the target before believing
// anything a collector reports. `echo` is the cheapest command that must
// succeed on any POSIX host we can reach.
func preflight(ctx context.Context, r exec.Runner) error {
	const token = "secscan-ok"
	res := r.Run(ctx, "echo", token)
	if res.Err != nil {
		return fmt.Errorf("transport error: %w", res.Err)
	}
	if !strings.Contains(res.Stdout, token) {
		detail := strings.TrimSpace(res.Stderr)
		if detail == "" {
			detail = fmt.Sprintf("exit %d with no output", res.ExitCode)
		}
		return fmt.Errorf("%s", detail)
	}
	return nil
}

// applyExposure propagates network reachability onto findings that describe a
// service. A CVSS 9.8 on a loopback-bound daemon is not the same risk as the
// same CVE on a socket bound to 0.0.0.0, and this is the only place that
// distinction gets made.
func applyExposure(fs []finding.Finding) {
	exposedPorts := map[string]bool{}
	for _, f := range fs {
		if f.RuleID == "network.wide-bind" && f.Exposed {
			if f.Component.Name != "" {
				exposedPorts[f.Component.Name] = true
			}
		}
	}
	if len(exposedPorts) == 0 {
		return
	}
	for i := range fs {
		if fs[i].Exposed {
			continue
		}
		// Container and service findings name their process/container; if that
		// process holds a wide-bound socket, the finding is externally reachable.
		if n := fs[i].Component.Name; n != "" && exposedPorts[n] {
			fs[i].Exposed = true
		}
	}
}

// Score converts findings into a 0–100 posture score, higher is better.
//
// The obvious implementation — sum a weight per finding — saturates. A host
// with 900 container-image CVEs scores 0.4, and so does a host with 3,000: the
// number stops distinguishing anything at exactly the point you most want it
// to. Worse, it says a host with 800 CVEs in one image is catastrophically
// worse than one with 20 unrelated critical misconfigurations, which is not
// how an operator would rank them.
//
// So the penalty is grouped by REMEDIATION ACTION, with diminishing returns
// inside each group. 800 CVEs cleared by one `docker pull` are one piece of
// work, and the score should reflect the work outstanding rather than the row
// count. The first finding in a group costs full weight, the rest decay — the
// group still counts for more than a single finding, just not 800× more.
func Score(fs []finding.Finding) float64 {
	weight := map[finding.Severity]float64{
		finding.SevCritical: 25, finding.SevHigh: 10,
		finding.SevMedium: 4, finding.SevLow: 1, finding.SevInfo: 0,
	}

	// Group by the action that would clear it; findings with no remediation
	// group by rule, which is the next-best proxy for "one piece of work".
	groups := map[string][]finding.Finding{}
	for _, f := range fs {
		if f.Status != finding.StatusOpen {
			continue
		}
		key := f.Remediation.Op + "|" + f.Remediation.Summary
		if f.Remediation.Summary == "" {
			key = f.RuleID
		}
		groups[key] = append(groups[key], f)
	}

	var penalty float64
	for _, g := range groups {
		// Worst first, so the decay applies to the tail rather than the head.
		finding.Sort(g)
		for i, f := range g {
			w := weight[f.Severity]
			if f.Exposed {
				w *= 1.5
			}
			if f.MitigationFactor > 0 && f.MitigationFactor < 1 {
				w *= f.MitigationFactor
			}
			// 1, 1/2, 1/3 … — the tenth instance of the same fixable problem
			// is not ten times the work of the first.
			penalty += w / float64(i+1)
		}
	}

	score := 100 / (1 + penalty/40)
	return float64(int64(score*10+0.5)) / 10
}

// Summarise builds the history row for a completed scan.
func Summarise(res Result, newN, fixedN int) store.ScanSummary {
	// Engines belong in the coverage record alongside collectors. Recording
	// only collectors made the Coverage view silently omit every external
	// engine — so a reader would see a complete-looking list that never
	// mentioned Trivy was absent, which is precisely the silent gap this
	// product exists to prevent.
	coverage := append([]store.CollectorRun(nil), res.Collectors...)
	for _, e := range res.Engines {
		coverage = append(coverage, store.CollectorRun{
			ID: e.ID, Ran: e.Ran, Skipped: e.Reason, Found: e.Found,
		})
	}

	counts := map[string]int{}
	for _, f := range res.Findings {
		if f.Status == finding.StatusOpen {
			counts[string(f.Severity)]++
		}
	}
	return store.ScanSummary{
		At:        clock.Now(),
		Target:    res.Asset.ID,
		Duration:  res.Duration.Round(time.Millisecond).String(),
		Counts:    counts,
		Total:     len(res.Findings),
		New:       newN,
		Fixed:     fixedN,
		Score:     Score(res.Findings),
		Collector: coverage,
	}
}

// Plan groups findings into the minimum ordered set of actions, most risk
// cleared first. This is the v1 remediation deliverable: a reviewed script,
// never an automatic change.
type Action struct {
	Summary      string   `json:"summary"`
	Command      string   `json:"command,omitempty"`
	Op           string   `json:"op"`
	RiskCleared  float64  `json:"risk_cleared"`
	FindingIDs   []string `json:"finding_ids"`
	FindingCount int      `json:"finding_count"`
}

// BuildPlan collapses findings by remediation, summing the risk each clears.
func BuildPlan(fs []finding.Finding) []Action {
	byKey := map[string]*Action{}
	for _, f := range fs {
		if f.Status != finding.StatusOpen || f.Remediation.Summary == "" {
			continue
		}
		key := f.Remediation.Op + "|" + f.Remediation.Summary + "|" + f.Remediation.Command
		a, ok := byKey[key]
		if !ok {
			a = &Action{
				Summary: f.Remediation.Summary,
				Command: f.Remediation.Command,
				Op:      f.Remediation.Op,
			}
			byKey[key] = a
		}
		a.RiskCleared += f.ResidualRisk
		a.FindingIDs = append(a.FindingIDs, f.ID)
		a.FindingCount++
	}
	out := make([]Action, 0, len(byKey))
	for _, a := range byKey {
		a.RiskCleared = float64(int64(a.RiskCleared*100+0.5)) / 100
		out = append(out, *a)
	}
	// Most risk cleared first; ties broken by name so the order is stable.
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j].RiskCleared > out[i].RiskCleared ||
				(out[j].RiskCleared == out[i].RiskCleared && out[j].Summary < out[i].Summary) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// PlanScript renders the plan as a shell script for a human to review and run.
// It is never executed by the scanner.
func PlanScript(actions []Action, assetName string) string {
	s := fmt.Sprintf("#!/usr/bin/env bash\n"+
		"# secscan remediation plan for %s\n"+
		"# Generated %s\n"+
		"#\n"+
		"# REVIEW EVERY LINE BEFORE RUNNING. This script was generated from scan\n"+
		"# findings; it has not been tested against this host's configuration.\n"+
		"set -euo pipefail\n\n", assetName, clock.Now().Format(time.RFC3339))
	for i, a := range actions {
		s += fmt.Sprintf("# %d. %s\n#    clears %.2f risk across %d finding(s)\n",
			i+1, a.Summary, a.RiskCleared, a.FindingCount)
		if a.Command == "" {
			s += "#    (manual — no safe automatic command)\n\n"
			continue
		}
		s += a.Command + "\n\n"
	}
	return s
}
