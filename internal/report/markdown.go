// Package report renders a scan as a document.
//
// The CLI and the web service run exactly the same scan through exactly the
// same code; the only difference is the rendering. That parity is deliberate —
// a report that disagrees with the dashboard is worse than either alone.
package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/core/scan"
)

// Render produces the assessment document from a scan result.
//
// It is written for someone who was not present for the scan: every number is
// explained, every finding carries its evidence, and the section saying what
// did NOT run comes before the findings rather than in an appendix. A reader
// who skims only the first page should still come away with an accurate
// impression — including of the gaps.
func Render(res scan.Result, score float64, generated time.Time) string {
	var b strings.Builder
	a := res.Asset

	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	// ---- header --------------------------------------------------------
	w("# Security posture assessment — %s", a.Name)
	w("")
	w("| | |")
	w("|---|---|")
	w("| **Host** | %s (%s) |", a.Name, orDash(a.Address))
	w("| **Operating system** | %s |", orDash(a.OS))
	w("| **Kernel** | %s |", orDash(a.Kernel))
	w("| **Scanned** | %s |", generated.Format(time.RFC1123))
	w("| **Duration** | %s |", res.Duration.Round(time.Millisecond))
	w("| **Posture score** | **%.1f / 100** |", score)
	w("| **Data quality** | %s |", provenanceNote(res.Provenance))
	w("")

	open := openFindings(res.Findings)
	counts := severityCounts(open)

	w("## Summary")
	w("")
	w("%d open finding(s): %s.", len(open), countLine(counts))
	if res.Mitigated > 0 {
		w("")
		w("%d finding(s) have their risk reduced by a compensating control that was verified "+
			"active on this host. %d were proven or refuted by a live test rather than inferred "+
			"from configuration.", res.Mitigated, res.Validated)
	}
	w("")
	w("> **How to read the risk numbers.** Each finding shows *inherent risk* — what it would " +
		"cost with no controls — and *residual risk*, which is what remains after the controls " +
		"actually in place. Residual is what the ordering below uses. Inherent is kept visible " +
		"because it is what the risk returns to if a control is removed or fails.")
	w("")

	// ---- coverage FIRST, not in an appendix -----------------------------
	// A reader who does not know what was skipped cannot judge what was found.
	var skipped []string
	for _, c := range res.Collectors {
		if !c.Ran {
			skipped = append(skipped, fmt.Sprintf("- **%s** — %s", c.ID, c.Skipped))
		}
	}
	for _, e := range res.Engines {
		if !e.Ran {
			skipped = append(skipped, fmt.Sprintf("- **%s** — %s", e.ID, e.Reason))
		}
	}
	w("## Coverage")
	w("")
	if len(skipped) == 0 {
		w("Every check ran.")
	} else {
		w("These checks did **not** run. Anything they would have found is not in this report — " +
			"an empty category below is only meaningful for the checks that actually executed.")
		w("")
		for _, s := range skipped {
			w("%s", s)
		}
	}
	w("")

	// ---- controls -------------------------------------------------------
	if len(res.Controls) > 0 {
		w("## Compensating controls in place")
		w("")
		w("| Control | Effect | What it does not cover |")
		w("|---|---|---|")
		for _, c := range res.Controls {
			w("| %s | ×%.2f | %s |", c.Name, c.Factor, oneLine(c.Limits))
		}
		w("")
	}

	// ---- exposure -------------------------------------------------------
	var exposed []finding.Finding
	for _, f := range open {
		if f.Exposed {
			exposed = append(exposed, f)
		}
	}
	if len(exposed) > 0 {
		w("## Exposed to the network")
		w("")
		w("Confirmed reachable from outside the host. Listed regardless of rank — a " +
			"well-defended entry point is still an entry point.")
		w("")
		w("| Residual | Severity | Service |")
		w("|---:|---|---|")
		for _, f := range exposed {
			w("| %.2f | %s | %s |", f.ResidualRisk, f.Severity, f.Title)
		}
		w("")
	}

	// ---- findings by category -------------------------------------------
	w("## Findings")
	w("")
	byCat := map[finding.Category][]finding.Finding{}
	for _, f := range open {
		byCat[f.Category] = append(byCat[f.Category], f)
	}
	for _, cat := range finding.AllCategories {
		fs := byCat[cat]
		if len(fs) == 0 {
			continue
		}
		w("### %s", cat.Label())
		w("")
		for _, f := range fs {
			writeFinding(&b, f)
		}
	}

	// ---- remediation plan ------------------------------------------------
	actions := scan.BuildPlan(res.Findings)
	if len(actions) > 0 {
		w("## Remediation plan")
		w("")
		w("The minimum set of actions, ordered by how much risk each one clears. " +
			"secscan does not run these — review, then apply.")
		w("")
		w("| # | Risk cleared | Findings | Action |")
		w("|---:|---:|---:|---|")
		for i, act := range actions {
			cmd := ""
			if act.Command != "" {
				cmd = " <br>`" + act.Command + "`"
			}
			w("| %d | %.2f | %d | %s%s |", i+1, act.RiskCleared, act.FindingCount, act.Summary, cmd)
		}
		w("")
	}

	w("---")
	w("")
	w("*Generated by secscan. Scan only systems you own or are authorised to test.*")
	return b.String()
}

func writeFinding(b *strings.Builder, f finding.Finding) {
	w := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }

	verdict := ""
	if f.Validation != nil {
		switch f.Validation.Verdict {
		case finding.VerdictConfirmed:
			verdict = " · ✅ **proven by a live test**"
		case finding.VerdictRefuted:
			verdict = " · ⚠️ **could not be exercised**"
		}
	}
	w("#### %s", f.Title)
	w("")
	w("`%s` · residual **%.2f** (inherent %.2f)%s", f.Severity, f.ResidualRisk, f.InherentRisk, verdict)
	w("")
	if f.Description != "" {
		w("%s", f.Description)
		w("")
	}
	if len(f.Mitigations) > 0 {
		w("**Compensating controls active** — risk reduced ×%.2f:", f.MitigationFactor)
		w("")
		for _, m := range f.Mitigations {
			w("- **%s** (×%.2f) — %s", m.Name, m.Factor, m.Detail)
			w("  - *Does not cover:* %s", oneLine(m.Limits))
		}
		w("")
	}
	if len(f.Recommended) > 0 {
		w("**Recommended compensating controls** (not currently in place) — useful when the " +
			"real fix needs a maintenance window:")
		w("")
		for _, m := range f.Recommended {
			w("- **%s** (would reduce ×%.2f) — %s", m.Name, m.Factor, m.Detail)
			w("  - *Would not cover:* %s", oneLine(m.Limits))
		}
		w("")
	}
	if f.Validation != nil && f.Validation.Verdict != finding.VerdictUnverified {
		w("**Validation** — %s", f.Validation.Method)
		w("")
		w("```")
		w("%s", f.Validation.Output)
		w("```")
		if f.Validation.Note != "" {
			w("")
			w("> %s", oneLine(f.Validation.Note))
		}
		w("")
	}
	if f.Remediation.Summary != "" {
		w("**Fix:** %s", f.Remediation.Summary)
		if f.Remediation.Command != "" {
			w("")
			w("```bash")
			w("%s", f.Remediation.Command)
			w("```")
		}
		w("")
	}
	if len(f.Evidence) > 0 {
		w("<details><summary>Evidence</summary>")
		w("")
		for _, e := range f.Evidence {
			if e.Command != "" {
				w("```console")
				w("$ %s", e.Command)
				w("%s", e.Output)
				w("```")
			} else {
				w("```")
				if e.Path != "" {
					w("%s", e.Path)
				}
				w("%s", e.Output)
				w("```")
			}
		}
		w("</details>")
		w("")
	}
}

// ---------------------------------------------------------------- helpers

func openFindings(fs []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Status == finding.StatusOpen {
			out = append(out, f)
		}
	}
	return out
}

func severityCounts(fs []finding.Finding) map[finding.Severity]int {
	c := map[finding.Severity]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

func countLine(c map[finding.Severity]int) string {
	order := []finding.Severity{finding.SevCritical, finding.SevHigh,
		finding.SevMedium, finding.SevLow, finding.SevInfo}
	var parts []string
	for _, s := range order {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func provenanceNote(p finding.Provenance) string {
	switch p {
	case finding.ProvLive:
		return "live — collected directly from the host during this scan"
	case finding.ProvPartial:
		return "**partial** — some collectors could not run; see Coverage"
	case finding.ProvUnavailable:
		return "**unavailable** — the target could not be reached"
	case finding.ProvDemo:
		return "**demo data — not from a real scan**"
	}
	return string(p)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
