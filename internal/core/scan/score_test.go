package scan

import (
	"fmt"
	"testing"

	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/store"
)

func mkFinding(sev finding.Severity, remedy string, i int) finding.Finding {
	return finding.Finding{
		Status: finding.StatusOpen, Severity: sev,
		RuleID:      fmt.Sprintf("rule.%d", i),
		Remediation: finding.Remediation{Op: "apply_patch", Summary: remedy},
	}
}

// TestScoreGroupsByRemediation is the property that keeps the number
// meaningful: 800 CVEs cleared by one image rebuild are one piece of work, and
// must not sink the score further than a spread of unrelated critical problems.
func TestScoreGroupsByRemediation(t *testing.T) {
	// 800 findings, all cleared by the same action.
	var oneAction []finding.Finding
	for i := 0; i < 800; i++ {
		oneAction = append(oneAction, mkFinding(finding.SevHigh, "Rebuild the app image", i))
	}
	// 20 findings, each needing its own distinct fix.
	var manyActions []finding.Finding
	for i := 0; i < 20; i++ {
		manyActions = append(manyActions, mkFinding(finding.SevCritical, fmt.Sprintf("Fix thing %d", i), i))
	}

	bulk, spread := Score(oneAction), Score(manyActions)

	if bulk <= 0 || spread <= 0 {
		t.Fatalf("scores saturated to zero: bulk=%.2f spread=%.2f", bulk, spread)
	}
	if spread >= bulk {
		t.Errorf("20 unrelated criticals (%.2f) should score WORSE than 800 findings "+
			"behind a single fix (%.2f) — the score tracks outstanding work, not row count",
			spread, bulk)
	}
}

// TestScoreStillDiscriminates: more of the same problem must still be worse,
// just not linearly worse.
func TestScoreStillDiscriminates(t *testing.T) {
	small := Score([]finding.Finding{mkFinding(finding.SevHigh, "same fix", 0)})
	var big []finding.Finding
	for i := 0; i < 50; i++ {
		big = append(big, mkFinding(finding.SevHigh, "same fix", i))
	}
	if Score(big) >= small {
		t.Error("50 instances must still score worse than 1")
	}
	if Score(big) <= 0 {
		t.Error("score reached zero and stopped conveying anything")
	}
}

// TestCoverageCountsNotApplicable: a collector that established its checks do
// not apply (DNS hygiene on an IP-addressed target) must count as coverage, or
// a finding it raised before it knew better can never be closed. A plain skip
// (could not run) must not count.
func TestCoverageCountsNotApplicable(t *testing.T) {
	cov := CoverageOf(Result{Collectors: []store.CollectorRun{
		{ID: "dns-hygiene", Skipped: "target is addressed by IP", NotApplicable: true},
		{ID: "listeners", Skipped: "ssh unreachable"},
		{ID: "accounts", Ran: true},
	}})
	if _, ok := cov["dns-hygiene"]; !ok {
		t.Error("not-applicable collector missing from coverage: its stale findings would stay open")
	}
	if _, ok := cov["listeners"]; ok {
		t.Error("a collector that could not run was counted as coverage: its findings would be wrongly closed")
	}
	if _, ok := cov["accounts"]; !ok {
		t.Error("a collector that ran is missing from coverage")
	}
}
