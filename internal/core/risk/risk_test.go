package risk

import (
	"math"
	"testing"

	"github.com/jchirayath/secscan/internal/core/finding"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 0.01 }

// TestExposureDominates is the thesis of the product in one test: the same
// vulnerability is not the same risk on loopback as it is on a wide-bound
// port. If this ever stops holding, the ranking is just CVSS again.
func TestExposureDominates(t *testing.T) {
	base := finding.Finding{Severity: finding.SevHigh, CVSS: 7.5}

	internal, _ := Score(base)

	exposed := base
	exposed.Exposed = true
	exposedScore, _ := Score(exposed)

	if exposedScore <= internal {
		t.Fatalf("exposed (%.2f) must outrank internal (%.2f)", exposedScore, internal)
	}
	if !approx(exposedScore, internal*ExposedMultiplier) {
		t.Errorf("exposed = %.2f, want %.2f", exposedScore, internal*ExposedMultiplier)
	}

	// A medium CVE that is actually reachable should outrank a high one that
	// is not — the ordering that raw CVSS gets wrong.
	reachableMedium := finding.Finding{Severity: finding.SevHigh, CVSS: 6.0, Exposed: true, KEV: true}
	unreachableCritical := finding.Finding{Severity: finding.SevCritical, CVSS: 9.8}
	rm, _ := Score(reachableMedium)
	uc, _ := Score(unreachableCritical)
	if rm <= uc {
		t.Errorf("KEV+exposed 6.0 (%.2f) should outrank unreachable 9.8 (%.2f)", rm, uc)
	}
}

func TestFactorsExplainTheScore(t *testing.T) {
	f := finding.Finding{
		Severity: finding.SevHigh, CVSS: 7.5,
		EPSS: 0.5, KEV: true, Exposed: true, AssetCritical: true,
	}
	score, factors := Score(f)

	// 7.5 × (1+2(0.5)) × 2.0 × 1.5 × 1.3 = 58.5
	if !approx(score, 58.5) {
		t.Errorf("score = %.2f, want 58.5", score)
	}
	// Every multiplier must be shown: "why is this at the top?" has to be
	// answerable from the UI, which is what these factors feed.
	if len(factors) != 5 {
		t.Fatalf("got %d factors, want 5 (base, epss, kev, exposed, critical)", len(factors))
	}
	product := 1.0
	for _, x := range factors {
		product *= x.Multiplier
	}
	if !approx(product, score) {
		t.Errorf("factors multiply to %.2f but score is %.2f — the explanation does not match the number",
			product, score)
	}
}

// TestSeverityWithoutCVSS: config weaknesses have no CVE, and must still rank
// on the same scale as CVEs rather than scoring zero.
func TestSeverityWithoutCVSS(t *testing.T) {
	for _, s := range []finding.Severity{
		finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow, finding.SevInfo,
	} {
		got, _ := Score(finding.Finding{Severity: s})
		if got <= 0 {
			t.Errorf("severity %s scored %.2f — a finding with no CVSS must still rank", s, got)
		}
	}
	crit, _ := Score(finding.Finding{Severity: finding.SevCritical})
	low, _ := Score(finding.Finding{Severity: finding.SevLow})
	if crit <= low {
		t.Errorf("critical (%.2f) must outrank low (%.2f)", crit, low)
	}
}
