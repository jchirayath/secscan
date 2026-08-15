// Package risk holds THE risk score. Exactly one implementation.
//
// The failure mode this prevents is a system that grows two scorers with
// slightly different weights — one the dashboard sorts on, another that decides
// remediation eligibility — so "why is this at the top?" has two answers and
// neither is wrong. Never again: this file is the only place
// a risk number is produced, and the guard test asserts no other package
// multiplies severity by anything.
package risk

import "github.com/jchirayath/secscan/internal/core/finding"

// Weights are named and exported so the UI can show its work. A user who asks
// "why is this first?" gets the actual multipliers, not a black box.
const (
	KEVMultiplier      = 2.0 // known-exploited in the wild dominates everything
	ExposedMultiplier  = 1.5 // reachable from outside the host's trust boundary
	CriticalMultiplier = 1.3 // asset tagged critical by the operator
	EPSSFactor         = 2.0 // score *= 1 + EPSSFactor*EPSS

	// ConfirmedMultiplier applies when a non-destructive test actually
	// demonstrated the weakness. Proof beats inference, and the ranking should
	// say so.
	ConfirmedMultiplier = 1.25
	// RefutedMultiplier applies when the test showed the condition does not
	// hold. It is deliberately not zero: the configuration is still wrong and
	// the thing preventing exploitation may itself be removed.
	RefutedMultiplier = 0.25
)

// Factor is one contribution to a score, for display.
type Factor struct {
	Name       string  `json:"name"`
	Multiplier float64 `json:"multiplier"`
	Why        string  `json:"why"`
}

// Score returns INHERENT risk — what this finding would cost with no
// compensating controls — and the factors that produced it.
//
// Base is CVSS when the finding has one, else a CVSS-shaped number derived
// from severity, so config weaknesses and CVEs rank on one scale.
//
// Residual risk is Score() reduced by the verified controls; see Apply.
func Score(f finding.Finding) (float64, []Factor) {
	base := f.CVSS
	if base <= 0 {
		base = f.Severity.BaseCVSS()
	}
	score := base
	factors := []Factor{{Name: "base", Multiplier: base, Why: baseWhy(f)}}

	if f.EPSS > 0 {
		m := 1 + EPSSFactor*f.EPSS
		score *= m
		factors = append(factors, Factor{"epss", m, "exploit-prediction score"})
	}
	if f.KEV {
		score *= KEVMultiplier
		factors = append(factors, Factor{"kev", KEVMultiplier, "on CISA Known Exploited Vulnerabilities"})
	}
	if f.Exposed {
		score *= ExposedMultiplier
		factors = append(factors, Factor{"exposed", ExposedMultiplier, "reachable beyond the host"})
	}
	if f.AssetCritical {
		score *= CriticalMultiplier
		factors = append(factors, Factor{"critical_asset", CriticalMultiplier, "asset marked critical"})
	}
	if f.Validation != nil {
		switch f.Validation.Verdict {
		case finding.VerdictConfirmed:
			score *= ConfirmedMultiplier
			factors = append(factors, Factor{"confirmed", ConfirmedMultiplier,
				"proven by a live test, not inferred"})
		case finding.VerdictRefuted:
			score *= RefutedMultiplier
			factors = append(factors, Factor{"refuted", RefutedMultiplier,
				"a live test showed this cannot currently be exercised"})
		}
	}
	return round2(score), factors
}

func baseWhy(f finding.Finding) string {
	if f.CVSS > 0 {
		return "CVSS base score"
	}
	return "derived from severity " + string(f.Severity)
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// Apply computes the full chain on each finding in place:
//
//	inherent  ×  mitigation factor  =  residual
//
// Residual is what the dashboard ranks on, what the posture score uses, and
// what the remediation plan orders by. Inherent is kept alongside it because it
// is what the risk snaps back to the moment a control is removed or found to
// have been ineffective — and because "we reduced this from 14.6 to 8.8 with
// fail2ban" is a far more useful sentence than either number alone.
func Apply(fs []finding.Finding) {
	for i := range fs {
		inherent, _ := Score(fs[i])
		fs[i].InherentRisk = inherent

		factor := fs[i].MitigationFactor
		if factor <= 0 || factor > 1 {
			factor = 1 // no controls, or a nonsense value: no discount
		}
		fs[i].ResidualRisk = round2(inherent * factor)
	}
}
