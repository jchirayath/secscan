package collect

import (
	"testing"

	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/core/risk"
)

func sshFinding() finding.Finding {
	return finding.Finding{
		RuleID: "network.wide-bind", Location: "tcp/22",
		Severity: finding.SevHigh, Exposed: true, AssetCritical: true,
		Title: "SSH (tcp/22) listening on all interfaces",
	}
}

func fail2ban() Control {
	return Control{
		ID: "fail2ban", Name: "fail2ban", Factor: 0.6, Ports: []int{22},
		Covers: []string{"network.wide-bind"}, Limits: "not a patch",
	}
}

// TestControlAppliesOnlyToItsPort: fail2ban's sshd jail protects 22. Letting it
// discount an exposed database on 5432 would be a fabricated reassurance.
func TestControlAppliesOnlyToItsPort(t *testing.T) {
	ssh := sshFinding()
	db := finding.Finding{
		RuleID: "network.wide-bind", Location: "tcp/5432",
		Severity: finding.SevHigh, Exposed: true,
	}
	fs := []finding.Finding{ssh, db}
	ApplyControls(fs, []Control{fail2ban()})

	if fs[0].MitigationFactor == 0 {
		t.Error("fail2ban did not apply to SSH on port 22")
	}
	if fs[1].MitigationFactor != 0 {
		t.Error("fail2ban discounted a finding on port 5432 — a control must never " +
			"reduce risk for something it does not protect")
	}
}

// TestControlAppliesOnlyToCoveredRules
func TestControlAppliesOnlyToCoveredRules(t *testing.T) {
	unrelated := finding.Finding{
		RuleID: "patch.updates-pending", Location: "", Severity: finding.SevHigh,
	}
	fs := []finding.Finding{unrelated}
	ApplyControls(fs, []Control{fail2ban()})
	if fs[0].MitigationFactor != 0 {
		t.Error("fail2ban discounted a missing-patch finding — no host control " +
			"mitigates an unpatched vulnerability")
	}
}

// TestMitigationIsFloored: defence in depth is real, but so is control failure.
// A stack of controls must never drive a finding to near-zero and out of sight.
func TestMitigationIsFloored(t *testing.T) {
	fs := []finding.Finding{sshFinding()}
	ApplyControls(fs, []Control{
		{ID: "a", Factor: 0.5, Ports: []int{22}, Covers: []string{"network.wide-bind"}},
		{ID: "b", Factor: 0.5, Ports: []int{22}, Covers: []string{"network.wide-bind"}},
		{ID: "c", Factor: 0.5, Ports: []int{22}, Covers: []string{"network.wide-bind"}},
	})
	if got := fs[0].MitigationFactor; got != MitigationFloor {
		t.Errorf("combined factor = %v, want the floor %v — controls must never "+
			"reduce a finding to invisibility", got, MitigationFloor)
	}
	risk.Apply(fs)
	if fs[0].ResidualRisk <= 0 {
		t.Error("residual risk reached zero; a mitigated finding is still a finding")
	}
}

// TestResidualChain is the arithmetic the UI shows: inherent × factor = residual.
func TestResidualChain(t *testing.T) {
	fs := []finding.Finding{sshFinding()}
	ApplyControls(fs, []Control{fail2ban()})
	risk.Apply(fs)

	f := fs[0]
	if f.InherentRisk <= 0 {
		t.Fatal("inherent risk not computed")
	}
	want := f.InherentRisk * f.MitigationFactor
	if diff := f.ResidualRisk - want; diff > 0.02 || diff < -0.02 {
		t.Errorf("residual %.2f != inherent %.2f × factor %.2f = %.2f",
			f.ResidualRisk, f.InherentRisk, f.MitigationFactor, want)
	}
	if f.ResidualRisk >= f.InherentRisk {
		t.Error("a compensating control did not reduce residual risk")
	}
	// Inherent must survive: it is what the risk returns to if the control goes.
	if f.InherentRisk != 14.63 {
		t.Errorf("inherent risk = %.2f, expected the unmitigated 14.63", f.InherentRisk)
	}
}

// TestEveryMitigationStatesItsLimits — a control shown without what it fails to
// cover is just a discount, and invites false confidence.
func TestEveryMitigationStatesItsLimits(t *testing.T) {
	fs := []finding.Finding{sshFinding()}
	ApplyControls(fs, []Control{fail2ban()})
	for _, m := range fs[0].Mitigations {
		if m.Limits == "" {
			t.Errorf("mitigation %q carries no stated limits", m.Name)
		}
	}
}

// ---- parsing -------------------------------------------------------------

func TestParseFail2banJails(t *testing.T) {
	out := `Status
|- Number of jail:      2
` + "`- Jail list:\tsshd, nginx-http-auth"
	jails := parseFail2banJails(out)
	if len(jails) != 2 || jails[0] != "sshd" {
		t.Errorf("parsed %v, want [sshd nginx-http-auth]", jails)
	}
}

func TestParseBannedCount(t *testing.T) {
	out := "Status for the jail: sshd\n|- Filter\n|  `- Currently failed: 1\n`- Actions\n   |- Currently banned: 7"
	if n := parseBannedCount(out); n != 7 {
		t.Errorf("got %d, want 7", n)
	}
}

// TestSectionEnabled: fail2ban installed but with the SSH jail disabled must NOT
// register as a control. Installed is not the same as effective.
func TestSectionEnabled(t *testing.T) {
	enabled := "[sshd]\nenabled = true\nport = ssh\n\n[nginx]\nenabled = false"
	disabled := "[sshd]\nenabled = false\n\n[nginx]\nenabled = true"
	other := "[nginx]\nenabled = true"

	if !sectionEnabled(enabled, sshJailNames) {
		t.Error("enabled sshd jail not detected")
	}
	if sectionEnabled(disabled, sshJailNames) {
		t.Error("disabled sshd jail counted as a control — installed is not effective")
	}
	if sectionEnabled(other, sshJailNames) {
		t.Error("an unrelated enabled jail counted as SSH protection")
	}
}
