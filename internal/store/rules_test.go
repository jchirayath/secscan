package store

import (
	"testing"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/finding"
)

func mk(id, engine, loc, comp, rule string) finding.Finding {
	return finding.Finding{ID: id, AssetID: "a", Engine: engine, Location: loc,
		Component: finding.Component{Name: comp}, RuleID: rule, Status: finding.StatusOpen,
		Severity: finding.SevHigh}
}

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var asset = finding.Asset{ID: "a"}

// Engine findings must close when the engine ran and no longer reports them —
// the bug that left 837 findings for long-gone images open on a production host.
func TestMergeClosesEngineFindings(t *testing.T) {
	s := open(t)
	s.Merge(asset, []finding.Finding{
		mk("gone", "trivy-image", "old:1", "x", "vuln.1"),
		mk("skipped", "trivy-image", "big:1", "x", "vuln.2"),
		mk("other", "gitleaks", "/f", "", "secret"),
	}, Coverage{"trivy-image": nil, "gitleaks": nil})

	// Next scan: trivy-image ran but did not get to big:1; gitleaks did not run.
	_, fixed, err := s.Merge(asset, nil, Coverage{"trivy-image": {"big:1"}})
	if err != nil {
		t.Fatal(err)
	}
	if fixed != 1 {
		t.Errorf("fixed = %d, want 1", fixed)
	}
	for id, want := range map[string]finding.Status{
		"gone":    finding.StatusFixed, // engine ran, image no longer reported
		"skipped": finding.StatusOpen,  // engine ran but never looked at big:1
		"other":   finding.StatusOpen,  // gitleaks did not run at all
	} {
		if f, _ := s.Get(id); f.Status != want {
			t.Errorf("%s: %s, want %s", id, f.Status, want)
		}
	}
}

func TestRuleSuppressesNowAndLater(t *testing.T) {
	s := open(t)
	cov := Coverage{"gitleaks": nil}
	s.Merge(asset, []finding.Finding{
		mk("k1", "gitleaks", "/opt/testssl.sh/etc/tls_data.txt:1", "", "secret"),
		mk("real", "gitleaks", "/home/me/.env:3", "", "secret"),
	}, cov)

	r, n, err := s.AddRule(Rule{Kind: finding.KindFalsePositive, Reason: "testssl sample keys",
		Match: RuleMatch{Engine: "gitleaks", Location: "/opt/testssl.sh/*"},
		Until: clock.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rule suppressed %d now, want 1", n)
	}

	// A later scan brings a NEW finding under the same pattern, and the
	// caller's slice must reflect the suppression (it feeds the score).
	next := []finding.Finding{
		mk("k1", "gitleaks", "/opt/testssl.sh/etc/tls_data.txt:1", "", "secret"),
		mk("k2", "gitleaks", "/opt/testssl.sh/testssl.sh:9", "", "secret"),
		mk("real", "gitleaks", "/home/me/.env:3", "", "secret"),
	}
	s.Merge(asset, next, cov)
	for _, f := range next {
		wantSup := f.ID != "real"
		if (f.Status == finding.StatusSuppressed) != wantSup {
			t.Errorf("%s in caller slice: %s", f.ID, f.Status)
		}
		if wantSup && (f.SuppressKind != finding.KindFalsePositive || f.SuppressRule != r.ID) {
			t.Errorf("%s: kind %q rule %q", f.ID, f.SuppressKind, f.SuppressRule)
		}
	}

	// Revoking the rule reopens both, and the next scan must not re-hide them
	// from the stale per-finding copy.
	if reopened, err := s.DeleteRule(r.ID); err != nil || reopened != 2 {
		t.Fatalf("DeleteRule = %d, %v; want 2 reopened", reopened, err)
	}
	again := []finding.Finding{mk("k1", "gitleaks", "/opt/testssl.sh/etc/tls_data.txt:1", "", "secret")}
	s.Merge(asset, again, cov)
	if again[0].Status != finding.StatusOpen {
		t.Errorf("after revoking the rule, k1 is %s", again[0].Status)
	}
}

func TestRuleValidation(t *testing.T) {
	s := open(t)
	until := clock.Now().Add(time.Hour)
	for name, r := range map[string]Rule{
		"engine only": {Kind: finding.KindFalsePositive, Reason: "x", Until: until, Match: RuleMatch{Engine: "trivy"}},
		"bare star":   {Kind: finding.KindFalsePositive, Reason: "x", Until: until, Match: RuleMatch{Location: "**"}},
		"no reason":   {Kind: finding.KindFalsePositive, Until: until, Match: RuleMatch{RuleID: "r"}},
		"bad kind":    {Kind: "ignore", Reason: "x", Until: until, Match: RuleMatch{RuleID: "r"}},
		"expired":     {Kind: finding.KindAcceptedRisk, Reason: "x", Until: clock.Now().Add(-time.Hour), Match: RuleMatch{RuleID: "r"}},
	} {
		if _, _, err := s.AddRule(r); err == nil {
			t.Errorf("%s: accepted, want refused", name)
		}
	}
}

func TestUnsuppress(t *testing.T) {
	s := open(t)
	s.Merge(asset, []finding.Finding{mk("f", "trivy", "h", "openssl", "vuln.1"), mk("g", "trivy", "h", "zlib", "vuln.2")}, Coverage{})
	if err := s.Suppress("f", finding.KindFalsePositive, "wrong package match", clock.Now().Add(time.Hour), "me", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Unsuppress("f"); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.Get("f"); f.Status != finding.StatusOpen || f.SuppressKind != "" {
		t.Errorf("after unsuppress: %+v", f)
	}
	s.AddRule(Rule{Kind: finding.KindAcceptedRisk, Reason: "x", Until: clock.Now().Add(time.Hour), Match: RuleMatch{Component: "zlib"}})
	if err := s.Unsuppress("g"); err == nil {
		t.Error("unsuppressing a rule-suppressed finding succeeded; it would come back next scan")
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"/opt/testssl.sh/*", "/opt/testssl.sh/etc/tls_data.txt:484", true},
		{"/opt/testssl.sh/*", "/opt/other/x", false},
		{"castopod/castopod:*", "castopod/castopod:1.15.7", true},
		{"linux-*-1017*", "linux-modules-7.0.0-1017-azure", true},
		{"a.b", "aXb", false}, // dots are literal
	} {
		if got := globMatch(c.p, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.p, c.s, got)
		}
	}
}
