package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// cannedRunner answers every Run with the same stdout. Enough for engines that
// issue one command and parse its JSON.
type cannedRunner struct{ out string }

func (c cannedRunner) Run(_ context.Context, argv ...string) exec.Result {
	return exec.Result{Command: strings.Join(argv, " "), Stdout: c.out}
}
func (cannedRunner) Has(context.Context, string) bool                { return true }
func (cannedRunner) ReadFile(context.Context, string) (string, bool) { return "", false }
func (cannedRunner) Target() exec.Target                             { return exec.Target{Name: "t"} }

func trivyJSON(t *testing.T, vulns map[string][]string) string {
	t.Helper()
	type v struct {
		VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity string
	}
	var vs []v
	for pkg, ids := range vulns {
		for _, id := range ids {
			vs = append(vs, v{id, pkg, "1", "2", "HIGH"})
		}
	}
	b, err := json.Marshal(map[string]any{"Results": []any{map[string]any{
		"Target": "host (ubuntu 24.04)", "Type": "ubuntu", "Vulnerabilities": vs,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestStaleKernelCollapses pins the host-kernel rule in both directions:
// packages of an installed-but-not-running kernel become ONE low finding per
// kernel, while the running kernel's packages and ordinary packages keep their
// per-CVE findings at full severity. Getting the second half wrong would hide
// live kernel CVEs, which is the worse error.
func TestStaleKernelCollapses(t *testing.T) {
	out := trivyJSON(t, map[string][]string{
		"linux-modules-7.0.0-1017-azure":   {"CVE-1", "CVE-2"},
		"linux-headers-7.0.0-1017-azure":   {"CVE-1", "CVE-2"},
		"linux-azure-7.0-tools-7.0.0-1017": {"CVE-1", "CVE-3"},
		"linux-modules-6.17.0-1021-azure":  {"CVE-9"},
		"linux-modules-7.0.0-1020-azure":   {"CVE-4"}, // the RUNNING kernel
		"linux-tools-common":               {"CVE-5"}, // no ABI in the name
		"openssl":                          {"CVE-6"},
	})
	a := &finding.Asset{ID: "host-a", Kernel: "7.0.0-1020-azure"}
	fs, err := Trivy{}.Run(context.Background(), cannedRunner{out}, a)
	if err != nil {
		t.Fatal(err)
	}

	var stale []finding.Finding
	perCVE := map[string]finding.Severity{}
	for _, f := range fs {
		if f.RuleID == "kernel.stale-installed" {
			stale = append(stale, f)
			continue
		}
		perCVE[f.Component.Name] = f.Severity
	}
	if len(stale) != 2 {
		t.Fatalf("got %d stale-kernel findings, want 2 (7.0.0-1017 and 6.17.0-1021)", len(stale))
	}
	for _, f := range stale {
		if f.Severity != finding.SevLow {
			t.Errorf("%s rated %s, want low — dormant, not absent", f.Title, f.Severity)
		}
	}
	var k1017 finding.Finding
	for _, f := range stale {
		if f.Component.Version == "7.0.0-1017" {
			k1017 = f
		}
	}
	if got := strings.Join(k1017.CVE, ","); got != "CVE-1,CVE-2,CVE-3" {
		t.Errorf("7.0.0-1017 CVEs = %s, want the union CVE-1,CVE-2,CVE-3", got)
	}
	if !strings.Contains(k1017.Remediation.Summary, "linux-modules-7.0.0-1017-azure") {
		t.Errorf("remediation does not name the packages to remove: %q", k1017.Remediation.Summary)
	}
	for _, pkg := range []string{"linux-modules-7.0.0-1020-azure", "linux-tools-common", "openssl"} {
		if perCVE[pkg] != finding.SevHigh {
			t.Errorf("%s: severity %q, want its own HIGH finding — only the NON-running kernel may be folded", pkg, perCVE[pkg])
		}
	}
}

// Without a known running kernel nothing can be called stale; every package
// must keep its own finding rather than be guessed about.
func TestStaleKernelNeedsRunningKernel(t *testing.T) {
	out := trivyJSON(t, map[string][]string{"linux-modules-7.0.0-1017-azure": {"CVE-1"}})
	fs, err := Trivy{}.Run(context.Background(), cannedRunner{out}, &finding.Asset{ID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID == "kernel.stale-installed" {
		t.Fatalf("with no running kernel known, got %+v; want the plain per-CVE finding", fs)
	}
}

func TestKernelABI(t *testing.T) {
	for in, want := range map[string]string{
		"linux-modules-7.0.0-1017-azure":       "7.0.0-1017",
		"linux-azure-7.0-tools-7.0.0-1017":     "7.0.0-1017",
		"linux-azure-6.17-headers-6.17.0-1021": "6.17.0-1021",
		"7.0.0-1020-azure":                     "7.0.0-1020",
		"linux-tools-common":                   "",
		"linux-azure-7.0-tools":                "",
		"libssl3":                              "",
	} {
		if got := kernelABI(in); got != want {
			t.Errorf("kernelABI(%q) = %q, want %q", in, got, want)
		}
	}
}
