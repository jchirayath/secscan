// Package engine wraps optional external scanners.
//
// Every engine is optional and auto-detected. A missing engine yields an
// explicit Status saying so — never a silent gap. The native collectors in
// package collect remain the primary source of findings (ARCHITECTURE.md — Collectors and engines).
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Status reports whether an engine ran, and if not, why.
type Status struct {
	ID        string `json:"id"`
	Installed bool   `json:"installed"`
	Ran       bool   `json:"ran"`
	Found     int    `json:"found"`
	Reason    string `json:"reason,omitempty"`
	Install   string `json:"install,omitempty"` // how to get it
	// NotCovered lists locations the engine is responsible for but did not
	// examine on this run (images past trivy-image's cap, images that failed
	// to scan). The store keeps their findings open instead of calling them
	// fixed — see store.Coverage.
	NotCovered []string `json:"not_covered,omitempty"`
}

// PartialEngine is implemented by engines that may skip part of what they are
// responsible for on a run, and can say which part.
type PartialEngine interface {
	RunPartial(ctx context.Context, r exec.Runner, a *finding.Asset) (fs []finding.Finding, notCovered []string, err error)
}

// Enablement answers whether a feature should run. Defined here as a narrow
// interface so package engine does not import package feature and create a
// cycle.
type Enablement interface{ IsEnabled(id string) bool }

// Engine is an optional external scanner.
type Engine interface {
	ID() string
	Binary() string
	InstallHint() string
	Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error)
}

// Expensive is implemented by engines whose runtime is measured in tens of
// minutes rather than seconds.
//
// This exists because of a concrete measurement: nuclei against a single host
// with 13,510 templates, rate-limited to a level that is safe to point at
// production, ran for over eight minutes without finishing. An engine like that
// cannot be in the default scan — not because it is not valuable, but because a
// scan that takes twenty minutes gets run monthly instead of nightly, and a
// monthly scan is how you find out about something six weeks late.
//
// Expensive engines are therefore OFF by default and say why, rather than being
// silently omitted or silently making every scan slow.
type Expensive interface {
	// WhyExpensive explains the cost in the operator's terms, shown in the UI
	// next to the toggle.
	WhyExpensive() string
}

// IsExpensive reports whether an engine opts out of the default scan.
func IsExpensive(e Engine) (string, bool) {
	if x, ok := e.(Expensive); ok {
		return x.WhyExpensive(), true
	}
	return "", false
}

// All returns every known engine adapter.
func All() []Engine {
	return []Engine{Trivy{}, TrivyImage{}, Gitleaks{}, OSVScanner{}, TestSSL{}, Nuclei{}}
}

// RunAll executes every installed engine, returning findings and per-engine
// status. An engine that errors degrades to a status entry — one broken tool
// never fails the scan.
func RunAll(ctx context.Context, r exec.Runner, a *finding.Asset, enabled Enablement) ([]finding.Finding, []Status) {
	var out []finding.Finding
	var statuses []Status

	for _, e := range All() {
		st := Status{ID: e.ID(), Install: e.InstallHint()}
		if enabled != nil && !enabled.IsEnabled(e.ID()) {
			if why, costly := IsExpensive(e); costly {
				st.Reason = "not enabled — " + why
			} else {
				st.Reason = "disabled by operator"
			}
			statuses = append(statuses, st)
			continue
		}
		if !r.Has(ctx, e.Binary()) {
			st.Reason = e.Binary() + " not installed on the target"
			statuses = append(statuses, st)
			continue
		}
		st.Installed = true
		var (
			fs      []finding.Finding
			skipped []string
			err     error
		)
		if pe, ok := e.(PartialEngine); ok {
			fs, skipped, err = pe.RunPartial(ctx, r, a)
		} else {
			fs, err = e.Run(ctx, r, a)
		}
		if err != nil {
			st.Reason = "engine failed: " + err.Error()
			statuses = append(statuses, st)
			continue
		}
		st.Ran, st.Found, st.NotCovered = true, len(fs), skipped
		out = append(out, fs...)
		statuses = append(statuses, st)
	}
	return out, statuses
}

// severityFrom maps an engine's severity vocabulary onto ours.
func severityFrom(s string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return finding.SevCritical
	case "HIGH":
		return finding.SevHigh
	case "MEDIUM", "MODERATE":
		return finding.SevMedium
	case "LOW":
		return finding.SevLow
	}
	return finding.SevInfo
}

// ------------------------------------------------------------------- Trivy

// Trivy scans the root filesystem for OS-package and language-dependency CVEs.
// It is the highest-value optional engine: one binary covers what would
// otherwise be several.
type Trivy struct{}

func (Trivy) ID() string     { return "trivy" }
func (Trivy) Binary() string { return "trivy" }
func (Trivy) InstallHint() string {
	return "https://aquasecurity.github.io/trivy — `brew install trivy` or the distro package"
}

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			PrimaryURL       string `json:"PrimaryURL"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (t Trivy) Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error) {
	now := clock.Now()
	// Measured on a stock Ubuntu 24.04 host: CRITICAL,HIGH,MEDIUM including
	// unfixed returns 35,326 vulnerabilities, of which 77 have a fix available.
	// The other 99.8% are kernel CVEs the operator cannot action — no patch
	// exists — and they bury the ones a single `apt upgrade` would close.
	// Tightening to fixable CRITICAL/HIGH gives 33.
	//
	// The cost is stated rather than hidden: an unfixed CRITICAL is still real
	// risk, and this engine will not report it. That trade is worth making
	// because a 35,000-row report is not read at all, but it is a trade.
	res := r.Run(ctx, "trivy", "rootfs", "--quiet", "--scanners", "vuln",
		"--format", "json", "--severity", "CRITICAL,HIGH", "--ignore-unfixed", "/")
	if res.Err != nil {
		return nil, res.Err
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return nil, fmt.Errorf("no output (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}

	var rep trivyReport
	if err := json.Unmarshal([]byte(res.Stdout), &rep); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}

	var out []finding.Finding
	// The same CVE is reported once per source package that ships the affected
	// binary, so a single kernel issue can appear a dozen times with identical
	// text. Collapse on CVE+package: the operator fixes it once.
	seen := map[string]bool{}
	running := kernelABI(a.Kernel)
	stale := map[string]*staleKernel{}
	for _, result := range rep.Results {
		for _, v := range result.Vulnerabilities {
			// Packages of a kernel that is installed but NOT running (the one
			// apt keeps as a fallback after an upgrade) are folded into one
			// finding per kernel — see staleKernelFinding.
			if abi := kernelABI(v.PkgName); running != "" && abi != "" && abi != running &&
				strings.HasPrefix(strings.ToLower(v.PkgName), "linux-") {
				sk := stale[abi]
				if sk == nil {
					sk = &staleKernel{abi: abi, target: result.Target, typ: result.Type,
						pkgs: map[string]bool{}, cves: map[string]bool{}}
					stale[abi] = sk
				}
				sk.pkgs[v.PkgName], sk.cves[v.VulnerabilityID] = true, true
				for _, c := range v.CVSS {
					if c.V3Score > sk.maxCVSS {
						sk.maxCVSS = c.V3Score
					}
				}
				continue
			}
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := severityFrom(v.Severity)
			title := v.Title
			if title == "" {
				title = fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName)
			}
			f := finding.New(a.ID, categoryForTrivy(result.Type), sev,
				"vuln."+strings.ToLower(v.VulnerabilityID), title, now)
			f.Description = v.Description
			f.Subcategory = result.Type
			f.Engine = t.ID()
			f.CVE = []string{v.VulnerabilityID}
			for _, c := range v.CVSS {
				if c.V3Score > f.CVSS {
					f.CVSS = c.V3Score
				}
			}
			if v.PrimaryURL != "" {
				f.References = []string{v.PrimaryURL}
			}
			f.Evidence = []finding.Evidence{{
				Command: res.Command,
				Output: fmt.Sprintf("%s: %s %s → fixed in %s (%s)",
					v.VulnerabilityID, v.PkgName, v.InstalledVersion,
					orNone(v.FixedVersion), result.Target),
			}}
			if v.FixedVersion != "" {
				f.Remediation = finding.Remediation{Op: "apply_patch",
					Summary: fmt.Sprintf("Upgrade %s to %s", v.PkgName, v.FixedVersion)}
			} else {
				f.Remediation = finding.Remediation{Op: "manual",
					Summary: fmt.Sprintf("No fix published for %s yet — mitigate or accept", v.VulnerabilityID)}
			}
			comp := finding.Component{Name: v.PkgName, Version: v.InstalledVersion, FixedVersion: v.FixedVersion}
			out = append(out, f.WithLocation(result.Target, comp))
		}
	}
	abis := make([]string, 0, len(stale))
	for abi := range stale {
		abis = append(abis, abi)
	}
	sort.Strings(abis)
	for _, abi := range abis {
		out = append(out, staleKernelFinding(a, now, res.Command, running, stale[abi]))
	}
	return out, nil
}

// kernelABIRe pulls the kernel ABI ("7.0.0-1017") out of a package name or a
// `uname -r` string: linux-modules-7.0.0-1017-azure,
// linux-azure-7.0-tools-7.0.0-1017, 7.0.0-1020-azure. Three dotted parts and
// a dash are required so "linux-azure-7.0-tools" alone does not match.
var kernelABIRe = regexp.MustCompile(`\d+\.\d+\.\d+-\d+`)

func kernelABI(s string) string { return kernelABIRe.FindString(s) }

type staleKernel struct {
	abi, target, typ string
	pkgs, cves       map[string]bool
	maxCVSS          float64
}

// staleKernelFinding reports an installed-but-not-running kernel as ONE
// finding instead of one per CVE per package.
//
// Trivy rates every CVE in every package of the old kernel as if it were live:
// on a production host, after a routine kernel upgrade, that was 787 CVEs × 7 packages =
// 5,509 HIGH findings, 82% of everything open, for code that was not executing.
// A container-scale problem gets a container-scale fix elsewhere in this
// package; this is the host equivalent.
//
// Not dropped and not informational: the kernel can still be booted (GRUB
// keeps it as the fallback entry, and an operator can pick it), so the CVEs
// are dormant rather than absent. Rated LOW, with the CVE list kept as
// evidence and the one action that clears all of them as the remediation.
func staleKernelFinding(a *finding.Asset, now time.Time, cmd, running string, sk *staleKernel) finding.Finding {
	pkgs := sortedKeys(sk.pkgs)
	cves := sortedKeys(sk.cves)
	f := finding.New(a.ID, categoryForTrivy(sk.typ), finding.SevLow, "kernel.stale-installed",
		fmt.Sprintf("Old kernel %s is still installed (not running): %d fixable CVEs", sk.abi, len(cves)), now)
	f.Subcategory = sk.typ
	f.Engine = "trivy"
	f.CVE = cves
	f.CVSS = sk.maxCVSS
	f.Description = fmt.Sprintf("This host runs kernel %s. Kernel %s is still installed — usually kept "+
		"by apt as a boot fallback after an upgrade — and Trivy reports %d CVEs across its %d packages "+
		"(highest CVSS %.1f). None of that code runs unless the machine is booted into %s, so these are "+
		"dormant, not exposed. Removing the old kernel clears all of them at once.",
		running, sk.abi, len(cves), len(pkgs), sk.maxCVSS, sk.abi)
	shown := cves
	if len(shown) > 25 {
		shown = shown[:25]
	}
	f.Evidence = []finding.Evidence{{
		Command: cmd,
		Output: fmt.Sprintf("running %s; installed %s packages: %s\n%d CVEs, e.g. %s",
			running, sk.abi, strings.Join(pkgs, " "), len(cves), strings.Join(shown, " ")),
	}}
	f.Remediation = finding.Remediation{Op: "manual",
		Summary: fmt.Sprintf("Remove kernel %s once %s has booted cleanly: sudo apt purge %s (or sudo apt autoremove --purge)",
			sk.abi, running, strings.Join(pkgs, " "))}
	return f.WithLocation(sk.target, finding.Component{Name: "linux kernel " + sk.abi, Version: sk.abi})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func categoryForTrivy(typ string) finding.Category {
	switch strings.ToLower(typ) {
	case "debian", "ubuntu", "alpine", "redhat", "centos", "rocky", "amazon", "oracle", "suse":
		return finding.CatPatch
	}
	return finding.CatDeps
}

func orNone(s string) string {
	if s == "" {
		return "(no fix)"
	}
	return s
}

// ---------------------------------------------------------------- Gitleaks

// Gitleaks finds committed credentials. Scoped to the target's home and /opt
// rather than the whole filesystem — a full-root secret scan on a busy server
// takes long enough that people stop running it.
type Gitleaks struct{}

func (Gitleaks) ID() string     { return "gitleaks" }
func (Gitleaks) Binary() string { return "gitleaks" }
func (Gitleaks) InstallHint() string {
	return "https://github.com/gitleaks/gitleaks — `brew install gitleaks`"
}

type gitleaksFinding struct {
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	RuleID      string `json:"RuleID"`
	Secret      string `json:"Secret"`
}

func (g Gitleaks) Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error) {
	now := clock.Now()
	// "--report-path -" is gitleaks' documented stdout. "/dev/stdout" worked on
	// Linux but gitleaks 8.30 on macOS refuses it as "not writable", writes
	// nothing, and the empty body below then read as a clean scan.
	res := r.Run(ctx, "gitleaks", "dir", "/opt", "--no-banner", "--report-format", "json", "--report-path", "-")
	if res.Err != nil {
		return nil, res.Err
	}
	// Fail closed. A run counts as a scan only if gitleaks wrote a JSON report
	// (a clean scan writes "[]"). exec does not treat a non-zero exit as an
	// error, and gitleaks exits 1 with EMPTY stdout when it fails (bad path,
	// unreadable config, crash). Reading that as "no leaks" made the engine
	// report Ran, and coverage then closed every open secret finding. Exit 1
	// is also how gitleaks reports leaks found, so a non-zero exit is accepted
	// only together with a non-empty report.
	body := strings.TrimSpace(res.Stdout)
	fail := func(why string) error {
		return fmt.Errorf("gitleaks %s (exit %d): %s", why, res.ExitCode, firstLine(res.Stderr))
	}
	if body == "" {
		return nil, fail("wrote no report")
	}
	var hits []gitleaksFinding
	if err := json.Unmarshal([]byte(body), &hits); err != nil {
		return nil, fmt.Errorf("parse gitleaks json: %w", err)
	}
	if res.ExitCode != 0 && len(hits) == 0 {
		return nil, fail("failed")
	}

	var out []finding.Finding
	for _, h := range hits {
		f := finding.New(a.ID, finding.CatSecrets, finding.SevHigh,
			"secrets."+strings.ToLower(h.RuleID),
			"Credential in "+h.File, now)
		f.Description = h.Description
		f.Engine = g.ID()
		// The secret itself is never stored — only enough to locate it.
		f.Evidence = []finding.Evidence{{
			Path:   h.File,
			Output: fmt.Sprintf("line %d — rule %s (value redacted)", h.StartLine, h.RuleID),
		}}
		f.Remediation = finding.Remediation{Op: "rotate_secret",
			Summary: "Rotate this credential, then remove it from the file and from history"}
		out = append(out, f.WithLocation(fmt.Sprintf("%s:%d", h.File, h.StartLine), finding.Component{}))
	}
	return out, nil
}

// -------------------------------------------------------------- OSVScanner

// OSVScanner checks language lockfiles against the OSV database — an
// independent second opinion to Trivy's dependency coverage.
type OSVScanner struct{}

func (OSVScanner) ID() string     { return "osv-scanner" }
func (OSVScanner) Binary() string { return "osv-scanner" }
func (OSVScanner) InstallHint() string {
	return "https://google.github.io/osv-scanner — `brew install osv-scanner`"
}

type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID      string   `json:"id"`
				Summary string   `json:"summary"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// osvRoot is where osv-scanner looks for lockfiles.
const osvRoot = "/opt"

// osvListRoots sorts osvRoot's entries into readable (R) and unreadable (U)
// by the scan account. POSIX sh only: BusyBox find has no -readable.
const osvListRoots = `for d in ` + osvRoot + `/* ` + osvRoot + `/.[!.]*; do ` +
	`[ -e "$d" ] || continue; ` +
	`if [ -d "$d" ] && ! { [ -r "$d" ] && [ -x "$d" ]; }; then echo "U $d"; else echo "R $d"; fi; done`

func (o OSVScanner) Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error) {
	fs, _, err := o.RunPartial(ctx, r, a)
	return fs, err
}

// RunPartial scans the entries of /opt the scan account can read and reports
// the others as not covered, so findings under them are neither re-raised nor
// closed. Engines deliberately run without sudo (exec.needsPrivilege), and
// osv-scanner 2.7 aborts the whole scan, exit 127 with no report, on the
// first directory it cannot open: on betty, root-only /opt/containerd. Before
// adapters failed closed, that abort read as a clean scan.
func (o OSVScanner) RunPartial(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, []string, error) {
	ls := r.Run(ctx, "sh", "-c", osvListRoots)
	if ls.Err != nil {
		return nil, nil, ls.Err
	}
	var roots, skipped []string
	for _, line := range strings.Split(ls.Stdout, "\n") {
		kind, path, ok := strings.Cut(strings.TrimSpace(line), " ")
		switch {
		case !ok:
		case kind == "R":
			roots = append(roots, path)
		case kind == "U":
			skipped = append(skipped, path+"/") // trailing slash: a directory prefix in store.Coverage
		}
	}
	if len(roots) == 0 {
		return nil, skipped, nil // nothing readable under /opt: an honest zero
	}
	fs, err := o.scan(ctx, r, a, roots)
	return fs, skipped, err
}

func (o OSVScanner) scan(ctx context.Context, r exec.Runner, a *finding.Asset, roots []string) ([]finding.Finding, error) {
	now := clock.Now()
	res := r.Run(ctx, append([]string{"osv-scanner", "scan", "--format", "json", "--recursive"}, roots...)...)
	if res.Err != nil {
		return nil, res.Err
	}
	body := strings.TrimSpace(res.Stdout)
	if body == "" {
		// Fail closed, as gitleaks does. osv-scanner exits 128 with no output
		// when there is nothing to scan ("no package sources found"), which is
		// an honest zero. Any other empty run (127 for a bad path, a crash) is
		// a failure, and must not let coverage close open findings.
		if res.ExitCode == 128 {
			return nil, nil
		}
		return nil, fmt.Errorf("osv-scanner wrote no report (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}
	var rep osvReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return nil, fmt.Errorf("parse osv-scanner json: %w", err)
	}

	var out []finding.Finding
	for _, result := range rep.Results {
		for _, p := range result.Packages {
			for _, v := range p.Vulnerabilities {
				f := finding.New(a.ID, finding.CatDeps, finding.SevMedium,
					"deps."+strings.ToLower(v.ID),
					fmt.Sprintf("%s in %s", v.ID, p.Package.Name), now)
				f.Description = v.Summary
				f.Engine = o.ID()
				f.CVE = cvesOf(v.Aliases)
				f.References = []string{"https://osv.dev/vulnerability/" + v.ID}
				f.Evidence = []finding.Evidence{{Command: res.Command,
					Output: fmt.Sprintf("%s %s in %s", p.Package.Name, p.Package.Version, result.Source.Path)}}
				f.Remediation = finding.Remediation{Op: "apply_patch",
					Summary: fmt.Sprintf("Update %s beyond %s", p.Package.Name, p.Package.Version)}
				out = append(out, f.WithLocation(result.Source.Path,
					finding.Component{Name: p.Package.Name, Version: p.Package.Version}))
			}
		}
	}
	return out, nil
}

func cvesOf(aliases []string) []string {
	var out []string
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
