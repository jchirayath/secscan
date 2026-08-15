// Package feature is the registry of every capability the scanner can run —
// native collectors and optional engines alike — and whether each is enabled.
//
// One registry rather than two lists: from the operator's point of view
// "container runtime checks" and "Trivy CVE scanning" are both just checks they
// may or may not want, and the difference (built in vs. external binary) is an
// implementation detail the UI surfaces rather than a reason to model them
// separately.
package feature

import (
	"github.com/jchirayath/secscan/internal/core/collect"
	"github.com/jchirayath/secscan/internal/core/engine"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Kind distinguishes what a feature needs to run.
type Kind string

const (
	KindCollector Kind = "collector" // built in, always available
	KindEngine    Kind = "engine"    // external binary, may be absent
)

// Feature is one toggleable capability.
type Feature struct {
	ID          string           `json:"id"`
	Kind        Kind             `json:"kind"`
	Category    finding.Category `json:"category"`
	Label       string           `json:"label"`
	Description string           `json:"description"`
	Enabled     bool             `json:"enabled"`

	// Expensive marks a check that is off by default because its runtime makes
	// it unsuitable for a routine scan. Why is shown next to the toggle.
	Expensive bool   `json:"expensive,omitempty"`
	WhyCostly string `json:"why_costly,omitempty"`

	// Engine-only fields.
	Binary      string `json:"binary,omitempty"`
	Installed   bool   `json:"installed,omitempty"`
	InstallHint string `json:"install_hint,omitempty"`
	Installable bool   `json:"installable,omitempty"`
}

// descriptions explain, in the operator's terms, what turning something off
// costs them. A toggle with no stated consequence invites switching things off
// to make the number go down.
var descriptions = map[string]string{
	"host-facts":  "Operating system, kernel, and whether a reboot is pending to activate installed updates.",
	"packages":    "Pending OS package updates and how many are security fixes. Also whether unattended upgrades are on.",
	"listeners":   "Every listening socket with its owning process, user and bind address. This is what the exposure model is built on — disabling it removes reachability weighting from every other finding.",
	"accounts":    "Empty passwords, duplicate UID-0 accounts, password policy, and passwordless sudo grants.",
	"sshd":        "SSH daemon configuration: root login, password authentication, empty passwords, X11 forwarding.",
	"hardening":   "Kernel sysctl posture, world-writable files in system directories, and whether a host firewall is active.",
	"containers":  "How containers are run — privileged, docker.sock mounted, root user, host namespaces, unpinned tags, missing limits.",
	"ops":         "Time synchronisation and audit logging: controls whose absence you discover at the worst moment.",
	"hygiene":     "Host hygiene: logging and rotation, sudoers depth, .ssh and sensitive-file permissions, writable cron jobs, unexpected SUID binaries, unowned files, mount hardening, and risky tooling. Individually unglamorous; together they are how a foothold becomes root.",
	"escalation":  "Local privilege-escalation paths: file capabilities, writable systemd units, writable directories in root's PATH, docker/lxd group membership, NFS no_root_squash, and core dumps from SUID programs. These are not weaknesses in the abstract — each is a working route to root if present.",
	"services":    "Configuration of the network daemons the host runs: Apache/nginx/Caddy hardening (version disclosure, directory listing, TRACE, exposed status pages, weak TLS, admin API binding), BIND (open resolver, zone transfer), NTP (amplification), and DHCP presence. The listener check tells you a web server is reachable; this tells you whether it is configured safely.",
	"dns-hygiene": "Public-record DNS and mail checks in the style of a DNS diagnostic tool: forward-confirmed reverse DNS, SPF, DMARC and MX sanity. These are lookups, not probes — nothing is sent to the target — and they cover spoofability, which no host-local check can see.",
	"validate":    "Proves or refutes findings with safe, non-destructive tests instead of inferring them from config: writes and removes a uniquely-named probe file to confirm writability, executes a trivial script to test noexec, asks SSH which auth methods it offers (never attempting one), and distinguishes effective capabilities from permitted-only. A refuted finding is weighted sharply down.",
	"controls":    "Detects compensating controls that are actually active (fail2ban with a loaded SSH jail, key-only SSH, AppArmor/SELinux enforcing) and reduces residual risk accordingly. Disabling this makes every finding show its inherent risk with no credit for the defences you have.",

	"trivy":       "CVE scanning of OS packages and language dependencies against multiple vulnerability feeds. The highest-value optional engine.",
	"gitleaks":    "Finds committed credentials and secrets on disk. Reports location only, never the secret value.",
	"trivy-image": "CVE scanning inside the container images that are actually running. Complements the runtime checks: those say how a container is run, this says what is in it. Capped at 10 images per scan, and it reports when that cap truncates coverage rather than letting a partial result read as clean.",
	"testssl":     "TLS as actually negotiated on the wire — protocol versions, cipher suites, forward secrecy and the named TLS vulnerabilities. Reports what the server offers, whatever its config file says.",
	"nuclei":      "Template-driven detection of known web vulnerabilities, exposed panels and leaked configuration, sent as real requests. Rate-limited to 20 req/s at medium and above so it stays safe to point at production.",
	"web-headers": "Fetches each site this host serves and reads what a browser reads: HSTS, CSP, framing and MIME-sniffing headers, cookie Secure/HttpOnly flags, and certificate expiry. Needs no external tool. Disabling it means nothing checks whether a certificate is about to lapse.",
	"osv-scanner": "Checks language lockfiles against Google's OSV database — an independent second opinion to Trivy.",
}

var labels = map[string]string{
	"host-facts": "Host facts", "packages": "OS packages", "listeners": "Listening sockets",
	"accounts": "Accounts & passwords", "sshd": "SSH daemon", "hardening": "System hardening",
	"containers": "Container runtime", "ops": "Operational readiness", "hygiene": "Host hygiene", "escalation": "Privilege-escalation paths", "validate": "Vulnerability validation", "services": "Service configuration", "dns-hygiene": "DNS & mail hygiene",
	"controls": "Compensating controls",
	"trivy":    "Trivy (host CVE scanning)", "trivy-image": "Trivy (container images)",
	"gitleaks": "gitleaks (secrets)", "osv-scanner": "osv-scanner (dependencies)",
	"testssl": "testssl.sh (TLS configuration)", "nuclei": "nuclei (web vulnerabilities)",
	"web-headers": "Web headers & certificates",
}

// State is the persisted enable/disable set. Absent means enabled: a new
// collector added in a later version is on by default rather than silently
// missing for everyone who already has a state file.
type State struct {
	Disabled map[string]bool `json:"disabled"`
	// Enabled records deliberate opt-ins for checks that are off by default.
	Enabled map[string]bool `json:"enabled,omitempty"`
}

// IsEnabled reports whether id should run.
//
// Absent means enabled, so a check added in a later version is on by default
// rather than silently missing for everyone who already has a state file. The
// exception is expensive checks, which must be opted into — see Enabled below.
func (s State) IsEnabled(id string) bool {
	if s.Disabled == nil {
		return true
	}
	return !s.Disabled[id]
}

// explicitlyEnabled reports whether the operator has deliberately turned this
// on. Expensive checks need that: defaulting them to enabled would make every
// routine scan take twenty minutes, and defaulting them to "disabled" in the
// Disabled map would be indistinguishable from the operator having switched
// them off, which would silently re-enable them on the next version bump.
func (s State) explicitlyEnabled(id string) bool { return s.Enabled[id] }

// ShouldRun is the single answer to "does this check execute?", honouring both
// the disable list and the opt-in required by expensive checks. The scan
// orchestrator and the UI must agree, so they both come through here.
func ShouldRun(st State, id string) bool {
	if !st.IsEnabled(id) {
		return false
	}
	for _, e := range engine.All() {
		if e.ID() != id {
			continue
		}
		if _, costly := engine.IsExpensive(e); costly {
			return st.explicitlyEnabled(id)
		}
	}
	return true
}

// All returns the full registry with enablement applied. installed is a lookup
// the caller supplies (it needs a Runner, which this package deliberately does
// not depend on).
func All(st State, installed map[string]bool) []Feature {
	var out []Feature

	for _, c := range collect.All() {
		out = append(out, Feature{
			ID: c.ID(), Kind: KindCollector, Category: c.Category(),
			Label: labelFor(c.ID()), Description: descriptions[c.ID()],
			Enabled: st.IsEnabled(c.ID()),
		})
	}
	// The controls detector is not a finding-producing Collector — it feeds the
	// risk model instead — but it is still a check the operator can turn off,
	// so it belongs in the same registry.
	cc := collect.ControlsCollector{}
	out = append(out, Feature{
		ID: cc.ID(), Kind: KindCollector, Category: cc.Category(),
		Label: labelFor(cc.ID()), Description: descriptions[cc.ID()],
		Enabled: st.IsEnabled(cc.ID()),
	})
	out = append(out, Feature{
		ID: "validate", Kind: KindCollector, Category: finding.CatHardening,
		Label: labelFor("validate"), Description: descriptions["validate"],
		Enabled: st.IsEnabled("validate"),
	})
	wh := collect.WebHeaders{}
	out = append(out, Feature{
		ID: wh.ID(), Kind: KindCollector, Category: wh.Category(),
		Label: labelFor(wh.ID()), Description: descriptions[wh.ID()],
		Enabled: st.IsEnabled(wh.ID()),
	})
	out = append(out, Feature{
		ID: "dns-hygiene", Kind: KindCollector, Category: finding.CatServices,
		Label: labelFor("dns-hygiene"), Description: descriptions["dns-hygiene"],
		Enabled: st.IsEnabled("dns-hygiene"),
	})
	for _, e := range engine.All() {
		why, costly := engine.IsExpensive(e)
		out = append(out, Feature{
			ID: e.ID(), Kind: KindEngine, Category: categoryForEngine(e.ID()),
			Label: labelFor(e.ID()), Description: descriptions[e.ID()],
			Enabled:   st.IsEnabled(e.ID()) && (!costly || st.explicitlyEnabled(e.ID())),
			Expensive: costly, WhyCostly: why,
			Binary:    e.Binary(),
			Installed: installed[e.ID()], InstallHint: e.InstallHint(),
			Installable: true,
		})
	}
	return out
}

func labelFor(id string) string {
	if l, ok := labels[id]; ok {
		return l
	}
	return id
}

func categoryForEngine(id string) finding.Category {
	switch id {
	case "trivy":
		return finding.CatPatch
	case "gitleaks":
		return finding.CatSecrets
	case "osv-scanner":
		return finding.CatDeps
	case "trivy-image":
		return finding.CatContainer
	case "testssl", "nuclei":
		return finding.CatWeb
	}
	return finding.CatOps
}

// Known reports whether id names a real feature — so a toggle for a typo'd or
// removed id is rejected rather than silently stored forever.
func Known(id string) bool {
	if id == "controls" || id == "validate" || id == "dns-hygiene" || id == "web-headers" {
		return true
	}
	for _, c := range collect.All() {
		if c.ID() == id {
			return true
		}
	}
	for _, e := range engine.All() {
		if e.ID() == id {
			return true
		}
	}
	return false
}
