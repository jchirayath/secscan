// Package finding is the normalized model every collector and engine adapter
// emits. Field names deliberately mirror common `finding`/`vulns` table shapes
// so an exporter between the two stays mechanical (ARCHITECTURE.md — Findings).
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Severity is the finding's intrinsic seriousness, before exposure weighting.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank orders severities for sorting (higher is worse).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// BaseCVSS supplies a CVSS-shaped number for findings that have no CVE, so
// configuration weaknesses and CVEs can be ranked on one scale.
func (s Severity) BaseCVSS() float64 {
	switch s {
	case SevCritical:
		return 9.5
	case SevHigh:
		return 7.5
	case SevMedium:
		return 5.0
	case SevLow:
		return 3.0
	default:
		return 1.0
	}
}

// Category is the dashboard's top-level grouping — the ten from PLAN.md §2.
type Category string

const (
	CatPatch     Category = "patch"     // OS packages, missing updates, EOL
	CatDeps      Category = "deps"      // application/language dependencies
	CatContainer Category = "container" // images and runtime posture
	CatWeb       Category = "web"       // HTTP services, TLS, headers, old JS
	CatNetwork   Category = "network"   // listening ports, exposure
	CatIdentity  Category = "identity"  // accounts, password policy, SSH keys
	CatHardening Category = "hardening" // kernel, filesystem, CIS-style config
	CatSecrets   Category = "secrets"   // credentials on disk / in repos
	CatServices  Category = "services"  // data stores and service config
	CatOps       Category = "ops"       // backups, logging, update mechanism
)

// AllCategories is the canonical display order.
var AllCategories = []Category{
	CatPatch, CatDeps, CatContainer, CatWeb, CatNetwork,
	CatIdentity, CatHardening, CatSecrets, CatServices, CatOps,
}

// Label is the human name shown in the UI.
func (c Category) Label() string {
	switch c {
	case CatPatch:
		return "Patches & OS vulnerabilities"
	case CatDeps:
		return "Application dependencies"
	case CatContainer:
		return "Containers"
	case CatWeb:
		return "Web services & TLS"
	case CatNetwork:
		return "Network exposure"
	case CatIdentity:
		return "Identity & credentials"
	case CatHardening:
		return "System hardening"
	case CatSecrets:
		return "Secrets & data exposure"
	case CatServices:
		return "Service configuration"
	case CatOps:
		return "Operational readiness"
	}
	return string(c)
}

// Status is the finding lifecycle.
type Status string

const (
	StatusOpen       Status = "open"
	StatusSuppressed Status = "suppressed"
	StatusFixed      Status = "fixed"
)

// SuppressKind says WHY a finding is suppressed. The two are kept apart because
// they mean opposite things to whoever reads the report later: an accepted risk
// is a real problem someone chose to live with, a false positive is a claim the
// scanner got wrong. Mixing them hides the first and lets the second rot.
type SuppressKind string

const (
	KindAcceptedRisk  SuppressKind = "accepted_risk"
	KindFalsePositive SuppressKind = "false_positive"
)

// Valid reports whether k is a known kind.
func (k SuppressKind) Valid() bool { return k == KindAcceptedRisk || k == KindFalsePositive }

// Provenance states how a surface came by its data. Nothing may present demo
// or stale data as live (ARCHITECTURE.md — Provenance and honest degradation).
type Provenance string

const (
	ProvLive        Provenance = "live"
	ProvCached      Provenance = "cached"
	ProvDemo        Provenance = "demo"
	ProvPartial     Provenance = "partial"
	ProvUnavailable Provenance = "unavailable"
)

// Component is the specific thing that is vulnerable, when there is one.
type Component struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

// Evidence is raw proof. Every finding carries at least one — no claim without
// proof. Command is the exact argv that produced Output.
type Evidence struct {
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Output  string `json:"output"`
}

// Remediation is the action that clears the finding. v1 never executes it; the
// planner groups these into a reviewed script (ARCHITECTURE.md — Remediation). The shape
// shaped so a future version can delegate to an external approval queue.
type Remediation struct {
	Op           string `json:"op"`                // apply_patch | change_config | close_port | rotate_secret | manual
	Summary      string `json:"summary"`           // one line, human
	Command      string `json:"command,omitempty"` // the concrete fix, when safely expressible
	AutoEligible bool   `json:"auto_eligible"`     // safe to run unattended (never true in v1)
}

// Mitigation is a compensating control that applies to a finding. It reduces
// risk; it never removes it. Limits is mandatory — a control presented without
// what it fails to cover is just a discount.
type Mitigation struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Detail string  `json:"detail"`
	Factor float64 `json:"factor"`
	Limits string  `json:"limits"`
}

// Verdict is the outcome of actually trying to prove a finding true.
type Verdict string

const (
	// VerdictUnverified — no safe test exists, or validation was not run.
	VerdictUnverified Verdict = "unverified"
	// VerdictConfirmed — a non-destructive test demonstrated the weakness is
	// real and reachable as an unprivileged caller.
	VerdictConfirmed Verdict = "confirmed"
	// VerdictRefuted — the test showed the condition does NOT hold. Something
	// upstream (a mount option, a kernel setting, a capability that is
	// permitted but not effective) prevents it.
	VerdictRefuted Verdict = "refuted"
)

// Validation records an attempt to prove a finding rather than infer it.
//
// Inference produces plausible findings; proof produces actionable ones. The
// distinction matters most in the refuted direction — a scanner that reports a
// weakness which cannot actually be exercised is spending the operator's
// attention on nothing, and that is how tools lose credibility.
//
// Every validator must be non-destructive: unique temp names, cleaned up, no
// persistence, no credentials attempted, no denial of service.
type Validation struct {
	Verdict Verdict `json:"verdict"`
	Method  string  `json:"method"`           // what was actually done
	Output  string  `json:"output,omitempty"` // the observed result
	Note    string  `json:"note,omitempty"`   // why refuted / why unverifiable
}

// Finding is one issue on one asset.
type Finding struct {
	ID          string   `json:"id"` // stable fingerprint — see Fingerprint
	AssetID     string   `json:"asset_id"`
	Category    Category `json:"category"`
	Subcategory string   `json:"subcategory,omitempty"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	RuleID      string   `json:"rule_id"`

	CVE  []string `json:"cve,omitempty"`
	CVSS float64  `json:"cvss,omitempty"`
	EPSS float64  `json:"epss,omitempty"`
	KEV  bool     `json:"kev,omitempty"`

	// Exposed is set by the reachability collector, not by the source engine.
	// It is the multiplier that separates "critical on loopback" from
	// "critical on a forwarded port".
	Exposed       bool `json:"exposed"`
	AssetCritical bool `json:"asset_critical"`

	Component   Component   `json:"component,omitempty"`
	Location    string      `json:"location,omitempty"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
	Engine      string      `json:"engine"` // which collector/adapter produced it
	Remediation Remediation `json:"remediation"`
	References  []string    `json:"references,omitempty"`

	Status         Status       `json:"status"`
	SuppressReason string       `json:"suppress_reason,omitempty"`
	SuppressUntil  *time.Time   `json:"suppress_until,omitempty"`
	SuppressKind   SuppressKind `json:"suppress_kind,omitempty"`
	// SuppressRule is set when a match rule, not a per-finding decision,
	// suppressed this finding; revoking the rule reopens it.
	SuppressRule string `json:"suppress_rule,omitempty"`

	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Occurrences int       `json:"occurrences"`

	// The risk model is explicit in three parts, because "risk score: 8.78"
	// answers nothing on its own:
	//
	//   InherentRisk      what this would cost with no controls in place
	//   Mitigations       the compensating controls verified to be active
	//   ResidualRisk      what is actually left — the number everything
	//                     ranks, scores and plans on
	//
	// Keeping inherent visible alongside residual matters: it is what the risk
	// returns to the moment a control is removed, fails, or is found to have
	// been misconfigured all along.
	// Validation is the result of trying to prove this finding, when a safe
	// test exists. It feeds the risk chain: a confirmed weakness is weighted
	// up, a refuted one is weighted sharply down.
	Validation *Validation `json:"validation,omitempty"`

	InherentRisk     float64      `json:"inherent_risk"`
	Mitigations      []Mitigation `json:"mitigations,omitempty"`
	MitigationFactor float64      `json:"mitigation_factor,omitempty"`
	// Recommended are controls that WOULD reduce this finding but are not in
	// place. The most common reason a finding stays open is that the real fix
	// needs a maintenance window — this is what you can do before then.
	Recommended  []Mitigation `json:"recommended,omitempty"`
	ResidualRisk float64      `json:"residual_risk"`
}

// Fingerprint is the stable identity of a finding across scans. It must depend
// only on *what and where*, never on when or on a mutable score — otherwise
// "new since last scan" and suppression both break.
func Fingerprint(assetID, ruleID, location string, c Component) string {
	h := sha256.New()
	for _, part := range []string{assetID, ruleID, location, c.Name, c.Version} {
		h.Write([]byte(strings.ToLower(strings.TrimSpace(part))))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// New builds a Finding with its fingerprint and timestamps set. Collectors use
// this rather than constructing the struct literal, so no path can forget the
// fingerprint.
func New(assetID string, cat Category, sev Severity, ruleID, title string, now time.Time) Finding {
	return Finding{
		ID:          Fingerprint(assetID, ruleID, "", Component{}),
		AssetID:     assetID,
		Category:    cat,
		Severity:    sev,
		RuleID:      ruleID,
		Title:       title,
		Status:      StatusOpen,
		FirstSeen:   now,
		LastSeen:    now,
		Occurrences: 1,
	}
}

// WithLocation re-fingerprints after a location or component is attached.
// Callers set those fields then call this; forgetting it yields collisions
// between findings that differ only by location, which the tests check for.
func (f Finding) WithLocation(loc string, c Component) Finding {
	f.Location = loc
	f.Component = c
	f.ID = Fingerprint(f.AssetID, f.RuleID, loc, c)
	return f
}

// Asset is a scanned host.
type Asset struct {
	ID       string    `json:"id"`   // stable: the target name
	Name     string    `json:"name"` // display
	Kind     string    `json:"kind"` // host
	Address  string    `json:"address,omitempty"`
	OS       string    `json:"os,omitempty"`
	OSFamily string    `json:"os_family,omitempty"` // debian | rhel | alpine | darwin
	Kernel   string    `json:"kernel,omitempty"`
	Critical bool      `json:"critical"`
	LastScan time.Time `json:"last_scan"`
}

// Sort orders findings for display: risk desc, then severity, then title, so
// the ordering is total and stable across runs.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		// Residual, not inherent: the ordering must reflect what is actually
		// left after the controls that are genuinely in place.
		if fs[i].ResidualRisk != fs[j].ResidualRisk {
			return fs[i].ResidualRisk > fs[j].ResidualRisk
		}
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].Title < fs[j].Title
	})
}
