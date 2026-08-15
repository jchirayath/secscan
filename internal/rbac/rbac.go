// Package rbac is the authorization model.
//
// The role vocabulary is kept deliberately small and stable so findings can be
// exchanged with other tools without remapping (ARCHITECTURE.md — Findings).
//
// The lesson being applied here is a common one: a service accumulates hundreds
// of route registrations against a handful of authorization call sites, while
// its documentation claims the API "enforces capability checks separately".
// Nobody decides that; it happens because nothing fails the build. Here every
// route declares a capability and ci/guards.sh fails the build on any that
// does not.
package rbac

// Role is what a principal is.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleAuditor  Role = "auditor"
	RoleAnalyst  Role = "security_analyst"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Capability is what a route needs.
type Capability string

const (
	CapFindingRead     Capability = "finding.read"
	CapEvidenceRead    Capability = "evidence.read"
	CapAuditRead       Capability = "audit.read"
	CapFindingSuppress Capability = "finding.suppress"
	CapScanRun         Capability = "scan.run"
	CapTargetWrite     Capability = "target.write"
	CapConfigRead      Capability = "config.read"
	// CapFeatureManage toggles checks on and off. Operator-level: it changes
	// what gets scanned, but nothing on the target.
	CapFeatureManage Capability = "feature.manage"
	// CapEngineInstall installs software ON the scanned host. This is the only
	// capability in the product that mutates a target, so it is admin-only.
	CapEngineInstall Capability = "engine.install"
	// CapRemediate applies a fix to a scanned host. Admin-only and separate
	// from engine.install: installing a scanner is a different decision from
	// changing a host's security configuration.
	CapRemediate Capability = "remediate.apply"
)

// grants is the full matrix. Roles are cumulative in practice but written out
// explicitly: an implicit hierarchy is where privilege-escalation bugs hide.
var grants = map[Role]map[Capability]bool{
	RoleViewer: {
		CapFindingRead: true,
	},
	RoleAuditor: {
		CapFindingRead: true, CapEvidenceRead: true, CapAuditRead: true,
	},
	RoleAnalyst: {
		CapFindingRead: true, CapEvidenceRead: true, CapAuditRead: true,
		CapFindingSuppress: true,
	},
	RoleOperator: {
		CapFindingRead: true, CapEvidenceRead: true, CapAuditRead: true,
		CapFindingSuppress: true, CapScanRun: true, CapTargetWrite: true,
		CapFeatureManage: true,
	},
	RoleAdmin: {
		CapFindingRead: true, CapEvidenceRead: true, CapAuditRead: true,
		CapFindingSuppress: true, CapScanRun: true, CapTargetWrite: true,
		CapConfigRead: true, CapFeatureManage: true, CapEngineInstall: true,
		CapRemediate: true,
	},
}

// Can reports whether role holds cap. Unknown roles hold nothing — deny is the
// default, including for a role string we do not recognise.
func Can(role Role, cap Capability) bool {
	return grants[role][cap]
}

// Capabilities lists what a role can do, for the UI to gate affordances. This
// is a display convenience; it is never the security boundary.
func Capabilities(role Role) []string {
	var out []string
	for c := range grants[role] {
		out = append(out, string(c))
	}
	return out
}

// Valid reports whether s names a real role.
func Valid(s string) bool {
	_, ok := grants[Role(s)]
	return ok
}

// FromClaims maps Entra app-role / group claims onto a Role, highest wins.
// An authenticated user with no recognised claim gets viewer, never more.
func FromClaims(claims []string) Role {
	best := RoleViewer
	rank := map[Role]int{RoleViewer: 0, RoleAuditor: 1, RoleAnalyst: 2, RoleOperator: 3, RoleAdmin: 4}
	for _, c := range claims {
		r := Role(c)
		if !Valid(string(r)) {
			continue
		}
		if rank[r] > rank[best] {
			best = r
		}
	}
	return best
}
