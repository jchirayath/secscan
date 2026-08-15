// Package remediate executes fixes — the only part of secscan that changes a
// scanned host on purpose.
//
// # The colour flags the change, not the finding
//
// This is the distinction the whole design rests on, and getting it backwards
// would be actively harmful. A CRITICAL finding can have a trivial fix (send a
// header). A LOW finding can have a fix that locks you out of the machine you
// are fixing (sshd_config, firewall rules, PAM). Severity says how bad the
// problem is; change-risk says how bad it would be if the fix went wrong.
//
// # Only green executes
//
// Amber and red are not "run with a warning" — they are not runnable here at
// all. An operator who wants them applies them by hand, having read the plan,
// with a console open. That is a deliberate refusal of the most requested
// feature in this space, because the failure mode is unrecoverable: a scanner
// that breaks sshd on a remote host has removed the means of repairing itself.
//
// # An allow-list, never a heuristic
//
// A fix is executable only if it appears in this catalogue with a hand-written
// playbook. Nothing is inferred from the Remediation.Command string a collector
// happened to emit. Generating shell from a finding and running it as root is
// how a scanner becomes the incident.
package remediate

import (
	"github.com/jchirayath/secscan/internal/core/finding"
)

// ChangeRisk is how dangerous applying the fix is.
type ChangeRisk string

const (
	// RiskGreen: reversible, idempotent, no service restart, and it cannot
	// affect the paths that keep us able to reach and repair the host —
	// networking, SSH, authentication, boot.
	RiskGreen ChangeRisk = "green"
	// RiskAmber: safe in principle but restarts a service, changes behaviour
	// for all users, or can break an application that depended on the old
	// setting. Needs a human and a maintenance window.
	RiskAmber ChangeRisk = "amber"
	// RiskRed: can remove our own access, is hard to reverse, or needs a
	// reboot to take effect or to recover from.
	RiskRed ChangeRisk = "red"
)

// Playbook is a hand-written, reviewed fix for one finding rule.
type Playbook struct {
	RuleID string
	Risk   ChangeRisk
	// Why explains the risk rating in the operator's terms. Shown before
	// anything runs — a colour without a reason is just a traffic light.
	Why string

	// Commands are [][]string — a list of argv, not a list of strings.
	//
	// The obvious `[]string` cannot distinguish "three commands" from "one
	// command with three arguments", and the two readings differ by whether
	// `sh -c "rm -rf ..."` runs as intended or as three separate commands. In
	// a component that executes as root, an ambiguity like that is not a
	// style question.

	// Backup captures the prior state so Rollback has something to restore.
	// A playbook with no backup is not green, whatever else it does.
	Backup [][]string
	// Apply is the change. Every command must be idempotent: running the fix
	// twice must not compound.
	Apply [][]string
	// Verify proves the fix took. Its exit status is the answer — zero means
	// the weakness is gone.
	Verify []string
	// Rollback restores the prior state if Verify fails.
	Rollback [][]string

	// Privileged means Apply and Rollback need root.
	//
	// Backup and Verify never get privilege, whatever this says. That is not an
	// oversight: verification is stronger when the unprivileged scanning user
	// performs it, because that is the same vantage point the collector had
	// when it reported the weakness. A verify that only passes as root proves
	// nothing about what an ordinary account can still see or do.
	//
	// This is separate from the collector's needs-privilege heuristic on
	// purpose. That list governs reads, is deliberately short, and must not
	// grow to accommodate writes.
	Privileged bool

	// TouchesAccessPath marks a fix that could interfere with reaching the
	// host. Nothing marked here can ever be green, and the constructor
	// enforces that rather than trusting the author.
	TouchesAccessPath bool
	// NeedsRestart names a service that must restart for the fix to take
	// effect. Anything here is at least amber.
	NeedsRestart string
}

// catalogue is the complete set of executable fixes. Adding one means writing
// the backup, the verification and the rollback — not just the change.
var catalogue = []Playbook{
	{
		RuleID:     "hygiene.log-dir-world-readable",
		Privileged: true,
		Risk:       RiskGreen,
		Why: "Removes the world-read bit from /var/log so ordinary local users can no longer " +
			"list what is being logged. It deliberately does NOT use `chmod 750`, which is the " +
			"usual advice and is wrong here: 750 also clears the world-execute bit, and non-root " +
			"daemons need that bit to traverse into their own log subdirectories. On a host where " +
			"chrony or landscape owns a directory under /var/log, 750 silently stops it logging " +
			"and the breakage surfaces days later in an unrelated service. The relative `o-r` " +
			"clears exactly the bit the finding is about and touches nothing else.",
		Backup: [][]string{{"stat", "-c", "%a %U:%G", "/var/log"}},
		Apply:  [][]string{{"chmod", "o-r", "/var/log"}},
		// Mirrors the collector's predicate (mode & 0004) rather than asserting
		// one exact mode, so verification answers the same question the next
		// scan will ask.
		Verify:   []string{"sh", "-c", `test $(( 0$(stat -c %a /var/log) & 04 )) -eq 0`},
		Rollback: [][]string{{"chmod", "o+r", "/var/log"}},
	},
	{
		RuleID:     "escalation.suid-dumpable",
		Privileged: true,
		Risk:       RiskGreen,
		Why: "Sets fs.suid_dumpable=0 so privileged processes stop writing memory to disk " +
			"on crash. Takes effect immediately, reverses immediately, restarts nothing, and " +
			"affects only what happens during a crash.",
		Backup: [][]string{{"sysctl", "-n", "fs.suid_dumpable"}},
		Apply: [][]string{
			// `echo`, not `printf '...\n'`: the printf form needs a literal
			// backslash in the argument, and a backslash cannot be pinned by an
			// exact sudoers rule without ambiguity. A fix that cannot be granted
			// narrowly is a fix that gets granted broadly.
			{"sh", "-c", "echo fs.suid_dumpable=0 > /etc/sysctl.d/90-secscan-suid-dumpable.conf"},
			{"sysctl", "-q", "-w", "fs.suid_dumpable=0"},
		},
		Verify: []string{"sh", "-c", `test "$(sysctl -n fs.suid_dumpable)" = "0"`},
		Rollback: [][]string{
			{"rm", "-f", "/etc/sysctl.d/90-secscan-suid-dumpable.conf"},
			{"sysctl", "-q", "-w", "fs.suid_dumpable=2"},
		},
	},
	{
		RuleID:     "hygiene.sensitive-file-permissions",
		Privileged: true,
		Risk:       RiskGreen,
		Why: "Clears the excess permission bits on the six paths the check covers: /etc/shadow, " +
			"/etc/gshadow, /etc/passwd, /etc/group, /etc/crontab and /root. Every chmod is " +
			"RELATIVE (o-rwx, g-w) rather than absolute, which is the point: `chmod 640 " +
			"/etc/shadow` would LOOSEN a host that had already tightened it to 600. Relative " +
			"modes can only remove access, so this fix cannot make a well-configured host worse, " +
			"and it is idempotent by construction. It does not touch sshd or PAM.",
		Backup: [][]string{{"sh", "-c",
			"stat -c '%n %a' /etc/shadow /etc/gshadow /etc/passwd /etc/group /etc/crontab /root 2>/dev/null"}},
		Apply: [][]string{
			{"sh", "-c", "chmod u-x,g-wx,o-rwx /etc/shadow /etc/gshadow 2>/dev/null; " +
				"chmod u-x,g-wx,o-wx /etc/passwd /etc/group /etc/crontab 2>/dev/null; " +
				"chmod g-w,o-rwx /root; true"},
		},
		// Every path the collector checks is verified, using the collector's own
		// comparison (mode &^ allowed). An earlier draft of this entry chmod'd
		// four paths and verified two, so a finding about /root would have
		// applied nothing to it, passed, and reported the weakness fixed. A
		// verify narrower than the check it answers is worse than no verify:
		// it converts an open finding into a false all-clear.
		Verify: []string{"sh", "-c",
			`for e in /etc/shadow:640 /etc/gshadow:640 /etc/passwd:644 /etc/group:644 /etc/crontab:644 /root:750; do ` +
				`p=${e%:*}; w=${e#*:}; m=$(stat -c %a "$p" 2>/dev/null) || continue; ` +
				`[ $(( 0$m & ~0$w )) -eq 0 ] || exit 1; done`,
		},
		// Rollback is intentionally absent-as-restore: the standard modes ARE
		// the safe state, so "undoing" to a looser mode would be reinstating a
		// weakness. Recorded prior state is in the backup output for a human.
		Rollback: nil,
	},
	{
		RuleID:     "ops.auto-updates-disabled",
		Privileged: true,
		Risk:       RiskAmber,
		Why: "Enabling unattended-upgrades installs a package and changes what the host does " +
			"unattended from then on. That is usually right, but it means future package " +
			"installs happen without a human present, which some estates deliberately forbid. " +
			"Apply it in a window, not from a scanner.",
		Backup: [][]string{{"cat", "/etc/apt/apt.conf.d/20auto-upgrades"}},
		Apply: [][]string{
			{"sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades"},
		},
		Verify:       []string{"sh", "-c", `grep -q '"1"' /etc/apt/apt.conf.d/20auto-upgrades`},
		NeedsRestart: "unattended-upgrades",
	},
	{
		RuleID: "identity.ssh-password-auth",
		Risk:   RiskRed,
		Why: "Disabling password authentication locks out anyone without a working key — " +
			"including you, if the key you are using now is the only one and it is not where " +
			"you think it is. This is the single most common way a hardening script ends in a " +
			"console session at a cloud provider. Do it by hand, with a second session open.",
		TouchesAccessPath: true,
	},
	{
		RuleID: "hardening.no-firewall",
		Risk:   RiskRed,
		Why: "Enabling a default-deny firewall on a remote host drops your own connection the " +
			"moment the policy applies unless SSH is allowed first, in the right order. " +
			"Recoverable only through an out-of-band console.",
		TouchesAccessPath: true,
	},
	{
		RuleID: "hygiene.mount-options",
		Risk:   RiskRed,
		Why: "Adding noexec/nosuid to /tmp or /dev/shm requires a remount and breaks anything " +
			"that executes from those paths — some JVMs, some installers, some container " +
			"runtimes. The failure appears later, in an unrelated service.",
		NeedsRestart: "remount",
	},
	{
		RuleID: "hygiene.no-account-lockout",
		Risk:   RiskRed,
		Why: "PAM lockout misconfiguration locks out every account, including root, and PAM " +
			"errors are not always visible until the next login attempt. It is also a " +
			"denial-of-service vector against your own service accounts if the threshold is " +
			"wrong.",
		TouchesAccessPath: true,
	},
	{
		RuleID: "patch.updates-pending",
		Risk:   RiskAmber,
		Why: "Applying pending updates is the single highest-value action available, and also " +
			"the one most likely to restart a service or pull in a behaviour change. It belongs " +
			"in a maintenance window with someone watching, not in a scanner's automation.",
		NeedsRestart: "varies",
	},
	{
		RuleID: "container.image-cve",
		Risk:   RiskAmber,
		Why: "Rebuilding or re-pulling an image and recreating its containers means downtime for " +
			"that service and a new image whose behaviour has not been tested here.",
		NeedsRestart: "container",
	},
}

// Lookup returns the playbook for a finding, if one exists.
//
// The match is on rule id, with a prefix fallback so families like
// container.image-cve.<cve> share one entry. Nothing outside this catalogue is
// executable — an unknown rule returns false rather than falling back to the
// Remediation.Command a collector emitted.
func Lookup(f finding.Finding) (Playbook, bool) {
	for _, p := range catalogue {
		if p.RuleID == f.RuleID {
			return normalise(p), true
		}
	}
	for _, p := range catalogue {
		if len(f.RuleID) > len(p.RuleID) && f.RuleID[:len(p.RuleID)] == p.RuleID {
			return normalise(p), true
		}
	}
	return Playbook{}, false
}

// normalise enforces the invariants rather than trusting the author of an
// entry to have applied them consistently. A playbook that touches the access
// path or needs a restart cannot be green however it was written, and one with
// no verification cannot be executable at all.
func normalise(p Playbook) Playbook {
	if p.TouchesAccessPath {
		p.Risk = RiskRed
	}
	if p.NeedsRestart != "" && p.Risk == RiskGreen {
		p.Risk = RiskAmber
	}
	if len(p.Verify) == 0 && p.Risk == RiskGreen {
		// A fix we cannot prove worked is not a fix we should apply
		// unattended.
		p.Risk = RiskAmber
	}
	return p
}

// Executable reports whether this fix may be applied by the tool.
func (p Playbook) Executable() bool {
	return p.Risk == RiskGreen && len(p.Apply) > 0 && len(p.Verify) > 0
}

// Classify returns the change-risk for a finding, and whether a playbook
// exists at all. Findings with no playbook are reported as unclassified rather
// than assumed safe.
func Classify(f finding.Finding) (ChangeRisk, string, bool) {
	p, ok := Lookup(f)
	if !ok {
		return "", "No reviewed fix exists for this finding, so it cannot be applied " +
			"automatically. The remediation text describes what to do by hand.", false
	}
	return p.Risk, p.Why, true
}
