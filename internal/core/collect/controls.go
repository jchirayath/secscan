package collect

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Compensating controls.
//
// "SSH is exposed on 0.0.0.0" and "SSH is exposed on 0.0.0.0, key-only, behind
// fail2ban" are not the same risk, but a scanner that only enumerates weakness
// reports them identically. Operators then learn to ignore the tool, which is
// the worst outcome available.
//
// Three rules keep this honest:
//
//  1. A control must be VERIFIED ACTIVE AND SCOPED TO THE SERVICE. fail2ban
//     running with no sshd jail does not protect SSH. Installed ≠ effective.
//  2. A control REDUCES risk, it never clears it. The total reduction is
//     floored, and a mitigated finding never drops out of view — because the
//     control itself can fail, be misconfigured, or be bypassed.
//  3. Every control states WHAT IT DOES NOT COVER. fail2ban stops password
//     guessing; it does nothing about a protocol bug in sshd or a stolen key.
//     A mitigation presented without its limits is just a discount.

// Control is a detected mitigation.
type Control struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Detail string  `json:"detail"`
	Factor float64 `json:"factor"` // risk multiplier, 0 < factor < 1
	Limits string  `json:"limits"` // what this does NOT protect against
	// Covers lists the finding rule IDs this control mitigates. Matching is
	// exact so a control can never quietly discount something unrelated.
	Covers []string `json:"covers"`
	// Ports narrows a control to specific listeners (fail2ban's sshd jail
	// protects 22, not everything the host listens on).
	Ports    []int            `json:"ports,omitempty"`
	Evidence finding.Evidence `json:"evidence"`
}

// MitigationFloor is the most any combination of controls may reduce a finding.
// Defence in depth is real, but so is control failure: a stack of mitigations
// that drove risk to near-zero would hide the finding, and hidden is exactly
// what an attacker needs.
const MitigationFloor = 0.35

// ControlsCollector detects mitigations. It emits no findings of its own — its
// output is consumed by the scan orchestrator to re-weight other findings.
type ControlsCollector struct{}

func (ControlsCollector) ID() string                 { return "controls" }
func (ControlsCollector) Category() finding.Category { return finding.CatHardening }

// Detect returns the active controls on the target.
func (c ControlsCollector) Detect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]Control, Note) {
	if a.OSFamily == "darwin" {
		return nil, Skip(c.ID(), "compensating-control detection is Linux-only for now")
	}
	var out []Control

	if ctl, ok := detectFail2ban(ctx, r); ok {
		out = append(out, ctl)
	}
	out = append(out, detectSSHHardening(ctx, r)...)
	if ctl, ok := detectAccountLockout(ctx, r); ok {
		out = append(out, ctl)
	}
	if ctl, ok := detectMAC(ctx, r); ok {
		out = append(out, ctl)
	}
	if ctl, ok := detectAutoUpdates(ctx, r); ok {
		out = append(out, ctl)
	}
	return out, Ran(c.ID(), 5)
}

// ---------------------------------------------------------------- fail2ban

// sshJailNames are what distributions call the SSH jail.
var sshJailNames = []string{"sshd", "ssh", "sshd-ddos", "ssh-iptables"}

func detectFail2ban(ctx context.Context, r exec.Runner) (Control, bool) {
	// Running is necessary but not sufficient — the jail matters.
	if !r.Run(ctx, "systemctl", "is-active", "fail2ban").OK() {
		return Control{}, false
	}

	// Authoritative: ask fail2ban which jails are actually loaded. This needs
	// root, so fall back to configuration when it is unavailable.
	if res := r.Run(ctx, "fail2ban-client", "status"); res.OK() {
		jails := parseFail2banJails(res.Stdout)
		matched := ""
		for _, j := range jails {
			for _, want := range sshJailNames {
				if strings.EqualFold(j, want) {
					matched = j
				}
			}
		}
		if matched == "" {
			// Running, but not protecting SSH. Saying otherwise would be the
			// dangerous kind of wrong.
			return Control{}, false
		}
		detail := fmt.Sprintf("fail2ban is active with the %q jail loaded", matched)
		if st := r.Run(ctx, "fail2ban-client", "status", matched); st.OK() {
			if banned := parseBannedCount(st.Stdout); banned >= 0 {
				detail += fmt.Sprintf("; %d address(es) currently banned", banned)
			}
		}
		return Control{
			ID: "fail2ban", Name: "fail2ban (SSH brute-force protection)",
			Detail: detail, Factor: 0.6, Ports: []int{22},
			Covers: []string{"network.wide-bind", "identity.ssh-password-auth"},
			Limits: "Rate-limits repeated failed logins. It does NOT protect against a " +
				"vulnerability in sshd itself, a stolen or leaked private key, a valid " +
				"credential obtained elsewhere, or a slow distributed guessing attack " +
				"below the ban threshold.",
			Evidence: finding.Evidence{Command: res.Command, Output: strings.TrimSpace(res.Stdout)},
		}, true
	}

	// Fallback: the service is active and an SSH jail is enabled in config.
	// Weaker evidence, so a smaller reduction — we know it is configured, not
	// that it loaded cleanly.
	if enabled, where := fail2banJailEnabledInConfig(ctx, r); enabled {
		return Control{
			ID: "fail2ban", Name: "fail2ban (SSH brute-force protection)",
			Detail: "fail2ban service is active and an SSH jail is enabled in " + where +
				" (could not query fail2ban-client — grant the scan account sudo for it to confirm the jail is loaded)",
			Factor: 0.75, Ports: []int{22},
			Covers: []string{"network.wide-bind", "identity.ssh-password-auth"},
			Limits: "Rate-limits repeated failed logins. It does NOT protect against a " +
				"vulnerability in sshd itself, a stolen private key, or a valid credential " +
				"obtained elsewhere. Jail status was inferred from configuration, not confirmed.",
			Evidence: finding.Evidence{Path: where, Output: "SSH jail enabled; fail2ban.service active"},
		}, true
	}
	return Control{}, false
}

// parseFail2banJails pulls the jail list out of `fail2ban-client status`.
func parseFail2banJails(out string) []string {
	for _, l := range lines(out) {
		i := strings.Index(strings.ToLower(l), "jail list:")
		if i < 0 {
			continue
		}
		var jails []string
		for _, j := range strings.Split(l[i+len("jail list:"):], ",") {
			if j = strings.TrimSpace(j); j != "" {
				jails = append(jails, j)
			}
		}
		return jails
	}
	return nil
}

// parseBannedCount reads "Currently banned: N" from a jail status.
func parseBannedCount(out string) int {
	for _, l := range lines(out) {
		low := strings.ToLower(l)
		if !strings.Contains(low, "currently banned") {
			continue
		}
		f := strings.Fields(l)
		if n, err := strconv.Atoi(f[len(f)-1]); err == nil {
			return n
		}
	}
	return -1
}

// fail2banJailEnabledInConfig looks for an enabled SSH jail without root.
func fail2banJailEnabledInConfig(ctx context.Context, r exec.Runner) (bool, string) {
	paths := []string{"/etc/fail2ban/jail.local", "/etc/fail2ban/jail.conf"}
	if res := r.Run(ctx, "ls", "/etc/fail2ban/jail.d"); res.OK() {
		for _, n := range lines(res.Stdout) {
			paths = append(paths, "/etc/fail2ban/jail.d/"+n)
		}
	}
	for _, p := range paths {
		body, ok := r.ReadFile(ctx, p)
		if !ok {
			continue
		}
		if sectionEnabled(body, sshJailNames) {
			return true, p
		}
	}
	return false, ""
}

// sectionEnabled reports whether an ini section named in `names` contains
// `enabled = true` before the next section starts.
func sectionEnabled(body string, names []string) bool {
	inSection := false
	for _, l := range lines(body) {
		if strings.HasPrefix(l, "[") {
			name := strings.Trim(l, "[]")
			inSection = false
			for _, n := range names {
				if strings.EqualFold(name, n) {
					inSection = true
				}
			}
			continue
		}
		if !inSection || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, found := strings.Cut(l, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "enabled") {
			continue
		}
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

// ------------------------------------------------------------ ssh hardening

// detectSSHHardening reads the EFFECTIVE sshd configuration via `sshd -T`,
// which resolves Include directives, Match blocks and compiled-in defaults —
// the things that make hand-parsing sshd_config quietly wrong.
func detectSSHHardening(ctx context.Context, r exec.Runner) []Control {
	res := r.Run(ctx, "sshd", "-T")
	if !res.OK() {
		if res = r.Run(ctx, "/usr/sbin/sshd", "-T"); !res.OK() {
			return nil
		}
	}
	kv := kvFile(res.Stdout, " ")
	var out []Control

	pwAuth := strings.EqualFold(kv["passwordauthentication"], "yes")
	kbd := strings.EqualFold(kv["kbdinteractiveauthentication"], "yes") ||
		strings.EqualFold(kv["challengeresponseauthentication"], "yes")

	if !pwAuth && !kbd {
		out = append(out, Control{
			ID: "ssh-key-only", Name: "SSH accepts keys only",
			Detail: "PasswordAuthentication and keyboard-interactive are both disabled, " +
				"so there is no password to guess",
			Factor: 0.5, Ports: []int{22},
			Covers: []string{"network.wide-bind"},
			Limits: "Eliminates password guessing entirely. It does NOT help if a private " +
				"key is stolen, if an authorised key is left behind by a former user, or " +
				"against a vulnerability in sshd itself.",
			Evidence: finding.Evidence{Command: res.Command,
				Output: "passwordauthentication no\nkbdinteractiveauthentication no"},
		})
	}

	if allow := firstNonEmptyKV(kv, "allowusers", "allowgroups"); allow != "" {
		out = append(out, Control{
			ID: "ssh-allowlist", Name: "SSH restricted to named users/groups",
			Detail:   "sshd only accepts: " + allow,
			Factor:   0.8,
			Ports:    []int{22},
			Covers:   []string{"network.wide-bind"},
			Limits:   "Narrows which accounts can authenticate. It does NOT protect the listed accounts themselves.",
			Evidence: finding.Evidence{Command: res.Command, Output: "allow list: " + allow},
		})
	}

	if n, err := strconv.Atoi(kv["maxauthtries"]); err == nil && n <= 3 {
		out = append(out, Control{
			ID: "ssh-maxauthtries", Name: "SSH limits authentication attempts",
			Detail:   fmt.Sprintf("MaxAuthTries is %d per connection", n),
			Factor:   0.9,
			Ports:    []int{22},
			Covers:   []string{"network.wide-bind"},
			Limits:   "Slows guessing per connection. An attacker can simply reconnect.",
			Evidence: finding.Evidence{Command: res.Command, Output: "maxauthtries " + kv["maxauthtries"]},
		})
	}
	return out
}

func firstNonEmptyKV(kv map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(kv[k]); v != "" {
			return v
		}
	}
	return ""
}

// detectAccountLockout finds PAM-level lockout. Where fail2ban protects the
// network path by banning source addresses, this protects every local
// authentication path — console, su, sudo, cron — by locking the account
// itself. They are complementary, which is why both can apply.
func detectAccountLockout(ctx context.Context, r exec.Runner) (Control, bool) {
	for _, p := range []string{
		"/etc/security/faillock.conf",
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
	} {
		body, ok := r.ReadFile(ctx, p)
		if !ok {
			continue
		}
		if !strings.Contains(body, "pam_faillock") && !strings.Contains(body, "pam_tally2") {
			continue
		}
		return Control{
			ID: "pam-lockout", Name: "Account lockout on repeated failures",
			Detail: "PAM is configured with faillock/tally2 in " + p,
			Factor: 0.75,
			Covers: []string{"identity.ssh-password-auth", "identity.weak-min-length"},
			Limits: "Locks an account after repeated failures across every PAM-using path. " +
				"It does NOT help against a correct credential obtained elsewhere, key-based " +
				"access, or a guessing rate kept below the threshold — and an aggressive " +
				"setting is itself a denial-of-service vector against your own users.",
			Evidence: finding.Evidence{Path: p, Output: "pam_faillock/pam_tally2 configured"},
		}, true
	}
	return Control{}, false
}

// ---------------------------------------------------------- MAC (LSM) layer

// detectMAC finds a mandatory-access-control layer in enforcing mode. It does
// not prevent a compromise; it constrains what the compromise can reach, which
// is why it applies to container and service findings rather than to network
// exposure.
func detectMAC(ctx context.Context, r exec.Runner) (Control, bool) {
	if res := r.Run(ctx, "getenforce"); res.OK() {
		if strings.EqualFold(strings.TrimSpace(res.Stdout), "Enforcing") {
			return Control{
				ID: "selinux", Name: "SELinux enforcing",
				Detail: "SELinux is in enforcing mode", Factor: 0.85,
				Covers: []string{"container.root-user", "container.unpinned-image", "hardening.world-writable"},
				Limits: "Constrains what a compromised process can reach. It does NOT prevent " +
					"the initial compromise, and a permissive or unconfined domain removes the benefit.",
				Evidence: finding.Evidence{Command: res.Command, Output: strings.TrimSpace(res.Stdout)},
			}, true
		}
		return Control{}, false
	}
	// aa-status --enabled exits 0 when AppArmor is enabled.
	if res := r.Run(ctx, "aa-status", "--enabled"); res.OK() {
		detail := "AppArmor is enabled"
		if p := r.Run(ctx, "aa-status", "--enforced"); p.OK() {
			if n := strings.TrimSpace(p.Stdout); n != "" {
				detail = fmt.Sprintf("AppArmor is enabled with %s profile(s) in enforce mode", n)
			}
		}
		return Control{
			ID: "apparmor", Name: "AppArmor enabled",
			Detail: detail, Factor: 0.85,
			Covers: []string{"container.root-user", "container.unpinned-image", "hardening.world-writable"},
			Limits: "Constrains what a confined process can reach. It does NOT prevent the " +
				"initial compromise, and processes without a profile run unconfined.",
			Evidence: finding.Evidence{Command: res.Command, Output: detail},
		}, true
	}
	return Control{}, false
}

// ------------------------------------------------------------------- apply

// ApplyControls attaches matching controls to findings and records the combined
// factor. Scoring happens later in package risk — this only decides what
// applies to what.
func ApplyControls(fs []finding.Finding, controls []Control) int {
	applied := 0
	for i := range fs {
		f := &fs[i]
		var factor = 1.0
		for _, c := range controls {
			if !controlApplies(*f, c) {
				continue
			}
			factor *= c.Factor
			f.Mitigations = append(f.Mitigations, finding.Mitigation{
				ID: c.ID, Name: c.Name, Detail: c.Detail,
				Factor: c.Factor, Limits: c.Limits,
			})
			f.Evidence = append(f.Evidence, finding.Evidence{
				Command: c.Evidence.Command,
				Path:    c.Evidence.Path,
				Output:  "compensating control — " + c.Name + ": " + c.Evidence.Output,
			})
		}
		if factor < 1.0 {
			if factor < MitigationFloor {
				factor = MitigationFloor
			}
			f.MitigationFactor = factor
			applied++
		}
	}
	return applied
}

// controlApplies decides whether a control covers a finding. Both the rule and
// (where the control is port-scoped) the port must match — a control never
// discounts something it does not actually protect.
func controlApplies(f finding.Finding, c Control) bool {
	var ruleMatch bool
	for _, rule := range c.Covers {
		if f.RuleID == rule {
			ruleMatch = true
			break
		}
	}
	if !ruleMatch {
		return false
	}
	if len(c.Ports) == 0 {
		return true
	}
	_, port, ok := protoPort(f.Location)
	if !ok {
		return false
	}
	for _, p := range c.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// ------------------------------------------------- recommended (not present)

// Catalogue is the set of controls secscan knows about, whether or not they are
// installed. Detection answers "what is protecting this?"; the same catalogue
// answers "what would?" — so a finding you cannot fix today still comes with a
// way to reduce its risk in the meantime.
//
// This matters because the most common reason a finding stays open is not
// disagreement, it is that the fix needs a maintenance window. "Bind sshd to
// loopback" may be weeks away; "put fail2ban in front of it" is this afternoon.
func Catalogue() []Control {
	return []Control{
		{
			ID: "fail2ban", Name: "fail2ban with an SSH jail", Factor: 0.6, Ports: []int{22},
			Covers: []string{"network.wide-bind", "identity.ssh-password-auth"},
			Detail: "Bans source addresses after repeated failed logins",
			Limits: "Does not help against a stolen key, a valid credential, or a flaw in sshd itself.",
		},
		{
			ID: "ssh-key-only", Name: "Key-only SSH authentication", Factor: 0.5, Ports: []int{22},
			Covers: []string{"network.wide-bind", "identity.ssh-password-auth", "identity.weak-min-length"},
			Detail: "Set PasswordAuthentication no and KbdInteractiveAuthentication no",
			Limits: "Removes password guessing entirely; a stolen private key still works.",
		},
		{
			ID: "pam-lockout", Name: "PAM account lockout (faillock)", Factor: 0.75,
			Covers: []string{"identity.ssh-password-auth", "identity.weak-min-length", "hygiene.no-account-lockout"},
			Detail: "Locks an account after repeated failures across every PAM path",
			Limits: "An aggressive threshold is itself a denial-of-service risk against your own users.",
		},
		{
			ID: "apparmor", Name: "AppArmor or SELinux in enforcing mode", Factor: 0.85,
			Covers: []string{"container.root-user", "container.unpinned-image", "hardening.world-writable",
				"escalation.capabilities", "hygiene.unexpected-suid"},
			Detail: "Confines what a compromised process can reach",
			Limits: "Does not prevent the initial compromise; unprofiled processes run unconfined.",
		},
		{
			ID: "host-firewall", Name: "Default-deny host firewall", Factor: 0.7,
			Covers: []string{"network.wide-bind", "services.dhcp-server-running"},
			Detail: "Restrict inbound to the ports and sources that need it (ufw/nftables)",
			Limits: "Protects nothing about the services you do allow through.",
		},
		{
			ID: "auto-updates", Name: "Unattended security upgrades", Factor: 0.8,
			Covers: []string{"patch.updates-pending"},
			Detail: "Applies published security fixes without waiting for someone to remember",
			Limits: "Closes known vulnerabilities only, and only after the vendor ships a fix.",
		},
		{
			ID: "reverse-proxy-auth", Name: "Authenticating reverse proxy in front of the service",
			Factor: 0.6,
			Covers: []string{"network.wide-bind", "services.apache-status-exposed"},
			Detail: "Terminate at a proxy that requires SSO before the service is reachable",
			Limits: "The service is still reachable if the proxy is bypassed or misconfigured.",
		},
	}
}

// Recommend returns catalogue controls that would reduce this finding and are
// not already active on the host.
func Recommend(f finding.Finding, active []Control) []finding.Mitigation {
	have := map[string]bool{}
	for _, c := range active {
		have[c.ID] = true
	}
	var out []finding.Mitigation
	for _, c := range Catalogue() {
		if have[c.ID] || !controlApplies(f, c) {
			continue
		}
		out = append(out, finding.Mitigation{
			ID: c.ID, Name: c.Name, Detail: c.Detail, Factor: c.Factor, Limits: c.Limits,
		})
	}
	return out
}

// ApplyRecommendations attaches suggested controls to every open finding that
// has no active control covering it.
func ApplyRecommendations(fs []finding.Finding, active []Control) int {
	n := 0
	for i := range fs {
		if len(fs[i].Mitigations) > 0 {
			continue // already protected; recommending more is noise
		}
		if rec := Recommend(fs[i], active); len(rec) > 0 {
			fs[i].Recommended = rec
			n++
		}
	}
	return n
}
