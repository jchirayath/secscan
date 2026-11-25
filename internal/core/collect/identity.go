package collect

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// ----------------------------------------------------------------- Accounts

// Accounts audits local account and password posture.
//
// This is the "weak passwords" capability done responsibly: policy and
// structural weakness only. No cracking, no spraying, no plaintext — an empty
// password field or a second UID-0 account is a certainty, not a guess, and
// finds real problems without ever touching a credential.
type Accounts struct{}

func (Accounts) ID() string                 { return "accounts" }
func (Accounts) Category() finding.Category { return finding.CatIdentity }

func (ac Accounts) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()
	passwd, ok := r.ReadFile(ctx, "/etc/passwd")
	if !ok {
		return nil, Skip(ac.ID(), "/etc/passwd unreadable (non-POSIX host?)")
	}

	var out []finding.Finding
	checks := 0

	// --- duplicate UID 0 -----------------------------------------------
	var uid0 []string
	for _, l := range lines(passwd) {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		if f[2] == "0" {
			uid0 = append(uid0, f[0])
		}
	}
	checks++
	if len(uid0) > 1 {
		f := finding.New(a.ID, finding.CatIdentity, finding.SevCritical,
			"identity.multiple-uid0",
			fmt.Sprintf("%d accounts have UID 0 (full root)", len(uid0)), now)
		f.Description = "Any account with UID 0 is root regardless of its name. Extra UID-0 accounts " +
			"are a classic persistence mechanism and defeat per-user accountability."
		f.Engine = ac.ID()
		f.Evidence = evFile("/etc/passwd", "UID 0 accounts: "+strings.Join(uid0, ", "))
		f.Remediation = finding.Remediation{Op: "change_config",
			Summary: "Remove the extra UID-0 accounts or give them unique non-zero UIDs"}
		out = append(out, f)
	}

	// --- empty password fields -----------------------------------------
	// /etc/shadow needs privilege; if we cannot read it we say so rather than
	// silently reporting "no weak passwords found".
	checks++
	if shadow, ok := r.ReadFile(ctx, "/etc/shadow"); ok {
		var empty, noExpire []string
		for _, l := range lines(shadow) {
			f := strings.Split(l, ":")
			if len(f) < 2 {
				continue
			}
			user, hash := f[0], f[1]
			if hash == "" {
				empty = append(empty, user)
			}
			// A locked account (! or *) is fine; a real hash that never
			// expires is a policy question, not a defect, so it stays low.
			if len(f) >= 5 && f[4] == "" && hash != "" && !strings.HasPrefix(hash, "!") && !strings.HasPrefix(hash, "*") {
				noExpire = append(noExpire, user)
			}
		}
		if len(empty) > 0 {
			f := finding.New(a.ID, finding.CatIdentity, finding.SevCritical,
				"identity.empty-password",
				fmt.Sprintf("%d account(s) have an empty password", len(empty)), now)
			f.Description = "An empty password field means the account authenticates with no secret at all."
			f.Engine = ac.ID()
			f.Evidence = evFile("/etc/shadow", "accounts with empty password: "+strings.Join(empty, ", "))
			f.Remediation = finding.Remediation{Op: "change_config",
				Summary: "Set a password or lock the account", Command: "sudo passwd -l <user>"}
			out = append(out, f)
		}
		if len(noExpire) > 0 {
			f := finding.New(a.ID, finding.CatIdentity, finding.SevLow,
				"identity.password-never-expires",
				fmt.Sprintf("%d account(s) have no password expiry", len(noExpire)), now)
			f.Engine = ac.ID()
			f.Evidence = evFile("/etc/shadow", strings.Join(noExpire, ", "))
			f.Remediation = finding.Remediation{Op: "change_config",
				Summary: "Set a maximum password age", Command: "sudo chage -M 365 <user>"}
			out = append(out, f)
		}
	} else {
		// Honest degradation: record that the strongest check could not run.
		f := finding.New(a.ID, finding.CatIdentity, finding.SevInfo,
			"identity.shadow-unreadable", "Password hash checks skipped — /etc/shadow not readable", now)
		f.Description = "Run the scan with a target configured for sudo to enable empty-password and " +
			"password-aging checks. Reporting this rather than silently passing."
		f.Engine = ac.ID()
		f.Evidence = evFile("/etc/shadow", "(permission denied)")
		f.Remediation = finding.Remediation{Op: "manual",
			Summary: "Grant the scan user sudo for `cat /etc/shadow`, or run the scan as root"}
		out = append(out, f)
	}

	// --- password policy ------------------------------------------------
	checks++
	if defs, ok := r.ReadFile(ctx, "/etc/login.defs"); ok {
		kv := kvFile(defs, " ")
		if v, err := strconv.Atoi(kv["pass_max_days"]); err == nil && v > 365 {
			f := finding.New(a.ID, finding.CatIdentity, finding.SevLow,
				"identity.weak-max-age", fmt.Sprintf("PASS_MAX_DAYS is %d", v), now)
			f.Engine = ac.ID()
			f.Evidence = evFile("/etc/login.defs", "PASS_MAX_DAYS "+kv["pass_max_days"])
			f.Remediation = finding.Remediation{Op: "change_config",
				Summary: "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs"}
			out = append(out, f)
		}
		if v, err := strconv.Atoi(kv["pass_min_len"]); err == nil && v > 0 && v < 12 {
			f := finding.New(a.ID, finding.CatIdentity, finding.SevMedium,
				"identity.weak-min-length", fmt.Sprintf("Minimum password length is %d", v), now)
			f.Engine = ac.ID()
			f.Evidence = evFile("/etc/login.defs", "PASS_MIN_LEN "+kv["pass_min_len"])
			f.Remediation = finding.Remediation{Op: "change_config",
				Summary: "Require at least 12 characters (pam_pwquality minlen)"}
			out = append(out, f)
		}
	}

	// --- passwordless sudo ----------------------------------------------
	checks++
	out = append(out, sudoersFindings(ctx, r, a, ac.ID(), now)...)

	return out, Ran(ac.ID(), checks)
}

func sudoersFindings(ctx context.Context, r exec.Runner, a *finding.Asset, engine string, t time.Time) []finding.Finding {
	var grants []string
	collect := func(path, content string) {
		for _, l := range lines(content) {
			if strings.HasPrefix(l, "#") || !strings.Contains(l, "NOPASSWD") {
				continue
			}
			grants = append(grants, path+": "+l)
		}
	}
	if s, ok := r.ReadFile(ctx, "/etc/sudoers"); ok {
		collect("/etc/sudoers", s)
	}
	if res := r.Run(ctx, "ls", "/etc/sudoers.d"); res.OK() {
		for _, name := range lines(res.Stdout) {
			p := "/etc/sudoers.d/" + name
			if s, ok := r.ReadFile(ctx, p); ok {
				collect(p, s)
			}
		}
	}
	if len(grants) == 0 {
		return nil
	}
	// NOPASSWD limited to specific commands is a normal, defensible pattern
	// (it is what this scanner asks for itself). Blanket ALL is not.
	sev := finding.SevLow
	title := fmt.Sprintf("%d passwordless sudo grant(s)", len(grants))
	for _, g := range grants {
		if strings.Contains(g, "ALL") && strings.Contains(g, "NOPASSWD: ALL") {
			sev = finding.SevHigh
			title = "Passwordless sudo to ALL commands"
			break
		}
	}
	f := finding.New(a.ID, finding.CatIdentity, sev, "identity.nopasswd-sudo", title, t)
	f.Description = "NOPASSWD removes the re-authentication step before privilege escalation. " +
		"Scoped to specific commands this is reasonable; scoped to ALL it means any compromise " +
		"of that account is immediately root."
	f.Engine = engine
	f.Evidence = evFile("/etc/sudoers.d", strings.Join(grants, "\n"))
	f.Remediation = finding.Remediation{Op: "change_config",
		Summary: "Restrict NOPASSWD to the specific commands that need it"}
	return []finding.Finding{f}
}

// --------------------------------------------------------------------- SSHD

// SSHD audits the SSH daemon configuration and authorized keys. SSH is almost
// always the way in, so its configuration is disproportionately worth checking.
type SSHD struct{}

func (SSHD) ID() string                 { return "sshd" }
func (SSHD) Category() finding.Category { return finding.CatIdentity }

// sshdRule is one config expectation.
type sshdRule struct {
	key    string
	bad    []string // values that are wrong
	deflt  string   // effective value when the directive is absent
	sev    finding.Severity
	rule   string
	title  string
	desc   string
	remedy string
}

var sshdRules = []sshdRule{
	{"permitrootlogin", []string{"yes"}, "prohibit-password", finding.SevHigh,
		"identity.ssh-root-login", "SSH permits direct root login",
		"Direct root login removes per-user accountability and makes root a guessable username for attacks.",
		"Set `PermitRootLogin no` in /etc/ssh/sshd_config"},
	{"passwordauthentication", []string{"yes"}, "yes", finding.SevMedium,
		"identity.ssh-password-auth", "SSH accepts password authentication",
		"Password auth exposes the host to credential stuffing and brute force. Keys do not have that failure mode.",
		"Set `PasswordAuthentication no` and ensure key access works first"},
	{"permitemptypasswords", []string{"yes"}, "no", finding.SevCritical,
		"identity.ssh-empty-password", "SSH permits empty passwords",
		"Any account with a blank password can be used to log in over the network.",
		"Set `PermitEmptyPasswords no`"},
	{"x11forwarding", []string{"yes"}, "no", finding.SevLow,
		"identity.ssh-x11-forwarding", "SSH X11 forwarding is enabled",
		"X11 forwarding widens the trust relationship between client and server; rarely needed on a server.",
		"Set `X11Forwarding no`"},
}

func (s SSHD) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()
	cfg, ok := r.ReadFile(ctx, "/etc/ssh/sshd_config")
	if !ok {
		// Distinguish "no sshd" from "cannot read it": Ubuntu 24.04 ships the
		// file 0600, and claiming "no SSH daemon" on a host we reached over SSH
		// is the kind of confident-and-wrong output this product must not emit.
		if r.Run(ctx, "test", "-e", "/etc/ssh/sshd_config").OK() {
			return nil, Skip(s.ID(),
				"/etc/ssh/sshd_config exists but is not readable — configure the target with -sudo to audit SSH")
		}
		return nil, Skip(s.ID(), "/etc/ssh/sshd_config not present — no SSH daemon on this host")
	}

	// Judge the EFFECTIVE configuration when sshd will tell us. `sshd -T`
	// resolves Include, applies first-value-wins, and fills compiled-in
	// defaults. Merging files by hand got all three wrong at once on betty
	// (2026-11-25): a drop-in setting X11Forwarding no — which sshd honours,
	// because drop-ins are read at the Include line near the TOP and the first
	// value wins — was either unreadable to the scan account or lost to the
	// stock "X11Forwarding yes" later in the main file, and the finding stayed
	// open after the fix.
	kv, source := map[string]string(nil), "sshd -T (effective configuration)"
	if eff := r.Run(ctx, "sshd", "-T"); eff.OK() {
		kv = kvFile(eff.Stdout, " ")
	} else if eff := r.Run(ctx, "/usr/sbin/sshd", "-T"); eff.OK() {
		kv = kvFile(eff.Stdout, " ")
	}
	if len(kv) == 0 {
		// Fallback: merge the files ourselves. Drop-ins are appended after
		// the main file and kvFile lets the later value win, which matches
		// sshd only when no drop-in conflicts with a later main-file line.
		source = "/etc/ssh/sshd_config + sshd_config.d (sshd -T unavailable; approximate)"
		merged := cfg
		if res := r.Run(ctx, "ls", "/etc/ssh/sshd_config.d"); res.OK() {
			for _, name := range lines(res.Stdout) {
				if !strings.HasSuffix(name, ".conf") {
					continue
				}
				if inc, ok := r.ReadFile(ctx, "/etc/ssh/sshd_config.d/"+name); ok {
					merged += "\n# --- /etc/ssh/sshd_config.d/" + name + "\n" + inc
				}
			}
		}
		kv = kvFile(merged, " ")
	}

	var out []finding.Finding
	for _, rule := range sshdRules {
		val, present := kv[rule.key]
		if !present {
			val = rule.deflt
		}
		if !contains(rule.bad, strings.ToLower(val)) {
			continue
		}
		f := finding.New(a.ID, finding.CatIdentity, rule.sev, rule.rule, rule.title, now)
		f.Description = rule.desc
		f.Subcategory = "sshd"
		f.Engine = s.ID()
		src := "explicitly set"
		if !present {
			src = "not set — this is the compiled-in default"
		}
		f.Evidence = evFile(source, fmt.Sprintf("%s %s   (%s)", rule.key, val, src))
		f.Remediation = finding.Remediation{Op: "change_config", Summary: rule.remedy}
		out = append(out, f.WithLocation("sshd_config:"+rule.key, finding.Component{}))
	}
	out = append(out, sshAlgorithms(ctx, r, a, now)...)
	return out, Ran(s.ID(), len(sshdRules)+len(weakSSHAlgorithms))
}

// weakSSHAlgorithms: algorithm families with known cryptographic weaknesses
// that OpenSSH still offers for backward compatibility.
//
// This check exists because a live nuclei run flagged ssh-sha1-hmac-algo on a
// host whose sshd_config this collector had already declared fine. Reading the
// four familiar directives (PermitRootLogin, PasswordAuthentication...) says
// nothing about which ciphers, MACs and key exchanges the daemon will actually
// negotiate, and that is where the real cryptographic weakness lives.
var weakSSHAlgorithms = []struct {
	directive string // as it appears in `sshd -T` output
	match     []string
	label     string
	why       string
}{
	{"macs", []string{"hmac-sha1", "hmac-md5", "umac-64", "-96"},
		"weak message authentication",
		"SHA-1 and MD5 based MACs, and truncated 64/96-bit variants, no longer provide " +
			"the integrity guarantee they were chosen for. An attacker who can position " +
			"themselves in the path has a far better chance of tampering undetected."},
	{"kexalgorithms", []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-group1"},
		"weak key exchange",
		"Group1 is 1024-bit and SHA-1 based; both are below current guidance and within " +
			"reach of a well-resourced attacker recording traffic now to decrypt later."},
	{"ciphers", []string{"3des-cbc", "arcfour", "-cbc"},
		"weak ciphers",
		"CBC-mode and RC4 ciphers have practical attacks against them in the SSH context. " +
			"The counter and AEAD modes offered alongside them are strictly better."},
}

// sshAlgorithms inspects what sshd will actually negotiate, via `sshd -T`,
// which resolves Include directives and compiled-in defaults — the things that
// make reading sshd_config by hand quietly wrong.
func sshAlgorithms(ctx context.Context, r exec.Runner, a *finding.Asset, t time.Time) []finding.Finding {
	res := r.Run(ctx, "sshd", "-T")
	if !res.OK() {
		if res = r.Run(ctx, "/usr/sbin/sshd", "-T"); !res.OK() {
			return nil
		}
	}
	kv := kvFile(res.Stdout, " ")

	var out []finding.Finding
	for _, rule := range weakSSHAlgorithms {
		offered := strings.ToLower(kv[rule.directive])
		if offered == "" {
			continue
		}
		var weak []string
		for _, algo := range strings.Split(offered, ",") {
			algo = strings.TrimSpace(algo)
			for _, m := range rule.match {
				if strings.Contains(algo, m) {
					weak = append(weak, algo)
					break
				}
			}
		}
		if len(weak) == 0 {
			continue
		}
		f := finding.New(a.ID, finding.CatIdentity, finding.SevMedium,
			"identity.ssh-weak-"+rule.directive,
			fmt.Sprintf("SSH offers %s (%d algorithm(s))", rule.label, len(weak)), t)
		f.Description = rule.why + " They remain enabled for compatibility with old clients; " +
			"if you have none, removing them costs nothing."
		f.Subcategory = "sshd"
		f.Engine = "sshd"
		f.Evidence = []finding.Evidence{{
			Command: res.Command,
			Output:  rule.directive + " offers:\n  " + strings.Join(weak, "\n  "),
		}}
		f.Remediation = finding.Remediation{Op: "change_config",
			Summary: fmt.Sprintf("Restrict %s in sshd_config to the modern set, then reload sshd", rule.directive),
			Command: "sudo sshd -T | grep " + rule.directive + "   # review, then set an explicit allow-list"}
		out = append(out, f.WithLocation("sshd_config:"+rule.directive, finding.Component{}))
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
