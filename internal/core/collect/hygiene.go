package collect

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Hygiene covers the unglamorous host checks a real assessment always includes
// and automated scanners routinely skip: is logging actually retained, are the
// permissions on the things that matter correct, can a non-root user edit
// something root executes, and is there tooling installed that has no business
// on a server.
//
// Most of these are individually boring. Together they are how a foothold turns
// into root: a writable cron script, an .ssh directory anyone can read, a log
// that rotated away the evidence.
type Hygiene struct{}

func (Hygiene) ID() string                 { return "hygiene" }
func (Hygiene) Category() finding.Category { return finding.CatHardening }

func (h Hygiene) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	if a.OSFamily == "darwin" || a.OSFamily == "" {
		return nil, Skip(h.ID(), "Linux host-hygiene checks do not apply to this OS")
	}
	now := clock.Now()
	var out []finding.Finding
	checks := 0

	type sub struct {
		name string
		fn   func(context.Context, exec.Runner, *finding.Asset) []finding.Finding
	}
	for _, s := range []sub{
		{"logging", h.logging},
		{"logrotate", h.logRotation},
		{"sudoers", h.sudoersDepth},
		{"ssh-perms", h.sshPermissions},
		{"sensitive-perms", h.sensitivePermissions},
		{"cron", h.cron},
		{"suid", h.suidAndUnowned},
		{"mounts", h.mountOptions},
		{"packages", h.riskyPackages},
		{"boot-kernel", h.bootAndKernel},
		{"account-lockout", h.accountLockout},
		{"user-crontabs", h.userCrontabs},
		{"package-integrity", h.packageIntegrity},
	} {
		checks++
		out = append(out, s.fn(ctx, r, a)...)
	}
	_ = now
	return out, Ran(h.ID(), checks)
}

// mk is a small constructor so every sub-check produces consistent findings.
func mk(a *finding.Asset, sev finding.Severity, rule, title, desc, remedy, cmd string,
	ev []finding.Evidence, sub string) finding.Finding {
	f := finding.New(a.ID, finding.CatHardening, sev, rule, title, clock.Now())
	f.Description = desc
	f.Subcategory = sub
	f.Engine = "hygiene"
	f.Evidence = ev
	f.Remediation = finding.Remediation{Op: "change_config", Summary: remedy, Command: cmd}
	return f
}

// ------------------------------------------------------------------ logging

func (h Hygiene) logging(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var out []finding.Finding

	// A syslog daemon OR journald must be collecting. Both absent means the
	// host keeps no durable record of anything.
	syslogActive := r.Run(ctx, "systemctl", "is-active", "rsyslog").OK() ||
		r.Run(ctx, "systemctl", "is-active", "syslog-ng").OK()
	journalActive := r.Run(ctx, "systemctl", "is-active", "systemd-journald").OK()

	if !syslogActive && !journalActive {
		out = append(out, mk(a, finding.SevHigh, "hygiene.no-logging",
			"No system logging daemon is running",
			"Neither rsyslog/syslog-ng nor systemd-journald is active. The host is not "+
				"recording authentication, service or kernel events, so an intrusion would "+
				"leave no trace to find.",
			"Enable systemd-journald or install rsyslog",
			"sudo systemctl enable --now systemd-journald",
			[]finding.Evidence{{Command: "systemctl is-active rsyslog syslog-ng systemd-journald",
				Output: "no logging daemon active"}}, "logging"))
		return out
	}

	// journald defaults to volatile storage on some images: logs live in
	// /run and vanish at reboot — precisely when you want them.
	if journalActive && !syslogActive {
		persistent := r.Run(ctx, "test", "-d", "/var/log/journal").OK()
		if !persistent {
			out = append(out, mk(a, finding.SevMedium, "hygiene.journal-volatile",
				"systemd-journald is not storing logs persistently",
				"/var/log/journal does not exist, so journald is keeping logs in /run and "+
					"they are lost on every reboot. Post-incident, the reboot is often the "+
					"first thing that happens.",
				"Enable persistent journal storage",
				"sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl restart systemd-journald",
				[]finding.Evidence{{Command: "test -d /var/log/journal", Output: "absent — journal is volatile"}},
				"logging"))
		}
	}

	// /var/log readable by everyone leaks a great deal: usernames, source IPs,
	// service internals, sometimes tokens in URLs.
	if res := r.Run(ctx, "stat", "-c", "%a %U %G", "/var/log"); res.OK() {
		mode := strings.Fields(strings.TrimSpace(res.Stdout))
		if len(mode) > 0 && worldReadable(mode[0]) {
			out = append(out, mk(a, finding.SevLow, "hygiene.log-dir-world-readable",
				"/var/log is world-readable",
				"Any local user can read system logs, which routinely contain usernames, "+
					"source addresses, service internals and occasionally credentials in URLs.",
				"Remove world-read from /var/log",
				"sudo chmod o-r /var/log",
				[]finding.Evidence{{Command: res.Command, Output: strings.TrimSpace(res.Stdout)}},
				"logging"))
		}
	}
	return out
}

func (h Hygiene) logRotation(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	// journald self-manages, so rotation only matters where files are written.
	hasLogrotate := r.Has(ctx, "logrotate")
	if !hasLogrotate {
		if r.Run(ctx, "test", "-d", "/var/log/journal").OK() {
			return nil // journald handles its own retention
		}
		return []finding.Finding{mk(a, finding.SevMedium, "hygiene.no-logrotate",
			"No log rotation is configured",
			"logrotate is not installed and journald is not managing retention. Log files "+
				"grow until the filesystem fills, which takes services down and, in the "+
				"meantime, makes the logs unusable.",
			"Install and configure logrotate",
			"sudo apt-get install -y logrotate",
			[]finding.Evidence{{Command: "command -v logrotate", Output: "not installed"}},
			"logging")}
	}

	// Installed is not the same as running. The status file records the last
	// rotation of each set; a stale one means the timer is not firing.
	// The status file is mode 0640 root:root, so reading it needs privilege we
	// may not have. `test -s` answers "exists and is non-empty" without it —
	// reporting "never ran" because we could not read the file would be exactly
	// the confidently-wrong output this product exists to avoid.
	for _, p := range []string{
		"/var/lib/logrotate/status",
		"/var/lib/logrotate/logrotate.status",
		"/var/lib/logrotate.status",
	} {
		if r.Run(ctx, "test", "-s", p).OK() {
			return nil
		}
	}
	return []finding.Finding{mk(a, finding.SevLow, "hygiene.logrotate-never-ran",
		"logrotate is installed but has never run",
		"No logrotate status file exists, so rotation has not executed. The timer or cron "+
			"entry is probably disabled — rotation configured but not running is the same "+
			"as no rotation.",
		"Check the logrotate timer",
		"sudo systemctl status logrotate.timer && sudo logrotate -d /etc/logrotate.conf",
		[]finding.Evidence{{Path: "/var/lib/logrotate/status", Output: "absent or empty"}},
		"logging")}
}

// ------------------------------------------------------------------ sudoers

func (h Hygiene) sudoersDepth(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var out []finding.Finding

	files := []string{"/etc/sudoers"}
	if res := r.Run(ctx, "ls", "/etc/sudoers.d"); res.OK() {
		for _, n := range lines(res.Stdout) {
			files = append(files, "/etc/sudoers.d/"+n)
		}
	}

	var blanket, dangerous []string
	for _, p := range files {
		body, ok := r.ReadFile(ctx, p)
		if !ok {
			continue
		}
		for _, l := range lines(body) {
			if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "Defaults") {
				continue
			}
			// `user ALL=(ALL) ALL` and `%group ALL=(ALL:ALL) ALL` are full root
			// for whoever holds them. root holding root is not a finding, and
			// a group grant is only meaningful once resolved to real accounts —
			// "%sudo can do anything" is noise; "these two people can" is not.
			if strings.Contains(l, "ALL=(ALL") && strings.HasSuffix(strings.TrimSpace(l), "ALL") {
				principal := strings.Fields(l)[0]
				if principal == "root" {
					continue
				}
				if holders := resolvePrincipal(ctx, r, principal); len(holders) > 0 {
					blanket = append(blanket, fmt.Sprintf("%s → %s  (%s)",
						principal, strings.Join(holders, ", "), p))
				}
			}
			// !authenticate removes the password prompt for a rule set; the
			// combination of that with a broad grant is a silent root path.
			if strings.Contains(l, "!authenticate") {
				dangerous = append(dangerous, p+": "+l)
			}
		}

		// A writable sudoers file is game over: anyone who can edit it grants
		// themselves root.
		if res := r.Run(ctx, "stat", "-c", "%a %U", p); res.OK() {
			f := strings.Fields(strings.TrimSpace(res.Stdout))
			if len(f) == 2 && (groupOrWorldWritable(f[0]) || f[1] != "root") {
				out = append(out, mk(a, finding.SevCritical, "hygiene.sudoers-writable",
					"Sudoers file "+p+" has unsafe ownership or permissions",
					"A sudoers file that is not root-owned and 0440 can be edited by someone "+
						"other than root, who can then grant themselves root. This is a direct "+
						"privilege-escalation path.",
					"Restore correct ownership and mode",
					fmt.Sprintf("sudo chown root:root %s && sudo chmod 0440 %s", p, p),
					[]finding.Evidence{{Command: res.Command, Output: strings.TrimSpace(res.Stdout) + " (want 440 root)"}},
					"sudo"))
			}
		}
	}

	if n := len(blanket); n > 0 {
		out = append(out, mk(a, finding.SevMedium, "hygiene.sudo-blanket-grant",
			fmt.Sprintf("%d account(s) hold unrestricted root via sudo", countHolders(blanket)),
			"These accounts can run any command as root. That is often intended — but "+
				"each is a full-privilege identity that should be inventoried and justified, "+
				"because over-provisioned sudo is how one compromised user becomes a "+
				"compromised host. Treat this as the roster to review, not as an alarm.",
			"Confirm every listed account still needs unrestricted root; scope the rest",
			"", []finding.Evidence{{Path: "/etc/sudoers.d", Output: strings.Join(blanket, "\n")}},
			"sudo"))
	}
	if n := len(dangerous); n > 0 {
		out = append(out, mk(a, finding.SevHigh, "hygiene.sudo-noauthenticate",
			fmt.Sprintf("%d sudoers rule(s) use !authenticate", n),
			"!authenticate disables the password prompt entirely for the matching rules, "+
				"so a hijacked shell escalates with no further check.",
			"Remove !authenticate, or narrow it to specific harmless commands",
			"", []finding.Evidence{{Path: "/etc/sudoers.d", Output: strings.Join(dangerous, "\n")}},
			"sudo"))
	}
	return out
}

// ------------------------------------------------------------- ssh key perms

func (h Hygiene) sshPermissions(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	// Loose .ssh permissions are both a disclosure risk (readable private keys,
	// editable authorized_keys = persistent backdoor) and a functional one:
	// sshd refuses keys from group/world-writable files.
	res := r.Run(ctx, "find", "/root", "/home", "-maxdepth", "3",
		"-name", ".ssh", "-o", "-name", "authorized_keys", "-o", "-name", "id_*")
	if !res.OK() {
		return nil
	}
	var bad []string
	for _, path := range lines(res.Stdout) {
		if strings.HasSuffix(path, ".pub") {
			continue // public keys are public
		}
		st := r.Run(ctx, "stat", "-c", "%a %U %n", path)
		if !st.OK() {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(st.Stdout))
		if len(fields) < 3 {
			continue
		}
		mode := fields[0]
		isDir := strings.HasSuffix(path, ".ssh")
		switch {
		case isDir && mode != "700":
			bad = append(bad, fmt.Sprintf("%s  mode %s (want 700)", path, mode))
		case !isDir && groupOrWorldReadable(mode):
			bad = append(bad, fmt.Sprintf("%s  mode %s (want 600)", path, mode))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return []finding.Finding{mk(a, finding.SevHigh, "hygiene.ssh-permissions",
		fmt.Sprintf("%d SSH key file(s) or directories have unsafe permissions", len(bad)),
		"Private keys readable beyond their owner can be stolen by any local user; a "+
			"writable authorized_keys lets one append their own key and hold persistent "+
			"access that survives password changes. sshd also refuses to use keys from "+
			"group- or world-writable locations, so this often breaks access too.",
		"Restore strict permissions",
		"sudo chmod 700 ~/.ssh && sudo chmod 600 ~/.ssh/authorized_keys ~/.ssh/id_*",
		[]finding.Evidence{{Command: "stat on ~/.ssh contents", Output: strings.Join(bad, "\n")}},
		"permissions")}
}

func (h Hygiene) sensitivePermissions(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	// Files whose correct mode is well known and whose exposure is serious.
	want := []struct {
		path    string
		maxMode int
		why     string
	}{
		{"/etc/shadow", 0o640, "password hashes become crackable offline by any local user"},
		{"/etc/gshadow", 0o640, "group password hashes are exposed"},
		{"/etc/passwd", 0o644, "a writable passwd file allows adding a UID-0 account"},
		{"/etc/group", 0o644, "a writable group file allows granting oneself sudo"},
		{"/etc/crontab", 0o644, "a writable crontab runs arbitrary commands as root"},
		{"/root", 0o750, "root's home is readable by other users"},
	}
	var bad []string
	for _, w := range want {
		st := r.Run(ctx, "stat", "-c", "%a %n", w.path)
		if !st.OK() {
			continue
		}
		f := strings.Fields(strings.TrimSpace(st.Stdout))
		if len(f) < 2 {
			continue
		}
		mode, err := strconv.ParseInt(f[0], 8, 32)
		if err != nil {
			continue
		}
		if int(mode)&^w.maxMode != 0 {
			bad = append(bad, fmt.Sprintf("%s mode %s (want %o or stricter) — %s", w.path, f[0], w.maxMode, w.why))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return []finding.Finding{mk(a, finding.SevHigh, "hygiene.sensitive-file-permissions",
		fmt.Sprintf("%d sensitive system file(s) are more permissive than they should be", len(bad)),
		"These files have well-known correct modes. Anything looser is either a "+
			"misconfiguration or the residue of an intrusion.",
		"Restore the standard modes",
		"sudo chmod 640 /etc/shadow /etc/gshadow; sudo chmod 644 /etc/passwd /etc/group; sudo chmod 750 /root",
		[]finding.Evidence{{Command: "stat -c '%a %n'", Output: strings.Join(bad, "\n")}},
		"permissions")}
}

// --------------------------------------------------------------------- cron

func (h Hygiene) cron(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var out []finding.Finding
	dirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
		"/etc/cron.weekly", "/etc/cron.monthly"}

	// A cron script writable by a non-root user is a scheduled root shell for
	// whoever can edit it — one of the most reliable escalation paths there is.
	args := append([]string{"find"}, dirs...)
	args = append(args, "/etc/crontab", "-maxdepth", "1", "-type", "f",
		"-perm", "/go+w", "-print")
	if res := r.Run(ctx, args...); res.OK() {
		if w := lines(res.Stdout); len(w) > 0 {
			out = append(out, mk(a, finding.SevCritical, "hygiene.cron-writable",
				fmt.Sprintf("%d cron job file(s) are writable by non-root users", len(w)),
				"Cron runs these as root on a schedule. Anyone who can edit one has a "+
					"guaranteed root shell at the next tick — no exploit required.",
				"Remove group/other write permission",
				"sudo chmod go-w <path>",
				[]finding.Evidence{{Command: res.Command, Output: strings.Join(w, "\n")}},
				"cron"))
		}
	}

	// Pipe-to-shell in a scheduled job means the host executes whatever a
	// remote server serves, every time it runs.
	grepArgs := append([]string{"grep", "-rlE", `(curl|wget)[^|]*\|[[:space:]]*(ba)?sh`}, dirs...)
	grepArgs = append(grepArgs, "/etc/crontab")
	if res := r.Run(ctx, grepArgs...); res.OK() {
		if hits := lines(res.Stdout); len(hits) > 0 {
			out = append(out, mk(a, finding.SevHigh, "hygiene.cron-pipe-to-shell",
				fmt.Sprintf("%d cron job(s) pipe a download straight into a shell", len(hits)),
				"The host executes, as root, whatever the remote server returns at that "+
					"moment. A compromise of that server — or of DNS, or of the transport — "+
					"is a compromise of this host, on a schedule.",
				"Pin and verify what is downloaded, or install it as a package",
				"", []finding.Evidence{{Command: res.Command, Output: strings.Join(hits, "\n")}},
				"cron"))
		}
	}

	// cron.allow/deny absent means every user may schedule jobs.
	denyExists := r.Run(ctx, "test", "-f", "/etc/cron.allow").OK() ||
		r.Run(ctx, "test", "-f", "/etc/cron.deny").OK()
	if !denyExists {
		out = append(out, mk(a, finding.SevLow, "hygiene.cron-unrestricted",
			"Any user can schedule cron jobs",
			"Neither /etc/cron.allow nor /etc/cron.deny exists, so every account can "+
				"schedule work. Useful for persistence after a compromise of any user.",
			"Restrict cron to the accounts that need it",
			"echo root | sudo tee /etc/cron.allow && sudo chmod 600 /etc/cron.allow",
			[]finding.Evidence{{Output: "neither /etc/cron.allow nor /etc/cron.deny present"}},
			"cron"))
	}
	return out
}

// ------------------------------------------------------------ suid / unowned

func (h Hygiene) suidAndUnowned(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var out []finding.Finding

	// Only unexpected SUID binaries are interesting; the standard set is long
	// and reporting it would train people to ignore this check.
	res := r.Run(ctx, "find", "/", "-xdev", "-type", "f", "-perm", "-4000", "-print")
	if res.OK() {
		var unusual []string
		for _, p := range lines(res.Stdout) {
			if !expectedSUID(p) {
				unusual = append(unusual, p)
			}
		}
		if len(unusual) > 0 {
			out = append(out, mk(a, finding.SevMedium, "hygiene.unexpected-suid",
				fmt.Sprintf("%d unexpected SUID binary/binaries", len(unusual)),
				"These run with the owner's privileges regardless of who invokes them. "+
					"Anything outside the distribution's standard set is either a deliberate "+
					"grant that should be documented, or a backdoor.",
				"Confirm each is intended; remove the SUID bit where it is not",
				"sudo chmod u-s <path>",
				[]finding.Evidence{{Command: res.Command, Output: strings.Join(unusual, "\n")}},
				"permissions"))
		}
	}

	// Files owned by a deleted user get silently inherited by the next account
	// created with that UID.
	if res := r.Run(ctx, "find", "/", "-xdev", "-nouser", "-o", "-xdev", "-nogroup"); res.OK() {
		if u := lines(res.Stdout); len(u) > 0 {
			shown := u
			if len(shown) > 20 {
				shown = shown[:20]
			}
			out = append(out, mk(a, finding.SevLow, "hygiene.unowned-files",
				fmt.Sprintf("%d file(s) have no valid owner or group", len(u)),
				"These belong to a UID/GID with no account. The next user created with that "+
					"numeric ID silently inherits ownership of all of them.",
				"Reassign or remove the orphaned files",
				"sudo find / -xdev \\( -nouser -o -nogroup \\) -exec ls -l {} +",
				[]finding.Evidence{{Command: res.Command, Output: strings.Join(shown, "\n")}},
				"permissions"))
		}
	}
	return out
}

func (h Hygiene) mountOptions(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	res := r.Run(ctx, "findmnt", "-rno", "TARGET,OPTIONS")
	if !res.OK() {
		return nil
	}
	// Writable, world-accessible directories should not be able to host
	// executables or device nodes — that is where dropped payloads land.
	want := map[string][]string{
		"/tmp":     {"nodev", "nosuid", "noexec"},
		"/var/tmp": {"nodev", "nosuid", "noexec"},
		"/dev/shm": {"nodev", "nosuid", "noexec"},
	}
	var missing []string
	for _, l := range lines(res.Stdout) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		opts, ok := want[f[0]]
		if !ok {
			continue
		}
		for _, o := range opts {
			if !strings.Contains(f[1], o) {
				missing = append(missing, fmt.Sprintf("%s is missing %s", f[0], o))
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []finding.Finding{mk(a, finding.SevLow, "hygiene.mount-options",
		fmt.Sprintf("%d hardening mount option(s) missing on temporary filesystems", len(missing)),
		"/tmp, /var/tmp and /dev/shm are world-writable and are where dropped payloads "+
			"land. nodev/nosuid/noexec stop them being used to execute code or create "+
			"device nodes.",
		"Add nodev,nosuid,noexec to those filesystems in /etc/fstab",
		"", []finding.Evidence{{Command: res.Command, Output: strings.Join(missing, "\n")}},
		"filesystem")}
}

func (h Hygiene) riskyPackages(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	// Cleartext-protocol servers and offensive tooling. Presence is not proof
	// of compromise, but each expands the attack surface or is an attacker's
	// convenience once they are on the host.
	risky := map[string]string{
		"telnetd": "cleartext remote shell — credentials cross the network in plain text",
		"rshd":    "cleartext remote shell with trust-based authentication",
		"rlogind": "cleartext remote login",
		"vsftpd":  "FTP transmits credentials in cleartext unless explicitly TLS-wrapped",
		"proftpd": "FTP transmits credentials in cleartext unless explicitly TLS-wrapped",
		"tftpd":   "TFTP has no authentication at all",
		"nc":      "netcat — a ready-made reverse shell and data-exfiltration tool",
		"ncat":    "netcat — a ready-made reverse shell and data-exfiltration tool",
		"nmap":    "network scanner — useful to an attacker for lateral movement",
		"tcpdump": "packet capture — can harvest credentials from the wire",
		"john":    "password cracker",
		"hydra":   "online password-guessing tool",
		"socat":   "flexible relay — commonly used for tunnelling and reverse shells",
	}
	var found []string
	for bin, why := range risky {
		if r.Has(ctx, bin) {
			found = append(found, fmt.Sprintf("%s — %s", bin, why))
		}
	}
	if len(found) == 0 {
		return nil
	}
	sev := finding.SevLow
	for _, f := range found {
		if strings.HasPrefix(f, "telnetd") || strings.HasPrefix(f, "rshd") || strings.HasPrefix(f, "rlogind") {
			sev = finding.SevHigh // a listening cleartext service is a different matter
		}
	}
	return []finding.Finding{mk(a, sev, "hygiene.risky-tools",
		fmt.Sprintf("%d risky tool(s) or cleartext service(s) installed", len(found)),
		"Each of these either exposes credentials on the wire or hands an attacker who "+
			"gains a foothold a capability they would otherwise have to bring with them. "+
			"Legitimate uses exist — the point is that each should be a deliberate choice.",
		"Remove what is not needed on a server",
		"", []finding.Evidence{{Command: "command -v <tool>", Output: strings.Join(found, "\n")}},
		"packages")}
}

// resolvePrincipal turns a sudoers principal into the accounts that actually
// hold it. `%sudo` means nothing without its membership.
func resolvePrincipal(ctx context.Context, r exec.Runner, principal string) []string {
	if !strings.HasPrefix(principal, "%") {
		return []string{principal}
	}
	group := strings.TrimPrefix(principal, "%")
	res := r.Run(ctx, "getent", "group", group)
	if !res.OK() {
		return nil
	}
	f := strings.Split(strings.TrimSpace(res.Stdout), ":")
	if len(f) < 4 {
		return nil
	}
	var members []string
	for _, m := range strings.Split(f[3], ",") {
		if m = strings.TrimSpace(m); m != "" && m != "root" {
			members = append(members, m)
		}
	}
	return members
}

// countHolders counts distinct accounts across the resolved grant lines.
func countHolders(grants []string) int {
	seen := map[string]bool{}
	for _, g := range grants {
		_, rest, ok := strings.Cut(g, "→ ")
		if !ok {
			continue
		}
		names, _, _ := strings.Cut(rest, "  (")
		for _, n := range strings.Split(names, ",") {
			if n = strings.TrimSpace(n); n != "" {
				seen[n] = true
			}
		}
	}
	return len(seen)
}

// ---------------------------------------------------------------- helpers

// expectedSUID is the standard distribution set. Keeping it explicit means a
// new SUID binary shows up rather than blending into a wall of normal ones.
var expectedSUIDNames = map[string]bool{
	"su": true, "sudo": true, "mount": true, "umount": true, "passwd": true,
	"chsh": true, "chfn": true, "newgrp": true, "gpasswd": true, "ping": true,
	"ping6": true, "fusermount": true, "fusermount3": true, "pkexec": true,
	"unix_chkpwd": true, "ssh-keysign": true, "dbus-daemon-launch-helper": true,
	"polkit-agent-helper-1": true, "chage": true, "expiry": true, "at": true,
	"crontab": true, "sg": true, "mount.nfs": true, "snap-confine": true,
	"suexec": true, "utempter": true, "write": true, "wall": true,
}

func expectedSUID(path string) bool {
	i := strings.LastIndex(path, "/")
	name := path
	if i >= 0 {
		name = path[i+1:]
	}
	return expectedSUIDNames[name]
}

func worldReadable(mode string) bool {
	n, err := strconv.ParseInt(mode, 8, 32)
	return err == nil && n&0o004 != 0
}

func groupOrWorldReadable(mode string) bool {
	n, err := strconv.ParseInt(mode, 8, 32)
	return err == nil && n&0o044 != 0
}

func groupOrWorldWritable(mode string) bool {
	n, err := strconv.ParseInt(mode, 8, 32)
	return err == nil && n&0o022 != 0
}

// ---------------------------------------------------- remaining CIS-adjacent

// bootAndKernel covers the boot chain and kernel-surface controls that a full
// assessment includes: an unprotected bootloader is physical-access root, and
// loadable filesystem/protocol modules are attack surface nobody uses.
func (h Hygiene) bootAndKernel(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var out []finding.Finding

	// A GRUB password stops someone with console access editing the kernel
	// command line to boot single-user and walk in as root. It matters on
	// physical and console-accessible hosts; on a cloud VM the serial console
	// is the equivalent door.
	hasGrubPw := false
	for _, p := range []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/etc/grub.d/40_custom"} {
		if body, ok := r.ReadFile(ctx, p); ok && strings.Contains(body, "password_pbkdf2") {
			hasGrubPw = true
			break
		}
	}
	if !hasGrubPw && r.Run(ctx, "test", "-d", "/boot/grub").OK() {
		out = append(out, mk(a, finding.SevLow, "hygiene.no-grub-password",
			"GRUB is not password-protected",
			"Anyone with console or serial access can edit the kernel command line at boot, "+
				"append init=/bin/sh, and get a root shell without any credential. On a cloud "+
				"VM the provider's serial console is the same door.",
			"Set a GRUB superuser password",
			"sudo grub-mkpasswd-pbkdf2  # then add set superusers / password_pbkdf2 to /etc/grub.d/40_custom",
			[]finding.Evidence{{Path: "/boot/grub/grub.cfg", Output: "no password_pbkdf2 directive found"}},
			"boot"))
	}

	// Filesystem and network modules that essentially no server needs, and
	// which have a long history of kernel CVEs.
	risky := []string{"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf", "usb-storage", "dccp", "sctp", "rds", "tipc"}
	var loadable []string
	for _, m := range risky {
		res := r.Run(ctx, "modprobe", "-n", "-v", m)
		// "install /bin/true" or "blacklist" means it is disabled.
		if res.OK() && !strings.Contains(res.Stdout, "/bin/true") && !strings.Contains(res.Stdout, "/bin/false") {
			loadable = append(loadable, m)
		}
	}
	if len(loadable) > 3 { // a couple is normal; the whole list is not
		out = append(out, mk(a, finding.SevLow, "hygiene.loadable-risky-modules",
			fmt.Sprintf("%d rarely-needed kernel modules can still be loaded", len(loadable)),
			"These filesystem and protocol modules have a history of kernel vulnerabilities "+
				"and are not used by a typical server. Every loadable one is attack surface "+
				"reachable by anything that can trigger an auto-load — including usb-storage, "+
				"which is how a physical attacker mounts removable media.",
			"Blacklist the modules that are not needed",
			"printf 'install %s /bin/true\\n' "+strings.Join(loadable, " ")+" | sudo tee /etc/modprobe.d/secscan-blacklist.conf",
			[]finding.Evidence{{Command: "modprobe -n -v <module>", Output: "loadable: " + strings.Join(loadable, ", ")}},
			"kernel"))
	}
	return out
}

// accountLockout checks whether repeated failed logins lock an account. Its
// absence is a finding; its presence is also a compensating control, and the
// controls collector picks it up separately.
func (h Hygiene) accountLockout(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	for _, p := range []string{
		"/etc/security/faillock.conf",
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	} {
		if body, ok := r.ReadFile(ctx, p); ok {
			if strings.Contains(body, "pam_faillock") || strings.Contains(body, "pam_tally2") {
				return nil
			}
		}
	}
	return []finding.Finding{mk(a, finding.SevMedium, "hygiene.no-account-lockout",
		"No account lockout after repeated failed logins",
		"Neither pam_faillock nor pam_tally2 is configured, so an attacker can guess "+
			"passwords indefinitely against any local authentication path — console, su, "+
			"sudo, and any PAM-using service. fail2ban protects the network path; this "+
			"protects the rest.",
		"Enable pam_faillock",
		"sudo pam-auth-update --enable faillock faillock_notify",
		[]finding.Evidence{{Path: "/etc/pam.d/common-auth", Output: "no pam_faillock or pam_tally2 module configured"}},
		"identity")}
}

// userCrontabs inspects per-user scheduled jobs, which live outside
// /etc/cron.* and are a favourite persistence location precisely because
// most audits only look at the system directories.
func (h Hygiene) userCrontabs(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	res := r.Run(ctx, "ls", "-1", "/var/spool/cron/crontabs")
	if !res.OK() {
		if res = r.Run(ctx, "ls", "-1", "/var/spool/cron"); !res.OK() {
			return nil
		}
	}
	users := lines(res.Stdout)
	if len(users) == 0 {
		return nil
	}
	return []finding.Finding{mk(a, finding.SevInfo, "hygiene.user-crontabs",
		fmt.Sprintf("%d per-user crontab(s) present", len(users)),
		"Per-user crontabs live outside /etc/cron.* and are a common persistence "+
			"mechanism for exactly that reason — most audits only inspect the system "+
			"directories. Each should correspond to something you know about.",
		"Review each user's scheduled jobs",
		"for u in "+strings.Join(users, " ")+"; do echo \"== $u\"; sudo crontab -l -u \"$u\"; done",
		[]finding.Evidence{{Command: res.Command, Output: "users with crontabs: " + strings.Join(users, ", ")}},
		"cron")}
}

// packageIntegrity detects files that differ from what the package manager
// installed — a strong signal of tampering or of an unmanaged change.
func (h Hygiene) packageIntegrity(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var res exec.Result
	switch a.OSFamily {
	case "debian":
		if !r.Has(ctx, "debsums") {
			return nil // not installed; absence of the tool is not a finding
		}
		res = r.Run(ctx, "debsums", "-ec")
	case "rhel":
		res = r.Run(ctx, "rpm", "-Va", "--nomtime", "--nomode", "--nouser", "--nogroup")
	default:
		return nil
	}
	changed := lines(res.Stdout)
	if len(changed) == 0 {
		return nil
	}
	if len(changed) > 20 {
		changed = changed[:20]
	}
	return []finding.Finding{mk(a, finding.SevMedium, "hygiene.package-integrity",
		fmt.Sprintf("%d packaged file(s) differ from what the package installed", len(changed)),
		"These files no longer match their package's checksums. Usually that is a local "+
			"edit nobody recorded; occasionally it is a replaced binary. Either way the host "+
			"is no longer what the package manager believes it is, and reinstalling the "+
			"package will silently revert the change.",
		"Review each difference and either package the change or restore the original",
		"", []finding.Evidence{{Command: res.Command, Output: strings.Join(changed, "\n")}},
		"integrity")}
}
