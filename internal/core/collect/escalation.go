package collect

import (
	"context"
	"fmt"
	"strings"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Escalation looks for local privilege-escalation primitives — the specific
// things an attacker with any shell on this host enumerates first.
//
// These differ from general hygiene in an important way: each one is not a
// weakness in the abstract, it is a *working path to root* if present. That is
// why they are scored higher than tidiness issues, and why the evidence names
// the exact file rather than a count.
//
// The check list follows what the standard offensive tooling actually looks
// for (LinPEAS, GTFOBins-driven enumeration) plus the CIS controls that map to
// escalation rather than to compliance paperwork.
type Escalation struct{}

func (Escalation) ID() string                 { return "escalation" }
func (Escalation) Category() finding.Category { return finding.CatIdentity }

func (e Escalation) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	if a.OSFamily == "darwin" || a.OSFamily == "" {
		return nil, Skip(e.ID(), "Linux escalation-path checks do not apply to this OS")
	}
	var out []finding.Finding
	checks := 0

	for _, fn := range []func(context.Context, exec.Runner, *finding.Asset) []finding.Finding{
		e.capabilities, e.writableUnits, e.rootPath, e.dockerGroup, e.nfsExports, e.coreDumps,
	} {
		checks++
		out = append(out, fn(ctx, r, a)...)
	}
	return out, Ran(e.ID(), checks)
}

func esc(a *finding.Asset, sev finding.Severity, rule, title, desc, remedy, cmd string,
	ev []finding.Evidence, sub string) finding.Finding {
	f := mk(a, sev, rule, title, desc, remedy, cmd, ev, sub)
	f.Category = finding.CatIdentity
	f.Engine = "escalation"
	return f
}

// ------------------------------------------------------------ capabilities

// dangerousCaps grant, directly or with a short hop, full root.
var dangerousCaps = map[string]string{
	"cap_setuid":          "lets the binary become any user, including root, directly",
	"cap_setgid":          "lets the binary become any group",
	"cap_dac_read_search": "bypasses all file-read permission checks — /etc/shadow becomes readable",
	"cap_dac_override":    "bypasses all file permission checks — any file becomes writable",
	"cap_sys_admin":       "near-equivalent to root; permits mount, and much else",
	"cap_sys_ptrace":      "permits attaching to and injecting into other processes, including root's",
	"cap_sys_module":      "permits loading kernel modules — total control of the kernel",
	"cap_chown":           "permits changing ownership of any file",
	"cap_fowner":          "bypasses ownership checks on chmod and similar",
}

// capabilities finds file capabilities, which are SUID's quieter cousin: they
// grant privilege without the SUID bit, so a SUID-only audit misses them
// entirely.
func (Escalation) capabilities(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	if !r.Has(ctx, "getcap") {
		return nil
	}
	res := r.Run(ctx, "getcap", "-r", "/usr", "/bin", "/sbin", "/opt", "/usr/local")
	if !res.OK() {
		return nil
	}
	var risky []string
	for _, l := range lines(res.Stdout) {
		low := strings.ToLower(l)
		for cap, why := range dangerousCaps {
			if strings.Contains(low, cap) {
				// ping legitimately carries cap_net_raw; that is not in our list.
				risky = append(risky, fmt.Sprintf("%s\n      → %s: %s", l, cap, why))
				break
			}
		}
	}
	if len(risky) == 0 {
		return nil
	}
	return []finding.Finding{esc(a, finding.SevHigh, "escalation.capabilities",
		fmt.Sprintf("%d binary/binaries carry privilege-granting capabilities", len(risky)),
		"File capabilities grant specific root powers without the SUID bit, so an audit "+
			"that only looks for SUID misses them. Any local user who can execute these "+
			"binaries may be able to use the capability to reach root — this is a standard "+
			"first-look item for anyone who lands a shell here.",
		"Confirm each capability is required; remove it otherwise",
		"sudo setcap -r <path>",
		[]finding.Evidence{{Command: res.Command, Output: strings.Join(risky, "\n")}},
		"escalation")}
}

// ---------------------------------------------------------- systemd units

// writableUnits finds service definitions a non-root user can edit. systemd
// runs most units as root, so a writable unit file — or a writable ExecStart
// target — is a root shell at the next start or reboot.
func (Escalation) writableUnits(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	res := r.Run(ctx, "find", "/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
		"-maxdepth", "2", "-type", "f", "-perm", "/go+w", "-print")
	if !res.OK() {
		return nil
	}
	units := lines(res.Stdout)
	if len(units) == 0 {
		return nil
	}
	return []finding.Finding{esc(a, finding.SevCritical, "escalation.writable-systemd-unit",
		fmt.Sprintf("%d systemd unit file(s) are writable by non-root users", len(units)),
		"systemd starts these as root. Anyone who can edit one can set ExecStart to a "+
			"command of their choosing and obtain root at the next start, reboot or timer "+
			"fire — no exploit needed, and it survives reboots.",
		"Remove group/other write permission from the unit files",
		"sudo chmod go-w <path> && sudo systemctl daemon-reload",
		[]finding.Evidence{{Command: res.Command, Output: strings.Join(units, "\n")}},
		"escalation")}
}

// -------------------------------------------------------------- root PATH

// rootPath finds writable directories that root's PATH searches. A root-run
// script calling `service` or `tar` without an absolute path will execute an
// attacker's binary if it lands earlier in PATH.
func (Escalation) rootPath(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	res := r.Run(ctx, "sh", "-c", `echo "$PATH"`)
	if !res.OK() {
		return nil
	}
	var writable []string
	for _, dir := range strings.Split(strings.TrimSpace(res.Stdout), ":") {
		if dir == "" || dir == "." {
			if dir == "." {
				writable = append(writable, ". (current directory in PATH — any directory "+
					"the process happens to be in becomes a search location)")
			}
			continue
		}
		// -L dereferences. Without it, usrmerge symlinks (/bin -> usr/bin)
		// report the link's own 0777 and every modern Ubuntu host looks
		// catastrophically misconfigured. The target's mode is the real one.
		st := r.Run(ctx, "stat", "-Lc", "%a %U %n", dir)
		if !st.OK() {
			continue
		}
		f := strings.Fields(strings.TrimSpace(st.Stdout))
		if len(f) < 3 {
			continue
		}
		if groupOrWorldWritable(f[0]) {
			writable = append(writable, fmt.Sprintf("%s mode %s owner %s", dir, f[0], f[1]))
		}
	}
	if len(writable) == 0 {
		return nil
	}
	return []finding.Finding{esc(a, finding.SevHigh, "escalation.writable-path-dir",
		fmt.Sprintf("%d writable director(ies) in PATH", len(writable)),
		"Scripts frequently invoke helpers by bare name rather than absolute path. A "+
			"writable directory earlier in PATH lets a local user plant a binary that a "+
			"root-run script then executes as root.",
		"Remove write access, or drop the directory from PATH",
		"sudo chmod go-w <dir>",
		[]finding.Evidence{{Command: res.Command, Output: strings.Join(writable, "\n")}},
		"escalation")}
}

// ------------------------------------------------------------ docker group

// dockerGroup reports members of the docker group. This is widely
// misunderstood as a convenience rather than what it is.
func (Escalation) dockerGroup(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	group, ok := r.ReadFile(ctx, "/etc/group")
	if !ok {
		return nil
	}
	var members []string
	for _, l := range lines(group) {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		if f[0] != "docker" && f[0] != "lxd" {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" && m != "root" {
				members = append(members, m+" (in group "+f[0]+")")
			}
		}
	}
	if len(members) == 0 {
		return nil
	}
	return []finding.Finding{esc(a, finding.SevHigh, "escalation.docker-group",
		fmt.Sprintf("%d non-root account(s) in the docker/lxd group", len(members)),
		"Membership of the docker group is equivalent to root. Any member can start a "+
			"container that mounts the host filesystem and read or write anything, without "+
			"sudo and without appearing in the sudo logs. It is frequently granted as a "+
			"convenience by people who do not realise it is a full privilege grant.",
		"Remove members who do not need root, or move them to a rootless/socket-proxy setup",
		"sudo gpasswd -d <user> docker",
		[]finding.Evidence{{Path: "/etc/group", Output: strings.Join(members, "\n")}},
		"escalation")}
}

// ------------------------------------------------------------ NFS exports

// nfsExports finds shares that let a remote root stay root.
func (Escalation) nfsExports(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	body, ok := r.ReadFile(ctx, "/etc/exports")
	if !ok {
		return nil
	}
	var bad []string
	for _, l := range lines(body) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "no_root_squash") {
			bad = append(bad, l)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return []finding.Finding{esc(a, finding.SevCritical, "escalation.nfs-no-root-squash",
		fmt.Sprintf("%d NFS export(s) use no_root_squash", len(bad)),
		"With no_root_squash, root on a client machine is root on this export. Anyone "+
			"who can mount it can write a SUID binary into the share and execute it here "+
			"to become root locally.",
		"Replace no_root_squash with root_squash and re-export",
		"sudo exportfs -ra",
		[]finding.Evidence{{Path: "/etc/exports", Output: strings.Join(bad, "\n")}},
		"escalation")}
}

// -------------------------------------------------------------- core dumps

// coreDumps checks whether crashed processes write memory to disk. Cores from
// a privileged daemon can contain keys, tokens and password material.
func (Escalation) coreDumps(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	res := r.Run(ctx, "sysctl", "-n", "fs.suid_dumpable")
	if !res.OK() {
		return nil
	}
	if strings.TrimSpace(res.Stdout) == "0" {
		return nil
	}
	return []finding.Finding{esc(a, finding.SevMedium, "escalation.suid-dumpable",
		"SUID programs are allowed to dump core",
		"fs.suid_dumpable is not 0, so a crashing privileged process can write its memory "+
			"to disk. Those cores routinely contain private keys, session tokens and "+
			"password material, readable by whoever can reach the dump location.",
		"Disable core dumps for SUID programs",
		"echo 'fs.suid_dumpable = 0' | sudo tee /etc/sysctl.d/91-secscan.conf && sudo sysctl --system",
		[]finding.Evidence{{Command: res.Command,
			Output: "fs.suid_dumpable = " + strings.TrimSpace(res.Stdout) + " (want 0)"}},
		"escalation")}
}
