package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// ---------------------------------------------------------------- Hardening

// Hardening checks kernel and filesystem posture — the CIS-style checks that
// need no rule engine to express.
type Hardening struct{}

func (Hardening) ID() string                 { return "hardening" }
func (Hardening) Category() finding.Category { return finding.CatHardening }

// sysctlRule is one expected kernel parameter.
type sysctlRule struct {
	key   string
	want  string
	sev   finding.Severity
	title string
	desc  string
}

var sysctlRules = []sysctlRule{
	{"net.ipv4.conf.all.accept_redirects", "0", finding.SevLow,
		"ICMP redirects accepted", "Accepting ICMP redirects lets an attacker on the local network reroute traffic."},
	{"net.ipv4.conf.all.rp_filter", "1", finding.SevLow,
		"Reverse-path filtering disabled", "Without rp_filter the host accepts spoofed source addresses."},
	{"kernel.randomize_va_space", "2", finding.SevMedium,
		"ASLR not fully enabled", "Address-space randomisation is a core mitigation against memory-corruption exploits."},
	{"net.ipv4.ip_forward", "0", finding.SevInfo,
		"IP forwarding enabled", "The host routes packets between interfaces. Expected on a router or container host; unexpected elsewhere."},
}

func (h Hardening) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()
	if a.OSFamily == "darwin" {
		return nil, Skip(h.ID(), "Linux sysctl/filesystem rules do not apply to macOS")
	}
	if !r.Has(ctx, "sysctl") {
		return nil, Skip(h.ID(), "sysctl not present")
	}

	var out []finding.Finding
	checks := 0

	for _, rule := range sysctlRules {
		checks++
		res := r.Run(ctx, "sysctl", "-n", rule.key)
		if !res.OK() {
			continue // parameter absent on this kernel — not a finding
		}
		got := strings.TrimSpace(res.Stdout)
		if got == rule.want {
			continue
		}
		// ip_forward=1 is normal on a container host; say so rather than
		// crying wolf on every Docker box.
		sev := rule.sev
		desc := rule.desc
		f := finding.New(a.ID, finding.CatHardening, sev, "hardening.sysctl", rule.title, now)
		f.Description = desc
		f.Subcategory = "kernel"
		f.Engine = h.ID()
		f.Evidence = []finding.Evidence{{Command: res.Command,
			Output: fmt.Sprintf("%s = %s (expected %s)", rule.key, got, rule.want)}}
		f.Remediation = finding.Remediation{Op: "change_config",
			Summary: fmt.Sprintf("Set %s=%s", rule.key, rule.want),
			Command: fmt.Sprintf("echo '%s = %s' | sudo tee /etc/sysctl.d/90-secscan.conf && sudo sysctl --system", rule.key, rule.want)}
		out = append(out, f.WithLocation("sysctl:"+rule.key, finding.Component{}))
	}

	// --- world-writable files outside the expected temp dirs -------------
	checks++
	res := r.Run(ctx, "find", "/etc", "/usr/local/bin", "/opt",
		"-xdev", "-type", "f", "-perm", "-0002", "-print")
	if res.OK() {
		if ww := lines(res.Stdout); len(ww) > 0 {
			f := finding.New(a.ID, finding.CatHardening, finding.SevHigh,
				"hardening.world-writable",
				fmt.Sprintf("%d world-writable file(s) in system directories", len(ww)), now)
			f.Description = "Any local user can modify these files. If one is executed by root — a cron " +
				"job, a service script — it is a direct privilege-escalation path."
			f.Engine = h.ID()
			f.Evidence = []finding.Evidence{{Command: res.Command, Output: truncate(strings.Join(ww, "\n"), 4000)}}
			f.Remediation = finding.Remediation{Op: "change_config",
				Summary: "Remove world-write permission", Command: "sudo chmod o-w <path>"}
			out = append(out, f)
		}
	}

	// --- firewall present and active -------------------------------------
	checks++
	if fw, active := firewallState(ctx, r); !active {
		f := finding.New(a.ID, finding.CatHardening, finding.SevMedium,
			"hardening.no-firewall", "No active host firewall", now)
		f.Description = "Nothing restricts inbound connections at the host. Every listening service " +
			"is reachable from any network the host can see, which is what turns a local service " +
			"into an internet-facing one."
		f.Engine = h.ID()
		f.Evidence = []finding.Evidence{{Output: fw}}
		f.Remediation = finding.Remediation{Op: "change_config",
			Summary: "Enable a default-deny inbound firewall",
			Command: "sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw enable"}
		out = append(out, f)
	}

	return out, Ran(h.ID(), checks)
}

func firewallState(ctx context.Context, r exec.Runner) (string, bool) {
	if r.Has(ctx, "ufw") {
		res := r.Run(ctx, "ufw", "status")
		if res.OK() {
			return "ufw status: " + firstLine(res.Stdout), strings.Contains(strings.ToLower(res.Stdout), "status: active")
		}
	}
	if r.Has(ctx, "firewall-cmd") {
		res := r.Run(ctx, "firewall-cmd", "--state")
		if res.OK() {
			return "firewall-cmd: " + firstLine(res.Stdout), strings.Contains(res.Stdout, "running")
		}
	}
	if r.Has(ctx, "nft") {
		res := r.Run(ctx, "nft", "list", "ruleset")
		if res.OK() && strings.TrimSpace(res.Stdout) != "" {
			return "nftables ruleset present", true
		}
	}
	if r.Has(ctx, "iptables") {
		res := r.Run(ctx, "iptables", "-S")
		if res.OK() {
			// A ruleset of only default-ACCEPT policies is not a firewall.
			for _, l := range lines(res.Stdout) {
				if strings.HasPrefix(l, "-A ") {
					return "iptables rules present", true
				}
			}
			return "iptables present but no rules (all-ACCEPT)", false
		}
	}
	return "no firewall tool found (ufw/firewalld/nft/iptables)", false
}

// --------------------------------------------------------------- Containers

// Containers audits how containers are *run*, not what is in them. Image CVE
// scanning is Trivy's job and it does it well; nothing in the OSS ecosystem
// consistently reports that a container is privileged with the docker socket
// mounted, which is a full host compromise waiting to happen.
type Containers struct{}

func (Containers) ID() string                 { return "containers" }
func (Containers) Category() finding.Category { return finding.CatContainer }

// dockerInspect is the subset of `docker inspect` we care about.
type dockerInspect struct {
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
		User  string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged    bool     `json:"Privileged"`
		NetworkMode   string   `json:"NetworkMode"`
		PidMode       string   `json:"PidMode"`
		Binds         []string `json:"Binds"`
		CapAdd        []string `json:"CapAdd"`
		Memory        int64    `json:"Memory"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

func (c Containers) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()
	if !r.Has(ctx, "docker") {
		return nil, Skip(c.ID(), "docker not installed")
	}
	ids := r.Run(ctx, "docker", "ps", "-q")
	if !ids.OK() {
		return nil, Skip(c.ID(), "docker present but not queryable (daemon down, or no permission): "+firstLine(ids.Stderr))
	}
	idList := lines(ids.Stdout)
	if len(idList) == 0 {
		return nil, Ran(c.ID(), 0)
	}

	var out []finding.Finding
	for _, id := range idList {
		res := r.Run(ctx, "docker", "inspect", id)
		if !res.OK() {
			continue
		}
		var insp []dockerInspect
		if err := json.Unmarshal([]byte(res.Stdout), &insp); err != nil || len(insp) == 0 {
			continue
		}
		ci := insp[0]
		name := strings.TrimPrefix(ci.Name, "/")
		comp := finding.Component{Name: name, Version: ci.Config.Image}

		add := func(sev finding.Severity, rule, title, desc, remedy string) {
			f := finding.New(a.ID, finding.CatContainer, sev, rule, title, now)
			f.Description = desc
			f.Subcategory = "runtime"
			f.Engine = c.ID()
			f.Evidence = []finding.Evidence{{Command: res.Command,
				Output: fmt.Sprintf("container=%s image=%s privileged=%v network=%s pid=%s user=%q binds=%v",
					name, ci.Config.Image, ci.HostConfig.Privileged, ci.HostConfig.NetworkMode,
					ci.HostConfig.PidMode, ci.Config.User, ci.HostConfig.Binds)}}
			f.Remediation = finding.Remediation{Op: "change_config", Summary: remedy}
			out = append(out, f.WithLocation("container:"+name, comp))
		}

		if ci.HostConfig.Privileged {
			add(finding.SevCritical, "container.privileged",
				"Container "+name+" runs privileged",
				"A privileged container has all capabilities and can access every device. Escaping to "+
					"the host is trivial, so this is equivalent to running the workload as host root.",
				"Remove --privileged and grant only the specific capabilities needed")
		}
		for _, b := range ci.HostConfig.Binds {
			if strings.Contains(b, "docker.sock") {
				add(finding.SevCritical, "container.docker-sock",
					"Container "+name+" mounts the Docker socket",
					"Access to /var/run/docker.sock is equivalent to root on the host: the container "+
						"can start a new privileged container mounting the host filesystem.",
					"Remove the docker.sock bind mount, or use a socket proxy with a restricted API surface")
				break
			}
		}
		if ci.Config.User == "" || ci.Config.User == "root" || ci.Config.User == "0" {
			add(finding.SevMedium, "container.root-user",
				"Container "+name+" runs as root",
				"Processes run as UID 0 inside the container. Combined with any escape primitive or "+
					"writable host mount, this becomes host root.",
				"Set a non-root USER in the image or `user:` in compose")
		}
		if ci.HostConfig.NetworkMode == "host" {
			add(finding.SevHigh, "container.host-network",
				"Container "+name+" uses host networking",
				"The container shares the host network namespace, so it can bind host ports directly "+
					"and reach anything the host can, bypassing container network isolation.",
				"Use a bridge network and publish only the ports required")
		}
		if strings.HasPrefix(ci.HostConfig.PidMode, "host") {
			add(finding.SevHigh, "container.host-pid",
				"Container "+name+" shares the host PID namespace",
				"The container can see and signal every process on the host.",
				"Remove --pid=host")
		}
		if strings.HasSuffix(ci.Config.Image, ":latest") || !strings.Contains(ci.Config.Image, ":") {
			add(finding.SevLow, "container.unpinned-image",
				"Container "+name+" runs an unpinned image tag",
				"`:latest` means the running image is not reproducible and can change under you. "+
					"It also makes it impossible to say which CVEs apply.",
				"Pin to an immutable digest (image@sha256:…)")
		}
		if ci.HostConfig.Memory == 0 {
			add(finding.SevLow, "container.no-memory-limit",
				"Container "+name+" has no memory limit",
				"An unbounded container can exhaust host memory and take down every other workload.",
				"Set a memory limit (`--memory` / `mem_limit`)")
		}
	}
	return out, Ran(c.ID(), len(idList))
}

// -------------------------------------------------------------- OpsReadiness

// OpsReadiness detects absent controls rather than present flaws — the things
// whose absence you only discover at the worst moment.
type OpsReadiness struct{}

func (OpsReadiness) ID() string                 { return "ops" }
func (OpsReadiness) Category() finding.Category { return finding.CatOps }

func (o OpsReadiness) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()
	var out []finding.Finding
	checks := 0

	// --- time sync -------------------------------------------------------
	checks++
	synced := false
	if res := r.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); res.OK() {
		synced = strings.TrimSpace(res.Stdout) == "yes"
	} else if r.Has(ctx, "chronyc") {
		synced = r.Run(ctx, "chronyc", "tracking").OK()
	}
	if !synced && a.OSFamily != "darwin" {
		f := finding.New(a.ID, finding.CatOps, finding.SevLow,
			"ops.no-time-sync", "System clock is not synchronised", now)
		f.Description = "Unsynchronised clocks break TLS certificate validation, log correlation across " +
			"hosts, and any time-based authentication (TOTP, Kerberos)."
		f.Engine = o.ID()
		f.Evidence = []finding.Evidence{{Output: "NTPSynchronized reported false or unavailable"}}
		f.Remediation = finding.Remediation{Op: "change_config",
			Summary: "Enable NTP", Command: "sudo timedatectl set-ntp true"}
		out = append(out, f)
	}

	// --- audit logging ---------------------------------------------------
	checks++
	if a.OSFamily != "darwin" {
		hasAudit := r.Run(ctx, "systemctl", "is-active", "auditd").OK()
		if !hasAudit {
			f := finding.New(a.ID, finding.CatOps, finding.SevLow,
				"ops.no-audit-logging", "auditd is not running", now)
			f.Description = "Without auditd there is no record of privileged syscalls, file access or " +
				"authentication events — so a compromise leaves little forensic trail."
			f.Engine = o.ID()
			f.Evidence = []finding.Evidence{{Command: "systemctl is-active auditd", Output: "inactive or not installed"}}
			f.Remediation = finding.Remediation{Op: "change_config",
				Summary: "Install and enable auditd", Command: "sudo apt-get install -y auditd && sudo systemctl enable --now auditd"}
			out = append(out, f)
		}
	}

	return out, Ran(o.ID(), checks)
}
