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

// ---------------------------------------------------------------- HostFacts

// HostFacts populates the Asset. It runs first; everything else branches on
// OSFamily. It emits findings only for facts that are themselves risks —
// today, a distribution past end-of-life.
type HostFacts struct{}

func (HostFacts) ID() string                 { return "host-facts" }
func (HostFacts) Category() finding.Category { return finding.CatPatch }

func (h HostFacts) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()

	if un := r.Run(ctx, "uname", "-s"); un.OK() {
		sys := strings.TrimSpace(un.Stdout)
		if sys == "Darwin" {
			a.OSFamily = "darwin"
			if v := r.Run(ctx, "sw_vers", "-productVersion"); v.OK() {
				a.OS = "macOS " + strings.TrimSpace(v.Stdout)
			}
		}
	}
	if rel, ok := r.ReadFile(ctx, "/etc/os-release"); ok {
		kv := kvFile(rel, "=")
		a.OS = kv["pretty_name"]
		switch {
		case kv["id_like"] != "":
			a.OSFamily = familyOf(kv["id_like"] + " " + kv["id"])
		default:
			a.OSFamily = familyOf(kv["id"])
		}
	}
	if k := r.Run(ctx, "uname", "-r"); k.OK() {
		a.Kernel = strings.TrimSpace(k.Stdout)
	}
	if a.OS == "" {
		return nil, Skip(h.ID(), "could not determine operating system (no /etc/os-release, no uname)")
	}

	var out []finding.Finding

	// A running kernel older than the newest installed one means a reboot is
	// pending — the patch is on disk but not in effect, which reads as "fixed"
	// to most scanners and is exactly the gap worth reporting.
	if pending, evd := rebootPending(ctx, r); pending {
		f := finding.New(a.ID, finding.CatPatch, finding.SevMedium,
			"patch.reboot-required", "Reboot required to activate installed kernel/library updates", now)
		f.Description = "Updates are installed on disk but the running kernel or libraries predate them. " +
			"The host is still exposed to whatever those updates fixed until it reboots."
		f.Engine = h.ID()
		f.Evidence = evd
		f.Remediation = finding.Remediation{
			Op: "change_config", Summary: "Schedule a reboot in the next maintenance window",
			Command: "sudo reboot",
		}
		out = append(out, f)
	}
	return out, Ran(h.ID(), 2)
}

func familyOf(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "debian"), strings.Contains(s, "ubuntu"):
		return "debian"
	case strings.Contains(s, "rhel"), strings.Contains(s, "fedora"),
		strings.Contains(s, "centos"), strings.Contains(s, "rocky"), strings.Contains(s, "alma"):
		return "rhel"
	case strings.Contains(s, "alpine"):
		return "alpine"
	case strings.Contains(s, "suse"):
		return "suse"
	}
	return "linux"
}

func rebootPending(ctx context.Context, r exec.Runner) (bool, []finding.Evidence) {
	if res := r.Run(ctx, "test", "-f", "/var/run/reboot-required"); res.OK() {
		txt, _ := r.ReadFile(ctx, "/var/run/reboot-required")
		return true, evFile("/var/run/reboot-required", txt+"\n(marker present)")
	}
	if res := r.Run(ctx, "needs-restarting", "-r"); res.Err == nil && res.ExitCode == 1 {
		return true, ev(res)
	}
	return false, nil
}

// ----------------------------------------------------------------- Packages

// Packages reports pending security updates and unmanaged update posture. It
// deliberately does not attempt CVE matching — Trivy/Grype do that far better,
// and this collector's job is to work when they are absent.
type Packages struct{}

func (Packages) ID() string                 { return "packages" }
func (Packages) Category() finding.Category { return finding.CatPatch }

func (p Packages) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()
	var out []finding.Finding

	switch a.OSFamily {
	case "debian":
		if !r.Has(ctx, "apt-get") {
			return nil, Skip(p.ID(), "apt-get not present on a debian-family host")
		}
		// `apt-get -s upgrade` is a simulation: it changes nothing, needs no
		// root, and lists exactly what would be installed.
		res := r.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
		if !res.OK() {
			return nil, Skip(p.ID(), "apt-get simulation failed: "+firstLine(res.Stderr))
		}
		var total, security int
		var names []string
		for _, l := range lines(res.Stdout) {
			if !strings.HasPrefix(l, "Inst ") {
				continue
			}
			total++
			f := strings.Fields(l)
			if len(f) > 1 {
				names = append(names, f[1])
			}
			if strings.Contains(strings.ToLower(l), "security") {
				security++
			}
		}
		if total > 0 {
			sev := finding.SevMedium
			if security > 0 {
				sev = finding.SevHigh
			}
			f := finding.New(a.ID, finding.CatPatch, sev,
				"patch.updates-pending",
				fmt.Sprintf("%d package updates pending (%d security)", total, security), now)
			f.Description = "Installed packages are behind the distribution's current versions. " +
				"Security updates close known, published vulnerabilities."
			f.Engine = p.ID()
			f.Evidence = []finding.Evidence{{Command: res.Command, Output: truncate(strings.Join(names, "\n"), 4000)}}
			f.Remediation = finding.Remediation{
				Op: "apply_patch", Summary: "Apply pending updates",
				Command: "sudo apt-get update && sudo apt-get upgrade",
			}
			out = append(out, f)
		}
		out = append(out, unattendedUpgrades(ctx, r, a, p.ID(), now)...)
		_ = now

	case "rhel":
		if !r.Has(ctx, "dnf") && !r.Has(ctx, "yum") {
			return nil, Skip(p.ID(), "neither dnf nor yum present")
		}
		mgr := "dnf"
		if !r.Has(ctx, "dnf") {
			mgr = "yum"
		}
		res := r.Run(ctx, mgr, "-q", "check-update", "--security")
		// check-update exits 100 when updates exist — that is success, not error.
		if res.Err == nil && (res.ExitCode == 100 || res.ExitCode == 0) {
			n := len(lines(res.Stdout))
			if res.ExitCode == 100 && n > 0 {
				f := finding.New(a.ID, finding.CatPatch, finding.SevHigh,
					"patch.updates-pending", fmt.Sprintf("%d security updates pending", n), now)
				f.Engine = p.ID()
				f.Evidence = ev(res)
				f.Remediation = finding.Remediation{Op: "apply_patch",
					Summary: "Apply pending security updates", Command: "sudo " + mgr + " update --security"}
				out = append(out, f)
			}
		}

	case "alpine":
		if !r.Has(ctx, "apk") {
			return nil, Skip(p.ID(), "apk not present")
		}
		if res := r.Run(ctx, "apk", "version", "-l", "<"); res.OK() {
			if n := len(lines(res.Stdout)) - 1; n > 0 {
				f := finding.New(a.ID, finding.CatPatch, finding.SevMedium,
					"patch.updates-pending", fmt.Sprintf("%d package updates pending", n), now)
				f.Engine = p.ID()
				f.Evidence = ev(res)
				f.Remediation = finding.Remediation{Op: "apply_patch",
					Summary: "Apply pending updates", Command: "sudo apk upgrade"}
				out = append(out, f)
			}
		}

	default:
		return nil, Skip(p.ID(), "no supported package manager for OS family "+a.OSFamily)
	}

	return out, Ran(p.ID(), 2)
}

func unattendedUpgrades(ctx context.Context, r exec.Runner, a *finding.Asset, engine string, t time.Time) []finding.Finding {
	cfg, ok := r.ReadFile(ctx, "/etc/apt/apt.conf.d/20auto-upgrades")
	enabled := ok && strings.Contains(cfg, `"1"`)
	if enabled {
		return nil
	}
	f := finding.New(a.ID, finding.CatOps, finding.SevMedium,
		"ops.auto-updates-disabled", "Automatic security updates are not enabled", t)
	f.Description = "Without unattended-upgrades, security patches apply only when someone " +
		"remembers to run them. On an internet-facing host this is the difference between " +
		"hours and months of exposure."
	f.Engine = engine
	if ok {
		f.Evidence = evFile("/etc/apt/apt.conf.d/20auto-upgrades", cfg)
	} else {
		f.Evidence = evFile("/etc/apt/apt.conf.d/20auto-upgrades", "(file absent)")
	}
	f.Remediation = finding.Remediation{Op: "change_config",
		Summary: "Enable unattended security upgrades",
		Command: "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"}
	return []finding.Finding{f}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------- Listeners

// Listeners maps every listening socket with the process and user that owns it,
// then flags wide binds — especially of management ports.
//
// This is the collector that produces the input for exposure weighting: no
// external scanner can tell you which process owns a port or what address it
// bound to, and that is precisely what separates a real risk from a theoretical
// one.
type Listeners struct{}

func (Listeners) ID() string                 { return "listeners" }
func (Listeners) Category() finding.Category { return finding.CatNetwork }

// Listener is one listening socket.
type Listener struct {
	Proto   string
	Addr    string
	Port    int
	Process string
	User    string
}

func (l Listeners) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	now := clock.Now()

	var res exec.Result
	switch {
	case r.Has(ctx, "ss"):
		res = r.Run(ctx, "ss", "-tulpnH")
	case r.Has(ctx, "netstat"):
		res = r.Run(ctx, "netstat", "-tulpn")
	default:
		return nil, Skip(l.ID(), "neither ss nor netstat present")
	}
	if !res.OK() {
		return nil, Skip(l.ID(), "socket enumeration failed: "+firstLine(res.Stderr))
	}

	listeners := parseSS(res.Stdout)
	if len(listeners) == 0 {
		return nil, Ran(l.ID(), 1)
	}

	var out []finding.Finding
	// A dual-stack service appears twice — 0.0.0.0:22 and [::]:22 — but it is
	// one service with one fix. Report it once.
	reported := map[string]bool{}
	for _, ln := range listeners {
		if !wideBind(ln.Addr) {
			continue
		}
		key := fmt.Sprintf("%s/%d", ln.Proto, ln.Port)
		if reported[key] {
			continue
		}
		reported[key] = true
		info := describePort(ln.Port)
		proc := nameOr(ln.Process, "")

		// Name the service and say plainly whether being public is expected.
		// A bare "Service on tcp/443 listening on all interfaces" reads as a
		// defect; a web server on 443 is doing its job, and a reader who is
		// alarmed by it once learns to ignore every network finding after.
		svcLabel := info.Service
		if svcLabel == "" {
			svcLabel = "Service"
		}
		if proc != "" {
			svcLabel += " (" + proc + ")"
		}

		sev := finding.SevLow
		title := fmt.Sprintf("%s on %s/%d is reachable on all interfaces", svcLabel, ln.Proto, ln.Port)
		desc := "The socket is bound to 0.0.0.0/::, so it accepts connections from any " +
			"network the host can reach, not just loopback."

		switch {
		case info.PublicByDesign:
			// Inventory, not alarm.
			sev = finding.SevInfo
			title = fmt.Sprintf("%s on %s/%d is public (expected for this service)", svcLabel, ln.Proto, ln.Port)
			desc = "This service is normally intended to be reachable from the internet, so " +
				"this entry is here to complete your attack-surface inventory rather than to " +
				"report a misconfiguration. " + info.Note
		case info.Service != "" && !info.PublicByDesign:
			sev = finding.SevHigh
			title = fmt.Sprintf("%s (%s/%d) is reachable on all interfaces", svcLabel, ln.Proto, ln.Port)
			desc = info.Note + " Exposed beyond loopback it is a direct target for " +
				"credential attacks and known exploits."
		}

		f := finding.New(a.ID, finding.CatNetwork, sev, "network.wide-bind", title, now)
		f.Description = desc
		f.Subcategory = "listening-port"
		f.Engine = l.ID()
		f.Exposed = true
		f.Evidence = []finding.Evidence{{
			Command: res.Command,
			Output:  fmt.Sprintf("%s %s:%d  process=%s user=%s", ln.Proto, ln.Addr, ln.Port, ln.Process, ln.User),
		}}
		remedy := fmt.Sprintf("Bind %s to 127.0.0.1, or restrict with a firewall rule", nameOr(ln.Process, "the service"))
		if info.PublicByDesign {
			remedy = "No action needed if this service is meant to be public — confirm it is, and that the service itself is hardened"
		}
		f.Remediation = finding.Remediation{Op: "close_port", Summary: remedy}
		out = append(out, f.WithLocation(fmt.Sprintf("%s/%d", ln.Proto, ln.Port),
			finding.Component{Name: ln.Process}))
	}
	return out, Ran(l.ID(), len(listeners))
}

func nameOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" || s == "-" {
		return fallback
	}
	return s
}

// parseSS handles `ss -tulpnH` output. Format is whitespace-separated with the
// local address as field 4 and an optional users:(("proc",pid=N,fd=M)) tail.
func parseSS(out string) []Listener {
	var res []Listener
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		proto := f[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		// ss -H: Netid State Recv-Q Send-Q Local:Port Peer:Port [users:...]
		local := f[4]
		if strings.HasPrefix(l, "tcp") && len(f) >= 5 {
			local = f[4]
		}
		addr, port, ok := splitHostPort(local)
		if !ok {
			continue
		}
		ln := Listener{Proto: proto, Addr: addr, Port: port}
		if i := strings.Index(l, `users:(("`); i >= 0 {
			rest := l[i+len(`users:(("`):]
			if j := strings.Index(rest, `"`); j > 0 {
				ln.Process = rest[:j]
			}
		}
		res = append(res, ln)
	}
	return res
}

// splitHostPort handles 0.0.0.0:22, [::]:22, *:22 and 127.0.0.1:6379.
func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	host, portStr := s[:i], s[i+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false
	}
	host = strings.Trim(host, "[]")
	if host == "*" {
		host = "0.0.0.0"
	}
	return host, port, true
}
