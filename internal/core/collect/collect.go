// Package collect holds the native collectors — the ones that need no external
// tool installed. They are the primary source of findings; engine adapters are
// enrichment (ARCHITECTURE.md — Collectors and engines).
//
// Every collector returns a Note alongside its findings. A collector that could
// not run says so explicitly: an empty result with no explanation is exactly
// the silent gap this product exists to avoid.
package collect

import (
	"context"
	"strings"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Note records what a collector did, including why it produced nothing.
type Note struct {
	Collector  string             `json:"collector"`
	Ran        bool               `json:"ran"`
	Skipped    string             `json:"skipped,omitempty"` // reason, when !Ran
	Checks     int                `json:"checks"`
	Provenance finding.Provenance `json:"provenance"`
}

// Skip builds a Note for a collector that could not run.
func Skip(id, reason string) Note {
	return Note{Collector: id, Ran: false, Skipped: reason, Provenance: finding.ProvUnavailable}
}

// Ran builds a Note for a collector that completed.
func Ran(id string, checks int) Note {
	return Note{Collector: id, Ran: true, Checks: checks, Provenance: finding.ProvLive}
}

// Collector inspects one aspect of a target.
type Collector interface {
	ID() string
	Category() finding.Category
	Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note)
}

// All returns every native collector, in run order. HostFacts must be first:
// it populates the Asset that the others branch on.
func All() []Collector {
	return []Collector{
		HostFacts{},
		Packages{},
		Listeners{},
		Accounts{},
		SSHD{},
		Hardening{},
		Hygiene{},
		Services{},
		Escalation{},
		Containers{},
		OpsReadiness{},
	}
}

// ---------- shared helpers ----------

// lines splits command output into non-empty trimmed lines.
func lines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// kvFile parses `key=value` / `key value` config files (os-release, login.defs,
// sshd_config), lower-casing keys and ignoring comments. Later occurrences win,
// which matches how sshd and login.defs actually resolve duplicates.
func kvFile(content string, sep string) map[string]string {
	out := map[string]string{}
	for _, l := range lines(content) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		var k, v string
		if sep == "=" {
			i := strings.Index(l, "=")
			if i < 0 {
				continue
			}
			k, v = l[:i], l[i+1:]
		} else {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			k, v = f[0], strings.Join(f[1:], " ")
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		out[k] = v
	}
	return out
}

// ev is a one-liner for building Evidence from a command result.
func ev(r exec.Result) []finding.Evidence {
	out := strings.TrimSpace(r.Stdout)
	if out == "" {
		out = strings.TrimSpace(r.Stderr)
	}
	return []finding.Evidence{{Command: r.Command, Output: truncate(out, 4000)}}
}

// evFile builds Evidence from a file excerpt.
func evFile(path, content string) []finding.Evidence {
	return []finding.Evidence{{Path: path, Output: truncate(strings.TrimSpace(content), 4000)}}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n… (truncated)"
}

// managementPorts are ports that should essentially never face an untrusted
// network. Used by the Listeners collector to raise severity on wide binds.
var managementPorts = map[int]string{
	22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
	2375: "Docker API (plaintext)", 2376: "Docker API", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
	9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

// PortInfo describes what a port is for and whether facing the internet is the
// normal, intended state for it.
//
// This distinction is the difference between a useful report and an alarming
// one. "Service on tcp/443 listening on all interfaces" reads as a defect; a
// web server on 443 is doing exactly its job. The finding still belongs in the
// inventory — you should be able to see your whole attack surface — but the
// text has to say which kind of thing it is, or the reader learns to distrust
// every network finding.
type PortInfo struct {
	Service string
	// PublicByDesign: being reachable from the internet is the point of this
	// service, not a mistake.
	PublicByDesign bool
	Note           string
}

var wellKnownPorts = map[int]PortInfo{
	80:   {"HTTP", true, "A web server on 80 is meant to be reachable. What matters is that it redirects to HTTPS and that the server itself is hardened."},
	443:  {"HTTPS", true, "A web server on 443 is meant to be reachable. What matters is the TLS configuration, the security headers, and the web server's own hardening — see the web-server checks."},
	25:   {"SMTP", true, "A mail server on 25 accepts mail from the internet by design. What matters is that it is not an open relay and offers STARTTLS."},
	53:   {"DNS", false, "A DNS server reachable from the internet must not offer recursion to arbitrary clients, or it becomes a DDoS amplifier."},
	123:  {"NTP", false, "An NTP server reachable from the internet can be abused for amplification if mode 6/7 queries are answered."},
	67:   {"DHCP", false, "DHCP is a local-segment protocol; it has no business facing a wider network."},
	587:  {"SMTP submission", true, "Mail submission is meant to be reachable, but must require authentication and TLS."},
	993:  {"IMAPS", true, "Mail retrieval over TLS, normally public."},
	995:  {"POP3S", true, "Mail retrieval over TLS, normally public."},
	21:   {"FTP", false, "FTP transmits credentials in cleartext unless explicitly wrapped in TLS."},
	161:  {"SNMP", false, "SNMP exposes device internals and is frequently left on a default community string."},
	389:  {"LDAP", false, "Directory services should not face an untrusted network in cleartext."},
	3000: {"HTTP (application)", false, "An application server on a high port is usually meant to sit behind a reverse proxy rather than face the internet directly."},
	8080: {"HTTP (alternate)", false, "Usually an application or admin interface intended to sit behind a proxy."},
	8443: {"HTTPS (alternate)", false, "Usually an application or admin interface intended to sit behind a proxy."},
	9090: {"HTTP (admin/metrics)", false, "Admin and metrics interfaces are rarely intended to be public."},
	9100: {"Prometheus node_exporter", false, "Exposes detailed host metrics; not intended to be public."},
}

// describePort returns the service name and context for a port.
func describePort(port int) PortInfo {
	if pi, ok := wellKnownPorts[port]; ok {
		return pi
	}
	if svc, ok := managementPorts[port]; ok {
		return PortInfo{Service: svc, PublicByDesign: false,
			Note: svc + " is a management or data service and should not face an untrusted network."}
	}
	return PortInfo{}
}

// wideBind reports whether an address binds all interfaces.
func wideBind(addr string) bool {
	switch addr {
	case "0.0.0.0", "*", "::", "[::]":
		return true
	}
	return false
}
