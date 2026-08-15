package collect

import (
	"context"
	"fmt"
	"strings"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Services inspects the configuration of the network daemons a host actually
// runs — web servers, DNS, NTP, DHCP, mail.
//
// The listener collector tells you a web server is reachable on 443, which is
// usually correct and intended. This collector answers the follow-up question
// that actually matters: is that web server configured safely? Same for a
// resolver that will answer for anyone, or an NTP daemon that will happily
// participate in an amplification attack.
//
// Everything here reads configuration on the host. Checks that require probing
// from outside live in the reachability and DNS-hygiene collectors.
type Services struct{}

func (Services) ID() string                 { return "services" }
func (Services) Category() finding.Category { return finding.CatServices }

func (s Services) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	if a.OSFamily == "darwin" || a.OSFamily == "" {
		return nil, Skip(s.ID(), "service configuration checks are Linux-only for now")
	}
	var out []finding.Finding
	checks := 0
	webFound := false
	for i, fn := range []func(context.Context, exec.Runner, *finding.Asset) []finding.Finding{
		s.apache, s.nginx, s.caddy, s.bind, s.ntp, s.dhcp,
	} {
		checks++
		fs := fn(ctx, r, a)
		if i < 3 && fs != nil {
			webFound = true
		}
		out = append(out, fs...)
	}
	// Config found on the host settles it either way.
	if !webFound {
		webFound = hasAnyWebConfig(ctx, r)
	}
	out = append(out, s.webConfigUnreachable(ctx, r, a, webFound)...)
	return out, Ran(s.ID(), checks)
}

// hasAnyWebConfig reports whether a web server's configuration exists on the
// host filesystem at all.
func hasAnyWebConfig(ctx context.Context, r exec.Runner) bool {
	for _, p := range []string{
		"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf",
		"/etc/nginx/nginx.conf", "/etc/caddy/Caddyfile",
	} {
		if r.Run(ctx, "test", "-e", p).OK() {
			return true
		}
	}
	return false
}

// webConfigUnreachable states plainly that a web server is reachable but its
// configuration could not be inspected — almost always because it runs in a
// container, where the config lives inside the image rather than on the host.
//
// Reporting nothing here would be the worst outcome: the operator would see a
// clean "Web services" category and reasonably conclude the web server had been
// checked and passed, when in fact it was never examined at all.
func (Services) webConfigUnreachable(ctx context.Context, r exec.Runner, a *finding.Asset, found bool) []finding.Finding {
	if found {
		return nil
	}
	listening := false
	for _, port := range []string{"80", "443"} {
		if r.Run(ctx, "sh", "-c", "ss -tlnH 2>/dev/null | grep -q ':"+port+" '").OK() {
			listening = true
		}
	}
	if !listening {
		return nil
	}
	return []finding.Finding{svc(a, finding.SevInfo, "services.web-config-not-inspected",
		"A web server is reachable, but its configuration was not inspected",
		"Ports 80/443 are serving, yet no Apache, nginx or Caddy configuration exists on "+
			"the host filesystem. The web server is almost certainly running in a container, "+
			"where its configuration lives inside the image. That means none of the web-server "+
			"hardening checks — version disclosure, directory listing, TLS versions, exposed "+
			"status pages, admin API binding — actually ran against it. This is recorded so an "+
			"empty result is not mistaken for a clean one.",
		"Inspect the config inside the container, or mount it on the host so scans can read it",
		"docker exec <container> cat /etc/caddy/Caddyfile",
		[]finding.Evidence{{Command: "test -e /etc/{apache2,nginx,caddy} configs",
			Output: "web server listening on 80/443, but no web server config found on the host filesystem"}},
		"web")}
}

func svc(a *finding.Asset, sev finding.Severity, rule, title, desc, remedy, cmd string,
	ev []finding.Evidence, sub string) finding.Finding {
	f := mk(a, sev, rule, title, desc, remedy, cmd, ev, sub)
	f.Category = finding.CatServices
	f.Engine = "services"
	return f
}

// readAny returns the first readable file from a list of candidate paths.
func readAny(ctx context.Context, r exec.Runner, paths ...string) (string, string, bool) {
	for _, p := range paths {
		if body, ok := r.ReadFile(ctx, p); ok {
			return body, p, true
		}
	}
	return "", "", false
}

// globCat concatenates every file matching a directory listing, so included
// config fragments are inspected rather than only the main file. Web server
// config is almost always split across sites-enabled/conf.d.
func globCat(ctx context.Context, r exec.Runner, dirs ...string) string {
	var b strings.Builder
	for _, d := range dirs {
		res := r.Run(ctx, "ls", "-1", d)
		if !res.OK() {
			continue
		}
		for _, n := range lines(res.Stdout) {
			if body, ok := r.ReadFile(ctx, d+"/"+n); ok {
				b.WriteString("# --- " + d + "/" + n + "\n")
				b.WriteString(body)
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

// ------------------------------------------------------------------- Apache

func (Services) apache(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	main, path, ok := readAny(ctx, r,
		"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf")
	if !ok {
		return nil
	}
	cfg := main + "\n" + globCat(ctx, r,
		"/etc/apache2/conf-enabled", "/etc/apache2/sites-enabled", "/etc/httpd/conf.d")
	low := strings.ToLower(cfg)
	var out []finding.Finding

	// Version disclosure: not an exploit, but it hands an attacker the exact
	// build to match against a CVE list.
	if !strings.Contains(low, "servertokens prod") {
		out = append(out, svc(a, finding.SevLow, "services.apache-version-disclosure",
			"Apache discloses its version in responses",
			"ServerTokens is not set to Prod, so Apache advertises its exact version (and "+
				"often the OS) in every response header and error page. That tells an attacker "+
				"precisely which vulnerability list to work through.",
			"Set ServerTokens Prod and ServerSignature Off",
			"echo -e 'ServerTokens Prod\\nServerSignature Off' | sudo tee /etc/apache2/conf-available/security-hardening.conf && sudo a2enconf security-hardening && sudo systemctl reload apache2",
			[]finding.Evidence{{Path: path, Output: "no 'ServerTokens Prod' directive found"}}, "apache"))
	}

	// Directory listing exposes files never meant to be discoverable —
	// backups, .sql dumps, editor swap files.
	if strings.Contains(low, "options") && strings.Contains(low, "indexes") &&
		!strings.Contains(low, "-indexes") {
		out = append(out, svc(a, finding.SevMedium, "services.apache-directory-listing",
			"Apache directory listing (Options Indexes) is enabled",
			"Directories without an index file render a browsable file listing. This routinely "+
				"exposes database dumps, backup archives, editor swap files and .git directories "+
				"that were never meant to be discoverable.",
			"Replace 'Options Indexes' with 'Options -Indexes'",
			"", []finding.Evidence{{Path: path, Output: grepFirst(cfg, "Indexes", 3)}}, "apache"))
	}

	// TRACE enables cross-site tracing; there is no legitimate production use.
	if !strings.Contains(low, "traceenable off") {
		out = append(out, svc(a, finding.SevLow, "services.apache-trace-enabled",
			"Apache TRACE method is not explicitly disabled",
			"TRACE echoes the request back, including headers and cookies. Combined with a "+
				"scripting flaw it enables cross-site tracing. There is no legitimate use for "+
				"it on a production server.",
			"Set TraceEnable Off",
			"", []finding.Evidence{{Path: path, Output: "no 'TraceEnable Off' directive found"}}, "apache"))
	}

	// mod_status leaks live request URLs, client addresses and server internals.
	if strings.Contains(low, "server-status") && !strings.Contains(low, "require local") {
		out = append(out, svc(a, finding.SevHigh, "services.apache-status-exposed",
			"Apache server-status may be reachable without restriction",
			"mod_status exposes live request URLs, client IP addresses, and server internals. "+
				"A /server-status handler without a Require local (or equivalent) restriction is "+
				"a real information-disclosure issue and a reconnaissance goldmine.",
			"Restrict the handler to localhost, or disable mod_status",
			"sudo a2dismod status && sudo systemctl reload apache2",
			[]finding.Evidence{{Path: path, Output: grepFirst(cfg, "server-status", 5)}}, "apache"))
	}
	return out
}

// -------------------------------------------------------------------- nginx

func (Services) nginx(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	main, path, ok := readAny(ctx, r, "/etc/nginx/nginx.conf")
	if !ok {
		return nil
	}
	cfg := main + "\n" + globCat(ctx, r, "/etc/nginx/conf.d", "/etc/nginx/sites-enabled")
	low := strings.ToLower(cfg)
	var out []finding.Finding

	if !strings.Contains(low, "server_tokens off") {
		out = append(out, svc(a, finding.SevLow, "services.nginx-version-disclosure",
			"nginx discloses its version in responses",
			"server_tokens is not off, so nginx advertises its exact version in response "+
				"headers and error pages, telling an attacker which CVE list applies.",
			"Set server_tokens off in the http block",
			"", []finding.Evidence{{Path: path, Output: "no 'server_tokens off' directive found"}}, "nginx"))
	}
	if strings.Contains(low, "autoindex on") {
		out = append(out, svc(a, finding.SevMedium, "services.nginx-directory-listing",
			"nginx directory listing (autoindex) is enabled",
			"autoindex renders a browsable file listing for directories without an index, "+
				"which routinely exposes backups, dumps and files never meant to be found.",
			"Set autoindex off",
			"", []finding.Evidence{{Path: path, Output: grepFirst(cfg, "autoindex", 3)}}, "nginx"))
	}
	// Deprecated TLS versions have known, practical weaknesses.
	if strings.Contains(low, "ssl_protocols") &&
		(strings.Contains(low, "tlsv1 ") || strings.Contains(low, "tlsv1.1") || strings.Contains(low, "sslv3")) {
		out = append(out, svc(a, finding.SevHigh, "services.nginx-weak-tls",
			"nginx offers deprecated TLS versions",
			"TLS 1.0/1.1 and SSLv3 have practical, published weaknesses and are rejected by "+
				"every current compliance regime. Offering them lets a downgrade attack pick them.",
			"Restrict to TLS 1.2 and 1.3",
			"# ssl_protocols TLSv1.2 TLSv1.3;",
			[]finding.Evidence{{Path: path, Output: grepFirst(cfg, "ssl_protocols", 3)}}, "nginx"))
	}
	return out
}

// -------------------------------------------------------------------- Caddy

func (Services) caddy(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	cfg, path, ok := readAny(ctx, r, "/etc/caddy/Caddyfile")
	if !ok {
		return nil
	}
	low := strings.ToLower(cfg)
	var out []finding.Finding

	// Caddy is secure by default, so there is little to flag — but the admin
	// API is a full control plane and binding it off-loopback is total
	// compromise of every site it serves.
	if strings.Contains(low, "admin ") && !strings.Contains(low, "admin off") &&
		!strings.Contains(low, "admin localhost") && !strings.Contains(low, "admin 127.0.0.1") {
		out = append(out, svc(a, finding.SevCritical, "services.caddy-admin-exposed",
			"Caddy admin API may be bound beyond loopback",
			"The Caddy admin API can rewrite the entire server configuration with an "+
				"unauthenticated POST. Reachable from anywhere but loopback, it is complete "+
				"control of every site this server hosts.",
			"Bind the admin endpoint to localhost, or turn it off",
			"# admin off   (or)   admin localhost:2019",
			[]finding.Evidence{{Path: path, Output: grepFirst(cfg, "admin", 3)}}, "caddy"))
	}
	if strings.Contains(low, "auto_https off") {
		out = append(out, svc(a, finding.SevMedium, "services.caddy-auto-https-off",
			"Caddy automatic HTTPS is disabled",
			"auto_https off turns off Caddy's certificate management and HTTP-to-HTTPS "+
				"redirect — the main reason to run Caddy. Traffic may be served in cleartext.",
			"Re-enable automatic HTTPS unless TLS is genuinely terminated upstream",
			"", []finding.Evidence{{Path: path, Output: grepFirst(cfg, "auto_https", 2)}}, "caddy"))
	}
	return out
}

// --------------------------------------------------------------- BIND / DNS

func (Services) bind(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	main, path, ok := readAny(ctx, r,
		"/etc/bind/named.conf.options", "/etc/named.conf", "/etc/bind/named.conf")
	if !ok {
		return nil
	}
	cfg := main + "\n" + globCat(ctx, r, "/etc/bind")
	low := strings.ToLower(cfg)
	var out []finding.Finding

	// An open resolver is the classic DDoS amplifier: small query, large
	// response, spoofed source. Operators are routinely contacted by their
	// provider about this.
	recursionOn := !strings.Contains(low, "recursion no")
	restricted := strings.Contains(low, "allow-recursion")
	if recursionOn && !restricted {
		out = append(out, svc(a, finding.SevCritical, "services.dns-open-resolver",
			"BIND allows recursion without an allow-recursion restriction",
			"A resolver that answers recursive queries for anyone is an open resolver. "+
				"Attackers use it as a DDoS amplifier — a small spoofed query produces a large "+
				"response aimed at the victim — and it is one of the fastest ways to have your "+
				"provider suspend the host. It also leaks your internal query patterns.",
			"Restrict recursion to your own networks, or disable it on an authoritative server",
			"# allow-recursion { localhost; 10.0.0.0/8; };   or   recursion no;",
			[]finding.Evidence{{Path: path, Output: "recursion is not disabled and no allow-recursion ACL was found"}},
			"dns"))
	}

	// Unrestricted AXFR hands over every record in the zone — a complete map
	// of the estate.
	if strings.Contains(low, "allow-transfer") &&
		(strings.Contains(low, "allow-transfer { any") || strings.Contains(low, "allow-transfer {any")) {
		out = append(out, svc(a, finding.SevHigh, "services.dns-zone-transfer-open",
			"BIND permits zone transfers to any host",
			"AXFR to any client hands an attacker every record in the zone: internal "+
				"hostnames, addressing, service locations — a complete map of the estate, for free.",
			"Restrict allow-transfer to your secondary name servers only",
			"", []finding.Evidence{{Path: path, Output: grepFirst(cfg, "allow-transfer", 3)}}, "dns"))
	}
	if !strings.Contains(low, "version ") {
		out = append(out, svc(a, finding.SevLow, "services.dns-version-disclosure",
			"BIND discloses its version",
			"version.bind CHAOS queries return the exact BIND build, which maps directly to "+
				"a published vulnerability list.",
			"Override the reported version",
			`# version "not disclosed";`,
			[]finding.Evidence{{Path: path, Output: "no 'version' directive in the options block"}}, "dns"))
	}
	return out
}

// ---------------------------------------------------------------------- NTP

func (Services) ntp(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	var out []finding.Finding

	// chrony: `allow` without a subnet permits the world.
	if cfg, path, ok := readAny(ctx, r, "/etc/chrony/chrony.conf", "/etc/chrony.conf"); ok {
		for _, l := range lines(cfg) {
			if strings.HasPrefix(l, "#") {
				continue
			}
			if strings.TrimSpace(l) == "allow" || strings.HasPrefix(strings.TrimSpace(l), "allow all") {
				out = append(out, svc(a, finding.SevHigh, "services.ntp-open-server",
					"chrony serves time to any client",
					"An unrestricted 'allow' turns this host into a public NTP server. NTP is a "+
						"favoured amplification vector — a small query can produce a much larger "+
						"response aimed at a spoofed victim.",
					"Restrict 'allow' to the networks that should get time from this host",
					"# allow 10.0.0.0/8",
					[]finding.Evidence{{Path: path, Output: l}}, "ntp"))
				break
			}
		}
	}

	// ntpd: the classic monlist/mode-7 amplification needs `noquery`.
	if cfg, path, ok := readAny(ctx, r, "/etc/ntp.conf"); ok {
		if !strings.Contains(cfg, "noquery") {
			out = append(out, svc(a, finding.SevHigh, "services.ntp-mode6-queries",
				"ntpd answers status queries (no 'noquery' restriction)",
				"Without 'restrict default ... noquery', ntpd answers mode 6/7 status queries. "+
					"These are the basis of the well-known NTP amplification attacks and also "+
					"disclose peer and system information.",
				"Add noquery to the default restrict line",
				"# restrict default kod nomodify notrap nopeer noquery",
				[]finding.Evidence{{Path: path, Output: "no 'noquery' in any restrict directive"}}, "ntp"))
		}
	}
	return out
}

// --------------------------------------------------------------------- DHCP

func (Services) dhcp(ctx context.Context, r exec.Runner, a *finding.Asset) []finding.Finding {
	running := r.Run(ctx, "systemctl", "is-active", "isc-dhcp-server").OK() ||
		r.Run(ctx, "systemctl", "is-active", "dhcpd").OK() ||
		r.Run(ctx, "systemctl", "is-active", "kea-dhcp4-server").OK()
	if !running {
		return nil
	}
	return []finding.Finding{svc(a, finding.SevInfo, "services.dhcp-server-running",
		"A DHCP server is running on this host",
		"DHCP hands clients their address, gateway and DNS server, so a DHCP server is a "+
			"position of considerable trust — a rogue or misconfigured one can redirect an "+
			"entire segment's traffic. This is informational: confirm it is intended, that its "+
			"scope is correct, and that it is not answering on an interface it should not.",
		"Confirm the server is intended and that its interfaces and scopes are correct",
		"", []finding.Evidence{{Command: "systemctl is-active isc-dhcp-server", Output: "active"}},
		"dhcp")}
}

// grepFirst returns up to n matching lines, for compact evidence.
func grepFirst(body, needle string, n int) string {
	var hits []string
	for _, l := range lines(body) {
		if strings.Contains(strings.ToLower(l), strings.ToLower(needle)) {
			hits = append(hits, l)
			if len(hits) >= n {
				break
			}
		}
	}
	if len(hits) == 0 {
		return fmt.Sprintf("(no line containing %q)", needle)
	}
	return strings.Join(hits, "\n")
}
