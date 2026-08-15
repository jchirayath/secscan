package collect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// WebHeaders fetches each site this host serves and reads what the browser
// would read: the response headers, the cookie attributes, and the certificate.
//
// It needs no external tool, which is the point. testssl.sh and nuclei are
// better at what they do, but they are optional and frequently absent, and the
// checks here — HSTS, CSP, framing, MIME sniffing, cookie flags, certificate
// expiry — are the ones whose absence shows up in a real incident most often.
// A host should not have to install anything to learn that its session cookie
// is missing HttpOnly or that its certificate expires on Saturday.
//
// Two honesty caveats, stated here because they bound every finding below:
//
//   - The request goes to the *name*, so if a CDN or an upstream reverse proxy
//     answers for that name, these are the edge's headers, not this host's.
//     The fix may therefore belong at the edge. The evidence records the URL
//     that was fetched so a reader can tell.
//   - Only the site root is fetched. Headers are commonly set per-location, so
//     "root has CSP" does not mean every path does. Nothing here claims it.
type WebHeaders struct {
	// Fetch is injectable so the checks can be exercised without a network.
	Fetch SiteFetcher
}

// NOTE: the socket listing deliberately uses the same `ss -tulpnH` invocation
// as the Listeners collector. A least-privilege scan account is granted exactly
// that command in sudoers; a different flag combination is a different command
// and gets denied, which is how this check silently produced nothing on its
// first run against a correctly-hardened host.
func (WebHeaders) ID() string                 { return "web-headers" }
func (WebHeaders) Category() finding.Category { return finding.CatWeb }

// SiteFetcher retrieves one site's root over HTTPS.
type SiteFetcher interface {
	Fetch(ctx context.Context, name string, port int) (*SiteResponse, error)
}

// SiteResponse is everything the checks need from one fetch. The body is
// deliberately absent: none of these checks read it, and not keeping it means
// a hostile response can never end up in a report.
type SiteResponse struct {
	URL        string
	Status     int
	Header     http.Header
	Cookies    []*http.Cookie
	TLSVersion string
	Cert       *x509.Certificate
	// StoppedAt is set when a redirect chain was deliberately not followed, so
	// a finding can say the headers came from a redirect rather than a page.
	StoppedAt string
}

// site is one name/port pair to check.
type site struct {
	Name string
	Port int
}

func (s site) String() string {
	if s.Port == 443 {
		return "https://" + s.Name + "/"
	}
	return "https://" + net.JoinHostPort(s.Name, strconv.Itoa(s.Port)) + "/"
}

// tlsWebPorts are the ports worth attempting an HTTPS fetch against. Plaintext
// web ports are excluded on purpose: they are normally an application server
// behind a proxy, and header checks against them measure the wrong tier.
var tlsWebPorts = map[int]bool{443: true, 8443: true, 9443: true}

// plainWebPorts exist only so a host serving HTTP with no HTTPS listener gets a
// precise skip reason instead of a blank one.
var plainWebPorts = map[int]bool{80: true, 3000: true, 8000: true, 8080: true, 8081: true, 9090: true}

func (w WebHeaders) Collect(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, Note) {
	names := webNames(r.Target())
	if len(names) == 0 {
		return nil, Skip(w.ID(), "this target has no host name or virtual hosts — a certificate "+
			"can only be validated against a name, so there is nothing to fetch")
	}

	ports, cmd, ok := listeningTCPPorts(ctx, r)
	if !ok {
		return nil, Skip(w.ID(), "could not enumerate listening ports ("+cmd+
			") — without it there is no way to know which web services this host runs")
	}
	var tlsPorts []int
	var plainSeen []int
	for p := range ports {
		if tlsWebPorts[p] {
			tlsPorts = append(tlsPorts, p)
		} else if plainWebPorts[p] {
			plainSeen = append(plainSeen, p)
		}
	}
	if len(tlsPorts) == 0 {
		reason := "no HTTPS listener found on 443, 8443 or 9443"
		if len(plainSeen) > 0 {
			reason += fmt.Sprintf(" (plaintext web ports %s are listening — if TLS is terminated "+
				"upstream, run these checks against the host that terminates it)", joinPorts(plainSeen))
		}
		return nil, Skip(w.ID(), reason)
	}
	sortInts(tlsPorts)

	f := w.Fetch
	if f == nil {
		f = dialFetcher{}
	}

	var out []finding.Finding
	var reached, failed int
	var reasons []string

	for _, name := range names {
		for _, port := range tlsPorts {
			s := site{Name: name, Port: port}
			resp, err := f.Fetch(ctx, name, port)
			if err != nil {
				failed++
				reasons = append(reasons, s.String()+": "+firstLine(err.Error()))
				out = append(out, w.fetchFailure(a, s, err)...)
				continue
			}
			reached++
			out = append(out, w.checkHeaders(a, s, resp)...)
			out = append(out, w.checkCookies(a, s, resp)...)
			out = append(out, w.checkCertificate(a, s, resp)...)
		}
	}

	// Never silently nothing: if not one site answered and the failures did not
	// even produce a certificate finding, the collector says why it is empty.
	if reached == 0 && len(out) == 0 {
		return nil, Skip(w.ID(), fmt.Sprintf("none of the %d site(s) could be fetched — %s",
			failed, strings.Join(reasons, "; ")))
	}
	n := Ran(w.ID(), reached*7)
	if failed > 0 {
		// Some of the estate was not measured. Claiming ProvLive would present a
		// partial picture as a complete one.
		n.Provenance = finding.ProvPartial
	}
	return out, n
}

// webNames is every DNS name this target answers for.
//
// A reverse proxy routes on the Host header, so fetching the address alone only
// ever reaches the default virtual host; every other site on the same port —
// with its own certificate and its own headers — stays invisible unless the
// operator has declared it.
func webNames(t exec.Target) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimSuffix(s, ".")
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		}
		if s == "" || s == "localhost" || net.ParseIP(s) != nil || seen[s] {
			// A bare IP is excluded deliberately: every certificate check
			// against it would fail on the name, reporting a mismatch that is
			// an artefact of how we connected rather than a real defect.
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(t.Host)
	for _, v := range t.VirtualHosts {
		add(v)
	}
	return out
}

// listeningTCPPorts collects the local ports with a listening TCP socket.
//
// It scans for the first address:port token on any line mentioning LISTEN,
// which is the one shape `ss` and `netstat` agree on across the flag
// combinations and versions in the wild.
func listeningTCPPorts(ctx context.Context, r exec.Runner) (map[int]bool, string, bool) {
	var res exec.Result
	switch {
	case r.Has(ctx, "ss"):
		res = r.Run(ctx, "ss", "-tulpnH")
	case r.Has(ctx, "netstat"):
		res = r.Run(ctx, "netstat", "-tln")
	default:
		return nil, "ss/netstat", false
	}
	if !res.OK() {
		return nil, res.Command, false
	}
	ports := map[int]bool{}
	for _, l := range lines(res.Stdout) {
		// `ss -tlnH` omits the LISTEN column on some builds; treat every line
		// as a candidate and let the address parse decide.
		for _, tok := range strings.Fields(l) {
			if _, port, ok := splitHostPort(tok); ok && port > 0 {
				ports[port] = true
				break
			}
		}
	}
	return ports, res.Command, true
}

// ------------------------------------------------------------------- checks

// hdr builds a finding attributed to this collector. mk() stamps the hardening
// category and the hygiene engine; both are overridden so the coverage
// drill-down attributes these to the check that actually produced them.
func hdr(a *finding.Asset, sev finding.Severity, rule, title, desc, remedy, cmd string,
	ev []finding.Evidence, sub string) finding.Finding {
	f := mk(a, sev, rule, title, desc, remedy, cmd, ev, sub)
	f.Category = finding.CatWeb
	f.Engine = "web-headers"
	// These sites answered from outside the host, so the exposure is not in
	// question — it was just demonstrated.
	f.Exposed = true
	return f
}

// securityHeaders is the set echoed as evidence on every header finding. Seeing
// what WAS set next to what was not is what makes a header finding actionable:
// it shows immediately whether the site has a security-header policy with a gap
// in it, or no policy at all.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"Server",
	"X-Powered-By",
}

func headerEvidence(resp *SiteResponse) []finding.Evidence {
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s → HTTP %d over %s\n", resp.URL, resp.Status, resp.TLSVersion)
	if resp.StoppedAt != "" {
		fmt.Fprintf(&b, "(%s — headers below are from that response)\n", resp.StoppedAt)
	}
	for _, h := range securityHeaders {
		if v := resp.Header.Get(h); v != "" {
			fmt.Fprintf(&b, "%s: %s\n", h, v)
		} else {
			fmt.Fprintf(&b, "%s: (absent)\n", h)
		}
	}
	return []finding.Evidence{{Command: "GET " + resp.URL, Output: truncate(strings.TrimSpace(b.String()), 4000)}}
}

func (w WebHeaders) checkHeaders(a *finding.Asset, s site, resp *SiteResponse) []finding.Finding {
	var out []finding.Finding
	loc := resp.URL
	ev := headerEvidence(resp)
	csp := resp.Header.Get("Content-Security-Policy")

	// --- HSTS ------------------------------------------------------------
	hsts := resp.Header.Get("Strict-Transport-Security")
	switch {
	case hsts == "":
		out = append(out, hdr(a, finding.SevMedium, "web.hsts-missing",
			"No HSTS on "+s.Name,
			"Without Strict-Transport-Security, a browser that is sent to http://"+s.Name+
				" — by a typed address, an old bookmark, or a link in an email — makes that first "+
				"request in cleartext. Anyone on the network path between the user and this server "+
				"can answer it, keep the victim on HTTP for the rest of the session, and read or "+
				"rewrite everything including the session cookie. The HTTPS redirect does not "+
				"prevent this; it happens after the interceptable request.",
			"Send Strict-Transport-Security on every HTTPS response, after confirming every "+
				"subdomain also serves HTTPS",
			`add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
			ev, "headers").WithLocation(loc+"#hsts", finding.Component{}))
	default:
		if age, ok := hstsMaxAge(hsts); ok && age < 15552000 {
			out = append(out, hdr(a, finding.SevLow, "web.hsts-short-max-age",
				fmt.Sprintf("HSTS max-age on %s is %d days", s.Name, age/86400),
				"A browser only remembers the HTTPS-only rule for max-age seconds after its last "+
					"visit. With a short window, a user who has not been here recently is back to an "+
					"interceptable first request — which is the exact case HSTS exists to close. "+
					"Six months is the practical floor and one year is required for preload lists.",
				"Raise max-age to 31536000 (one year) once you are confident every subdomain serves HTTPS",
				`add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
				ev, "headers").WithLocation(loc+"#hsts-max-age", finding.Component{}))
		}
	}

	// --- CSP -------------------------------------------------------------
	if csp == "" {
		sev := finding.SevMedium
		title := "No Content-Security-Policy on " + s.Name
		extra := ""
		if ro := resp.Header.Get("Content-Security-Policy-Report-Only"); ro != "" {
			// A report-only policy is real work already done, so this is not the
			// same finding as having none — but it blocks nothing.
			sev = finding.SevLow
			title = "Content-Security-Policy is report-only on " + s.Name
			extra = " A report-only policy is present, so the hard part — working out what the " +
				"site actually loads — has been done. It currently blocks nothing; only the " +
				"enforcing header does."
		}
		out = append(out, hdr(a, sev, "web.csp-missing", title,
			"CSP is what limits the damage when a cross-site scripting bug does get through, and "+
				"one eventually does. Without it, any injected script — from a bug in your code, a "+
				"compromised third-party tag, or a supply-chain change in a CDN-hosted library — runs "+
				"with the full privileges of the page: it can read the DOM, take anything in local "+
				"storage, and post it anywhere it likes."+extra,
			"Deploy a policy in report-only mode first, then enforce it once the reports are clean",
			`add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;`,
			ev, "headers").WithLocation(loc+"#csp", finding.Component{}))
	}

	// --- MIME sniffing ---------------------------------------------------
	nosniff := strings.TrimSpace(resp.Header.Get("X-Content-Type-Options"))
	if !strings.EqualFold(nosniff, "nosniff") {
		what := "is absent"
		if nosniff != "" {
			what = "is set to " + strconv.Quote(nosniff) + ", which browsers ignore"
		}
		out = append(out, hdr(a, finding.SevLow, "web.nosniff-missing",
			"X-Content-Type-Options "+what+" on "+s.Name,
			"Browsers may disregard the declared Content-Type and guess from the bytes. Where a "+
				"site serves anything a user supplied — an upload, an avatar, a generated export — a "+
				"file stored as harmless text can be sniffed as script or as a stylesheet and executed "+
				"in this origin. Modern browsers sniff in fewer situations than they used to, so this "+
				"is a small residual risk rather than a large one; it is also a one-line fix.",
			"Send X-Content-Type-Options: nosniff on every response",
			`add_header X-Content-Type-Options "nosniff" always;`,
			ev, "headers").WithLocation(loc+"#nosniff", finding.Component{}))
	}

	// Cross-origin isolation and Permissions-Policy.
	//
	// Added after a live nuclei run flagged these on both public sites while
	// this collector reported only the missing CSP. They sit at info because
	// their absence is a missed hardening opportunity rather than a live
	// weakness — grouped into one finding, because they share a cause (nobody
	// has set the modern isolation headers) and one fix.
	modern := []struct{ header, why string }{
		{"Permissions-Policy", "controls which browser features (camera, microphone, geolocation, " +
			"payment) this origin and anything it embeds may use"},
		{"Cross-Origin-Opener-Policy", "stops a window this site opens, or that opened it, from " +
			"retaining a reference it can use for cross-origin attacks"},
		{"Cross-Origin-Embedder-Policy", "stops the page loading cross-origin resources that have " +
			"not opted in, which is what makes cross-origin isolation possible"},
		{"Cross-Origin-Resource-Policy", "stops other origins embedding this site's resources"},
		{"X-Permitted-Cross-Domain-Policies", "stops legacy Flash/PDF clients requesting a " +
			"cross-domain policy from this origin"},
	}
	var absent []string
	for _, m := range modern {
		if strings.TrimSpace(resp.Header.Get(m.header)) == "" {
			absent = append(absent, m.header+" — "+m.why)
		}
	}
	if len(absent) > 0 {
		out = append(out, hdr(a, finding.SevInfo, "web.modern-isolation-headers",
			fmt.Sprintf("%d modern isolation header(s) not set on %s", len(absent), s.Name),
			"These are defence-in-depth headers that constrain what the browser will let this "+
				"origin and its embeds do. Their absence is not an exploitable weakness on its own — "+
				"which is why this is informational — but each one closes a class of cross-origin "+
				"attack cheaply, and a site that sets none of them is relying entirely on the older "+
				"headers above.",
			"Add the isolation headers that suit the site; Permissions-Policy and "+
				"Cross-Origin-Resource-Policy are usually the two with the best ratio of value to risk",
			`add_header Cross-Origin-Resource-Policy "same-origin" always;`,
			[]finding.Evidence{{
				Command: "GET https://" + s.Name + "/",
				Output:  "not set:\n  " + strings.Join(absent, "\n  "),
			}}, "headers").WithLocation(loc+"#isolation", finding.Component{}))
	}

	// --- clickjacking ----------------------------------------------------
	xfo := strings.TrimSpace(resp.Header.Get("X-Frame-Options"))
	if xfo == "" && !cspHasDirective(csp, "frame-ancestors") {
		out = append(out, hdr(a, finding.SevMedium, "web.framing-unrestricted",
			"Nothing restricts who may frame "+s.Name,
			"Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so any site on the "+
				"internet can load these pages in an invisible frame over its own content. A signed-in "+
				"visitor who thinks they are clicking something on the attacker's page is clicking a "+
				"control on yours, with their session attached. That is only worth exploiting on pages "+
				"that carry authenticated state — but only the root page was checked here, so whether "+
				"such pages exist behind it is not something this finding can tell you.",
			"Set CSP frame-ancestors (X-Frame-Options is the legacy fallback for older browsers)",
			`add_header Content-Security-Policy "frame-ancestors 'none'" always;`,
			ev, "headers").WithLocation(loc+"#frame-ancestors", finding.Component{}))
	}

	// --- version disclosure ----------------------------------------------
	var disclosing []string
	for _, h := range []string{"Server", "X-Powered-By"} {
		v := strings.TrimSpace(resp.Header.Get(h))
		// A bare product name ("nginx", "Apache") is not worth a finding; a
		// version number is, because that is what turns a scan into a shortlist.
		if v != "" && containsDigit(v) {
			disclosing = append(disclosing, h+": "+v)
		}
	}
	if len(disclosing) > 0 {
		out = append(out, hdr(a, finding.SevLow, "web.version-disclosure",
			"Server software version is advertised by "+s.Name,
			"The response names the exact software version in use ("+strings.Join(disclosing, "; ")+
				"). This does not create a vulnerability, but it removes the reconnaissance step "+
				"from exploiting one: when a CVE lands for this version, mass scanners select "+
				"targets from this header directly, and this host is on the list within hours "+
				"instead of needing to be probed.",
			"Suppress the version in the response (nginx: server_tokens off; Apache: "+
				"ServerTokens Prod; PHP: expose_php Off)",
			"server_tokens off;",
			ev, "headers").WithLocation(loc+"#version-disclosure", finding.Component{}))
	}
	return out
}

// checkCookies inspects Set-Cookie attributes.
//
// Cookie VALUES are never recorded. A Set-Cookie on the root of a live site is
// very often a session identifier, and a scanner that writes one into a report
// has turned its own output into the credential store it is warning about.
func (w WebHeaders) checkCookies(a *finding.Asset, s site, resp *SiteResponse) []finding.Finding {
	var out []finding.Finding
	for _, c := range resp.Cookies {
		var missing []string
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if len(missing) == 0 {
			continue
		}

		// Both missing is materially worse than either alone: the cookie is
		// readable by script AND recoverable from the wire, so there is no
		// single control left standing.
		sev := finding.SevMedium
		if len(missing) == 2 {
			sev = finding.SevHigh
		}

		var why []string
		if !c.Secure {
			why = append(why, "Without Secure, the browser will attach this cookie to a plain "+
				"http:// request to the same host, so anyone on the network path can read it — "+
				"and an attacker who can inject any content into any page can force exactly such "+
				"a request.")
		}
		if !c.HttpOnly {
			why = append(why, "Without HttpOnly, any JavaScript running in this origin can read "+
				"the cookie, so a single cross-site scripting bug anywhere on the site is enough "+
				"to hand the session to someone else.")
		}
		sameSite := ""
		if c.SameSite == http.SameSiteDefaultMode {
			sameSite = " SameSite is also unset; browsers now default it to Lax, which is " +
				"reasonable, but stating it explicitly means the behaviour does not depend on the " +
				"browser version."
		}

		out = append(out, hdr(a, sev, "web.cookie-attributes",
			fmt.Sprintf("Cookie %q on %s is set without %s", c.Name, s.Name, strings.Join(missing, " or ")),
			strings.Join(why, " ")+sameSite+
				" Whether this particular cookie carries a session or something inert was not "+
				"determined — only its attributes were read.",
			fmt.Sprintf("Set %s on the %q cookie where the application issues it",
				strings.Join(missing, " and "), c.Name),
			fmt.Sprintf("Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax; Path=/", c.Name),
			[]finding.Evidence{{
				Command: "GET " + resp.URL,
				// Attributes only — never the value.
				Output: fmt.Sprintf("Set-Cookie: %s=<redacted>; Path=%s; Secure=%t; HttpOnly=%t; SameSite=%s",
					c.Name, orDefault(c.Path, "/"), c.Secure, c.HttpOnly, sameSiteName(c.SameSite)),
			}},
			"cookies").WithLocation(resp.URL+"#cookie="+c.Name, finding.Component{Name: c.Name}))
	}
	return out
}

// checkCertificate reports certificates that are close enough to expiry that
// renewal has to happen now.
//
// The thresholds are chosen around how renewal actually fails. ACME clients
// renew at 30 days remaining, so a certificate still unrenewed inside that
// window means the automation is not working — the alert has to fire while
// there is still time to find out why, not on the last day. Under 7 days there
// is no longer room for a business week of investigation, which is why that step
// is critical rather than merely urgent: expiry is a total outage, every browser
// shows a full-page interstitial and every API client fails the handshake.
func (w WebHeaders) checkCertificate(a *finding.Asset, s site, resp *SiteResponse) []finding.Finding {
	cert := resp.Cert
	if cert == nil {
		return nil
	}
	remaining := cert.NotAfter.Sub(clock.Now())
	days := int(remaining.Hours() / 24)

	var sev finding.Severity
	var title string
	switch {
	case remaining <= 0:
		sev, title = finding.SevCritical, fmt.Sprintf("TLS certificate for %s expired %d day(s) ago", s.Name, -days)
	case days < 7:
		sev, title = finding.SevCritical, fmt.Sprintf("TLS certificate for %s expires in %d day(s)", s.Name, days)
	case days < 30:
		sev, title = finding.SevHigh, fmt.Sprintf("TLS certificate for %s expires in %d days", s.Name, days)
	default:
		return nil
	}

	f := hdr(a, sev, "web.tls-cert-expiring", title,
		fmt.Sprintf("The certificate presented by %s is valid until %s. When it lapses this is not a "+
			"degraded experience, it is an outage: browsers show a full-page interstitial that most "+
			"users will not click through, and every API client and integration fails the handshake "+
			"outright. Renewals that are supposed to be automatic are exactly the ones that fail "+
			"quietly — a renewal timer that stopped weeks ago looks identical to one that is working "+
			"until the day it does not.",
			s.Name, cert.NotAfter.UTC().Format(time.RFC3339)),
		"Renew the certificate now, then check why the automatic renewal did not run "+
			"(systemctl status certbot.timer, or the equivalent for your ACME client)",
		"sudo certbot renew --force-renewal && sudo systemctl reload nginx",
		[]finding.Evidence{{
			Command: "TLS handshake with " + resp.URL,
			Output: fmt.Sprintf("subject: %s\nissuer: %s\nnot before: %s\nnot after: %s (%d day(s) remaining)\ndns names: %s",
				cert.Subject.CommonName, cert.Issuer.CommonName,
				cert.NotBefore.UTC().Format(time.RFC3339),
				cert.NotAfter.UTC().Format(time.RFC3339), days,
				strings.Join(cert.DNSNames, ", ")),
		}},
		"tls")
	return []finding.Finding{f.WithLocation(resp.URL+"#certificate",
		finding.Component{Name: cert.Issuer.CommonName})}
}

// fetchFailure turns a failed fetch into something readable.
//
// Certificate errors are the interesting case. They arrive as handshake
// failures, but "could not connect" would be a false and comforting summary of
// an expired or mismatched certificate — the users are seeing an interstitial
// right now. So the specific x509 failures become findings in their own right,
// and only genuinely unexplained failures degrade to an informational note.
func (w WebHeaders) fetchFailure(a *finding.Asset, s site, err error) []finding.Finding {
	loc := s.String()
	ev := []finding.Evidence{{Command: "GET " + loc, Output: err.Error()}}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return []finding.Finding{hdr(a, finding.SevCritical, "web.tls-cert-expired",
			"TLS certificate for "+s.Name+" is expired or not yet valid",
			"The handshake was rejected because the certificate is outside its validity window. "+
				"Every browser reaching this site is showing a full-page security interstitial and "+
				"every API client is failing to connect — this is a live outage, not a warning about "+
				"a future one.",
			"Renew the certificate and reload the web server, then fix the renewal automation",
			"sudo certbot renew --force-renewal && sudo systemctl reload nginx",
			ev, "tls").WithLocation(loc+"#certificate", finding.Component{})}
	}

	var wrongHost *x509.HostnameError
	if errors.As(err, &wrongHost) {
		return []finding.Finding{hdr(a, finding.SevHigh, "web.tls-cert-name-mismatch",
			"TLS certificate for "+s.Name+" does not cover that name",
			"The server presented a certificate issued for a different name. Visitors get a security "+
				"warning they must click through, which trains them to click through the identical "+
				"warning a real interception attack would produce. Note the connection was made to "+
				"this name from outside, so the certificate the default virtual host serves may "+
				"simply be the wrong one for this site.",
			"Issue or install a certificate covering "+s.Name+", or route the name to the vhost that has one",
			"", ev, "tls").WithLocation(loc+"#certificate", finding.Component{})}
	}

	var unknownCA x509.UnknownAuthorityError
	if errors.As(err, &unknownCA) {
		return []finding.Finding{hdr(a, finding.SevMedium, "web.tls-cert-untrusted",
			"TLS certificate for "+s.Name+" is not issued by a trusted authority",
			"The certificate chain does not lead to a public root — typically a self-signed "+
				"certificate or a private CA. Inside an estate that trusts that CA this is a "+
				"deliberate and fine arrangement; reachable by anyone else it means visitors are "+
				"asked to accept a certificate they cannot verify, and an interception attack "+
				"looks exactly the same to them.",
			"Install a publicly trusted certificate, or confirm this name is only ever reached "+
				"by clients that trust the private CA",
			"", ev, "tls").WithLocation(loc+"#certificate", finding.Component{})}
	}

	// Anything else — DNS, refused connection, timeout, a TLS version below the
	// 1.2 floor. Recorded rather than dropped: a site the operator believes is
	// being checked, and is not, is the worst outcome available here.
	return []finding.Finding{hdr(a, finding.SevInfo, "web.site-not-checked",
		"Web checks did not run against "+s.Name,
		"This site could not be fetched from the scanner, so none of the header, cookie or "+
			"certificate checks ran against it. The cause may be entirely benign — the name may "+
			"resolve elsewhere, or a firewall may block the scanner — but the result is a gap in "+
			"coverage, and an empty result here must not be read as a clean one.",
		"Confirm the name resolves to this host and that the scanner can reach it, or remove "+
			"it from the target's virtual-host list if it is no longer served here",
		"", ev, "coverage").WithLocation(loc+"#unreachable", finding.Component{})}
}

// ------------------------------------------------------------------ fetching

const (
	webDialTimeout = 6 * time.Second
	webFetchBudget = 12 * time.Second
	webMaxHops     = 3
)

// dialFetcher speaks HTTP/1.1 over a TLS connection it owns.
//
// The shared internal/httpx client is not used here for one specific reason:
// its Get returns the body and discards the response, and the response headers
// and the peer certificate ARE the finding in this collector. Owning the
// connection also means a single dial answers both questions — what the
// certificate says and what the headers say — instead of two round trips to a
// production site. The two properties httpx exists to guarantee are kept
// explicitly: a TLS 1.2 floor, and a hard timeout on every fetch.
type dialFetcher struct{}

func (d dialFetcher) Fetch(ctx context.Context, name string, port int) (*SiteResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, webFetchBudget)
	defer cancel()

	path := "/"
	for hop := 0; ; hop++ {
		resp, err := fetchOnce(ctx, name, port, path)
		if err != nil {
			return nil, err
		}
		loc := resp.Header.Get("Location")
		if resp.Status < 300 || resp.Status > 399 || loc == "" {
			return resp, nil
		}
		if hop >= webMaxHops {
			resp.StoppedAt = "stopped after " + strconv.Itoa(webMaxHops) + " redirects"
			return resp, nil
		}
		next, err := url.Parse(loc)
		if err != nil {
			resp.StoppedAt = "unparseable Location header"
			return resp, nil
		}
		// Only same-name, same-port redirects are followed. A redirect to
		// another host leads to a system this scan was not asked to touch, and
		// the headers there would be attributed to the wrong asset.
		if next.Host != "" && !strings.EqualFold(hostOnly(next.Host), name) {
			resp.StoppedAt = "redirects to " + hostOnly(next.Host) + ", which was not followed"
			return resp, nil
		}
		if next.Scheme != "" && next.Scheme != "https" {
			resp.StoppedAt = "redirects to " + next.Scheme + ", which was not followed"
			return resp, nil
		}
		p := next.EscapedPath()
		if p == "" {
			p = "/"
		}
		if next.RawQuery != "" {
			p += "?" + next.RawQuery
		}
		if p == path {
			resp.StoppedAt = "redirect loop"
			return resp, nil
		}
		path = p
	}
}

func fetchOnce(ctx context.Context, name string, port int, path string) (*SiteResponse, error) {
	addr := net.JoinHostPort(name, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: webDialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	// The read deadline is driven from the context rather than a SetDeadline
	// call, because the only time source available here is clock.Now(), and a
	// frozen test clock would make an absolute deadline meaningless.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	// Certificates ARE verified. Accepting any certificate would turn an
	// expired or mismatched one — a real, user-visible failure — into a silent
	// success, which is the opposite of what this collector is for. The TLS 1.2
	// floor matches internal/httpx; a server below it fails the handshake and
	// is reported as unchecked with the reason attached.
	conn := tls.Client(raw, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	hostHeader := name
	if port != 443 {
		hostHeader = addr
	}
	target := "https://" + hostHeader + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "secscan/1 (security posture scan; reads response headers only)")
	req.Header.Set("Accept", "*/*")
	// Connection: close — one request per connection keeps the read bounded and
	// leaves nothing idle on a production server.
	req.Close = true
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	// The body is never read: no check needs it, and never holding it means no
	// response content can reach a report.
	defer resp.Body.Close()

	st := conn.ConnectionState()
	out := &SiteResponse{
		URL:        target,
		Status:     resp.StatusCode,
		Header:     resp.Header,
		Cookies:    resp.Cookies(),
		TLSVersion: tls.VersionName(st.Version),
	}
	if len(st.PeerCertificates) > 0 {
		out.Cert = st.PeerCertificates[0]
	}
	return out, nil
}

// ------------------------------------------------------------------- helpers

// hstsMaxAge extracts max-age from a Strict-Transport-Security header.
func hstsMaxAge(v string) (int, bool) {
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "max-age") {
			continue
		}
		i := strings.Index(part, "=")
		if i < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(part[i+1:]), `"`))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// cspHasDirective reports whether a CSP names a directive. Directives are
// separated by ';' and the name is the first token of each.
func cspHasDirective(csp, name string) bool {
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(strings.TrimSpace(d))
		if len(f) > 0 && strings.EqualFold(f[0], name) {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	}
	return "(unset)"
}

func orDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// hostOnly strips a port from a URL host, tolerating IPv6 brackets.
func hostOnly(h string) string {
	if x, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(x, "[]")
	}
	return strings.Trim(h, "[]")
}

func joinPorts(ports []int) string {
	sortInts(ports)
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p)
	}
	return strings.Join(out, ", ")
}

// sortInts is an insertion sort: these slices hold a handful of ports, and
// pulling in sort for that is more import than it is worth.
func sortInts(xs []int) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
