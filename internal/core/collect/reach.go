package collect

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/core/finding"
)

// Reachability turns "bound to 0.0.0.0" into "actually reachable, and by whom".
//
// This is the half of the exposure model that a host-local collector cannot
// answer. A socket bound to all interfaces is only *potentially* exposed: a
// cloud NSG, a security group, or an upstream firewall may drop it entirely,
// and an authenticating reverse proxy may front it. Scoring on the bind address
// alone over-ranks both cases — which is exactly what happened in testing, where
// ttyd binds 0.0.0.0:7681 but is unreachable externally and fronted by Caddy
// with Entra sign-in.
//
// The probe runs from the scanner's vantage point, so what it measures is
// literally "can something outside the host reach this?" — the question that
// matters.
type Reachability struct {
	// Probe is the dialer, injectable for tests.
	Probe Prober
}

// Prober answers whether host:port accepts a connection, and what answers.
type Prober interface {
	Dial(ctx context.Context, hostport string, timeout time.Duration) bool
	HTTPProbe(ctx context.Context, url string, timeout time.Duration) (status int, location string, ok bool)
}

// Exposure is the verdict for one listener.
type Exposure int

const (
	// ExposureUnknown — we could not test (no public address for the target).
	ExposureUnknown Exposure = iota
	// ExposureBlocked — bound wide, but not reachable from outside. Something
	// upstream is protecting it.
	ExposureBlocked
	// ExposureProxied — reachable, but an authenticating proxy stands in front.
	ExposureProxied
	// ExposureOpen — reachable, and nothing asked us who we were.
	ExposureOpen
)

func (e Exposure) String() string {
	switch e {
	case ExposureBlocked:
		return "blocked upstream"
	case ExposureProxied:
		return "behind authentication"
	case ExposureOpen:
		return "openly reachable"
	}
	return "not tested"
}

// realProber uses the network. Timeouts are short: a scan must not stall on a
// silently-dropped packet, and a drop is itself the answer.
type realProber struct{}

func (realProber) Dial(ctx context.Context, hostport string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (realProber) HTTPProbe(ctx context.Context, url string, timeout time.Duration) (int, string, bool) {
	// This client deliberately does NOT follow redirects — the redirect target
	// is the signal we are looking for.
	//
	// secscan:allow-insecure-tls  Certificate validation is skipped for THIS
	// probe only. Justification: we are measuring reachability, not consuming
	// content. Nothing from the response is trusted, stored or rendered beyond
	// the status code and the Location host. Verifying instead would make every
	// self-signed service fail the handshake and be misreported as unreachable
	// — i.e. it would *under*-report exposure, which is the dangerous direction
	// for a security tool. This is the only permitted use in the codebase and
	// ci/guards.sh requires this marker to be present.
	client := &http.Client{ //secscan:allow-http-client-literal probe needs redirect suppression
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //secscan:allow-insecure-tls exposure probe
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), true
}

// authenticatingHosts are redirect targets that mean "an identity provider is
// in front of this". A service that bounces an anonymous request to one of
// these is not an open service.
var authenticatingHosts = []string{
	"login.microsoftonline.com",
	"login.microsoft.com",
	"sts.windows.net",
	"accounts.google.com",
	"okta.com",
	"auth0.com",
}

// Classify probes one wide-bound port on the target's public address, plus any
// virtual hosts the operator has declared.
//
// The aggregate rule is worst-case: if ANY name served on that port answers
// anonymously, the port is openly reachable. A single protected vhost does not
// make the port safe, and saying otherwise would be the comfortable-but-wrong
// answer.
func (rc Reachability) Classify(ctx context.Context, publicHost string, port int, proto string, vhosts ...string) (Exposure, string) {
	if publicHost == "" || proto != "tcp" {
		return ExposureUnknown, "no public address to probe from outside"
	}
	p := rc.Probe
	if p == nil {
		p = realProber{}
	}

	hostport := net.JoinHostPort(publicHost, fmt.Sprint(port))
	if !p.Dial(ctx, hostport, 4*time.Second) {
		return ExposureBlocked, fmt.Sprintf(
			"TCP connect to %s from outside the host failed — a firewall or "+
				"cloud security group is dropping it", hostport)
	}

	// It answers. Now find out whether anything asks who we are — for the
	// default site and for every declared virtual host.
	names := append([]string{publicHost}, vhosts...)
	var open, protected []string
	sawHTTP := false

	for _, name := range names {
		verdict, detail := rc.probeName(ctx, p, name, port)
		switch verdict {
		case ExposureProxied:
			sawHTTP = true
			protected = append(protected, name+" ("+detail+")")
		case ExposureOpen:
			sawHTTP = true
			open = append(open, name+" ("+detail+")")
		}
	}

	switch {
	case !sawHTTP:
		return ExposureOpen, fmt.Sprintf(
			"TCP connect to %s from outside the host succeeded (no HTTP response to fingerprint)", hostport)
	case len(open) > 0:
		msg := "reachable from outside without authentication: " + strings.Join(open, ", ")
		if len(protected) > 0 {
			msg += ". Other names on this port ARE protected: " + strings.Join(protected, ", ") +
				" — but the port is only as protected as its weakest site."
		}
		return ExposureOpen, msg
	default:
		return ExposureProxied, "reachable, but every site probed on this port requires " +
			"authentication: " + strings.Join(protected, ", ")
	}
}

// probeName tests one Host name on a port, following the scheme most likely to
// answer first.
func (rc Reachability) probeName(ctx context.Context, p Prober, name string, port int) (Exposure, string) {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(name, fmt.Sprint(port)))
		status, loc, ok := p.HTTPProbe(ctx, url, 5*time.Second)
		if !ok {
			continue
		}
		if status == 401 || status == 403 {
			return ExposureProxied, fmt.Sprintf("HTTP %d to an anonymous request", status)
		}
		if loc != "" {
			for _, idp := range authenticatingHosts {
				if strings.Contains(strings.ToLower(loc), idp) {
					return ExposureProxied, "redirects to " + idp
				}
			}
		}
		return ExposureOpen, fmt.Sprintf("HTTP %d", status)
	}
	return ExposureUnknown, ""
}

// Apply re-weights network findings using live reachability, and annotates each
// with what was actually observed. Called by the scan orchestrator after the
// Listeners collector has run.
//
// The severity movement is the point:
//   - blocked upstream  → drop to info and clear Exposed. The bind is untidy,
//     not dangerous.
//   - behind auth       → down one step, keep it visible. An authenticating
//     proxy is a real control, but it is one control.
//   - openly reachable  → keep, and say so with evidence.
func (rc Reachability) Apply(ctx context.Context, fs []finding.Finding, publicHost string, vhosts ...string) int {
	tested := 0
	for i := range fs {
		f := &fs[i]
		if f.RuleID != "network.wide-bind" {
			continue
		}
		proto, port, ok := protoPort(f.Location)
		if !ok {
			continue
		}
		verdict, why := rc.Classify(ctx, publicHost, port, proto, vhosts...)
		if verdict == ExposureUnknown {
			continue
		}
		tested++

		f.Evidence = append(f.Evidence, finding.Evidence{
			Command: fmt.Sprintf("probe %s:%d from the scanner", publicHost, port),
			Output:  why,
		})
		f.Subcategory = "listening-port/" + verdict.String()

		switch verdict {
		case ExposureBlocked:
			f.Exposed = false
			f.Severity = finding.SevInfo
			f.Title = strings.Replace(f.Title, "listening on all interfaces",
				"binds all interfaces (blocked upstream)", 1)
			f.Description += "\n\nVerified from outside the host: the port is not reachable. " +
				"A firewall or cloud security group is blocking it, so this is a tidiness " +
				"issue rather than an exposure."
			f.Remediation.Summary = "Optional: bind to 127.0.0.1 so the host does not rely " +
				"solely on the upstream firewall"
		case ExposureProxied:
			f.Exposed = true
			f.Severity = downOne(f.Severity)
			f.Title = strings.Replace(f.Title, "listening on all interfaces",
				"reachable, behind authentication", 1)
			f.Description += "\n\nVerified from outside the host: reachable, but an " +
				"authenticating proxy stands in front. That is a real control — the " +
				"residual risk is that the service itself is reachable if the proxy is " +
				"bypassed or misconfigured."
			f.Remediation.Summary = "Confirm the service only accepts connections from the " +
				"proxy (bind to loopback or the proxy's interface)"
		case ExposureOpen:
			f.Exposed = true
			f.Description += "\n\nVerified from outside the host: openly reachable with no " +
				"authentication challenge."
		}
	}
	return tested
}

func downOne(s finding.Severity) finding.Severity {
	switch s {
	case finding.SevCritical:
		return finding.SevHigh
	case finding.SevHigh:
		return finding.SevMedium
	case finding.SevMedium:
		return finding.SevLow
	}
	return finding.SevLow
}

// protoPort parses the "tcp/22" location the Listeners collector writes.
func protoPort(loc string) (string, int, bool) {
	i := strings.Index(loc, "/")
	if i < 0 {
		return "", 0, false
	}
	proto := loc[:i]
	var port int
	if _, err := fmt.Sscanf(loc[i+1:], "%d", &port); err != nil {
		return "", 0, false
	}
	return proto, port, true
}
