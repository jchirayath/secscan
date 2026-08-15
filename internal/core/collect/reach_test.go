package collect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/secscan/internal/core/finding"
)

// fakeProber replays scripted network behaviour so the exposure logic is
// tested without touching the network.
type fakeProber struct {
	dialable map[string]bool
	http     map[string]struct {
		status int
		loc    string
		ok     bool
	}
}

func (f fakeProber) Dial(_ context.Context, hostport string, _ time.Duration) bool {
	return f.dialable[hostport]
}

func (f fakeProber) HTTPProbe(_ context.Context, url string, _ time.Duration) (int, string, bool) {
	r, ok := f.http[url]
	if !ok {
		return 0, "", false
	}
	return r.status, r.loc, r.ok
}

type httpResp = struct {
	status int
	loc    string
	ok     bool
}

// TestBlockedUpstreamIsNotExposed is a real-world case: a service bound to
// 0.0.0.0 but dropped by a cloud security group. Scoring it as internet-facing
// is the over-ranking that erodes trust in the whole ordering.
func TestBlockedUpstreamIsNotExposed(t *testing.T) {
	rc := Reachability{Probe: fakeProber{dialable: map[string]bool{}}}
	verdict, why := rc.Classify(context.Background(), "host.example", 7681, "tcp")

	if verdict != ExposureBlocked {
		t.Fatalf("verdict = %v, want blocked", verdict)
	}
	if !strings.Contains(why, "firewall") {
		t.Errorf("explanation should name the cause: %q", why)
	}
}

// TestIdentityProviderRedirectIsProxied is the app.example.net case: reachable,
// but an anonymous request bounces to Entra.
func TestIdentityProviderRedirectIsProxied(t *testing.T) {
	rc := Reachability{Probe: fakeProber{
		dialable: map[string]bool{"host.example:443": true},
		http: map[string]httpResp{
			"https://host.example:443/": {302, "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?x=1", true},
		},
	}}
	verdict, why := rc.Classify(context.Background(), "host.example", 443, "tcp")

	if verdict != ExposureProxied {
		t.Fatalf("verdict = %v, want proxied", verdict)
	}
	if !strings.Contains(why, "login.microsoftonline.com") {
		t.Errorf("explanation should name the identity provider: %q", why)
	}
}

// TestWorstCaseAcrossVirtualHosts: one protected vhost must not make a port
// look safe when another on the same port answers anonymously.
func TestWorstCaseAcrossVirtualHosts(t *testing.T) {
	rc := Reachability{Probe: fakeProber{
		dialable: map[string]bool{"host.example:443": true},
		http: map[string]httpResp{
			"https://host.example:443/": {200, "", true},
			"https://ssh.example:443/":  {302, "https://login.microsoftonline.com/t/oauth2/v2.0/authorize", true},
		},
	}}
	verdict, why := rc.Classify(context.Background(), "host.example", 443, "tcp", "ssh.example")

	if verdict != ExposureOpen {
		t.Fatalf("verdict = %v, want open — a port is only as protected as its weakest site", verdict)
	}
	// The protected site must still be reported, or the operator cannot tell
	// which name is the problem.
	if !strings.Contains(why, "ssh.example") || !strings.Contains(why, "host.example") {
		t.Errorf("explanation should name both sites: %q", why)
	}
}

func TestAllVirtualHostsProtected(t *testing.T) {
	idp := "https://login.microsoftonline.com/t/oauth2/v2.0/authorize"
	rc := Reachability{Probe: fakeProber{
		dialable: map[string]bool{"host.example:443": true},
		http: map[string]httpResp{
			"https://host.example:443/": {401, "", true},
			"https://ssh.example:443/":  {302, idp, true},
		},
	}}
	if v, _ := rc.Classify(context.Background(), "host.example", 443, "tcp", "ssh.example"); v != ExposureProxied {
		t.Errorf("verdict = %v, want proxied when every site authenticates", v)
	}
}

// TestApplyRewritesSeverity checks the finding actually moves, not just the
// verdict — this is what changes the ranking.
func TestApplyRewritesSeverity(t *testing.T) {
	mk := func(loc string, sev finding.Severity) finding.Finding {
		return finding.Finding{
			RuleID: "network.wide-bind", Location: loc, Severity: sev,
			Exposed: true, Title: "Service on " + loc + " listening on all interfaces",
		}
	}
	fs := []finding.Finding{mk("tcp/7681", finding.SevLow), mk("tcp/22", finding.SevHigh)}

	rc := Reachability{Probe: fakeProber{
		dialable: map[string]bool{"host.example:22": true}, // 7681 blocked
		http:     map[string]httpResp{},
	}}
	n := rc.Apply(context.Background(), fs, "host.example")
	if n != 2 {
		t.Fatalf("probed %d ports, want 2", n)
	}

	blocked := fs[0]
	if blocked.Exposed {
		t.Error("blocked port still marked exposed")
	}
	if blocked.Severity != finding.SevInfo {
		t.Errorf("blocked port severity = %s, want info", blocked.Severity)
	}
	if !strings.Contains(blocked.Title, "blocked upstream") {
		t.Errorf("title not updated: %q", blocked.Title)
	}
	if len(blocked.Evidence) == 0 {
		t.Error("no probe evidence attached — the reclassification must be justified")
	}

	open := fs[1]
	if !open.Exposed || open.Severity != finding.SevHigh {
		t.Errorf("reachable port was downgraded: exposed=%v sev=%s", open.Exposed, open.Severity)
	}
}

func TestProtoPort(t *testing.T) {
	cases := []struct {
		in    string
		proto string
		port  int
		ok    bool
	}{
		{"tcp/22", "tcp", 22, true},
		{"udp/443", "udp", 443, true},
		{"nonsense", "", 0, false},
		{"tcp/", "", 0, false},
	}
	for _, c := range cases {
		p, n, ok := protoPort(c.in)
		if ok != c.ok || (ok && (p != c.proto || n != c.port)) {
			t.Errorf("protoPort(%q) = (%q,%d,%v), want (%q,%d,%v)", c.in, p, n, ok, c.proto, c.port, c.ok)
		}
	}
}
