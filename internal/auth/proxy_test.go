package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jchirayath/secscan/internal/config"
	"github.com/jchirayath/secscan/internal/rbac"
)

func proxyMode(t *testing.T, admins, domains []string) *proxyAuth {
	t.Helper()
	a, err := New(&config.Config{
		AuthMode:       "proxy",
		TrustedProxies: []string{"172.18.0.0/16"},
		AdminEmails:    admins,
		AllowedDomains: domains,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p, ok := a.(*proxyAuth)
	if !ok {
		t.Fatalf("want *proxyAuth, got %T", a)
	}
	return p
}

// req builds a request as it arrives from the reverse proxy: from a trusted
// peer, carrying the identity header the proxy set.
func req(email string, roles string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.18.0.2:54321"
	if email != "" {
		r.Header.Set("X-MS-CLIENT-PRINCIPAL-NAME", email)
	}
	if roles != "" {
		r.Header.Set("X-MS-CLIENT-PRINCIPAL-ROLES", roles)
	}
	return r
}

// The regression this file exists for. Identity-aware proxies commonly forward
// an email and no roles at all — oauth2-proxy does — and proxy mode used to
// derive the role ONLY from the roles header. That left the configured admin
// authenticated but stuck on viewer, with the scan controls absent and nothing
// on screen explaining why. SECSCAN_ADMIN_EMAILS must elevate here exactly as
// it does in entra mode.
func TestProxyAdminEmailElevatesWithoutRolesHeader(t *testing.T) {
	p := proxyMode(t, []string{"admin@example.com"}, nil)

	got, err := p.Authenticate(req("admin@example.com", ""))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Role != rbac.RoleAdmin {
		t.Errorf("admin email did not elevate: got role %q, want %q", got.Role, rbac.RoleAdmin)
	}
}

func TestProxyAdminEmailIsCaseInsensitive(t *testing.T) {
	p := proxyMode(t, []string{"Admin@Example.com"}, nil)

	got, err := p.Authenticate(req("admin@example.COM", ""))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Role != rbac.RoleAdmin {
		t.Errorf("got role %q, want %q — directory casing must not decide access", got.Role, rbac.RoleAdmin)
	}
}

// Elevation is per-identity, not a blanket grant to everyone the proxy lets in.
func TestProxyNonAdminStaysViewer(t *testing.T) {
	p := proxyMode(t, []string{"admin@example.com"}, nil)

	got, err := p.Authenticate(req("someone@example.com", ""))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Role != rbac.RoleViewer {
		t.Errorf("got role %q, want %q", got.Role, rbac.RoleViewer)
	}
}

// A proxy that DOES send roles keeps working, and the admin list can only ever
// raise the result — never quietly lower a role the proxy asserted.
func TestProxyRolesHeaderStillHonoured(t *testing.T) {
	p := proxyMode(t, []string{"admin@example.com"}, nil)

	got, err := p.Authenticate(req("someone@example.com", "operator"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Role != rbac.RoleOperator {
		t.Errorf("roles header ignored: got %q, want %q", got.Role, rbac.RoleOperator)
	}
}

// The proxy vouches for who the caller is; it does not decide whether that
// identity may use this instance. A proxy shared between apps will happily
// authenticate someone outside the intended tenant.
func TestProxyRejectsIdentityOutsideAllowedDomains(t *testing.T) {
	p := proxyMode(t, nil, []string{"example.com"})

	if _, err := p.Authenticate(req("intruder@evil.test", "")); err == nil {
		t.Fatal("identity outside the allowed domains was accepted")
	}
	if _, err := p.Authenticate(req("ok@example.com", "")); err != nil {
		t.Fatalf("in-domain identity rejected: %v", err)
	}
}

func TestProxyEmptyAllowedDomainsPermitsAny(t *testing.T) {
	p := proxyMode(t, nil, nil)
	if _, err := p.Authenticate(req("anyone@anywhere.test", "")); err != nil {
		t.Fatalf("empty allow-list should not restrict: %v", err)
	}
}

// The peer check is the whole basis for trusting the header at all.
func TestProxyRejectsUntrustedPeer(t *testing.T) {
	p := proxyMode(t, []string{"admin@example.com"}, nil)

	r := req("admin@example.com", "admin")
	r.RemoteAddr = "203.0.113.7:1234" // not in 172.18.0.0/16
	if _, err := p.Authenticate(r); err == nil {
		t.Fatal("identity headers from an untrusted peer were accepted — auth bypass")
	}
}

func TestProxyRejectsMissingIdentityHeader(t *testing.T) {
	p := proxyMode(t, []string{"admin@example.com"}, nil)

	if _, err := p.Authenticate(req("", "")); err == nil {
		t.Fatal("request with no identity header was accepted")
	}
}
