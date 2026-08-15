package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/auth"
	"github.com/jchirayath/secscan/internal/rbac"
)

// fakeAuth lets a test act as any role without an Entra tenant.
type fakeAuth struct {
	p   auth.Principal
	err error
}

func (f fakeAuth) Authenticate(*http.Request) (auth.Principal, error) { return f.p, f.err }
func (fakeAuth) Mode() string                                        { return "test" }
func (fakeAuth) Routes(*http.ServeMux)                               {}

func serverWith(t *testing.T, a auth.Authenticator) *Server {
	t.Helper()
	lg, err := audit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Server{auth: a, audit: lg, scanning: map[string]bool{}}
}

// TestGuardEnforcesCapabilityPerRole is the test that matters most in this
// package. The classic gap is hundreds of routes against a few capability checks
// while its UI claims otherwise; this asserts the boundary actually exists for
// every role, including the denial cases.
func TestGuardEnforcesCapabilityPerRole(t *testing.T) {
	cases := []struct {
		role rbac.Role
		cap  rbac.Capability
		want int
	}{
		{rbac.RoleViewer, rbac.CapFindingRead, 200},
		{rbac.RoleViewer, rbac.CapEvidenceRead, 403},
		{rbac.RoleViewer, rbac.CapScanRun, 403},
		{rbac.RoleViewer, rbac.CapFindingSuppress, 403},
		{rbac.RoleAuditor, rbac.CapEvidenceRead, 200},
		{rbac.RoleAuditor, rbac.CapAuditRead, 200},
		{rbac.RoleAuditor, rbac.CapFindingSuppress, 403},
		{rbac.RoleAuditor, rbac.CapScanRun, 403},
		{rbac.RoleAnalyst, rbac.CapFindingSuppress, 200},
		{rbac.RoleAnalyst, rbac.CapScanRun, 403},
		{rbac.RoleOperator, rbac.CapScanRun, 200},
		{rbac.RoleOperator, rbac.CapConfigRead, 403},
		{rbac.RoleAdmin, rbac.CapConfigRead, 200},
	}

	for _, c := range cases {
		s := serverWith(t, fakeAuth{p: auth.Principal{Email: "u@example.com", Role: c.role}})
		h := s.Guard(c.cap, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
		if rec.Code != c.want {
			t.Errorf("role %s cap %s: got %d, want %d", c.role, c.cap, rec.Code, c.want)
		}
	}
}

// TestGuardDeniesUnauthenticated proves the default is deny, not allow.
func TestGuardDeniesUnauthenticated(t *testing.T) {
	s := serverWith(t, fakeAuth{err: http.ErrNoCookie})
	called := false
	h := s.Guard(rbac.CapFindingRead, func(http.ResponseWriter, *http.Request) { called = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))

	if rec.Code != 401 {
		t.Errorf("got %d, want 401", rec.Code)
	}
	if called {
		t.Error("handler ran despite failed authentication — this is an auth bypass")
	}
}

// TestGuardDeniesUnknownRole covers the case where a forged or stale session
// carries a role string we do not recognise. An unknown role must hold nothing.
func TestGuardDeniesUnknownRole(t *testing.T) {
	s := serverWith(t, fakeAuth{p: auth.Principal{Email: "u@example.com", Role: rbac.Role("superuser")}})
	h := s.Guard(rbac.CapFindingRead, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Code != 403 {
		t.Errorf("unknown role got %d, want 403", rec.Code)
	}
}

// TestDenialsAreAudited: a denial nobody can see is not a control.
func TestDenialsAreAudited(t *testing.T) {
	dir := t.TempDir()
	lg, _ := audit.Open(dir)
	s := &Server{
		auth:  fakeAuth{p: auth.Principal{Email: "viewer@example.com", Role: rbac.RoleViewer}},
		audit: lg, scanning: map[string]bool{},
	}
	h := s.Guard(rbac.CapScanRun, func(http.ResponseWriter, *http.Request) {})
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/scan", nil))

	entries := lg.Tail(10)
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Result != "denied" {
		t.Errorf("result = %q, want denied", e.Result)
	}
	// Caller AND role, separately. A record with only
	// one of them cannot answer "which of the four admins?" or "under what
	// privilege?".
	if e.Caller != "viewer@example.com" {
		t.Errorf("caller = %q", e.Caller)
	}
	if e.Role != "viewer" {
		t.Errorf("role = %q — caller and role must both be recorded", e.Role)
	}
}

// principalFor builds a test principal for a role name.
func principalFor(role string) auth.Principal {
	return auth.Principal{Email: role + "@example.com", Name: role, Role: rbac.Role(role)}
}
