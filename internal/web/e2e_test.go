package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/secscan/internal/config"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/scan"
	"github.com/jchirayath/secscan/internal/store"
)

// End-to-end: boot the real server on a real socket, run a real scan against
// localhost, and drive the whole API the way the dashboard does. No mocks in
// the path — if this passes, the product works.
//
// The one thing stubbed is the authenticator, so the suite can act as each role
// without an Entra tenant. Everything else is production code.

type e2e struct {
	t    *testing.T
	base string
	srv  *Server
}

func startE2E(t *testing.T, role string) *e2e {
	t.Helper()
	dir := t.TempDir()

	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// localhost target: no SSH, no network, works in CI.
	if err := st.SetTargets([]exec.Target{{Name: "localhost"}}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Home: dir, Bind: "127.0.0.1:0", AuthMode: "local",
		ScanTimeout: 90 * time.Second, SSHTimeout: 5 * time.Second,
		HTTPTimeout: 10 * time.Second, SessionTTL: time.Hour,
	}
	srv, err := New(cfg, st, "e2e")
	if err != nil {
		t.Fatal(err)
	}
	srv.auth = fakeAuth{p: principalFor(role)}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.securityHeaders(srv.mux), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})

	return &e2e{t: t, base: "http://" + ln.Addr().String(), srv: srv}
}

func (e *e2e) do(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.base+path, rdr)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var out map[string]any
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// seedScan runs a genuine scan of localhost through production code.
func (e *e2e) seedScan() {
	e.t.Helper()
	res, err := scan.Run(context.Background(), exec.Target{Name: "localhost"}, scan.Options{
		Timeout: 90 * time.Second, SkipEngines: true, SkipReachability: true,
	})
	if err != nil {
		e.t.Fatalf("scan: %v", err)
	}
	if _, _, err := e.srv.store.Merge(res.Asset, res.Findings, scan.CoverageOf(res)); err != nil {
		e.t.Fatal(err)
	}
	if err := e.srv.store.AppendHistory(scan.Summarise(res, len(res.Findings), 0)); err != nil {
		e.t.Fatal(err)
	}
}

// ---------------------------------------------------------------- the flow

// TestE2E_FullJourney walks the exact path a user takes through the dashboard.
func TestE2E_FullJourney(t *testing.T) {
	e := startE2E(t, "admin")
	e.seedScan()

	t.Run("healthz needs no auth", func(t *testing.T) {
		resp, err := http.Get(e.base + "/healthz")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("healthz: %v %v", err, resp)
		}
		resp.Body.Close()
	})

	t.Run("UI shell serves with a strict CSP", func(t *testing.T) {
		resp, err := http.Get(e.base + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("got %d", resp.StatusCode)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("CSP missing %q: %s", want, csp)
			}
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Error("missing X-Frame-Options: DENY")
		}
		body, _ := io.ReadAll(resp.Body)
		// The asset URL must carry the running version. A browser that cached
		// app.js under a bare URL would otherwise keep serving it after an
		// upgrade, pairing an old UI with a new API — which surfaces as
		// unreproducible bugs rather than as "your cache is stale".
		if !strings.Contains(string(body), `src="/app.js?v=e2e"`) {
			t.Errorf("shell must reference a version-stamped bundle, got:\n%s", body)
		}
		if !strings.Contains(string(body), `href="/app.css?v=e2e"`) {
			t.Error("stylesheet URL is not version-stamped")
		}
	})

	t.Run("assets revalidate rather than being cached forever", func(t *testing.T) {
		resp, err := http.Get(e.base + "/app.js")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Fatal("no ETag on a static asset")
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("Cache-Control = %q, want no-cache", cc)
		}
		// A matching ETag must produce a 304, or "no-cache" would mean
		// re-transferring the whole bundle on every navigation.
		req, _ := http.NewRequest("GET", e.base+"/app.js", nil)
		req.Header.Set("If-None-Match", etag)
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r2.Body.Close()
		if r2.StatusCode != http.StatusNotModified {
			t.Errorf("matching ETag returned %d, want 304", r2.StatusCode)
		}
	})

	t.Run("static assets serve", func(t *testing.T) {
		for _, path := range []string{"/app.js", "/app.css"} {
			code, _ := e.do("GET", path, nil)
			if code != 200 {
				t.Errorf("%s: got %d", path, code)
			}
		}
	})

	var findingID string

	t.Run("overview carries provenance and real findings", func(t *testing.T) {
		code, body := e.do("GET", "/api/overview", nil)
		if code != 200 {
			t.Fatalf("got %d", code)
		}
		if body["provenance"] != "live" {
			t.Errorf("provenance = %v, want live", body["provenance"])
		}
		if body["as_of"] == nil {
			t.Error("no as_of timestamp")
		}
		d := body["data"].(map[string]any)
		if score, _ := d["score"].(float64); score <= 0 || score > 100 {
			t.Errorf("score %v out of range", d["score"])
		}
		cats := d["categories"].([]any)
		if len(cats) != 10 {
			t.Errorf("got %d categories, want 10", len(cats))
		}
		if len(d["assets"].([]any)) == 0 {
			t.Fatal("no assets after a scan")
		}
	})

	t.Run("findings list paginates", func(t *testing.T) {
		code, body := e.do("GET", "/api/findings?page_size=1", nil)
		if code != 200 {
			t.Fatalf("got %d", code)
		}
		if body["page_size"].(float64) != 1 {
			t.Errorf("page_size = %v", body["page_size"])
		}
		data := body["data"].([]any)
		if len(data) != 1 {
			t.Fatalf("got %d rows for page_size=1", len(data))
		}
		findingID = data[0].(map[string]any)["id"].(string)
	})

	t.Run("finding detail shows evidence and explains the score", func(t *testing.T) {
		code, body := e.do("GET", "/api/findings/"+findingID, nil)
		if code != 200 {
			t.Fatalf("got %d", code)
		}
		d := body["data"].(map[string]any)
		f := d["finding"].(map[string]any)
		if f["title"] == "" {
			t.Error("finding has no title")
		}
		if len(f["evidence"].([]any)) == 0 {
			t.Error("no evidence — no claim without proof")
		}
		factors := d["risk_factors"].([]any)
		if len(factors) == 0 {
			t.Fatal("no risk factors — the score must be explainable")
		}
		// The factors must actually multiply to the score shown.
		product := 1.0
		for _, x := range factors {
			product *= x.(map[string]any)["multiplier"].(float64)
		}
		got := f["residual_risk"].(float64)
		if diff := product - got; diff > 0.02 || diff < -0.02 {
			t.Errorf("factors multiply to %.2f but residual_risk is %.2f", product, got)
		}
	})

	t.Run("unknown finding is a clean 404", func(t *testing.T) {
		code, body := e.do("GET", "/api/findings/nope", nil)
		if code != 404 {
			t.Fatalf("got %d", code)
		}
		if body["error"].(map[string]any)["code"] != "not_found" {
			t.Errorf("code = %v", body["error"])
		}
	})

	t.Run("suppression requires a reason and an expiry", func(t *testing.T) {
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/suppress",
			map[string]any{"reason": "", "days": 30}); code != 400 {
			t.Errorf("empty reason accepted (%d)", code)
		}
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/suppress",
			map[string]any{"reason": "ok", "days": 9999}); code != 400 {
			t.Errorf("9999-day suppression accepted (%d)", code)
		}
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/suppress",
			map[string]any{"reason": "accepted for the test", "days": 7}); code != 200 {
			t.Errorf("valid suppression rejected (%d)", code)
		}
	})

	t.Run("a suppressed finding leaves the open set", func(t *testing.T) {
		_, body := e.do("GET", "/api/findings", nil)
		for _, row := range body["data"].([]any) {
			if row.(map[string]any)["id"] == findingID {
				t.Error("suppressed finding still in the default list — " +
					"an accepted risk must stop dominating the dashboard")
			}
		}
	})

	t.Run("false positive: mark, revoke, and refuse a bad kind", func(t *testing.T) {
		// findingID is suppressed as an accepted risk above; revoke it first.
		if code, body := e.do("POST", "/api/findings/"+findingID+"/unsuppress", nil); code != 200 {
			t.Fatalf("unsuppress: %d %v", code, body)
		}
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/suppress",
			map[string]any{"kind": "ignore", "reason": "x", "days": 7}); code != 400 {
			t.Errorf("unknown kind accepted (%d)", code)
		}
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/suppress",
			map[string]any{"kind": "false_positive", "reason": "scanner matched the wrong package", "days": 90}); code != 200 {
			t.Fatalf("false positive rejected (%d)", code)
		}
		_, body := e.do("GET", "/api/findings/"+findingID, nil)
		f := body["data"].(map[string]any)["finding"].(map[string]any)
		if f["suppress_kind"] != "false_positive" {
			t.Errorf("suppress_kind = %v, want false_positive", f["suppress_kind"])
		}
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/unsuppress", nil); code != 200 {
			t.Errorf("revoking the false positive failed (%d)", code)
		}
	})

	t.Run("rules: too-broad refused, create applies, delete reopens", func(t *testing.T) {
		if code, _ := e.do("POST", "/api/rules", map[string]any{
			"kind": "false_positive", "reason": "x", "days": 30,
			"match": map[string]any{"engine": "sshd"}}); code != 400 {
			t.Errorf("engine-only rule accepted (%d) — it would hide everything one tool says", code)
		}
		_, body := e.do("GET", "/api/findings/"+findingID, nil)
		ruleID := body["data"].(map[string]any)["finding"].(map[string]any)["rule_id"].(string)
		code, body := e.do("POST", "/api/rules", map[string]any{
			"kind": "false_positive", "reason": "not applicable on this host", "days": 30,
			"match": map[string]any{"rule_id": ruleID}})
		if code != 200 {
			t.Fatalf("create rule: %d %v", code, body)
		}
		data := body["data"].(map[string]any)
		if data["suppressed"].(float64) < 1 {
			t.Errorf("rule suppressed %v findings, want >= 1", data["suppressed"])
		}
		id := data["rule"].(map[string]any)["id"].(string)
		if code, _ := e.do("POST", "/api/findings/"+findingID+"/unsuppress", nil); code != 409 {
			t.Errorf("unsuppressing a rule-held finding gave %d, want 409 — it would come back next scan", code)
		}
		_, body = e.do("GET", "/api/rules", nil)
		if len(body["data"].([]any)) != 1 {
			t.Errorf("GET /api/rules = %v", body["data"])
		}
		code, body = e.do("DELETE", "/api/rules/"+id, nil)
		if code != 200 || body["data"].(map[string]any)["reopened"].(float64) < 1 {
			t.Errorf("delete rule: %d %v", code, body)
		}
	})

	t.Run("plan orders actions by risk cleared", func(t *testing.T) {
		code, body := e.do("GET", "/api/plan", nil)
		if code != 200 {
			t.Fatalf("got %d", code)
		}
		actions := body["data"].([]any)
		prev := 1e9
		for _, a := range actions {
			got := a.(map[string]any)["risk_cleared"].(float64)
			if got > prev {
				t.Errorf("plan out of order: %.2f after %.2f", got, prev)
			}
			prev = got
		}
	})

	t.Run("features list every check", func(t *testing.T) {
		code, body := e.do("GET", "/api/features", nil)
		if code != 200 {
			t.Fatalf("got %d", code)
		}
		feats := body["data"].(map[string]any)["features"].([]any)
		if len(feats) < 10 {
			t.Fatalf("got %d features, expected all collectors + engines", len(feats))
		}
		for _, f := range feats {
			m := f.(map[string]any)
			if m["description"] == "" {
				t.Errorf("feature %v has no description — a toggle with no stated "+
					"consequence invites switching checks off", m["id"])
			}
		}
	})

	t.Run("disabling a check is honoured and reported, not hidden", func(t *testing.T) {
		if code, _ := e.do("POST", "/api/features/containers",
			map[string]any{"enabled": false}); code != 200 {
			t.Fatalf("toggle failed (%d)", code)
		}
		res, err := scan.Run(context.Background(), exec.Target{Name: "localhost"}, scan.Options{
			Timeout: 60 * time.Second, SkipEngines: true, SkipReachability: true,
			Features: e.srv.store.Features(),
		})
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, c := range res.Collectors {
			if c.ID == "containers" {
				found = true
				if c.Ran {
					t.Error("disabled collector still ran")
				}
				if c.Skipped != "disabled by operator" {
					t.Errorf("skip reason = %q, want 'disabled by operator'", c.Skipped)
				}
			}
		}
		if !found {
			t.Error("disabled collector vanished from the coverage report entirely — " +
				"it must be reported as disabled, never omitted")
		}
		_, _ = e.do("POST", "/api/features/containers", map[string]any{"enabled": true})
	})

	t.Run("unknown feature is rejected", func(t *testing.T) {
		if code, _ := e.do("POST", "/api/features/not-a-real-check",
			map[string]any{"enabled": false}); code != 404 {
			t.Errorf("got %d, want 404", code)
		}
	})

	t.Run("engine install refuses without confirmation", func(t *testing.T) {
		code, body := e.do("POST", "/api/engines/trivy/install",
			map[string]any{"target": "localhost", "confirm": false})
		if code != 400 {
			t.Fatalf("got %d, want 400", code)
		}
		if !strings.Contains(fmt.Sprint(body["error"]), "confirm") {
			t.Errorf("error should explain the confirmation requirement: %v", body["error"])
		}
	})

	t.Run("audit recorded caller and role for every mutation", func(t *testing.T) {
		code, body := e.do("GET", "/api/audit", nil)
		if code != 200 {
			t.Fatalf("got %d", code)
		}
		entries := body["data"].([]any)
		if len(entries) == 0 {
			t.Fatal("no audit entries after suppressing and toggling")
		}
		seen := map[string]bool{}
		for _, x := range entries {
			m := x.(map[string]any)
			if m["caller"] == "" || m["role"] == "" {
				t.Errorf("audit entry missing caller or role: %v", m)
			}
			seen[m["action"].(string)] = true
		}
		for _, want := range []string{"finding.suppress", "feature.disable", "feature.enable"} {
			if !seen[want] {
				t.Errorf("action %q was not audited", want)
			}
		}
	})
}

// TestE2E_RoleBoundaries drives the API as each role against the live server.
func TestE2E_RoleBoundaries(t *testing.T) {
	cases := []struct {
		role                       string
		findings, evidence, audit  int
		suppress, scan, features   int
		install                    int
	}{
		{"viewer", 200, 403, 403, 403, 403, 403, 403},
		{"auditor", 200, 200, 200, 403, 403, 403, 403},
		{"security_analyst", 200, 200, 200, 400, 403, 403, 403},
		{"operator", 200, 200, 200, 400, 200, 200, 403},
		{"admin", 200, 200, 200, 400, 200, 200, 400},
	}

	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			e := startE2E(t, c.role)
			e.seedScan()

			_, body := e.do("GET", "/api/findings?page_size=1", nil)
			id := "x"
			if rows, ok := body["data"].([]any); ok && len(rows) > 0 {
				id = rows[0].(map[string]any)["id"].(string)
			}

			check := func(name string, want int, method, path string, payload any) {
				got, _ := e.do(method, path, payload)
				if got != want {
					t.Errorf("%s: %s %s = %d, want %d", name, method, path, got, want)
				}
			}
			check("findings", c.findings, "GET", "/api/findings", nil)
			check("evidence", c.evidence, "GET", "/api/findings/"+id, nil)
			check("audit", c.audit, "GET", "/api/audit", nil)
			// 400 here means "allowed through the guard, rejected on validation"
			// — which is the correct signal that the capability was held.
			check("suppress", c.suppress, "POST", "/api/findings/"+id+"/suppress",
				map[string]any{"reason": "", "days": 0})
			check("scan", c.scan, "POST", "/api/scan", map[string]any{"target": "localhost"})
			check("features", c.features, "POST", "/api/features/containers",
				map[string]any{"enabled": true})
			check("install", c.install, "POST", "/api/engines/trivy/install",
				map[string]any{"target": "localhost", "confirm": false})
		})
	}
}
