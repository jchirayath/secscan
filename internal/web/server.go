// Package web serves the JSON API and the embedded dashboard.
//
// Two rules run through every route:
//   - one envelope, one error registry — no handler encodes JSON by hand;
//   - every route declares a capability and is wrapped by Guard. A route with
//     no capability fails ci/guards.sh, so the "575 routes, 3 checks" outcome
//     cannot happen here.
package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/secscan/internal/apierr"
	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/auth"
	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/config"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/core/risk"
	"github.com/jchirayath/secscan/internal/core/scan"
	"github.com/jchirayath/secscan/internal/rbac"
	"github.com/jchirayath/secscan/internal/store"
)

//go:embed ui/*
var uiFS embed.FS

// Server is the dashboard.
type Server struct {
	cfg     *config.Config
	store   *store.Store
	auth    auth.Authenticator
	audit   *audit.Log
	version string
	mux     *http.ServeMux

	// scanning guards against concurrent runs of the same target, which would
	// interleave writes to the same asset.
	scanning map[string]bool
	scanMu   sync.Mutex // guards scanning: the scheduler and HTTP scans race on it
}

// New builds the server.
func New(cfg *config.Config, st *store.Store, version string) (*Server, error) {
	a, err := auth.New(cfg)
	if err != nil {
		return nil, err
	}
	lg, err := audit.Open(cfg.Home)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, store: st, auth: a, audit: lg,
		version: version, mux: http.NewServeMux(), scanning: map[string]bool{},
	}
	s.routes()
	return s, nil
}

// ---------------------------------------------------------------- envelope

// envelope is the one response shape. `provenance` is mandatory: no surface
// may present demo or stale data as live (ARCHITECTURE.md — Provenance and honest degradation).
type envelope struct {
	Data       any                `json:"data"`
	Provenance finding.Provenance `json:"provenance"`
	AsOf       time.Time          `json:"as_of"`
	Note       string             `json:"note,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("response encode failed", slog.String("err", err.Error()))
	}
}

func writeData(w http.ResponseWriter, v any, prov finding.Provenance, note string) {
	writeJSON(w, http.StatusOK, envelope{Data: v, Provenance: prov, AsOf: clock.Now(), Note: note})
}

func writeErr(w http.ResponseWriter, code apierr.Code, msg string) {
	writeJSON(w, code.HTTPStatus(), map[string]any{"error": apierr.New(code, msg)})
}

// ------------------------------------------------------------------- guard

type ctxKey int

const principalKey ctxKey = 1

// Guard authenticates the request, checks the capability, and audits denials.
// Deny is the default: any error path returns without calling next.
func (s *Server) Guard(cap rbac.Capability, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.auth.Authenticate(r)
		if err != nil {
			s.audit.Write(audit.Entry{
				Caller: "anonymous", Role: "none", Action: string(cap),
				Target: r.URL.Path, Result: "denied", Detail: err.Error(),
				RemoteIP: peerIP(r),
			})
			// A browser navigating HTML should be sent to sign in; an API
			// caller should get a clean 401 rather than a redirect it cannot follow.
			if s.auth.Mode() == "entra" && acceptsHTML(r) {
				http.Redirect(w, r, "/auth/login?next="+r.URL.Path, http.StatusFound)
				return
			}
			writeErr(w, apierr.Unauthorized, "authentication required")
			return
		}
		if !rbac.Can(p.Role, cap) {
			s.audit.Write(audit.Entry{
				Caller: p.Email, Role: string(p.Role), Action: string(cap),
				Target: r.URL.Path, Result: "denied", Detail: "capability not held",
				RemoteIP: peerIP(r),
			})
			writeErr(w, apierr.Forbidden,
				fmt.Sprintf("role %s does not hold %s", p.Role, cap))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}

// decodeJSON reads a bounded JSON body. Bounded because an unbounded read on
// an authenticated endpoint is still a memory-exhaustion primitive.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v)
}

func principalOf(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(principalKey).(auth.Principal)
	return p
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// ------------------------------------------------------------------ routes

func (s *Server) routes() {
	s.auth.Routes(s.mux)

	// Unauthenticated: liveness only. Deliberately reveals nothing.
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})

	// cap:finding.read
	s.mux.HandleFunc("GET /api/overview", s.Guard(rbac.CapFindingRead, s.handleOverview))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/findings", s.Guard(rbac.CapFindingRead, s.handleFindings))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/assets", s.Guard(rbac.CapFindingRead, s.handleAssets))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/plan", s.Guard(rbac.CapFindingRead, s.handlePlan))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/history", s.Guard(rbac.CapFindingRead, s.handleHistory))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/me", s.Guard(rbac.CapFindingRead, s.handleMe))
	// cap:evidence.read
	s.mux.HandleFunc("GET /api/findings/{id}", s.Guard(rbac.CapEvidenceRead, s.handleFinding))
	// cap:audit.read
	s.mux.HandleFunc("GET /api/audit", s.Guard(rbac.CapAuditRead, s.handleAudit))
	// cap:finding.suppress
	s.mux.HandleFunc("POST /api/findings/{id}/suppress", s.Guard(rbac.CapFindingSuppress, s.handleSuppress))
	// cap:finding.suppress
	s.mux.HandleFunc("POST /api/findings/{id}/unsuppress", s.Guard(rbac.CapFindingSuppress, s.handleUnsuppress))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/rules", s.Guard(rbac.CapFindingRead, s.handleRules))
	// cap:finding.suppress
	s.mux.HandleFunc("POST /api/rules", s.Guard(rbac.CapFindingSuppress, s.handleRuleCreate))
	// cap:finding.suppress
	s.mux.HandleFunc("DELETE /api/rules/{id}", s.Guard(rbac.CapFindingSuppress, s.handleRuleDelete))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/findings/{id}/remediate", s.Guard(rbac.CapFindingRead, s.handleRemediatePlan))
	// cap:remediate.apply
	s.mux.HandleFunc("POST /api/findings/{id}/remediate", s.Guard(rbac.CapRemediate, s.handleRemediateApply))
	// cap:scan.run
	s.mux.HandleFunc("POST /api/scan", s.Guard(rbac.CapScanRun, s.handleScan))
	// cap:target.write
	s.mux.HandleFunc("GET /api/targets", s.Guard(rbac.CapTargetWrite, s.handleTargets))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/features", s.Guard(rbac.CapFindingRead, s.handleFeatures))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/trend", s.Guard(rbac.CapFindingRead, s.handleTrend))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/snapshots/diff", s.Guard(rbac.CapFindingRead, s.handleSnapshotDiff))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/snapshots/settings", s.Guard(rbac.CapFindingRead, s.handleSnapshotSettings))
	// cap:config.read
	s.mux.HandleFunc("POST /api/snapshots/settings", s.Guard(rbac.CapConfigRead, s.handleSnapshotSettings))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/summary", s.Guard(rbac.CapFindingRead, s.handleSummary))
	// cap:finding.read
	s.mux.HandleFunc("GET /api/coverage/{id}", s.Guard(rbac.CapFindingRead, s.handleCoverageDetail))
	// cap:feature.manage
	s.mux.HandleFunc("POST /api/features/{id}", s.Guard(rbac.CapFeatureManage, s.handleFeatureToggle))
	// cap:engine.install
	s.mux.HandleFunc("GET /api/engines/{id}/install", s.Guard(rbac.CapEngineInstall, s.handleEngineInstallPlan))
	// cap:engine.install
	s.mux.HandleFunc("POST /api/engines/{id}/install", s.Guard(rbac.CapEngineInstall, s.handleEngineInstall))

	// The UI itself is behind finding.read: an unauthenticated visitor gets
	// the sign-in redirect, not an empty shell that then 401s.
	s.mux.HandleFunc("GET /", s.Guard(rbac.CapFindingRead, s.handleUI))
	s.mux.HandleFunc("GET /app.js", s.Guard(rbac.CapFindingRead, s.handleAsset))
	s.mux.HandleFunc("GET /app.css", s.Guard(rbac.CapFindingRead, s.handleAsset))
}

// --------------------------------------------------------------- handlers

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	writeData(w, map[string]any{
		"email":        p.Email,
		"name":         p.Name,
		"role":         p.Role,
		"capabilities": rbac.Capabilities(p.Role),
		"auth_mode":    s.auth.Mode(),
		"version":      s.version,
	}, finding.ProvLive, "")
}

// Grouped is a finding shown once with a count of how many places it occurs.
type Grouped struct {
	finding.Finding
	// Instances is how many findings collapsed into this row, and Locations
	// names them, so the collapse never hides where the problem actually is.
	Instances int      `json:"instances,omitempty"`
	Locations []string `json:"locations,omitempty"`
}

// collapseByRule groups findings that are the same problem in different places.
// It keeps the highest-risk member as the representative, so the ordering the
// caller relies on is unchanged.
func collapseByRule(fs []finding.Finding) []Grouped {
	seen := map[string]int{} // rule → index in out
	var out []Grouped
	for _, f := range fs {
		if f.Status != finding.StatusOpen {
			continue
		}
		// Group on title within an asset, not on rule id.
		//
		// Rule id looks like the safer key but is wrong here: Trivy reports the
		// same issue under both a CVE and a GHSA identifier, so two rows share
		// a title and differ only in an id the reader cannot see. Title is what
		// the reader is actually comparing, and it stays distinct for the
		// generic rules — network.wide-bind names its port, so per-port
		// findings do not over-collapse.
		key := f.AssetID + "|" + f.Title
		if i, ok := seen[key]; ok {
			out[i].Instances++
			if loc := locationOf(f); loc != "" {
				out[i].Locations = append(out[i].Locations, loc)
			}
			continue
		}
		seen[key] = len(out)
		g := Grouped{Finding: f, Instances: 1}
		if loc := locationOf(f); loc != "" {
			g.Locations = []string{loc}
		}
		out = append(out, g)
	}
	return out
}

func locationOf(f finding.Finding) string {
	if f.Location != "" {
		return f.Location
	}
	return f.Component.Name
}

// CategoryCount is one dashboard tile.
type CategoryCount struct {
	Category finding.Category `json:"category"`
	Label    string           `json:"label"`
	Counts   map[string]int   `json:"counts"`
	Total    int              `json:"total"`
	TopRisk  float64          `json:"top_risk"`
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	all := s.store.Findings(store.Filter{})
	assets := s.store.Assets()

	byCat := map[finding.Category]*CategoryCount{}
	for _, c := range finding.AllCategories {
		byCat[c] = &CategoryCount{Category: c, Label: c.Label(), Counts: map[string]int{}}
	}
	for _, f := range all {
		cc, ok := byCat[f.Category]
		if !ok {
			continue
		}
		cc.Counts[string(f.Severity)]++
		cc.Total++
		if f.ResidualRisk > cc.TopRisk {
			cc.TopRisk = f.ResidualRisk
		}
	}
	cats := make([]CategoryCount, 0, len(finding.AllCategories))
	for _, c := range finding.AllCategories {
		cats = append(cats, *byCat[c])
	}

	// The same CVE lands in several container images, producing rows whose
	// titles are identical and whose only difference is the image name. Five
	// consecutive "crypto/tls: Incorrect certificate validation" entries read
	// as a rendering bug, and they crowd out the eight distinct problems the
	// panel exists to show. Collapse them for display — the individual findings
	// are untouched and still reachable by drilling in.
	top := collapseByRule(all)
	if len(top) > 8 {
		top = top[:8]
	}

	// Exposure is a different question from risk ranking, and it must not be
	// answerable only by scrolling. "What can reach this host from outside?"
	// deserves its own always-visible list: a well-mitigated SSH port is
	// correctly ranked below an unpatched CVE, but it is still the way in, and
	// dropping off the top-N list is not the same as being unimportant.
	var exposed []finding.Finding
	for _, f := range all {
		if f.Exposed && f.Status == finding.StatusOpen {
			exposed = append(exposed, f)
		}
	}

	// Controls detected on any asset, so the operator can see what is actually
	// defending them rather than inferring it from individual findings.
	controlSeen := map[string]finding.Mitigation{}
	for _, f := range all {
		for _, m := range f.Mitigations {
			controlSeen[m.ID] = m
		}
	}
	controls := make([]finding.Mitigation, 0, len(controlSeen))
	for _, m := range controlSeen {
		controls = append(controls, m)
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].Name < controls[j].Name })

	// Provenance is derived, not asserted: with no assets there is nothing
	// live to report, and saying "live" over an empty set would be a lie.
	prov, note := finding.ProvLive, ""
	if len(assets) == 0 {
		prov, note = finding.ProvUnavailable, "no scan has run yet — run `secscan scan`"
	}

	writeData(w, map[string]any{
		"score":      scan.Score(all),
		"categories": cats,
		"top":        top,
		"assets":     assets,
		"total":      len(all),
		"exposed":    exposed,
		"controls":   controls,
		"history":    s.store.History(30),
	}, prov, note)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.Filter{
		AssetID:         q.Get("asset"),
		Category:        finding.Category(q.Get("category")),
		Severity:        finding.Severity(q.Get("severity")),
		Status:          finding.Status(q.Get("status")),
		IncludeInactive: q.Get("include_inactive") == "true",
	}
	all := s.store.Findings(f)

	page, size := pagination(q)
	total := len(all)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data":       all[start:end],
		"page":       page,
		"page_size":  size,
		"total":      total,
		"has_more":   end < total,
		"provenance": finding.ProvLive,
		"as_of":      clock.Now(),
	})
}

func pagination(q map[string][]string) (page, size int) {
	page, size = 1, 100
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if v, err := strconv.Atoi(get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(get("page_size")); err == nil && v > 0 && v <= 500 {
		size = v
	}
	return page, size
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, ok := s.store.Get(id)
	if !ok {
		writeErr(w, apierr.NotFound, "no finding with id "+id)
		return
	}
	// Show the work: the risk number is never bare in this product. The detail
	// view gets the full chain — inherent, the controls that reduce it, and the
	// residual that everything actually ranks on.
	_, factors := riskFactors(f)
	writeData(w, map[string]any{
		"finding":      f,
		"risk_factors": factors,
	}, finding.ProvLive, "")
}

func (s *Server) handleAssets(w http.ResponseWriter, _ *http.Request) {
	writeData(w, s.store.Assets(), finding.ProvLive, "")
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	f := store.Filter{AssetID: r.URL.Query().Get("asset")}
	actions := scan.BuildPlan(s.store.Findings(f))
	writeData(w, actions, finding.ProvLive, "")
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	writeData(w, s.store.History(100), finding.ProvLive, "")
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	writeData(w, s.audit.Tail(200), finding.ProvLive, "")
}

func (s *Server) handleTargets(w http.ResponseWriter, _ *http.Request) {
	writeData(w, s.store.Targets(), finding.ProvLive, "")
}

func (s *Server) handleSuppress(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")

	var body struct {
		Kind   finding.SuppressKind `json:"kind"`
		Reason string               `json:"reason"`
		Days   int                  `json:"days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, apierr.BadRequest, "body must be JSON {kind, reason, days}")
		return
	}
	if body.Kind == "" {
		body.Kind = finding.KindAcceptedRisk // the only kind before false positives existed
	}
	if !body.Kind.Valid() {
		writeErr(w, apierr.BadRequest, "kind must be accepted_risk or false_positive")
		return
	}
	// A reason and an expiry are mandatory: an accepted risk with neither is
	// indistinguishable from an ignored one.
	if strings.TrimSpace(body.Reason) == "" {
		writeErr(w, apierr.BadRequest, "a reason is required to suppress a finding")
		return
	}
	if body.Days <= 0 || body.Days > 365 {
		writeErr(w, apierr.BadRequest, "days must be between 1 and 365 — suppressions expire by design")
		return
	}

	until := clock.Now().AddDate(0, 0, body.Days)
	if err := s.store.Suppress(id, body.Kind, body.Reason, until, p.Email, string(p.Role)); err != nil {
		writeErr(w, apierr.NotFound, err.Error())
		return
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "finding.suppress",
		Target: id, Result: "allowed",
		Detail:   fmt.Sprintf("%s until %s: %s", body.Kind, until.Format(time.DateOnly), body.Reason),
		RemoteIP: peerIP(r),
	})
	writeData(w, map[string]any{"id": id, "kind": body.Kind, "until": until}, finding.ProvLive, "")
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var body struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)

	targets := s.store.Targets()
	if len(targets) == 0 {
		targets = []exec.Target{{Name: "localhost"}}
	}
	var chosen *exec.Target
	for i := range targets {
		if body.Target == "" || targets[i].Name == body.Target {
			chosen = &targets[i]
			break
		}
	}
	if chosen == nil {
		writeErr(w, apierr.NotFound, "no target named "+body.Target)
		return
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "scan.run",
		Target: chosen.Name, Result: "allowed", RemoteIP: peerIP(r),
	})

	res, sum, err := s.runScan(r.Context(), *chosen)
	var se storeError
	switch {
	case errors.Is(err, errScanBusy):
		writeErr(w, apierr.Conflict, "a scan of "+chosen.Name+" is already running")
		return
	case errors.As(err, &se):
		writeErr(w, apierr.StoreFailed, se.Error())
		return
	case err != nil:
		writeErr(w, apierr.ScanFailed, err.Error())
		return
	}
	writeData(w, map[string]any{
		"summary":    sum,
		"collectors": res.Collectors,
		"engines":    res.Engines,
	}, res.Provenance, "")
}

// ------------------------------------------------------------------- serve

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// Unknown paths are the SPA's routes; it resolves them client-side.
		writeErr(w, apierr.NotFound, "no such path")
		return
	}
	s.serveEmbedded(w, r, "ui/app.html", "text/html; charset=utf-8")
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/app.js":
		s.serveEmbedded(w, r, "ui/app.js", "application/javascript; charset=utf-8")
	case "/app.css":
		s.serveEmbedded(w, r, "ui/app.css", "text/css; charset=utf-8")
	default:
		writeErr(w, apierr.NotFound, "no such asset")
	}
}

// assetETag is the content hash of an embedded asset, computed once on first
// serve. Without it the browser keeps a cached app.js after a binary upgrade
// and the operator sees a stale UI talking to a new API — which presents as
// bizarre, unreproducible bugs rather than as "your cache is old".
var (
	assetETag   = map[string]string{}
	assetETagMu sync.Mutex
)

func etagFor(name string, b []byte) string {
	assetETagMu.Lock()
	defer assetETagMu.Unlock()
	if e, ok := assetETag[name]; ok {
		return e
	}
	sum := sha256.Sum256(b)
	e := `"` + hex.EncodeToString(sum[:8]) + `"`
	assetETag[name] = e
	return e
}

func (s *Server) serveEmbedded(w http.ResponseWriter, r *http.Request, name, ctype string) {
	b, err := uiFS.ReadFile(name)
	if err != nil {
		writeErr(w, apierr.Internal, "embedded asset missing: "+name)
		return
	}

	// "no-cache" means revalidate every time, not never cache: the browser
	// still gets a 304 and skips the transfer when nothing has changed.
	etag := etagFor(name, b)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Stamp the running version into the asset URLs. Cache headers alone are
	// not enough: a browser that cached app.js before those headers existed
	// keeps serving it. A version-bearing URL is a different cache entry, so a
	// new binary can never be paired with an old UI.
	if name == "ui/app.html" {
		b = []byte(strings.ReplaceAll(string(b), "__VERSION__", s.version))
	}

	w.Header().Set("Content-Type", ctype)
	// The dashboard renders findings that contain attacker-influenced strings
	// (file paths, process names, package names). A strict CSP means even a
	// missed escape cannot become script execution.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; "+
			"connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(b)
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) int {
	srv := &http.Server{
		Addr:              s.cfg.Bind,
		Handler:           s.securityHeaders(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute, // a synchronous scan can be slow
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	go s.scheduler(ctx)

	slog.Info("secscan listening",
		slog.String("addr", s.cfg.Bind),
		slog.String("auth", s.auth.Mode()),
		slog.String("version", s.version))
	if s.auth.Mode() == "local" {
		fmt.Printf("\n  \033[33m⚠  authentication disabled (local mode, loopback only)\033[0m\n")
	}
	fmt.Printf("  → http://%s\n\n", s.cfg.Bind)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", slog.String("err", err.Error()))
			return 1
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		slog.Info("shut down cleanly")
	}
	return 0
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if s.cfg.AuthMode != "local" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// riskFactors re-derives the score breakdown for the detail view. It calls the
// single risk implementation rather than reconstructing the maths — the whole
// point of package risk is that there is exactly one.
func riskFactors(f finding.Finding) (float64, []risk.Factor) {
	return risk.Score(f)
}
