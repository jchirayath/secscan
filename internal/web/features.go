package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/jchirayath/secscan/internal/apierr"
	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/core/engine"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/feature"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/core/scan"
	"github.com/jchirayath/secscan/internal/store"
)

// handleFeatures lists every check the scanner can run, with its enablement and
// — for engines — whether the binary is actually present on the target.
//
// Installed-ness is probed live rather than cached: a stale "installed: true"
// would make the UI offer to run something that is not there.
func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request) {
	targetName := r.URL.Query().Get("target")
	t, ok := s.resolveTarget(targetName)

	installed := map[string]bool{}
	prov, note := finding.ProvLive, ""
	if ok {
		runner := exec.New(t, s.cfg.SSHTimeout)
		for _, e := range engine.All() {
			installed[e.ID()] = runner.Has(r.Context(), e.Binary())
		}
	} else {
		// Be explicit that installed-ness is unknown rather than showing every
		// engine as absent, which would read as "nothing is installed".
		prov = finding.ProvPartial
		note = "no target selected — engine installation status not probed"
	}

	feats := feature.All(s.store.Features(), installed)
	writeData(w, map[string]any{
		"features": feats,
		"target":   t.Name,
	}, prov, note)
}

// handleFeatureToggle enables or disables one check.
func (s *Server) handleFeatureToggle(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")

	if !feature.Known(id) {
		writeErr(w, apierr.NotFound, "no feature named "+id)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, apierr.BadRequest, "body must be JSON {enabled: bool}")
		return
	}
	if err := s.store.SetFeature(id, body.Enabled); err != nil {
		writeErr(w, apierr.StoreFailed, err.Error())
		return
	}

	// Turning a check off is a security-relevant decision — it is how findings
	// disappear without being fixed — so it is audited like any other.
	action := "feature.disable"
	if body.Enabled {
		action = "feature.enable"
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: action,
		Target: id, Result: "allowed", RemoteIP: peerIP(r),
	})
	writeData(w, map[string]any{"id": id, "enabled": body.Enabled}, finding.ProvLive, "")
}

// handleEngineInstallPlan shows what installing an engine would do, without
// doing it. The operator sees the exact commands before confirming.
func (s *Server) handleEngineInstallPlan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := s.resolveTarget(r.URL.Query().Get("target"))
	if !ok {
		writeErr(w, apierr.NotFound, "no such target")
		return
	}
	family := s.osFamilyOf(t.Name)
	if family == "" {
		writeErr(w, apierr.NotConfigured,
			"scan the target once before installing — the OS family is not known yet")
		return
	}
	writeData(w, engine.PlanInstall(id, family), finding.ProvLive, "")
}

// handleEngineInstall performs the install. This is the ONLY endpoint in the
// product that changes the scanned host, which is why it is admin-only,
// requires an explicit confirmation flag, and is audited before it runs.
func (s *Server) handleEngineInstall(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")

	var body struct {
		Target  string `json:"target"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, apierr.BadRequest, "body must be JSON {target, confirm}")
		return
	}
	if !body.Confirm {
		writeErr(w, apierr.BadRequest,
			"installation modifies the target host; resend with confirm=true")
		return
	}
	t, ok := s.resolveTarget(body.Target)
	if !ok {
		writeErr(w, apierr.NotFound, "no such target")
		return
	}
	family := s.osFamilyOf(t.Name)
	if family == "" {
		writeErr(w, apierr.NotConfigured,
			"scan the target once before installing — the OS family is not known yet")
		return
	}

	// Audited BEFORE the attempt, so a install that hangs or crashes the
	// process still leaves a record that it was started and by whom.
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "engine.install",
		Target: id + " on " + t.Name, Result: "allowed",
		Detail: "modifies the target host", RemoteIP: peerIP(r),
	})

	runner := exec.New(t, s.cfg.ScanTimeout)
	res := engine.Install(r.Context(), runner, id, family)

	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "engine.install.result",
		Target: id + " on " + t.Name,
		Result: map[bool]string{true: "allowed", false: "error"}[res.OK],
		Detail: res.Error, RemoteIP: peerIP(r),
	})

	if !res.OK {
		writeJSON(w, http.StatusOK, envelope{
			Data: res, Provenance: finding.ProvLive,
			Note: "installation did not complete — see output",
		})
		return
	}
	writeData(w, res, finding.ProvLive, "")
}

// resolveTarget finds a configured target by name, defaulting to the first one
// (or localhost when none are configured).
func (s *Server) resolveTarget(name string) (exec.Target, bool) {
	targets := s.store.Targets()
	if len(targets) == 0 {
		return exec.Target{Name: "localhost"}, name == "" || name == "localhost"
	}
	for _, t := range targets {
		if t.Name == name {
			return t, true
		}
	}
	if name == "" {
		return targets[0], true
	}
	return exec.Target{}, false
}

// osFamilyOf reads the family discovered by the last scan of that asset.
func (s *Server) osFamilyOf(assetID string) string {
	for _, a := range s.store.Assets() {
		if a.ID == assetID {
			return a.OSFamily
		}
	}
	return ""
}

// handleCoverageDetail answers "what did this specific check actually do?".
//
// The coverage list tells you a collector ran and found three things. This
// tells you what it inspects, which findings are its, and — when it did not run
// — precisely why and what to do about it. That last part is the point: a
// skipped check is only useful information if the reader can act on the reason.
func (s *Server) handleCoverageDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Locate the most recent run of this collector across scan history.
	var run *store.CollectorRun
	var scannedAt, target string
	for _, h := range s.store.History(50) {
		target = h.Target
		for i := range h.Collector {
			if h.Collector[i].ID == id {
				run = &h.Collector[i]
				scannedAt = h.At.Format(time.RFC3339)
			}
		}
	}

	// Probe installation state rather than passing an empty map: an engine that
	// IS installed would otherwise be reported as absent here while the Checks
	// view says the opposite, and two screens disagreeing is worse than either
	// being wrong on its own.
	installed := map[string]bool{}
	if t, ok := s.resolveTarget(r.URL.Query().Get("target")); ok {
		runner := exec.New(t, s.cfg.SSHTimeout)
		for _, e := range engine.All() {
			if e.ID() == id {
				installed[e.ID()] = runner.Has(r.Context(), e.Binary())
			}
		}
	}

	// The registry supplies the human description of what this check covers.
	var feat *feature.Feature
	for _, f := range feature.All(s.store.Features(), installed) {
		if f.ID == id {
			cp := f
			feat = &cp
		}
	}
	if run == nil && feat == nil {
		writeErr(w, apierr.NotFound, "no check named "+id)
		return
	}

	found := s.store.Findings(store.Filter{Engine: id})

	// The transcript is what this check actually ran. It is the difference
	// between a claim and evidence — an operator can read the commands and
	// their output rather than trusting the conclusion.
	asset := r.URL.Query().Get("asset")
	if asset == "" {
		asset = target
	}
	transcript := s.store.Transcript(asset, id)

	// Severity breakdown of what this specific check contributed, so a reader
	// can judge whether disabling it would actually cost them anything.
	counts := map[string]int{}
	for _, f := range found {
		counts[string(f.Severity)]++
	}

	prov, note := finding.ProvLive, ""
	if run == nil {
		prov = finding.ProvUnavailable
		note = "this check has not run in the recorded scan history"
	}

	writeData(w, map[string]any{
		"id":         id,
		"feature":    feat,
		"run":        run,
		"scanned_at": scannedAt,
		"findings":   found,
		"counts":     counts,
		"transcript": transcript,
	}, prov, note)
}

// CheckResult is one row of the assessment scorecard.
type CheckResult struct {
	ID       string           `json:"id"`
	Label    string           `json:"label"`
	Kind     feature.Kind     `json:"kind"`
	Category finding.Category `json:"category"`
	Enabled  bool             `json:"enabled"`

	Ran     bool   `json:"ran"`
	Skipped string `json:"skipped,omitempty"`
	Checks  int    `json:"checks"`

	Found  int            `json:"found"`
	Counts map[string]int `json:"counts"`
	// TopRisk is the highest residual risk this check surfaced, so the row
	// conveys severity as well as volume.
	TopRisk float64 `json:"top_risk"`

	// Status collapses the above into the single word a reader actually wants,
	// because "ran, found nothing" and "did not run" look identical in a count
	// column and mean opposite things.
	Status string `json:"status"` // clean | findings | skipped | disabled | never-run
}

// supportingCheck names the checks that never raise findings of their own —
// they detect controls, or prove/refute other findings. Their contribution
// shows up as a changed risk number elsewhere, not as a row of results.
func supportingCheck(id string) bool {
	return id == "controls" || id == "validate" || id == "host-facts"
}

// handleSummary is the assessment scorecard: every check the scanner has, what
// it did on the last scan, and what it found — on one page.
//
// This exists because the information was previously split across three views:
// which checks exist (Checks), which ran (Coverage), and what was found
// (Overview). Answering "what was assessed and what came of it?" meant holding
// three pages in your head, which is exactly the question a reader opens a
// security tool to answer.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	// Last run of each check, by id.
	runs := map[string]store.CollectorRun{}
	var lastAt, target string
	for _, h := range s.store.History(50) {
		for _, c := range h.Collector {
			runs[c.ID] = c
		}
		lastAt, target = h.At.Format(time.RFC3339), h.Target
	}

	// Scope findings to the asset the coverage record describes. Aggregating
	// findings across every asset while reporting coverage from one scan
	// produces rows like "skipped, 2 findings" — internally contradictory, and
	// exactly the kind of quiet wrongness that costs a tool its credibility.
	all := s.store.Findings(store.Filter{AssetID: target})
	byEngine := map[string][]finding.Finding{}
	for _, f := range all {
		byEngine[f.Engine] = append(byEngine[f.Engine], f)
	}

	state := s.store.Features()
	var rows []CheckResult
	for _, feat := range feature.All(state, map[string]bool{}) {
		run, ranAtAll := runs[feat.ID]
		fs := byEngine[feat.ID]

		row := CheckResult{
			ID: feat.ID, Label: feat.Label, Kind: feat.Kind,
			Category: feat.Category, Enabled: feat.Enabled,
			Ran: run.Ran, Skipped: run.Skipped, Checks: run.Checks,
			Found: len(fs), Counts: map[string]int{},
		}
		for _, f := range fs {
			row.Counts[string(f.Severity)]++
			if f.ResidualRisk > row.TopRisk {
				row.TopRisk = f.ResidualRisk
			}
		}

		switch {
		case !feat.Enabled:
			row.Status = "disabled"
		case !ranAtAll:
			row.Status = "never-run"
		case !run.Ran:
			row.Status = "skipped"
		case len(fs) > 0:
			row.Status = "findings"
		case supportingCheck(feat.ID):
			// These produce no findings by design — they feed the risk model.
			// Calling them "clean" would imply they looked for problems and
			// found none, which is not what happened.
			row.Status = "applied"
		default:
			row.Status = "clean"
		}
		rows = append(rows, row)
	}

	// Worst first: findings, then the checks that could not run (because an
	// unknown is more actionable than a pass), then clean.
	rank := map[string]int{"findings": 0, "skipped": 1, "never-run": 2, "disabled": 3, "clean": 4, "applied": 5}
	sort.Slice(rows, func(i, j int) bool {
		if rank[rows[i].Status] != rank[rows[j].Status] {
			return rank[rows[i].Status] < rank[rows[j].Status]
		}
		return rows[i].TopRisk > rows[j].TopRisk
	})

	tally := map[string]int{}
	for _, r := range rows {
		tally[r.Status]++
	}

	prov, note := finding.ProvLive, ""
	if lastAt == "" {
		prov, note = finding.ProvUnavailable, "no scan has run yet"
	}

	// The human label for each category lives on the server; sending it avoids
	// the UI keeping a second copy that can drift out of step.
	labels := map[string]string{}
	for _, c := range finding.AllCategories {
		labels[string(c)] = c.Label()
	}

	writeData(w, map[string]any{
		"checks":          rows,
		"category_labels": labels,
		"tally":           tally,
		"score":           scan.Score(all),
		"total":           len(all),
		"target":          target,
		"scanned_at":      lastAt,
	}, prov, note)
}
