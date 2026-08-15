package web

import (
	"net/http"
	"strconv"

	"github.com/jchirayath/secscan/internal/apierr"
	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/snapshot"
)

// snapshots opens the configured snapshot store.
func (s *Server) snapshots() (*snapshot.Store, error) {
	return snapshot.Open(s.cfg.SnapshotDir)
}

// handleTrend returns posture over time for an asset.
//
// It reads only the metadata sidecars, never the snapshots themselves: a year
// of daily scans is a year of findings, and drawing a line should not require
// decompressing all of it.
func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	sn, err := s.snapshots()
	if err != nil {
		writeErr(w, apierr.NotConfigured, err.Error())
		return
	}
	metas, err := sn.List(r.URL.Query().Get("asset"))
	if err != nil {
		writeErr(w, apierr.StoreFailed, err.Error())
		return
	}

	prov, note := finding.ProvLive, ""
	switch len(metas) {
	case 0:
		prov = finding.ProvUnavailable
		note = "no snapshots yet — run a scan, or point SECSCAN_SNAPSHOT_DIR at an existing directory"
	case 1:
		// One point is not a trend, and drawing it as though it were invites
		// reading a direction into a single measurement.
		note = "only one snapshot so far — a trend needs at least two scans"
	}

	writeData(w, map[string]any{
		"snapshots": metas,
		"dir":       sn.Dir(),
		"keep":      s.cfg.SnapshotKeep,
	}, prov, note)
}

// handleSnapshotDiff compares two snapshots, defaulting to the two most recent.
func (s *Server) handleSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	sn, err := s.snapshots()
	if err != nil {
		writeErr(w, apierr.NotConfigured, err.Error())
		return
	}
	q := r.URL.Query()
	asset := q.Get("asset")
	if asset == "" {
		writeErr(w, apierr.BadRequest, "asset is required")
		return
	}

	fromID, toID := q.Get("from"), q.Get("to")
	if fromID == "" || toID == "" {
		metas, err := sn.List(asset)
		if err != nil || len(metas) < 2 {
			writeErr(w, apierr.NotFound,
				"need at least two snapshots of this asset to compare")
			return
		}
		fromID, toID = metas[len(metas)-2].ID, metas[len(metas)-1].ID
	}

	from, err := sn.Load(asset, fromID)
	if err != nil {
		writeErr(w, apierr.NotFound, "from: "+err.Error())
		return
	}
	to, err := sn.Load(asset, toID)
	if err != nil {
		writeErr(w, apierr.NotFound, "to: "+err.Error())
		return
	}

	d := snapshot.Compare(from, to)
	d.From, d.To = fromID, toID

	// A score that improved because a check stopped running is not an
	// improvement, and the UI must be able to say so rather than draw a
	// reassuring line.
	note := ""
	if len(d.CoverageLost) > 0 && d.ScoreDelta > 0 {
		note = "the score improved, but checks that ran in the earlier scan did not run in " +
			"the later one — some of this movement may be reduced coverage rather than fixes"
	}
	writeData(w, d, finding.ProvLive, note)
}

// handleSnapshotSettings reports where snapshots are written, and lets an admin
// change it.
//
// The directory is operator-defined, which makes it an input worth treating
// carefully: this process may run as a privileged-ish account, and a path is a
// capability. It must be absolute, and the change is audited like any other
// configuration change.
func (s *Server) handleSnapshotSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sn, err := s.snapshots()
		dir, ok := s.cfg.SnapshotDir, true
		if err != nil {
			ok = false
		} else {
			dir = sn.Dir()
		}
		metas, _ := sn.List("")
		writeData(w, map[string]any{
			"dir": dir, "writable": ok, "keep": s.cfg.SnapshotKeep,
			"count": len(metas),
		}, finding.ProvLive, "")
		return
	}

	p := principalOf(r)
	var body struct {
		Dir  string `json:"dir"`
		Keep int    `json:"keep"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, apierr.BadRequest, "body must be JSON {dir, keep}")
		return
	}

	// Open validates absoluteness and creates the directory, so a bad path
	// fails here rather than silently at the end of the next scan.
	store, err := snapshot.Open(body.Dir)
	if err != nil {
		writeErr(w, apierr.BadRequest, err.Error())
		return
	}
	if body.Keep < 0 {
		writeErr(w, apierr.BadRequest, "keep must be zero (retain everything) or positive")
		return
	}

	s.cfg.SnapshotDir, s.cfg.SnapshotKeep = store.Dir(), body.Keep
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "snapshot.settings",
		Target: store.Dir(), Result: "allowed",
		Detail: "retention " + itoa(body.Keep), RemoteIP: peerIP(r),
	})

	// Changing it at runtime affects this process only. Saying so avoids the
	// worse outcome: an operator who believes it persisted and finds snapshots
	// back in the old place after a restart.
	writeData(w, map[string]any{"dir": store.Dir(), "keep": body.Keep},
		finding.ProvLive,
		"applied to the running process; set SECSCAN_SNAPSHOT_DIR to make it survive a restart")
}

func itoa(n int) string {
	if n == 0 {
		return "unlimited"
	}
	return strconv.Itoa(n)
}
