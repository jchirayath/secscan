package web

import (
	"net/http"

	"github.com/jchirayath/secscan/internal/apierr"
	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/remediate"
)

// handleRemediatePlan classifies the change-risk of fixing a finding and shows
// exactly what would run — without running it.
//
// This endpoint is deliberately readable by anyone who can read findings: the
// classification is information, and hiding it would make the refusals look
// arbitrary. Only the apply endpoint is privileged.
func (s *Server) handleRemediatePlan(w http.ResponseWriter, r *http.Request) {
	f, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, apierr.NotFound, "no finding with id "+r.PathValue("id"))
		return
	}
	writeData(w, remediate.PlanFor(f), finding.ProvLive, "")
}

// handleRemediateApply executes a green fix, verifies it, and rescans the
// finding's asset so the dashboard reflects reality rather than an assumption.
func (s *Server) handleRemediateApply(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")

	f, ok := s.store.Get(id)
	if !ok {
		writeErr(w, apierr.NotFound, "no finding with id "+id)
		return
	}

	var body struct {
		Confirm bool `json:"confirm"`
		DryRun  bool `json:"dry_run"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeErr(w, apierr.BadRequest, "body must be JSON {confirm, dry_run}")
		return
	}

	plan := remediate.PlanFor(f)
	if !plan.Executable {
		// The refusal carries its reason, because "no" without "why" trains
		// people to look for a way around it.
		writeJSON(w, apierr.Forbidden.HTTPStatus(), map[string]any{
			"error": apierr.New(apierr.Forbidden, plan.Blocked),
			"plan":  plan,
		})
		return
	}
	if !body.Confirm && !body.DryRun {
		writeErr(w, apierr.BadRequest,
			"this changes the target host; resend with confirm=true, or dry_run=true to see the steps")
		return
	}

	target, found := s.resolveTarget(f.AssetID)
	if !found {
		writeErr(w, apierr.NotFound, "no configured target for asset "+f.AssetID)
		return
	}

	// Audited before the attempt, so an apply that hangs or crashes the
	// process still leaves a record of what was started and by whom.
	action := "remediate.apply"
	if body.DryRun {
		action = "remediate.dryrun"
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: action,
		Target: f.AssetID + " / " + f.RuleID, Result: "allowed",
		Detail: "change-risk " + string(plan.Risk), RemoteIP: peerIP(r),
	})

	runner := exec.New(target, s.cfg.ScanTimeout)
	res := remediate.Apply(r.Context(), runner, f, remediate.Options{DryRun: body.DryRun})

	outcome := "allowed"
	if res.Error != "" {
		outcome = "error"
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: action + ".result",
		Target: f.AssetID + " / " + f.RuleID, Result: outcome,
		Detail: resultDetail(res), RemoteIP: peerIP(r),
	})

	note := ""
	if res.Verified {
		note = "verified on the host; rescan to update the dashboard"
	}
	writeData(w, map[string]any{"plan": plan, "result": res}, finding.ProvLive, note)
}

func resultDetail(res remediate.Result) string {
	switch {
	case res.Verified:
		return "applied and verified"
	case res.RolledBack:
		return "failed and rolled back: " + res.Error
	case res.Applied:
		return "applied but NOT verified: " + res.Error
	}
	return res.Error
}
