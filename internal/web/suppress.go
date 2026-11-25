package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/apierr"
	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/store"
)

// handleUnsuppress revokes a per-finding suppression (accepted risk or false
// positive). Rule-driven suppressions are revoked through their rule.
func (s *Server) handleUnsuppress(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")
	if err := s.store.Unsuppress(id); err != nil {
		code := apierr.Conflict
		if strings.Contains(err.Error(), "not found") {
			code = apierr.NotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "finding.unsuppress",
		Target: id, Result: "allowed", RemoteIP: peerIP(r),
	})
	writeData(w, map[string]any{"id": id, "status": finding.StatusOpen}, finding.ProvLive, "")
}

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	now := clock.Now()
	type row struct {
		store.Rule
		Expired    bool `json:"expired"`
		Suppressed int  `json:"suppressed"` // findings it is hiding right now
	}
	counts := map[string]int{}
	for _, f := range s.store.Findings(store.Filter{IncludeInactive: true}) {
		if f.Status == finding.StatusSuppressed && f.SuppressRule != "" {
			counts[f.SuppressRule]++
		}
	}
	rules := s.store.Rules()
	out := make([]row, 0, len(rules))
	for _, rl := range rules {
		out = append(out, row{Rule: rl, Expired: !now.Before(rl.Until), Suppressed: counts[rl.ID]})
	}
	writeData(w, out, finding.ProvLive, "")
}

// handleRuleCreate stores a match rule and applies it to current findings.
// Same discipline as a single suppression: kind, reason and expiry are all
// mandatory, and the store refuses matches too broad to be a decision.
func (s *Server) handleRuleCreate(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var body struct {
		Kind   finding.SuppressKind `json:"kind"`
		Reason string               `json:"reason"`
		Days   int                  `json:"days"`
		Match  store.RuleMatch      `json:"match"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, apierr.BadRequest, "body must be JSON {kind, reason, days, match}")
		return
	}
	if body.Days <= 0 || body.Days > 365 {
		writeErr(w, apierr.BadRequest, "days must be between 1 and 365 — suppressions expire by design")
		return
	}
	rule, n, err := s.store.AddRule(store.Rule{
		Kind: body.Kind, Reason: strings.TrimSpace(body.Reason), Match: body.Match,
		Until: clock.Now().AddDate(0, 0, body.Days), By: p.Email, Role: string(p.Role),
	})
	if err != nil {
		writeErr(w, apierr.BadRequest, err.Error())
		return
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "rule.create",
		Target: rule.ID, Result: "allowed", RemoteIP: peerIP(r),
		Detail: fmt.Sprintf("%s until %s, match %+v, suppressed %d now: %s",
			rule.Kind, rule.Until.Format(time.DateOnly), rule.Match, n, rule.Reason),
	})
	writeData(w, map[string]any{"rule": rule, "suppressed": n}, finding.ProvLive, "")
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")
	n, err := s.store.DeleteRule(id)
	if err != nil {
		writeErr(w, apierr.NotFound, err.Error())
		return
	}
	s.audit.Write(audit.Entry{
		Caller: p.Email, Role: string(p.Role), Action: "rule.delete",
		Target: id, Result: "allowed", RemoteIP: peerIP(r),
		Detail: fmt.Sprintf("reopened %d finding(s)", n),
	})
	writeData(w, map[string]any{"id": id, "reopened": n}, finding.ProvLive, "")
}
