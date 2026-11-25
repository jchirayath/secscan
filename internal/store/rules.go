package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Rule suppresses every finding it matches — the ones open now and the ones
// future scans produce. Per-finding suppression cannot carry a false positive:
// a finding's ID changes with the component version, so the next upstream
// patch resurrects every "fixed" decision, and 30 identical test-fixture keys
// would need 30 clicks. A rule states the pattern once.
//
// Rules expire like every other suppression. A false positive that is still a
// false positive in a year costs one renewal; one that silently became real
// costs much more.
type Rule struct {
	ID     string               `json:"id"`
	Kind   finding.SuppressKind `json:"kind"`
	Reason string               `json:"reason"`
	Match  RuleMatch            `json:"match"`
	Until  time.Time            `json:"until"`
	By     string               `json:"by"`
	Role   string               `json:"role"`
	At     time.Time            `json:"at"`
}

// RuleMatch is ANDed: every non-empty field must match. Component and Location
// accept '*' as "any run of characters, '/' included" — locations are paths and
// image references, where shell-style globs that stop at '/' surprise people.
type RuleMatch struct {
	AssetID   string `json:"asset_id,omitempty"`
	Engine    string `json:"engine,omitempty"`
	RuleID    string `json:"rule_id,omitempty"` // exact, e.g. vuln.cve-2026-12345
	Component string `json:"component,omitempty"`
	Location  string `json:"location,omitempty"`
}

// Validate refuses rules too broad to be a considered decision. Engine and
// asset alone would hide everything one tool reports; a bare "*" pattern is the
// same thing spelled differently.
func (m RuleMatch) Validate() error {
	narrow := 0
	if m.RuleID != "" {
		narrow++
	}
	for _, p := range []string{m.Component, m.Location} {
		if p == "" {
			continue
		}
		if strings.Trim(p, "*") == "" {
			return fmt.Errorf("pattern %q matches everything — name what the rule is about", p)
		}
		narrow++
	}
	if narrow == 0 {
		return errors.New("a rule needs at least one of rule_id, component or location; engine and asset only narrow it further")
	}
	return nil
}

// Matches reports whether f falls under m.
func (m RuleMatch) Matches(f finding.Finding) bool {
	if m.AssetID != "" && m.AssetID != f.AssetID {
		return false
	}
	if m.Engine != "" && m.Engine != f.Engine {
		return false
	}
	if m.RuleID != "" && !strings.EqualFold(m.RuleID, f.RuleID) {
		return false
	}
	if m.Component != "" && !globMatch(m.Component, f.Component.Name) {
		return false
	}
	if m.Location != "" && !globMatch(m.Location, f.Location) {
		return false
	}
	return true
}

func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$")
	return err == nil && re.MatchString(s)
}

func (r Rule) active(now time.Time) bool { return now.Before(r.Until) }

// applyRule marks f suppressed by r.
func applyRule(f *finding.Finding, r Rule) {
	until := r.Until
	f.Status = finding.StatusSuppressed
	f.SuppressKind = r.Kind
	f.SuppressReason = r.Reason
	f.SuppressUntil = &until
	f.SuppressRule = r.ID
}

func clearSuppression(f *finding.Finding) {
	f.Status = finding.StatusOpen
	f.SuppressKind, f.SuppressReason, f.SuppressRule = "", "", ""
	f.SuppressUntil = nil
}

// firstRule returns the first active rule matching f. Caller holds the lock.
func (s *Store) firstRule(f finding.Finding, now time.Time) (Rule, bool) {
	for _, r := range s.st.Rules {
		if r.active(now) && r.Match.Matches(f) {
			return r, true
		}
	}
	return Rule{}, false
}

// AddRule stores r and applies it to every open finding it matches now.
// It returns the stored rule (with ID) and how many findings it suppressed.
func (s *Store) AddRule(r Rule) (Rule, int, error) {
	if !r.Kind.Valid() {
		return Rule{}, 0, fmt.Errorf("kind must be %q or %q", finding.KindAcceptedRisk, finding.KindFalsePositive)
	}
	if strings.TrimSpace(r.Reason) == "" {
		return Rule{}, 0, errors.New("a reason is required")
	}
	if err := r.Match.Validate(); err != nil {
		return Rule{}, 0, err
	}
	now := clock.Now()
	if !r.Until.After(now) {
		return Rule{}, 0, errors.New("the rule would already have expired")
	}
	r.At = now
	sum := sha256.Sum256([]byte(fmt.Sprintf("%+v|%s", r.Match, now.Format(time.RFC3339Nano))))
	r.ID = "r-" + hex.EncodeToString(sum[:])[:10]

	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Rules = append(s.st.Rules, r)
	n := 0
	for id, f := range s.st.Findings {
		if f.Status != finding.StatusOpen || !r.Match.Matches(f) {
			continue
		}
		applyRule(&f, r)
		s.st.Findings[id] = f
		n++
	}
	return r, n, s.save()
}

// Rules returns every rule, newest first, expired ones included so a reader
// can see what used to be hidden and why.
func (s *Store) Rules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Rule(nil), s.st.Rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// DeleteRule revokes a rule and reopens the findings it was hiding.
func (s *Store) DeleteRule(id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, r := range s.st.Rules {
		if r.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return 0, fmt.Errorf("rule %s not found", id)
	}
	s.st.Rules = append(s.st.Rules[:idx], s.st.Rules[idx+1:]...)
	n := 0
	now := clock.Now()
	for fid, f := range s.st.Findings {
		if f.SuppressRule != id || f.Status != finding.StatusSuppressed {
			continue
		}
		clearSuppression(&f)
		// Another rule may still cover it; honour that rather than flapping.
		if r, ok := s.firstRule(f, now); ok {
			applyRule(&f, r)
		} else {
			n++
		}
		s.st.Findings[fid] = f
	}
	return n, s.save()
}

// Unsuppress revokes a per-finding suppression. A finding hidden by a rule is
// refused: reopening it alone would last until the next scan re-applied the
// rule, which reads as a bug. Revoke or narrow the rule instead.
func (s *Store) Unsuppress(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.st.Findings[id]
	if !ok {
		return fmt.Errorf("finding %s not found", id)
	}
	if f.Status != finding.StatusSuppressed {
		return fmt.Errorf("finding %s is not suppressed", id)
	}
	if f.SuppressRule != "" {
		return fmt.Errorf("finding %s is suppressed by rule %s — revoke the rule instead", id, f.SuppressRule)
	}
	clearSuppression(&f)
	s.st.Findings[id] = f
	delete(s.st.Suppressions, id)
	return s.save()
}

// Coverage says which collectors and engines ran, and for each the locations
// it is responsible for but did NOT examine this time (nil: it examined
// everything). Merge only closes a missing finding when its producer ran and
// the finding's location is not in that list — absence of evidence from a
// place nobody looked proves nothing. Expressed as exclusions rather than as a
// list of covered places so that findings for things that are simply gone (an
// image no container runs any more) close, instead of lingering forever.
type Coverage map[string][]string

func (c Coverage) covers(engine, location string) bool {
	skipped, ok := c[engine]
	if !ok {
		return false
	}
	for _, l := range skipped {
		if l == location {
			return false
		}
	}
	return true
}
