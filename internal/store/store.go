// Package store persists state. No database: a JSON document for current state
// plus an append-only JSONL file for scan history, loaded into an in-memory
// index at boot (ARCHITECTURE.md — Constraints).
//
// A single-host scanner produces thousands of findings, not millions. When a
// deployment outgrows that, the Store interface is the seam where a SQLite
// implementation drops in without touching a caller.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/feature"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Suppression is an accepted risk. Reason and expiry are mandatory at the API
// layer: an accepted risk with no stated reason is indistinguishable from an
// ignored one, and one with no expiry is forever.
type Suppression struct {
	FindingID string               `json:"finding_id"`
	Kind      finding.SuppressKind `json:"kind,omitempty"`
	Reason    string               `json:"reason"`
	Until     time.Time            `json:"until"`
	By        string               `json:"by"`
	Role      string               `json:"role"`
	At        time.Time            `json:"at"`
}

// ScanSummary is one history row.
type ScanSummary struct {
	At        time.Time      `json:"at"`
	Target    string         `json:"target"`
	Duration  string         `json:"duration"`
	Counts    map[string]int `json:"counts"` // severity → count
	Total     int            `json:"total"`
	New       int            `json:"new"`
	Fixed     int            `json:"fixed"`
	Score     float64        `json:"score"` // posture score 0-100, higher is better
	Collector []CollectorRun `json:"collectors"`
}

// CollectorRun records what one collector did — including why it was skipped.
type CollectorRun struct {
	ID      string `json:"id"`
	Ran     bool   `json:"ran"`
	Skipped string `json:"skipped,omitempty"`
	// NotApplicable: the collector established its checks cannot apply to this
	// target, which counts as coverage (see collect.NotApplicable).
	NotApplicable bool `json:"not_applicable,omitempty"`
	Checks        int  `json:"checks"`
	Found         int  `json:"found"`
}

// state is the on-disk document.
type state struct {
	Version      int                        `json:"version"`
	Assets       map[string]finding.Asset   `json:"assets"`
	Findings     map[string]finding.Finding `json:"findings"`
	Suppressions map[string]Suppression     `json:"suppressions"`
	Rules        []Rule                     `json:"rules,omitempty"`
	Targets      []exec.Target              `json:"targets"`
	Features     feature.State              `json:"features"`
	// Transcripts hold the LAST scan's command log per asset. Only the latest
	// is kept: history would grow without bound, and a transcript is useful for
	// "what did this run just now?" rather than as an archive.
	Transcripts map[string]map[string][]exec.Step `json:"transcripts,omitempty"`
	UpdatedAt   time.Time                         `json:"updated_at"`
}

// Store is the persistence seam.
type Store struct {
	mu  sync.RWMutex
	dir string
	st  state
}

// Open loads (or initialises) the store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	s := &Store{dir: dir, st: state{
		Version:      1,
		Assets:       map[string]finding.Asset{},
		Findings:     map[string]finding.Finding{},
		Suppressions: map[string]Suppression{},
	}}
	b, err := os.ReadFile(s.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("parse state (corrupt %s): %w", s.statePath(), err)
	}
	// Defensive: an older or hand-edited file may have null maps.
	if s.st.Assets == nil {
		s.st.Assets = map[string]finding.Asset{}
	}
	if s.st.Findings == nil {
		s.st.Findings = map[string]finding.Finding{}
	}
	if s.st.Suppressions == nil {
		s.st.Suppressions = map[string]Suppression{}
	}
	return s, nil
}

func (s *Store) statePath() string   { return filepath.Join(s.dir, "state.json") }
func (s *Store) historyPath() string { return filepath.Join(s.dir, "history.jsonl") }

// save writes atomically: a partial write must never replace good state.
func (s *Store) save() error {
	s.st.UpdatedAt = clock.Now()
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}

// Merge folds a scan's findings into stored state and returns (new, fixed).
//
// Identity is the fingerprint, so a finding keeps FirstSeen across scans and
// "new since last scan" stays meaningful. Findings previously open for this
// asset that this scan did not re-observe are marked fixed — but only where
// cov says the producer ran and looked, otherwise a skipped collector (or an
// image beyond trivy-image's cap) would silently "fix" everything it used to
// report. Until 2026-11 this was keyed on collectors alone, so findings from
// external engines (trivy, gitleaks, ...) could never be closed at all.
func (s *Store) Merge(asset finding.Asset, found []finding.Finding, cov Coverage) (newN, fixedN int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := clock.Now()
	seen := map[string]bool{}
	// Index, not range copy: the caller's slice is updated in place so the
	// scan summary and score count what the store now says is open, not what
	// the scanner saw before suppressions were applied.
	for i := range found {
		f := &found[i]
		seen[f.ID] = true
		if prev, ok := s.st.Findings[f.ID]; ok {
			f.FirstSeen = prev.FirstSeen
			f.Occurrences = prev.Occurrences + 1
			// A per-finding suppression survives rescans until it expires.
			// A rule's survives only while the rule exists: revoking it must
			// win even if the finding still carries the old expiry.
			if prev.Status == finding.StatusSuppressed && now.Before(derefTime(prev.SuppressUntil)) &&
				(prev.SuppressRule == "" || s.ruleExists(prev.SuppressRule)) {
				f.Status = finding.StatusSuppressed
				f.SuppressKind = prev.SuppressKind
				f.SuppressReason = prev.SuppressReason
				f.SuppressUntil = prev.SuppressUntil
				f.SuppressRule = prev.SuppressRule
			}
		} else {
			newN++
		}
		if f.Status == finding.StatusOpen {
			if r, ok := s.firstRule(*f, now); ok {
				applyRule(f, r)
			}
		}
		s.st.Findings[f.ID] = *f
	}

	for id, prev := range s.st.Findings {
		if prev.AssetID != asset.ID || seen[id] || prev.Status == finding.StatusFixed {
			continue
		}
		if !cov.covers(prev.Engine, prev.Location) {
			continue // producer didn't run, or didn't look there — absence proves nothing
		}
		prev.Status = finding.StatusFixed
		prev.LastSeen = now
		s.st.Findings[id] = prev
		fixedN++
	}

	s.st.Assets[asset.ID] = asset
	return newN, fixedN, s.save()
}

func (s *Store) ruleExists(id string) bool {
	for _, r := range s.st.Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// AppendHistory adds one scan summary to the append-only log.
func (s *Store) AppendHistory(sum ScanSummary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.historyPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// History returns up to n most-recent summaries, oldest first.
func (s *Store) History(n int) []ScanSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := os.ReadFile(s.historyPath())
	if err != nil {
		return nil
	}
	var all []ScanSummary
	for _, line := range splitLines(b) {
		var sum ScanSummary
		if json.Unmarshal(line, &sum) == nil {
			all = append(all, sum)
		}
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// Findings returns findings matching f, sorted by risk.
func (s *Store) Findings(filter Filter) []finding.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []finding.Finding
	for _, f := range s.st.Findings {
		if filter.match(f) {
			out = append(out, f)
		}
	}
	finding.Sort(out)
	return out
}

// Filter narrows a Findings query. Zero-valued fields are ignored.
//
// The default is deliberately "open only". A risk someone explicitly accepted
// should not keep dominating the dashboard and the score — that is the whole
// point of accepting it — and a fixed finding is history. Both remain
// reachable by asking for them with Status.
type Filter struct {
	AssetID  string
	Engine   string // which collector produced it — drives the coverage drill-down
	Category finding.Category
	Severity finding.Severity
	Status   finding.Status
	// IncludeInactive brings suppressed and fixed findings back in, for the
	// "everything we know about this asset" view.
	IncludeInactive bool
}

func (f Filter) match(x finding.Finding) bool {
	if f.AssetID != "" && x.AssetID != f.AssetID {
		return false
	}
	if f.Engine != "" && x.Engine != f.Engine {
		return false
	}
	if f.Category != "" && x.Category != f.Category {
		return false
	}
	if f.Severity != "" && x.Severity != f.Severity {
		return false
	}
	// An explicit status request wins — that is how the UI shows the accepted
	// -risk register.
	if f.Status != "" {
		return x.Status == f.Status
	}
	if !f.IncludeInactive && x.Status != finding.StatusOpen {
		return false
	}
	return true
}

// Get returns one finding.
func (s *Store) Get(id string) (finding.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.st.Findings[id]
	return f, ok
}

// Suppress accepts a risk, recording who did it and under which role.
func (s *Store) Suppress(id string, kind finding.SuppressKind, reason string, until time.Time, by, role string) error {
	if !kind.Valid() {
		return fmt.Errorf("kind must be %q or %q", finding.KindAcceptedRisk, finding.KindFalsePositive)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.st.Findings[id]
	if !ok {
		return fmt.Errorf("finding %s not found", id)
	}
	f.Status = finding.StatusSuppressed
	f.SuppressKind = kind
	f.SuppressReason = reason
	f.SuppressUntil = &until
	f.SuppressRule = ""
	s.st.Findings[id] = f
	s.st.Suppressions[id] = Suppression{
		FindingID: id, Kind: kind, Reason: reason, Until: until,
		By: by, Role: role, At: clock.Now(),
	}
	return s.save()
}

// Assets returns all known assets, name-sorted.
func (s *Store) Assets() []finding.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]finding.Asset, 0, len(s.st.Assets))
	for _, a := range s.st.Assets {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Targets returns the configured scan targets.
func (s *Store) Targets() []exec.Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]exec.Target(nil), s.st.Targets...)
}

// SetTargets replaces the target list.
func (s *Store) SetTargets(t []exec.Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Targets = t
	return s.save()
}

// SetTranscript replaces the recorded command log for an asset.
func (s *Store) SetTranscript(assetID string, t map[string][]exec.Step) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Transcripts == nil {
		s.st.Transcripts = map[string]map[string][]exec.Step{}
	}
	s.st.Transcripts[assetID] = t
	return s.save()
}

// Transcript returns the recorded steps for one check on one asset.
func (s *Store) Transcript(assetID, checkID string) []exec.Step {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Transcripts[assetID][checkID]
}

// Features returns the persisted enable/disable set.
func (s *Store) Features() feature.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := feature.State{Disabled: map[string]bool{}, Enabled: map[string]bool{}}
	for k, v := range s.st.Features.Disabled {
		out.Disabled[k] = v
	}
	for k, v := range s.st.Features.Enabled {
		out.Enabled[k] = v
	}
	return out
}

// SetFeature enables or disables one capability.
func (s *Store) SetFeature(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Features.Disabled == nil {
		s.st.Features.Disabled = map[string]bool{}
	}
	if s.st.Features.Enabled == nil {
		s.st.Features.Enabled = map[string]bool{}
	}
	if enabled {
		delete(s.st.Features.Disabled, id)
		s.st.Features.Enabled[id] = true // records a deliberate opt-in
	} else {
		s.st.Features.Disabled[id] = true
		delete(s.st.Features.Enabled, id)
	}
	return s.save()
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
