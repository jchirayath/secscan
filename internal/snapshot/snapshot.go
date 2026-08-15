// Package snapshot records a point-in-time copy of every finding from a scan,
// so posture can be compared across weeks rather than only observed today.
//
// The existing history file already carries a score and severity counts per
// run, which is enough to draw a line. It is not enough to answer the question
// that actually follows a moving line: *what changed?* That needs the findings
// themselves, which is what a snapshot keeps.
//
// Snapshots are written outside the state file for three reasons: they grow
// without bound while state does not, they are the thing an operator most often
// wants to keep on a different disk or ship to another system, and losing them
// costs history rather than function.
package snapshot

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/core/finding"
)

// Snapshot is one scan's complete result, as it stood at that moment.
type Snapshot struct {
	Version  int               `json:"version"`
	At       time.Time         `json:"at"`
	Asset    finding.Asset     `json:"asset"`
	Score    float64           `json:"score"`
	Findings []finding.Finding `json:"findings"`

	// Coverage records which checks ran, because a score that improved because
	// a check stopped running is not an improvement — and without this, the two
	// are indistinguishable in a trend line.
	Coverage []CoverageRow `json:"coverage"`
}

// CoverageRow mirrors store.CollectorRun without importing it, so package
// snapshot stays free of a dependency on the live store.
type CoverageRow struct {
	ID      string `json:"id"`
	Ran     bool   `json:"ran"`
	Skipped string `json:"skipped,omitempty"`
	Found   int    `json:"found"`
}

// Meta is the cheap summary, readable without decompressing a whole snapshot.
// A trend over a year of daily scans should not require reading a year of
// findings.
type Meta struct {
	ID      string         `json:"id"` // the filename stem, sortable by time
	At      time.Time      `json:"at"`
	Asset   string         `json:"asset"`
	Score   float64        `json:"score"`
	Total   int            `json:"total"`
	Counts  map[string]int `json:"counts"`
	Ran     int            `json:"checks_ran"`
	Skipped int            `json:"checks_skipped"`
	SizeKB  int64          `json:"size_kb"`
}

// Store writes and reads snapshots under a directory the operator chooses.
type Store struct{ dir string }

// Open prepares the snapshot directory.
//
// Mode 0700 is deliberate: a snapshot holds every finding for a host, which is
// a map of its weaknesses. Leaving that world-readable would make this feature
// a disclosure of exactly the kind the scanner reports elsewhere.
func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("snapshot directory is empty")
	}
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("snapshot directory must be an absolute path, got %q", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the configured directory.
func (s *Store) Dir() string { return s.dir }

// safeAsset keeps an asset name usable as a directory component. Asset names
// come from operator-supplied target names, so a name like "../../etc" must not
// be able to steer where a file lands.
func safeAsset(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "unnamed"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// Write stores a snapshot, gzipped. A year of daily scans of a busy host is
// otherwise hundreds of megabytes of highly repetitive JSON.
func (s *Store) Write(snap Snapshot) (Meta, error) {
	snap.Version = 1
	assetDir := filepath.Join(s.dir, safeAsset(snap.Asset.ID))
	if err := os.MkdirAll(assetDir, 0o700); err != nil {
		return Meta{}, err
	}

	// A sortable, human-readable stem means `ls` gives chronological order and
	// a filename alone identifies the run.
	id := snap.At.UTC().Format("20060102T150405Z")
	path := filepath.Join(assetDir, id+".json.gz")

	// Write to a temp file and rename: an interrupted write must not leave a
	// half-snapshot that later reads as a real one.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Meta{}, err
	}
	zw := gzip.NewWriter(f)
	if err := json.NewEncoder(zw).Encode(snap); err != nil {
		zw.Close()
		f.Close()
		os.Remove(tmp)
		return Meta{}, err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return Meta{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return Meta{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return Meta{}, err
	}

	meta := metaOf(snap, id)
	if fi, err := os.Stat(path); err == nil {
		meta.SizeKB = (fi.Size() + 1023) / 1024
	}
	// The sidecar is what List reads, so a trend over a long history never has
	// to decompress anything.
	if err := s.writeMeta(assetDir, id, meta); err != nil {
		return meta, err
	}
	return meta, nil
}

func (s *Store) writeMeta(assetDir, id string, m Meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(assetDir, id+".meta.json"), b, 0o600)
}

func metaOf(snap Snapshot, id string) Meta {
	counts := map[string]int{}
	open := 0
	for _, f := range snap.Findings {
		if f.Status != finding.StatusOpen {
			continue
		}
		open++
		counts[string(f.Severity)]++
	}
	ran, skipped := 0, 0
	for _, c := range snap.Coverage {
		if c.Ran {
			ran++
		} else {
			skipped++
		}
	}
	return Meta{
		ID: id, At: snap.At, Asset: snap.Asset.ID, Score: snap.Score,
		Total: open, Counts: counts, Ran: ran, Skipped: skipped,
	}
}

// List returns snapshot metadata for an asset, oldest first. An empty asset
// returns every asset's snapshots.
func (s *Store) List(asset string) ([]Meta, error) {
	var out []Meta

	assets := []string{}
	if asset != "" {
		assets = append(assets, safeAsset(asset))
	} else {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				assets = append(assets, e.Name())
			}
		}
	}

	for _, a := range assets {
		dir := filepath.Join(s.dir, a)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".meta.json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var m Meta
			if json.Unmarshal(b, &m) == nil {
				out = append(out, m)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// Load reads a full snapshot.
func (s *Store) Load(asset, id string) (Snapshot, error) {
	// id comes from a URL, so it is constrained to the shape Write produces
	// rather than trusted as a path component.
	if !validID(id) {
		return Snapshot{}, fmt.Errorf("malformed snapshot id %q", id)
	}
	path := filepath.Join(s.dir, safeAsset(asset), id+".json.gz")
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s is not readable gzip: %w", id, err)
	}
	defer zr.Close()

	var snap Snapshot
	if err := json.NewDecoder(zr).Decode(&snap); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s is corrupt: %w", id, err)
	}
	return snap, nil
}

// validID accepts only the timestamp shape Write emits: 20060102T150405Z.
func validID(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := time.Parse("20060102T150405Z", id)
	return err == nil
}

// Diff is what changed between two snapshots.
type Diff struct {
	// One tag per field: declaring them together as `json:"from,to"` gives BOTH
	// the tag "from" with an option "to", so the diff emitted two "from" keys
	// and no "to" at all. go vet caught it.
	From       string            `json:"from"`
	To         string            `json:"to"`
	FromAt     time.Time         `json:"from_at"`
	ToAt       time.Time         `json:"to_at"`
	ScoreDelta float64           `json:"score_delta"`
	New        []finding.Finding `json:"new"`
	Fixed      []finding.Finding `json:"fixed"`
	Unchanged  int               `json:"unchanged"`
	// CoverageLost names checks that ran in the earlier snapshot but not the
	// later one. This is the honest counterpart to a score that went up: a
	// posture can improve because a problem was fixed, or because the check
	// that found it stopped running, and only one of those is good news.
	CoverageLost []string `json:"coverage_lost,omitempty"`
}

// Compare diffs two snapshots by finding fingerprint.
func Compare(from, to Snapshot) Diff {
	d := Diff{
		FromAt: from.At, ToAt: to.At,
		ScoreDelta: round2(to.Score - from.Score),
	}

	inFrom := map[string]finding.Finding{}
	for _, f := range from.Findings {
		if f.Status == finding.StatusOpen {
			inFrom[f.ID] = f
		}
	}
	for _, f := range to.Findings {
		if f.Status != finding.StatusOpen {
			continue
		}
		if _, ok := inFrom[f.ID]; ok {
			d.Unchanged++
			delete(inFrom, f.ID)
			continue
		}
		d.New = append(d.New, f)
	}
	for _, f := range inFrom {
		d.Fixed = append(d.Fixed, f)
	}
	finding.Sort(d.New)
	finding.Sort(d.Fixed)

	ranIn := func(s Snapshot) map[string]bool {
		m := map[string]bool{}
		for _, c := range s.Coverage {
			if c.Ran {
				m[c.ID] = true
			}
		}
		return m
	}
	before, after := ranIn(from), ranIn(to)
	for id := range before {
		if !after[id] {
			d.CoverageLost = append(d.CoverageLost, id)
		}
	}
	sort.Strings(d.CoverageLost)
	return d
}

// Prune keeps the newest n snapshots per asset and deletes the rest, returning
// how many were removed. Retention is the operator's call, so zero means keep
// everything.
func (s *Store) Prune(asset string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	metas, err := s.List(asset)
	if err != nil {
		return 0, err
	}
	byAsset := map[string][]Meta{}
	for _, m := range metas {
		byAsset[m.Asset] = append(byAsset[m.Asset], m)
	}

	removed := 0
	for a, list := range byAsset {
		if len(list) <= keep {
			continue
		}
		// List is oldest-first, so the excess is at the front.
		for _, m := range list[:len(list)-keep] {
			dir := filepath.Join(s.dir, safeAsset(a))
			_ = os.Remove(filepath.Join(dir, m.ID+".json.gz"))
			_ = os.Remove(filepath.Join(dir, m.ID+".meta.json"))
			removed++
		}
	}
	return removed, nil
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
