package main

import (
	"testing"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/store"
)

// openStore gives each test its own state directory.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return st
}

func names(ts []exec.Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	return out
}

// A second `add` under an existing name must REPLACE that target, not append a
// second one. The old behaviour appended, and because targets are matched by
// name, `scan web01` then silently ran against whichever entry came first — so
// correcting a target's address appeared to work while every scan still used
// the stale one.
func TestTargetsAddReplacesExistingName(t *testing.T) {
	st := openStore(t)

	if rc := cmdTargets(st, []string{"add", "web01", "scan@10.0.0.1"}); rc != 0 {
		t.Fatalf("first add: rc=%d", rc)
	}
	if rc := cmdTargets(st, []string{"add", "web01", "scan@10.0.0.2", "-sudo"}); rc != 0 {
		t.Fatalf("second add: rc=%d", rc)
	}

	got := st.Targets()
	if len(got) != 1 {
		t.Fatalf("want 1 target after re-adding the same name, got %d: %v", len(got), names(got))
	}
	if got[0].Host != "10.0.0.2" {
		t.Errorf("address not updated: got %q, want 10.0.0.2", got[0].Host)
	}
	if !got[0].UseSudo {
		t.Error("flags from the second add were not applied (-sudo lost)")
	}
}

// Editing a target must not reshuffle the list, or `targets` output jumps
// around every time an address is corrected.
func TestTargetsAddKeepsPosition(t *testing.T) {
	st := openStore(t)
	for _, n := range []string{"a", "b", "c"} {
		if rc := cmdTargets(st, []string{"add", n, "scan@" + n}); rc != 0 {
			t.Fatalf("add %s: rc=%d", n, rc)
		}
	}
	if rc := cmdTargets(st, []string{"add", "b", "scan@newb"}); rc != 0 {
		t.Fatalf("re-add b: rc=%d", rc)
	}

	got := names(st.Targets())
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order changed: got %v, want %v", got, want)
		}
	}
}

// State files written by the old appending behaviour already contain
// duplicates. An `add` must collapse them rather than leaving the extras to go
// on shadowing scans.
func TestTargetsAddCollapsesPreExistingDuplicates(t *testing.T) {
	st := openStore(t)
	if err := st.SetTargets([]exec.Target{
		{Name: "dup", Host: "old-1"},
		{Name: "keep", Host: "keep"},
		{Name: "dup", Host: "old-2"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if rc := cmdTargets(st, []string{"add", "dup", "scan@fresh"}); rc != 0 {
		t.Fatalf("add: rc=%d", rc)
	}

	got := st.Targets()
	var dups int
	for _, tg := range got {
		if tg.Name == "dup" {
			dups++
			if tg.Host != "fresh" {
				t.Errorf("surviving dup has stale address %q", tg.Host)
			}
		}
	}
	if dups != 1 {
		t.Fatalf("want exactly 1 %q target, got %d: %v", "dup", dups, names(got))
	}
	if len(got) != 2 {
		t.Fatalf("unrelated targets disturbed: %v", names(got))
	}
}

// rm is the complement: it clears every entry with the name, which is what
// makes recovery from a duplicated state file possible at all.
func TestTargetsRemoveAllWithName(t *testing.T) {
	st := openStore(t)
	if err := st.SetTargets([]exec.Target{
		{Name: "dup", Host: "1"},
		{Name: "other", Host: "2"},
		{Name: "dup", Host: "3"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if rc := cmdTargets(st, []string{"rm", "dup"}); rc != 0 {
		t.Fatalf("rm: rc=%d", rc)
	}
	got := names(st.Targets())
	if len(got) != 1 || got[0] != "other" {
		t.Fatalf("rm should remove every entry named dup; got %v", got)
	}
}
