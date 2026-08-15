// Package clock is the injectable time source. Business logic calls clock.Now()
// so tests can control time; bare time.Now() outside adapters is a CI failure
// (ARCHITECTURE.md — Time).
package clock

import "time"

// Clock yields the current instant.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// Real is the production clock. All times are UTC so stored timestamps are
// comparable regardless of where a scan ran.
var Real Clock = realClock{}

// Fixed returns a Clock frozen at t — for tests and golden fixtures.
func Fixed(t time.Time) Clock { return fixedClock{t: t.UTC()} }

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

// Now is the package-level convenience used by production code paths that have
// no natural place to thread a Clock. Tests that need determinism inject a
// Clock explicitly rather than reassigning this.
func Now() time.Time { return Real.Now() }
