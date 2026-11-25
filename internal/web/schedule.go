package web

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jchirayath/secscan/internal/audit"
	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/scan"
	"github.com/jchirayath/secscan/internal/store"
)

// Scheduled scans run INSIDE `serve`, not from cron. The store loads state.json
// once and keeps it in memory, so a separate `secscan scan` process would write
// results the running dashboard never shows — and the dashboard's next write
// (a suppression, a feature toggle) would then overwrite them. Scanning through
// the server's own store is the only way both views stay one view.

var errScanBusy = errors.New("a scan of this target is already running")

// storeError marks a scan that ran but whose results could not be persisted,
// so the HTTP handler can answer StoreFailed rather than ScanFailed.
type storeError struct{ error }

// claim marks a target as being scanned; false means a scan is already running.
func (s *Server) claim(name string) bool {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scanning[name] {
		return false
	}
	s.scanning[name] = true
	return true
}

func (s *Server) release(name string) {
	s.scanMu.Lock()
	delete(s.scanning, name)
	s.scanMu.Unlock()
}

// runScan scans one target and merges the result into the store. Shared by
// POST /api/scan and the scheduler so the two cannot drift apart.
func (s *Server) runScan(ctx context.Context, t exec.Target) (scan.Result, store.ScanSummary, error) {
	if !s.claim(t.Name) {
		return scan.Result{}, store.ScanSummary{}, errScanBusy
	}
	defer s.release(t.Name)

	res, err := scan.Run(ctx, t, scan.Options{
		Timeout:  s.cfg.ScanTimeout,
		Features: s.store.Features(),
	})
	if err != nil {
		return res, store.ScanSummary{}, err
	}
	newN, fixedN, err := s.store.Merge(res.Asset, res.Findings, scan.CoverageOf(res))
	if err != nil {
		return res, store.ScanSummary{}, storeError{err}
	}
	if err := s.store.SetTranscript(res.Asset.ID, res.Transcript); err != nil {
		slog.Warn("transcript persist failed", slog.String("err", err.Error()))
	}
	sum := scan.Summarise(res, newN, fixedN)
	if err := s.store.AppendHistory(sum); err != nil {
		slog.Warn("history append failed", slog.String("err", err.Error()))
	}
	return res, sum, nil
}

// scheduler scans every configured target each SECSCAN_SCAN_INTERVAL, one at a
// time. The first pass waits a short delay after startup so a restart loop does
// not turn into a scan loop, and a container restart still produces fresh
// results soon instead of up to a full interval later.
func (s *Server) scheduler(ctx context.Context) {
	every := s.cfg.ScanInterval
	if every <= 0 {
		return
	}
	slog.Info("scheduled scans enabled", slog.String("every", every.String()))
	wait := 2 * time.Minute
	if every < wait {
		wait = every
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.scanAll(ctx)
		timer.Reset(every)
	}
}

func (s *Server) scanAll(ctx context.Context) {
	targets := s.store.Targets()
	if len(targets) == 0 {
		targets = []exec.Target{{Name: "localhost"}}
	}
	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}
		start := clock.Now()
		_, sum, err := s.runScan(ctx, t)
		result := "allowed"
		if err != nil {
			result = "error"
		}
		s.audit.Write(audit.Entry{
			Caller: "scheduler", Role: "system", Action: "scan.run",
			Target: t.Name, Result: result, Detail: errString(err),
		})
		if err != nil {
			slog.Warn("scheduled scan failed", slog.String("target", t.Name), slog.String("err", err.Error()))
			continue
		}
		slog.Info("scheduled scan done", slog.String("target", t.Name),
			slog.Float64("score", sum.Score), slog.Duration("took", clock.Now().Sub(start).Round(time.Second)))
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
