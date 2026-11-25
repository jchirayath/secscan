package main

// Binary smoke test: build the real `secscan` and drive it the way an operator
// and the container healthcheck do.
//
// Unit tests exercise packages; they do not prove the shipped binary starts,
// scans, persists and serves. That is the property an automated update can
// break without any unit test noticing — a Go toolchain bump that changes
// ServeMux pattern handling, a flag that stops parsing, a state file that no
// longer round-trips — and it is the one every update PR must show is intact
// before it merges. So this runs in plain `go test ./...` (about two seconds),
// not behind a flag: a gate that has to be remembered is a gate that gets
// skipped. `go test -short` leaves it out.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildBinary compiles cmd/secscan once per test binary run.
func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("binary smoke test skipped in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "secscan")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := osexec.Command(gobin, "build", "-trimpath", "-ldflags", "-X main.Version=smoke", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// secscanEnv isolates the binary from the developer's real state and config:
// a fresh SECSCAN_HOME, and every other SECSCAN_* variable dropped so a local
// .envrc cannot change what the test exercises.
func secscanEnv(home string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SECSCAN_") {
			env = append(env, kv)
		}
	}
	return append(append(env, "SECSCAN_HOME="+home, "SECSCAN_AUTH_MODE=local", "SECSCAN_LOG_LEVEL=warn"), extra...)
}

func run(t *testing.T, bin, home string, args ...string) (stdout, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := osexec.CommandContext(ctx, bin, args...)
	cmd.Env = secscanEnv(home)
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Run(); err != nil {
		t.Fatalf("secscan %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, o.String(), e.String())
	}
	return o.String(), e.String()
}

func TestSmokeBinaryScan(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	if out, _ := run(t, bin, home, "version"); strings.TrimSpace(out) != "secscan smoke" {
		t.Fatalf("version = %q, want the ldflags-stamped %q", out, "secscan smoke")
	}

	// Native collectors only: deterministic, offline, and the engines have their
	// own contract tests (internal/core/engine/contract_test.go).
	out, _ := run(t, bin, home, "scan", "-json", "-no-engines", "-no-snapshot")
	var res struct {
		Asset struct {
			ID, Name string
		} `json:"asset"`
		Findings []struct {
			ID       string `json:"id"`
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"findings"`
		Collectors []struct {
			ID      string `json:"id"`
			Ran     bool   `json:"ran"`
			Skipped string `json:"skipped"`
		} `json:"collectors"`
		Engines []struct {
			ID     string `json:"id"`
			Ran    bool   `json:"ran"`
			Reason string `json:"reason"`
		} `json:"engines"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("scan -json is not valid JSON: %v\n%.400s", err, out)
	}
	if res.Asset.Name != "localhost" {
		t.Errorf("asset = %q, want the default localhost target", res.Asset.Name)
	}

	ran := 0
	for _, c := range res.Collectors {
		if c.Ran {
			ran++
		} else if strings.TrimSpace(c.Skipped) == "" {
			// "Not run" with no reason is the silent gap this product forbids.
			t.Errorf("collector %s did not run and gave no reason", c.ID)
		}
	}
	// host-facts reads uname and os-release, which every supported platform
	// has; if even that fails the transport itself is broken.
	if ran < 3 {
		t.Errorf("only %d collectors ran on localhost; expected the portable ones (host-facts, listeners, …): %+v", ran, res.Collectors)
	}
	if len(res.Engines) == 0 {
		t.Error("no engine statuses — every known engine must report, even when skipped")
	}
	for _, e := range res.Engines {
		if e.Ran || e.Reason == "" {
			t.Errorf("engine %s: ran=%v reason=%q under -no-engines", e.ID, e.Ran, e.Reason)
		}
	}
	sev := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, f := range res.Findings {
		if f.ID == "" || f.RuleID == "" || f.Title == "" || !sev[f.Severity] {
			t.Errorf("malformed finding: %+v", f)
		}
	}

	// The scan must have persisted: plan and the Markdown report read it back.
	if _, err := os.Stat(filepath.Join(home, "state.json")); err != nil {
		t.Fatalf("scan did not write state.json: %v", err)
	}
	run(t, bin, home, "plan")
	md, _ := run(t, bin, home, "scan", "-no-engines", "-no-snapshot", "-report", "-")
	if !strings.HasPrefix(strings.TrimSpace(md), "#") {
		t.Errorf("-report - did not produce Markdown: %.200q", md)
	}
}

func TestSmokeBinaryServe(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	// Reserve a free loopback port. There is a small window between closing the
	// listener and the server binding it; on a CI runner that is acceptable,
	// and binding :0 would leave no way to learn the port from outside.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	cmd := osexec.Command(bin, "serve", "-bind", addr, "-auth", "local")
	cmd.Env = secscanEnv(home)
	stderr, _ := cmd.StderrPipe()
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	logDone := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			logs.WriteString(sc.Text() + "\n")
		}
		close(logDone)
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	base := "http://" + addr
	client := &http.Client{Timeout: 5 * time.Second}
	get := func(path string) (int, string) {
		resp, err := client.Get(base + path)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(b)
	}

	// /healthz is what the container healthcheck probes.
	deadline := time.Now().Add(20 * time.Second)
	for {
		code, body := get("/healthz")
		if code == 200 && body == "ok" {
			break
		}
		select {
		case err := <-exited:
			<-logDone
			t.Fatalf("serve exited before becoming healthy: %v\n%s", err, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve not healthy within 20s (last: %d %q)", code, body)
		}
		time.Sleep(100 * time.Millisecond)
	}

	for _, p := range []string{"/api/overview", "/api/features", "/api/me"} {
		code, body := get(p)
		if code != 200 {
			t.Errorf("GET %s = %d: %.200s", p, code, body)
			continue
		}
		if !json.Valid([]byte(body)) {
			t.Errorf("GET %s returned non-JSON: %.200s", p, body)
		}
	}
	if code, body := get("/"); code != 200 || !strings.Contains(strings.ToLower(body), "<html") {
		t.Errorf("GET / = %d, want the dashboard HTML", code)
	}
	for _, p := range []string{"/app.js", "/app.css"} {
		if code, _ := get(p); code != 200 {
			t.Errorf("GET %s = %d, want the embedded asset", p, code)
		}
	}

	// A clean shutdown on SIGINT is what `docker stop` relies on.
	if runtime.GOOS != "windows" {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case err := <-exited:
			if err != nil {
				<-logDone
				t.Errorf("serve did not exit cleanly on SIGINT: %v\n%s", err, logs.String())
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-logDone
			t.Errorf("serve still running 10s after SIGINT\n%s", logs.String())
		}
	}
}
