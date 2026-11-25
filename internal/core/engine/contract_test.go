package engine

// Engine contract tests: run the REAL external binaries and feed their real
// output through the real adapters.
//
// The unit tests in this package pin parsers against captured fixtures, which
// proves the parser matches output some past version produced. It cannot prove
// the version we pin today still produces it — and every engine bump is exactly
// the moment that stops being true. The testssl adapter once parsed nothing at
// all against the real tool; an automated version bump that silently did the
// same would ship a scanner that reports "ran, found 0" while seeing
// everything. These tests are what make it safe to let a bot move the pins:
// a bump that changes an output shape or a CLI flag fails here, on the PR.
//
// Each test plants something the engine must find, so "parsed without error"
// is not enough — an empty result fails too.
//
// They need network (vulnerability databases, image pulls) and minutes of run
// time, so they are opt-in:
//
//	SECSCAN_ENGINE_CONTRACT=1 go test -run Contract ./internal/core/engine/
//
// With the variable set, a missing binary is a FAILURE, not a skip: CI installs
// the pinned versions (ci/engines.sh) and a test that quietly skipped because
// the install broke would pass a PR it never checked. To run a subset locally,
// list the ones to leave out in SECSCAN_ENGINE_CONTRACT_SKIP (comma-separated
// engine IDs).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// rewriteRunner runs commands on the local machine but lets a test redirect
// the fixed paths an engine scans (/opt, /) to a fixture directory, and report
// a different target host. The engine code under test is unchanged: it builds
// the same argv it would in production, and only the path it points at moves.
type rewriteRunner struct {
	exec.Runner
	target  exec.Target
	rewrite func(argv []string) []string
}

func (r rewriteRunner) Run(ctx context.Context, argv ...string) exec.Result {
	return r.Runner.Run(ctx, r.rewrite(argv)...)
}
func (r rewriteRunner) Target() exec.Target { return r.target }

func contractRunner(host string, rewrite func([]string) []string) exec.Runner {
	return rewriteRunner{
		Runner:  exec.New(exec.Target{Name: "contract"}, 15*time.Minute),
		target:  exec.Target{Name: "contract", Host: host},
		rewrite: rewrite,
	}
}

// requireEngine decides whether this engine's contract runs, and fails rather
// than skips when the operator asked for contracts and the binary is missing.
func requireEngine(t *testing.T, id string, binaries ...string) {
	t.Helper()
	if os.Getenv("SECSCAN_ENGINE_CONTRACT") == "" {
		t.Skip("engine contract tests are opt-in: set SECSCAN_ENGINE_CONTRACT=1")
	}
	for _, s := range strings.Split(os.Getenv("SECSCAN_ENGINE_CONTRACT_SKIP"), ",") {
		if strings.TrimSpace(s) == id {
			t.Skipf("%s listed in SECSCAN_ENGINE_CONTRACT_SKIP", id)
		}
	}
	for _, b := range binaries {
		if _, err := osexec.LookPath(b); err != nil {
			t.Fatalf("%s contract requested but %s is not on PATH — install the pinned version "+
				"with ci/engines.sh install, or list %s in SECSCAN_ENGINE_CONTRACT_SKIP", id, b, id)
		}
	}
}

// replaceArg swaps every argv element equal to from.
func replaceArg(argv []string, from, to string) []string {
	out := append([]string(nil), argv...)
	for i, a := range out {
		if a == from {
			out[i] = to
		}
	}
	return out
}

func asset() *finding.Asset { return &finding.Asset{ID: "contract", Name: "contract", Kind: "host"} }

// A dependency with fixable HIGH advisories that every vulnerability database
// carries (CVE-2020-8203, CVE-2021-23337; fixed in 4.17.21). Old and famous on
// purpose: the contract is "the engine still reports what it obviously should",
// not a test of database freshness.
const vulnLodash = "4.17.15"

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustFind(t *testing.T, id string, fs []finding.Finding, err error, want func(finding.Finding) bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s adapter failed against the real binary: %v", id, err)
	}
	if len(fs) == 0 {
		t.Fatalf("%s ran and reported nothing, but the fixture plants something it must find — "+
			"the output shape or CLI has probably changed", id)
	}
	for _, f := range fs {
		if f.Engine != id {
			t.Errorf("finding %q attributed to engine %q, want %q", f.Title, f.Engine, id)
		}
		if want(f) {
			return
		}
	}
	t.Fatalf("%s returned %d findings but none matched the planted fixture; first: %+v", id, len(fs), fs[0].Title)
}

func TestContractTrivy(t *testing.T) {
	requireEngine(t, "trivy", "trivy")
	root := t.TempDir()
	// rootfs mode reads installed packages, not lockfiles, so the fixture is an
	// installed node_modules entry.
	writeFile(t, filepath.Join(root, "app/node_modules/lodash/package.json"),
		`{"name":"lodash","version":"`+vulnLodash+`","license":"MIT"}`)

	r := contractRunner("", func(argv []string) []string {
		if len(argv) > 1 && argv[0] == "trivy" && argv[1] == "rootfs" {
			return replaceArg(argv, "/", root)
		}
		return argv
	})
	fs, err := Trivy{}.Run(context.Background(), r, asset())
	mustFind(t, "trivy", fs, err, func(f finding.Finding) bool {
		return len(f.CVE) > 0 && strings.HasPrefix(f.CVE[0], "CVE-") && f.Remediation.Op == "apply_patch"
	})
}

func TestContractOSVScanner(t *testing.T) {
	requireEngine(t, "osv-scanner", "osv-scanner")
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app/package-lock.json"), `{
  "name": "contract", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "contract", "version": "1.0.0", "dependencies": {"lodash": "`+vulnLodash+`"}},
    "node_modules/lodash": {"version": "`+vulnLodash+`"}
  }
}`)
	r := contractRunner("", func(argv []string) []string {
		if len(argv) > 0 && argv[0] == "osv-scanner" {
			return replaceArg(argv, "/opt", root)
		}
		return argv
	})
	fs, err := OSVScanner{}.Run(context.Background(), r, asset())
	mustFind(t, "osv-scanner", fs, err, func(f finding.Finding) bool {
		return strings.Contains(f.Title, "lodash")
	})
}

// plantedToken builds a credential-shaped string at run time. Written as a
// literal it would be committed to this repository and trip the repo's own
// secret scanning; derived from a hash it is high-entropy (gitleaks ignores
// low-entropy look-alikes) yet obviously fake.
func plantedToken() string {
	sum := sha256.Sum256([]byte("secscan engine contract fixture"))
	body := hex.EncodeToString(sum[:])[:36]
	return "gh" + "p_" + body
}

func TestContractGitleaks(t *testing.T) {
	requireEngine(t, "gitleaks", "gitleaks")
	root := t.TempDir()
	tok := plantedToken()
	writeFile(t, filepath.Join(root, "app/deploy.sh"), "export GITHUB_TOKEN="+tok+"\n")

	r := contractRunner("", func(argv []string) []string {
		if len(argv) > 0 && argv[0] == "gitleaks" {
			return replaceArg(argv, "/opt", root)
		}
		return argv
	})
	fs, err := Gitleaks{}.Run(context.Background(), r, asset())
	mustFind(t, "gitleaks", fs, err, func(f finding.Finding) bool {
		return strings.Contains(f.Title, "deploy.sh")
	})
	// The adapter promises never to store the secret. An upstream change that
	// moved the value into a field we copy would break that promise silently.
	for _, f := range fs {
		for _, e := range f.Evidence {
			if strings.Contains(e.Output, tok) || strings.Contains(f.Description, tok) {
				t.Fatalf("finding %q carries the secret value — redaction broke", f.Title)
			}
		}
	}
}

// contractTemplate matches a header only the test server sends, so the result
// does not depend on nuclei's public template set (which the test does not
// download) and cannot match anything by accident.
const contractTemplate = `id: secscan-contract-canary
info:
  name: secscan contract canary
  author: secscan
  severity: medium
  description: Matches the canary header served by the secscan engine contract test.
  reference: https://github.com/jchirayath/secscan
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "X-Secscan-Contract: canary"
`

func canaryServer(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Secscan-Contract", "canary")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestContractNuclei(t *testing.T) {
	requireEngine(t, "nuclei", "nuclei")
	srv := canaryServer(t)
	tpl := filepath.Join(t.TempDir(), "canary.yaml")
	writeFile(t, tpl, contractTemplate)
	// Keep nuclei from fetching ~13k public templates on first run: the
	// contract is about the CLI and the JSONL shape, not the template corpus.
	t.Setenv("DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD", "true")
	t.Setenv("HOME", t.TempDir())

	host := strings.TrimPrefix(srv.URL, "https://")
	r := contractRunner(host, func(argv []string) []string {
		if len(argv) > 0 && argv[0] == "nuclei" {
			return append(append([]string(nil), argv...), "-t", tpl, "-duc", "-no-interactsh")
		}
		return argv
	})
	fs, err := Nuclei{}.Run(context.Background(), r, asset())
	mustFind(t, "nuclei", fs, err, func(f finding.Finding) bool {
		return f.RuleID == "web.nuclei.secscan-contract-canary" && f.Severity == finding.SevMedium
	})
}

func TestContractTestSSL(t *testing.T) {
	requireEngine(t, "testssl", "testssl.sh")
	srv := canaryServer(t)
	host := strings.TrimPrefix(srv.URL, "https://")
	r := contractRunner(host, func(argv []string) []string { return argv })
	// A clean handshake can legitimately yield zero MEDIUM+ entries, so the
	// contract here is the parse: an error means testssl's JSON moved (the
	// adapter distinguishes "clean" from "unrecognised shape" — see
	// parseTestSSL), or that it could not run at all on this machine.
	if _, err := (TestSSL{}).Run(context.Background(), r, asset()); err != nil {
		t.Fatalf("testssl adapter failed against the real binary: %v", err)
	}
}

func TestContractTrivyImage(t *testing.T) {
	requireEngine(t, "trivy-image", "trivy", "docker")
	ctx := context.Background()
	// An old, small image with fixable OS-package CVEs. The label lets the
	// runner restrict `docker ps` to this container, so a developer's own
	// running containers are never scanned by a test.
	const image = "alpine:3.10"
	const label = "secscan-contract=1"
	run := osexec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--label", label, image, "sleep", "900")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v: %s", image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = osexec.Command("docker", "rm", "-f", id).Run() })

	r := contractRunner("", func(argv []string) []string {
		if len(argv) == 3 && argv[0] == "docker" && argv[1] == "ps" && argv[2] == "-q" {
			return []string{"docker", "ps", "-q", "--filter", "label=" + label}
		}
		return argv
	})
	fs, err := TrivyImage{}.Run(ctx, r, asset())
	mustFind(t, "trivy-image", fs, err, func(f finding.Finding) bool {
		return len(f.CVE) > 0 && f.Subcategory == "image" && strings.Contains(f.Remediation.Summary, image)
	})
}
