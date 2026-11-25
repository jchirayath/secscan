package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/jchirayath/secscan/internal/core/exec"
)

// gitleaksRunner answers every Run with one fixed result.
type gitleaksRunner struct{ res exec.Result }

func (c gitleaksRunner) Run(context.Context, ...string) exec.Result      { return c.res }
func (c gitleaksRunner) Has(context.Context, string) bool                { return true }
func (c gitleaksRunner) ReadFile(context.Context, string) (string, bool) { return "", false }
func (c gitleaksRunner) Target() exec.Target                             { return exec.Target{Name: "t", Host: "host.example.net"} }

// TestGitleaksFailsClosed: a gitleaks run that wrote no report must be an
// error, not a clean scan. Before this, exit 1 with empty stdout (how gitleaks
// fails) returned no findings and no error, the engine reported Ran, and
// coverage closed every open secret finding.
func TestGitleaksFailsClosed(t *testing.T) {
	leak := `[{"Description":"AWS","File":"/opt/x/.env","StartLine":3,"RuleID":"aws-access-token","Secret":"s"}]`
	cases := []struct {
		name      string
		res       exec.Result
		wantErr   bool
		wantFound int
	}{
		{"clean scan", exec.Result{Stdout: "[]\n"}, false, 0},
		{"leaks found (exit 1 with report)", exec.Result{Stdout: leak, ExitCode: 1}, false, 1},
		{"crash: exit 1, no report", exec.Result{ExitCode: 1, Stderr: "FTL open /opt: permission denied"}, true, 0},
		{"exit 0 but no report", exec.Result{}, true, 0},
		{"exit 1 with empty report", exec.Result{Stdout: "[]", ExitCode: 1}, true, 0},
		{"garbage output", exec.Result{Stdout: "not json"}, true, 0},
	}
	for _, c := range cases {
		fs, err := Gitleaks{}.Run(context.Background(), gitleaksRunner{c.res}, asset())
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
		}
		if len(fs) != c.wantFound {
			t.Errorf("%s: %d findings, want %d", c.name, len(fs), c.wantFound)
		}
	}
}

// osvRunner answers the /opt listing and the osv-scanner run separately, and
// records the osv-scanner argv.
type osvRunner struct {
	listing string
	scan    exec.Result
	argv    *[]string
}

func (o osvRunner) Run(_ context.Context, argv ...string) exec.Result {
	if argv[0] == "sh" {
		return exec.Result{Stdout: o.listing}
	}
	if o.argv != nil {
		*o.argv = argv
	}
	return o.scan
}
func (o osvRunner) Has(context.Context, string) bool                { return true }
func (o osvRunner) ReadFile(context.Context, string) (string, bool) { return "", false }
func (o osvRunner) Target() exec.Target                             { return exec.Target{Name: "t"} }

// TestOSVScannerFailsClosed: exit 128 with no output means "no package
// sources", an honest zero; any other empty run is a failure.
func TestOSVScannerFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		res     exec.Result
		wantErr bool
	}{
		{"clean scan", exec.Result{Stdout: `{"results":[]}`}, false},
		{"nothing to scan (128)", exec.Result{ExitCode: 128}, false},
		{"abort (127), no report", exec.Result{ExitCode: 127, Stderr: "openat opt/x: permission denied"}, true},
		{"exit 0 but no report", exec.Result{}, true},
	}
	for _, c := range cases {
		_, err := OSVScanner{}.Run(context.Background(), osvRunner{listing: "R /opt/az\nEND\n", scan: c.res}, asset())
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
		}
	}
}

// TestOSVScannerListingFailsClosed: if the /opt listing fails or is cut
// short, the run is an error, never an empty-but-clean scan.
func TestOSVScannerListingFailsClosed(t *testing.T) {
	for name, listing := range map[string]string{
		"no output":       "",
		"truncated":       "R /opt/az\n",
		"marker mid-path": "R /opt/END\n",
	} {
		if _, _, err := (OSVScanner{}).RunPartial(context.Background(), osvRunner{listing: listing, scan: exec.Result{Stdout: `{"results":[]}`}}, asset()); err == nil {
			t.Errorf("%s: no error, so a failed listing would read as an empty /opt", name)
		}
	}
}

// TestOSVScannerSkipsUnreadable: osv-scanner 2.7 aborts the whole scan on the
// first directory it cannot open (root-only /opt/containerd on a production
// host). Only readable entries are passed to it; unreadable ones come back as
// not covered, with a trailing slash so store.Coverage treats them as a prefix.
func TestOSVScannerSkipsUnreadable(t *testing.T) {
	var argv []string
	r := osvRunner{
		listing: "R /opt/az\nU /opt/containerd\nR /opt/testssl.sh\nEND\n",
		scan:    exec.Result{Stdout: `{"results":[]}`},
		argv:    &argv,
	}
	_, skipped, err := OSVScanner{}.RunPartial(context.Background(), r, asset())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	if !strings.HasSuffix(got, "--recursive /opt/az /opt/testssl.sh") {
		t.Errorf("osv-scanner argv = %q, want only the readable roots", got)
	}
	if len(skipped) != 1 || skipped[0] != "/opt/containerd/" {
		t.Errorf("skipped = %q, want [/opt/containerd/]", skipped)
	}
	if _, skipped, err := (OSVScanner{}).RunPartial(context.Background(), osvRunner{listing: "U /opt/containerd\nEND\n"}, asset()); err != nil || len(skipped) != 1 {
		t.Errorf("nothing readable: err=%v skipped=%q, want an honest zero with the skip recorded", err, skipped)
	}
}

// TestNucleiFailsClosed: no output on exit 0 is "nothing matched"; no output
// on a non-zero exit is a failed run.
func TestNucleiFailsClosed(t *testing.T) {
	if _, err := (Nuclei{}).Run(context.Background(), gitleaksRunner{exec.Result{}}, asset()); err != nil {
		t.Errorf("exit 0, no output: err = %v, want a clean result", err)
	}
	if _, err := (Nuclei{}).Run(context.Background(), gitleaksRunner{exec.Result{ExitCode: 1, Stderr: "FTL templates not found"}}, asset()); err == nil {
		t.Error("exit 1, no output: no error, so a failed run would close open findings")
	}
}
