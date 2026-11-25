package engine

import (
	"context"
	"testing"

	"github.com/jchirayath/secscan/internal/core/exec"
)

// gitleaksRunner answers every Run with one fixed result.
type gitleaksRunner struct{ res exec.Result }

func (c gitleaksRunner) Run(context.Context, ...string) exec.Result      { return c.res }
func (c gitleaksRunner) Has(context.Context, string) bool                { return true }
func (c gitleaksRunner) ReadFile(context.Context, string) (string, bool) { return "", false }
func (c gitleaksRunner) Target() exec.Target                             { return exec.Target{Name: "t"} }

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
