// Command secscan is a compact security posture scanner: one static binary,
// no runtime dependencies, an Entra-gated dashboard.
//
// Usage:
//
//	secscan scan [target...]   run a scan (default: localhost)
//	secscan serve              start the dashboard
//	secscan targets            list/add scan targets
//	secscan plan [target]      print the remediation plan / script
//	secscan config             print resolved configuration (secrets redacted)
//	secscan version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/config"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
	"github.com/jchirayath/secscan/internal/core/scan"
	"github.com/jchirayath/secscan/internal/remediate"
	"github.com/jchirayath/secscan/internal/report"
	"github.com/jchirayath/secscan/internal/snapshot"
	"github.com/jchirayath/secscan/internal/store"
	"github.com/jchirayath/secscan/internal/web"
)

// Version is stamped at build time: -ldflags "-X main.Version=…"
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	if cmd == "version" {
		fmt.Println("secscan", Version)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	setupLogging(cfg.LogLevel)

	st, err := store.Open(cfg.Home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "scan":
		os.Exit(cmdScan(ctx, cfg, st, args))
	case "serve":
		os.Exit(cmdServe(ctx, cfg, st, args))
	case "targets":
		os.Exit(cmdTargets(st, args))
	case "rules":
		os.Exit(cmdRules(st, args))
	case "plan":
		os.Exit(cmdPlan(st, args))
	case "trend":
		os.Exit(cmdTrend(cfg, args))
	case "fix":
		os.Exit(cmdFix(ctx, cfg, st, args))
	case "config":
		if len(args) > 0 && (args[0] == "-example" || args[0] == "--example") {
			for _, l := range config.Example() {
				fmt.Println(l)
			}
			return
		}
		fmt.Printf("%-32s %-28s %s\n", "KEY", "VALUE", "DESCRIPTION")
		for _, l := range cfg.Redacted() {
			fmt.Println(l)
		}
		fmt.Printf("\nstate: %s\n", cfg.Home)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `secscan — compact security posture scanner

  secscan scan [name...]    scan targets;  -report FILE writes a Markdown assessment
  secscan serve             start the web dashboard
  secscan targets           list targets;  targets add <name> [user@host] [-key F] [-sudo] [-critical]
  secscan plan [name]       remediation plan;  -script to emit a shell script
  secscan trend [name]      posture over time from snapshots;  -diff to compare the last two
  secscan fix [target]      classify fixes by change-risk;  -apply runs the green ones
  secscan rules             suppression rules;  rules add -kind false_positive|accepted_risk
                            -reason TEXT -days N [-rule ID] [-component GLOB] [-location GLOB]
                            [-engine E] [-asset A];  rules rm <id>   (stop serve first)
  secscan config            print resolved configuration;  -example emits a .env template
  secscan version

Scan only systems you own or are authorised to test.
`)
}

func setupLogging(level string) {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

// ------------------------------------------------------------------- scan

func cmdScan(ctx context.Context, cfg *config.Config, st *store.Store, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the full result as JSON")
	mdOut := fs.String("report", "", "write a Markdown assessment report to this path (- for stdout)")
	snapDir := fs.String("snapshot-dir", cfg.SnapshotDir, "where to write the per-scan snapshot")
	noSnap := fs.Bool("no-snapshot", false, "skip writing a snapshot for this run")
	skipEngines := fs.Bool("no-engines", false, "native collectors only")
	_ = fs.Parse(permuteFlags(fs, args))

	targets := resolveTargets(st, fs.Args())
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets configured; add one with `secscan targets add`")
		return 1
	}

	exitCode := 0
	for _, t := range targets {
		res, err := scan.Run(ctx, t, scan.Options{
			Timeout:     cfg.ScanTimeout,
			SkipEngines: *skipEngines,
			Features:    st.Features(),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %s: %v\n", t.Name, err)
			exitCode = 1
			continue
		}

		newN, fixedN, err := st.Merge(res.Asset, res.Findings, scan.CoverageOf(res))
		if err != nil {
			fmt.Fprintf(os.Stderr, "persist %s: %v\n", t.Name, err)
			exitCode = 1
		}
		if !*noSnap {
			if meta, err := writeSnapshot(*snapDir, cfg.SnapshotKeep, res); err != nil {
				// A snapshot is history, not function: failing to write one must
				// not fail the scan that produced real findings.
				fmt.Fprintf(os.Stderr, "snapshot not written: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "snapshot %s (%d KB) in %s\n", meta.ID, meta.SizeKB, *snapDir)
			}
		}
		if err := st.SetTranscript(res.Asset.ID, res.Transcript); err != nil {
			slog.Warn("transcript persist failed", slog.String("err", err.Error()))
		}
		sum := scan.Summarise(res, newN, fixedN)
		if err := st.AppendHistory(sum); err != nil {
			slog.Warn("history append failed", slog.String("err", err.Error()))
		}

		if *mdOut != "" {
			doc := report.Render(res, sum.Score, clock.Now())
			if *mdOut == "-" {
				fmt.Print(doc)
			} else {
				path := *mdOut
				if len(targets) > 1 {
					// One file per target rather than silently overwriting.
					path = strings.TrimSuffix(path, ".md") + "-" + t.Name + ".md"
				}
				if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "write report: %v\n", err)
					exitCode = 1
				} else {
					fmt.Fprintf(os.Stderr, "report written to %s\n", path)
				}
			}
			continue
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
			continue
		}
		printResult(res, sum)
	}
	return exitCode
}

func printResult(res scan.Result, sum store.ScanSummary) {
	a := res.Asset
	fmt.Printf("\n\033[1m%s\033[0m  %s\n", a.Name, a.Address)
	if a.OS != "" {
		fmt.Printf("  %s · kernel %s\n", a.OS, a.Kernel)
	}
	fmt.Printf("  posture score \033[1m%.1f\033[0m/100 · %d findings · %s",
		sum.Score, sum.Total, sum.Duration)
	if res.Provenance != finding.ProvLive {
		fmt.Printf(" · \033[33m%s data\033[0m", res.Provenance)
	}
	fmt.Println()

	order := []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow, finding.SevInfo}
	var parts []string
	for _, s := range order {
		if n := sum.Counts[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", colorSev(s), n))
		}
	}
	if len(parts) > 0 {
		fmt.Printf("  %s\n", strings.Join(parts, "  "))
	}
	if sum.New > 0 || sum.Fixed > 0 {
		fmt.Printf("  %d new · %d fixed since last scan\n", sum.New, sum.Fixed)
	}

	fmt.Println("\n  Top findings by risk:")
	shown := 0
	for _, f := range res.Findings {
		if f.Status != finding.StatusOpen || shown >= 10 {
			continue
		}
		exposed := ""
		if f.Exposed {
			exposed = " \033[31m[exposed]\033[0m"
		}
		fmt.Printf("   %5.1f  %-9s %s%s\n", f.ResidualRisk, colorSev(f.Severity), f.Title, exposed)
		shown++
	}
	if shown == 0 {
		fmt.Println("   (none open)")
	}

	// Honest accounting: what did not run is as important as what did.
	var skipped []string
	for _, c := range res.Collectors {
		if !c.Ran {
			skipped = append(skipped, "    "+c.ID+" — "+c.Skipped)
		}
	}
	for _, e := range res.Engines {
		if !e.Ran {
			skipped = append(skipped, "    "+e.ID+" — "+e.Reason)
		}
	}
	if len(skipped) > 0 {
		fmt.Printf("\n  \033[33mNot run (%d):\033[0m\n%s\n", len(skipped), strings.Join(skipped, "\n"))
	}
	fmt.Println()
}

func colorSev(s finding.Severity) string {
	switch s {
	case finding.SevCritical:
		return "\033[41;97mCRITICAL\033[0m"
	case finding.SevHigh:
		return "\033[31mHIGH\033[0m    "
	case finding.SevMedium:
		return "\033[33mMEDIUM\033[0m  "
	case finding.SevLow:
		return "\033[36mLOW\033[0m     "
	}
	return "INFO    "
}

// ------------------------------------------------------------------ serve

func cmdServe(ctx context.Context, cfg *config.Config, st *store.Store, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	bind := fs.String("bind", cfg.Bind, "listen address")
	authMode := fs.String("auth", cfg.AuthMode, "entra | proxy | local")
	_ = fs.Parse(permuteFlags(fs, args))

	cfg.Bind, cfg.AuthMode = *bind, *authMode

	srv, err := web.New(cfg, st, Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return srv.ListenAndServe(ctx)
}

// ---------------------------------------------------------------- targets

func cmdTargets(st *store.Store, args []string) int {
	if len(args) == 0 {
		ts := st.Targets()
		if len(ts) == 0 {
			fmt.Println("no targets configured (scans default to localhost)")
			return 0
		}
		fmt.Printf("%-16s %-28s %-8s %s\n", "NAME", "ADDRESS", "SUDO", "KEY")
		for _, t := range ts {
			addr := "localhost"
			if t.Host != "" {
				addr = t.Host
				if t.User != "" {
					addr = t.User + "@" + t.Host
				}
			}
			fmt.Printf("%-16s %-28s %-8v %s\n", t.Name, addr, t.UseSudo, t.KeyFile)
		}
		return 0
	}

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("targets add", flag.ExitOnError)
		key := fs.String("key", "", "SSH private key file")
		useSudo := fs.Bool("sudo", false, "allow `sudo -n` for privileged reads")
		critical := fs.Bool("critical", false, "mark asset as critical (raises risk)")
		port := fs.Int("port", 0, "SSH port")
		insecure := fs.Bool("insecure-host-key", false, "DISABLE SSH host-key verification for this target")
		vhosts := fs.String("vhosts", "", "comma-separated extra DNS names this host serves (probed for per-site auth)")
		// Go's flag package stops at the first non-flag argument, so
		// `targets add web01 user@host -sudo` would silently drop -sudo and
		// produce a target that cannot read anything privileged. Permute
		// flags ahead of positionals first.
		_ = fs.Parse(permuteFlags(fs, args[1:]))

		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: secscan targets add <name> [user@host]")
			return 2
		}
		t := exec.Target{Name: rest[0], UseSudo: *useSudo, Critical: *critical,
			KeyFile: *key, Port: *port, InsecureHostKey: *insecure}
		for _, v := range strings.Split(*vhosts, ",") {
			if v = strings.TrimSpace(v); v != "" {
				t.VirtualHosts = append(t.VirtualHosts, v)
			}
		}
		if len(rest) > 1 {
			hostSpec := rest[1]
			if i := strings.Index(hostSpec, "@"); i >= 0 {
				t.User, t.Host = hostSpec[:i], hostSpec[i+1:]
			} else {
				t.Host = hostSpec
			}
		}
		// Upsert, never blind-append. A plain append meant re-running `add`
		// with a corrected address left BOTH entries in place, and since
		// targets are matched by name, `scan <name>` then silently picked
		// whichever came first — so a target could appear fixed while every
		// scan still ran against the old address. Replacing in place also
		// makes `add` the natural way to edit a target, which is what
		// operators reach for; there is no `targets edit`.
		//
		// The name is replaced at its existing position rather than appended,
		// so `targets` output does not reshuffle when a target is edited. Any
		// further entries sharing the name are dropped, which repairs state
		// files that already accumulated duplicates under the old behaviour.
		ts := st.Targets()
		out := make([]exec.Target, 0, len(ts)+1)
		replaced := false
		for _, ex := range ts {
			if ex.Name != t.Name {
				out = append(out, ex)
				continue
			}
			if !replaced {
				out = append(out, t) // keep position
				replaced = true
			}
			// duplicates beyond the first are discarded
		}
		if !replaced {
			out = append(out, t)
		}
		if err := st.SetTargets(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if replaced {
			fmt.Printf("updated target %s\n", t.Name)
		} else {
			fmt.Printf("added target %s\n", t.Name)
		}
		return 0

	case "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: secscan targets rm <name>")
			return 2
		}
		var kept []exec.Target
		for _, t := range st.Targets() {
			if t.Name != args[1] {
				kept = append(kept, t)
			}
		}
		if err := st.SetTargets(kept); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("removed target %s\n", args[1])
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown targets subcommand:", args[0])
	return 2
}

// ------------------------------------------------------------------- plan

func cmdPlan(st *store.Store, args []string) int {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	script := fs.Bool("script", false, "emit a reviewable shell script")
	_ = fs.Parse(permuteFlags(fs, args))

	filter := store.Filter{}
	name := "all targets"
	if len(fs.Args()) > 0 {
		filter.AssetID = fs.Args()[0]
		name = filter.AssetID
	}
	found := st.Findings(filter)
	actions := scan.BuildPlan(found)
	if len(actions) == 0 {
		fmt.Println("nothing to do — no open findings with a remediation")
		return 0
	}
	if *script {
		fmt.Print(scan.PlanScript(actions, name))
		return 0
	}
	fmt.Printf("Remediation plan for %s — %d actions, most risk cleared first\n\n", name, len(actions))
	for i, a := range actions {
		fmt.Printf("%2d. %s\n    clears %.2f risk across %d finding(s)\n", i+1, a.Summary, a.RiskCleared, a.FindingCount)
		if a.Command != "" {
			fmt.Printf("    $ %s\n", a.Command)
		}
		fmt.Println()
	}
	return 0
}

// writeSnapshot records this run for later comparison.
func writeSnapshot(dir string, keep int, res scan.Result) (snapshot.Meta, error) {
	sn, err := snapshot.Open(dir)
	if err != nil {
		return snapshot.Meta{}, err
	}
	var cov []snapshot.CoverageRow
	for _, c := range res.Collectors {
		cov = append(cov, snapshot.CoverageRow{ID: c.ID, Ran: c.Ran, Skipped: c.Skipped, Found: c.Found})
	}
	for _, e := range res.Engines {
		cov = append(cov, snapshot.CoverageRow{ID: e.ID, Ran: e.Ran, Skipped: e.Reason, Found: e.Found})
	}
	meta, err := sn.Write(snapshot.Snapshot{
		At: clock.Now(), Asset: res.Asset,
		Score: scan.Score(res.Findings), Findings: res.Findings, Coverage: cov,
	})
	if err != nil {
		return meta, err
	}
	if n, err := sn.Prune(res.Asset.ID, keep); err == nil && n > 0 {
		fmt.Fprintf(os.Stderr, "pruned %d old snapshot(s), keeping %d\n", n, keep)
	}
	return meta, nil
}

// -------------------------------------------------------------------- fix

// cmdFix classifies every open finding by the risk of FIXING it — which is a
// different question from how severe the finding is — and applies only the
// green ones.
func cmdFix(ctx context.Context, cfg *config.Config, st *store.Store, args []string) int {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	apply := fs.Bool("apply", false, "actually apply the green fixes (default is to list only)")
	dry := fs.Bool("dry-run", false, "show the exact steps for green fixes without running them")
	sudoers := fs.Bool("sudoers", false, "print the exact sudoers entries the green fixes need")
	_ = fs.Parse(permuteFlags(fs, args))

	if *sudoers {
		return cmdFixSudoers(ctx, cfg, st, fs.Args())
	}

	filter := store.Filter{}
	if a := fs.Args(); len(a) > 0 {
		filter.AssetID = a[0]
	}
	found := st.Findings(filter)
	if len(found) == 0 {
		fmt.Println("no open findings")
		return 0
	}

	var green []finding.Finding
	byRisk := map[remediate.ChangeRisk][]remediate.Plan{}
	var unclassified int

	for _, f := range found {
		pl := remediate.PlanFor(f)
		if pl.Risk == "" {
			unclassified++
			continue
		}
		byRisk[pl.Risk] = append(byRisk[pl.Risk], pl)
		if pl.Executable {
			green = append(green, f)
		}
	}

	fmt.Printf("\nChange-risk of fixing — %d open finding(s)\n", len(found))
	fmt.Printf("This rates the FIX, not the finding. A critical problem can have a trivial\n")
	fmt.Printf("fix; a low one can have a fix that locks you out of the host.\n\n")

	for _, r := range []remediate.ChangeRisk{remediate.RiskGreen, remediate.RiskAmber, remediate.RiskRed} {
		plans := byRisk[r]
		if len(plans) == 0 {
			continue
		}
		// Group by playbook, not by rule: one catalogue entry can cover a
		// whole family, and printing its advice once per member is noise.
		order := []string{}
		count := map[string]int{}
		why := map[string]string{}
		for _, pl := range plans {
			if count[pl.Playbook] == 0 {
				order = append(order, pl.Playbook)
				why[pl.Playbook] = pl.Why
			}
			count[pl.Playbook]++
		}
		fmt.Printf("%s — %d finding(s) in %d group(s)\n", riskLabel(r), len(plans), len(order))
		for _, k := range order {
			n := ""
			if count[k] > 1 {
				n = fmt.Sprintf("  (%d findings)", count[k])
			}
			fmt.Printf("   %s%s\n", k, n)
			fmt.Printf("      %s\n", wrap(why[k], 72, "      "))
		}
		fmt.Println()
	}
	if unclassified > 0 {
		fmt.Printf("%d finding(s) have no reviewed fix and cannot be applied automatically.\n",
			unclassified)
		fmt.Printf("Nothing is generated from a finding's own command text: running generated\n")
		fmt.Printf("shell as root is how a scanner becomes the incident.\n\n")
	}

	if !*apply && !*dry {
		if len(green) > 0 {
			fmt.Printf("Run `secscan fix -dry-run` to see the steps, or `-apply` to run the %d green fix(es).\n", len(green))
		}
		return 0
	}
	if len(green) == 0 {
		fmt.Println("nothing green to apply")
		return 0
	}

	targets := resolveTargets(st, nil)
	byName := map[string]exec.Target{}
	for _, t := range targets {
		byName[t.Name] = t
	}

	failures := 0
	for _, f := range green {
		t, ok := byName[f.AssetID]
		if !ok {
			fmt.Fprintf(os.Stderr, "no configured target for %s; skipping\n", f.AssetID)
			continue
		}
		r := exec.New(t, cfg.ScanTimeout)
		res := remediate.Apply(ctx, r, f, remediate.Options{DryRun: *dry})
		printFixResult(res, *dry)
		if res.Error != "" {
			failures++
		}
	}
	if failures > 0 {
		return 1
	}
	if !*dry {
		fmt.Println("Rescan to confirm the dashboard matches the host: secscan scan")
	}
	return 0
}

// cmdFixSudoers resolves each command on the target and prints exact-match
// sudoers entries. Paths are resolved on the host rather than assumed, because
// a rule written against the wrong path does not fail loudly — it just never
// matches, and the fix reports "not permitted" forever.
func cmdFixSudoers(ctx context.Context, cfg *config.Config, st *store.Store, argv []string) int {
	targets := resolveTargets(st, argv)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets configured")
		return 1
	}
	t := targets[0]
	r := exec.New(t, cfg.ScanTimeout)
	user := t.User
	if user == "" {
		user = "%wheel"
	}

	cache := map[string]string{}
	resolve := func(name string) string {
		if strings.HasPrefix(name, "/") {
			return name
		}
		if v, ok := cache[name]; ok {
			return v
		}
		v := ""
		if res := r.Run(ctx, "command", "-v", name); res.OK() {
			v = strings.TrimSpace(res.Stdout)
		}
		cache[name] = v
		return v
	}

	fmt.Printf("# target: %s (%s)\n", t.Name, t.Host)
	for _, line := range remediate.Sudoers(user, resolve) {
		fmt.Println(line)
	}
	return 0
}

func printFixResult(res remediate.Result, dry bool) {
	head := "\033[32m✓\033[0m"
	switch {
	case res.Error != "" && res.RolledBack:
		head = "\033[31m✗ rolled back\033[0m"
	case res.Error != "":
		head = "\033[31m✗\033[0m"
	case dry:
		head = "\033[36mdry run\033[0m"
	}
	fmt.Printf("%s %s\n", head, res.Title)
	for _, s := range res.Steps {
		mark := "·"
		if !s.OK {
			mark = "\033[31m!\033[0m"
		}
		fmt.Printf("   %s %-8s %s\n", mark, s.Phase, s.Command)
		if s.Output != "" && (!s.OK || s.Phase == "backup" || dry) {
			fmt.Printf("        %s\n", firstLineOf(s.Output))
		}
	}
	if res.Error != "" {
		fmt.Printf("   \033[31m%s\033[0m\n", res.Error)
	} else if res.Verified {
		fmt.Printf("   \033[32mverified on the host\033[0m\n")
	}
	fmt.Println()
}

func riskLabel(r remediate.ChangeRisk) string {
	switch r {
	case remediate.RiskGreen:
		return "\033[42;30m GREEN \033[0m safe to apply automatically"
	case remediate.RiskAmber:
		return "\033[43;30m AMBER \033[0m needs a human and a maintenance window"
	}
	return "\033[41;97m RED \033[0m this tool will not apply these"
}

func wrap(s string, width int, indent string) string {
	var out, line []string
	n := 0
	for _, w := range strings.Fields(s) {
		if n+len(w) > width && len(line) > 0 {
			out = append(out, strings.Join(line, " "))
			line, n = nil, 0
		}
		line = append(line, w)
		n += len(w) + 1
	}
	if len(line) > 0 {
		out = append(out, strings.Join(line, " "))
	}
	return strings.Join(out, "\n"+indent)
}

func firstLineOf(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// ------------------------------------------------------------------ trend

func cmdTrend(cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("trend", flag.ExitOnError)
	dir := fs.String("snapshot-dir", cfg.SnapshotDir, "snapshot directory to read")
	diff := fs.Bool("diff", false, "show what changed between the last two snapshots")
	_ = fs.Parse(permuteFlags(fs, args))

	sn, err := snapshot.Open(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	asset := ""
	if a := fs.Args(); len(a) > 0 {
		asset = a[0]
	}
	metas, err := sn.List(asset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(metas) == 0 {
		fmt.Printf("no snapshots in %s — run a scan first\n", sn.Dir())
		return 0
	}

	if *diff {
		if asset == "" {
			asset = metas[len(metas)-1].Asset
		}
		if len(metas) < 2 {
			fmt.Println("only one snapshot — a comparison needs two")
			return 0
		}
		from, err1 := sn.Load(asset, metas[len(metas)-2].ID)
		to, err2 := sn.Load(asset, metas[len(metas)-1].ID)
		if err1 != nil || err2 != nil {
			fmt.Fprintln(os.Stderr, "load:", err1, err2)
			return 1
		}
		printDiff(snapshot.Compare(from, to))
		return 0
	}

	fmt.Printf("Posture over time — %s\n\n", sn.Dir())
	fmt.Printf("%-22s %6s %7s %9s %s\n", "WHEN", "SCORE", "OPEN", "COVERAGE", "SEVERITY")
	for _, m := range metas {
		cov := fmt.Sprintf("%d/%d", m.Ran, m.Ran+m.Skipped)
		var sev []string
		for _, s := range []finding.Severity{finding.SevCritical, finding.SevHigh, finding.SevMedium, finding.SevLow} {
			if n := m.Counts[string(s)]; n > 0 {
				sev = append(sev, fmt.Sprintf("%s %d", colorSev(s), n))
			}
		}
		fmt.Printf("%-22s %6.1f %7d %9s %s\n",
			m.At.Local().Format("2006-01-02 15:04"), m.Score, m.Total, cov, strings.Join(sev, " "))
	}

	if len(metas) > 1 {
		first, last := metas[0], metas[len(metas)-1]
		d := last.Score - first.Score
		word := "unchanged"
		if d > 0 {
			word = "improved"
		} else if d < 0 {
			word = "worsened"
		}
		fmt.Printf("\nScore %s by %.1f across %d scans.\n", word, math.Abs(d), len(metas))
	}
	return 0
}

func printDiff(d snapshot.Diff) {
	fmt.Printf("Comparing %s → %s\n\n", d.FromAt.Local().Format("2006-01-02 15:04"),
		d.ToAt.Local().Format("2006-01-02 15:04"))
	sign := "+"
	if d.ScoreDelta < 0 {
		sign = ""
	}
	fmt.Printf("  score %s%.1f · %d new · %d fixed · %d unchanged\n\n",
		sign, d.ScoreDelta, len(d.New), len(d.Fixed), d.Unchanged)

	if len(d.CoverageLost) > 0 {
		fmt.Printf("  \033[33mCoverage dropped: %s\033[0m\n", strings.Join(d.CoverageLost, ", "))
		fmt.Printf("  Findings those checks would have raised are absent, not resolved.\n\n")
	}
	show := func(label string, fs []finding.Finding) {
		if len(fs) == 0 {
			return
		}
		fmt.Printf("  %s (%d):\n", label, len(fs))
		for i, f := range fs {
			if i >= 10 {
				fmt.Printf("    …and %d more\n", len(fs)-10)
				break
			}
			fmt.Printf("    %s %s\n", colorSev(f.Severity), f.Title)
		}
		fmt.Println()
	}
	show("New", d.New)
	show("Fixed", d.Fixed)
}

// ---------------------------------------------------------------- helpers

// permuteFlags reorders argv so every flag precedes every positional, letting
// `scan web01 -report out.md` behave the way anyone would expect (Go's flag
// package stops parsing at the first non-flag argument).
//
// Whether a flag takes a value is derived from the FlagSet rather than a
// hand-maintained list. The hand-maintained version silently dropped -sudo,
// then later -report, because someone added a flag and forgot the other place —
// exactly the kind of duplicated knowledge that rots.
func permuteFlags(fs *flag.FlagSet, args []string) []string {
	takesValue := func(name string) bool {
		f := fs.Lookup(strings.TrimLeft(name, "-"))
		if f == nil {
			return false
		}
		// Boolean flags are self-contained (-sudo); everything else consumes
		// the following argument (-key FILE).
		bf, ok := f.Value.(interface{ IsBoolFlag() bool })
		return !(ok && bf.IsBoolFlag())
	}

	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		// `-flag=value` is self-contained; `-flag value` needs its operand.
		if !strings.Contains(a, "=") && takesValue(a) && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

func resolveTargets(st *store.Store, names []string) []exec.Target {
	all := st.Targets()
	if len(all) == 0 {
		all = []exec.Target{{Name: "localhost"}}
	}
	if len(names) == 0 {
		return all
	}
	var out []exec.Target
	for _, n := range names {
		for _, t := range all {
			if t.Name == n {
				out = append(out, t)
			}
		}
	}
	return out
}

var _ = time.Now

// ------------------------------------------------------------------ rules

// cmdRules manages suppression rules from the command line.
//
// It writes state.json directly. A running `secscan serve` holds state in
// memory and will overwrite this file on its next save, so stop the server
// first (or use the dashboard / POST /api/rules, which go through the running
// store). Rules made here are recorded as by "cli:<user>" so the audit trail
// does not pretend a dashboard user made them.
func cmdRules(st *store.Store, args []string) int {
	if len(args) == 0 || args[0] == "list" {
		rules := st.Rules()
		if len(rules) == 0 {
			fmt.Println("no suppression rules")
			return 0
		}
		now := clock.Now()
		for _, r := range rules {
			state := "until " + r.Until.Format(time.DateOnly)
			if !now.Before(r.Until) {
				state = "EXPIRED"
			}
			fmt.Printf("%s  %-14s %-16s %+v\n    %s (by %s)\n", r.ID, r.Kind, state, r.Match, r.Reason, r.By)
		}
		return 0
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("rules add", flag.ExitOnError)
		kind := fs.String("kind", "", "false_positive | accepted_risk")
		reason := fs.String("reason", "", "why (required)")
		days := fs.Int("days", 0, "expiry in days, 1-365 (required)")
		var m store.RuleMatch
		fs.StringVar(&m.RuleID, "rule", "", "exact rule id, e.g. vuln.cve-2026-12345")
		fs.StringVar(&m.Component, "component", "", "component name glob ('*' spans '/')")
		fs.StringVar(&m.Location, "location", "", "location glob ('*' spans '/')")
		fs.StringVar(&m.Engine, "engine", "", "only findings from this engine/collector")
		fs.StringVar(&m.AssetID, "asset", "", "only findings on this asset")
		_ = fs.Parse(args[1:])
		if *days < 1 || *days > 365 {
			fmt.Fprintln(os.Stderr, "-days must be between 1 and 365 — suppressions expire by design")
			return 2
		}
		by := "cli"
		if u := os.Getenv("USER"); u != "" { //secscan:allow-getenv attribution only, not configuration
			by += ":" + u
		}
		r, n, err := st.AddRule(store.Rule{Kind: finding.SuppressKind(*kind), Reason: strings.TrimSpace(*reason),
			Match: m, Until: clock.Now().AddDate(0, 0, *days), By: by, Role: "cli"})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf("rule %s added; suppressed %d open finding(s) now, and future scans will match it\n", r.ID, n)
		return 0
	case "rm":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: secscan rules rm <id>")
			return 2
		}
		n, err := st.DeleteRule(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("rule %s removed; %d finding(s) reopened\n", args[1], n)
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: secscan rules [list | add ... | rm <id>]")
	return 2
}
