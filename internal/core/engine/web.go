package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// This file holds the two engines that look at a host from the outside, over
// HTTP(S), rather than reading its filesystem.
//
// That difference matters more than it looks. Every other engine inspects
// state; these two send traffic to a running production service. So both are
// deliberately bounded — severity floors, rate limits, connection timeouts —
// and the bounds are part of the contract, not tuning knobs. An unbounded web
// scan against a live site is an outage with a security-tool label on it.
//
// Both need an externally resolvable name. A scan of a local host with no
// Target.Host has nothing to point at, and both say so rather than reporting a
// clean zero — a web engine that silently finds nothing is indistinguishable
// from a web engine that never ran.

// ------------------------------------------------------------------ TestSSL

// TestSSL wraps testssl.sh, which is the most thorough TLS configuration
// checker that exists and is a shell script, so it adds no build dependency.
//
// It covers the half of TLS that a certificate check cannot: protocol versions
// still offered, cipher suites, forward secrecy, renegotiation, compression,
// and the named vulnerabilities (Heartbleed, ROBOT, LUCKY13). Those are
// properties of the negotiation, only visible by actually negotiating.
type TestSSL struct{}

func (TestSSL) ID() string     { return "testssl" }
func (TestSSL) Binary() string { return "testssl.sh" }

// WhyExpensive: a full testssl.sh run negotiates every cipher suite and probes
// each named TLS vulnerability in turn, which is minutes per endpoint.
func (TestSSL) WhyExpensive() string {
	return "testssl.sh negotiates every cipher suite and probes each named TLS vulnerability " +
		"individually, which takes minutes per endpoint. Enable it when you are reviewing TLS " +
		"specifically, rather than on every routine scan."
}

func (TestSSL) InstallHint() string {
	return "https://testssl.sh — `brew install testssl` or clone the repo (it is a single shell script)"
}

// testsslFinding is one entry of testssl.sh's JSON output.
type testsslFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
}

// parseTestSSL handles both output shapes testssl.sh produces.
//
// `--jsonfile` writes a flat array of {id,severity,finding,cve}. `--jsonfile-pretty`
// — which is what we ask for, because it also carries the target and the
// per-section grouping — writes an OBJECT: {scanResult:[{protocols:[…],
// vulnerabilities:[…], headerResponse:[…], …}]}, plus a `clientProblem*` array
// for problems with the local openssl rather than with the target.
//
// The first implementation assumed the flat array, which parsed nothing at all
// against real output. Accepting both shapes is cheap and means an operator who
// changes the flag does not silently lose every finding.
func parseTestSSL(body string) ([]testsslFinding, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("testssl.sh produced no output")
	}

	if trimmed[0] == '[' {
		var flat []testsslFinding
		if err := json.Unmarshal([]byte(trimmed), &flat); err != nil {
			return nil, fmt.Errorf("parse testssl.sh json array: %w", err)
		}
		return flat, nil
	}

	var doc struct {
		ScanResult []map[string]json.RawMessage `json:"scanResult"`
		// clientProblem1 is testssl reporting a problem with the LOCAL openssl,
		// not with the target. Without this field the document parses to an
		// empty scanResult and gets reported as "the target completed no
		// handshake", which points the operator at the wrong machine entirely.
		ClientProblem []testsslFinding `json:"clientProblem1"`
	}
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return nil, fmt.Errorf("parse testssl.sh json (expected either a top-level array "+
			"or an object with scanResult; got %.60q): %w", trimmed, err)
	}
	if len(doc.ScanResult) == 0 {
		if len(doc.ClientProblem) > 0 {
			return nil, fmt.Errorf("testssl.sh could not run on THIS machine, so nothing was "+
				"tested against the target: %s", doc.ClientProblem[0].Finding)
		}
		return nil, fmt.Errorf("testssl.sh returned no scanResult — the target may not have " +
			"completed a TLS handshake")
	}

	// Sections whose entries are per-check findings. Deliberately NOT
	// `browserSimulations` or `cipherTests`, which are inventories rather than
	// findings and would add hundreds of rows that are never actionable.
	sections := []string{
		"protocols", "ciphers", "serverPreferences", "fs",
		"serverDefaults", "headerResponse", "vulnerabilities", "rating",
	}

	var out []testsslFinding
	knownSections := 0
	for _, sr := range doc.ScanResult {
		for _, name := range sections {
			raw, ok := sr[name]
			if !ok {
				continue
			}
			knownSections++
			var entries []testsslFinding
			if err := json.Unmarshal(raw, &entries); err != nil {
				continue // a section we do not recognise must not sink the rest
			}
			out = append(out, entries...)
		}
	}

	// "Found nothing" and "could not read the output" look identical in a
	// length check and mean opposite things. A well-configured endpoint
	// genuinely produces a scanResult whose every section is an empty array —
	// that is a clean pass and must be reported as one. Only the absence of
	// the sections THEMSELVES indicates the format moved under us.
	if knownSections == 0 {
		return nil, fmt.Errorf("testssl.sh returned a scanResult containing none of the " +
			"expected sections (protocols, ciphers, vulnerabilities, …) — its JSON shape " +
			"has probably changed and this adapter needs updating")
	}
	return out, nil
}

func (t TestSSL) Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error) {
	now := clock.Now()

	host := strings.TrimSpace(r.Target().Host)
	if host == "" {
		return nil, fmt.Errorf("no host name for this target — testssl.sh negotiates TLS with a " +
			"remote name, and a local scan has none to point it at")
	}

	// --severity MEDIUM is the noise floor, not an opinion about what matters:
	// below it testssl.sh reports every individual cipher it offered, which is
	// hundreds of INFO lines per host and drowns the handful of entries an
	// operator can act on. The OK-severity entries are dropped for the same
	// reason — a passed check is not a finding.
	//
	// The JSON goes to a temp file, not to /dev/stdout. --quiet silences the
	// banner but not everything: warnings about the local openssl still go to
	// stdout, so pointing --jsonfile-pretty at /dev/stdout interleaves the
	// document with ANSI-coloured console text and the parse dies on the first
	// escape byte. That is exactly what happened once testssl had something to
	// say. The old form worked only for as long as it stayed silent, which is
	// not a property to depend on; separating the streams removes the class.
	//
	// The URL is a positional argument rather than interpolated into the
	// script, so a hostile target name has no path into the shell.
	const script = `f=$(mktemp) || exit 90
testssl.sh --jsonfile-pretty "$f" --quiet --severity MEDIUM "$1" >/dev/null 2>&1
rc=$?
cat "$f"
rm -f "$f"
exit $rc`
	res := r.Run(ctx, "sh", "-c", script, "sh", "https://"+host)
	if res.Err != nil {
		return nil, res.Err
	}
	body := strings.TrimSpace(res.Stdout)
	if body == "" {
		return nil, fmt.Errorf("no output (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}

	hits, err := parseTestSSL(body)
	if err != nil {
		return nil, err
	}

	target := "https://" + host
	var out []finding.Finding
	for _, h := range hits {
		sev, skip := testsslSeverity(h.Severity)
		if skip {
			continue
		}
		id := strings.TrimSpace(h.ID)
		if id == "" {
			continue
		}

		f := finding.New(a.ID, finding.CatWeb, sev,
			"web.testssl."+strings.ToLower(id),
			testsslTitle(id, h.Finding), now)
		f.Description = fmt.Sprintf(
			"testssl.sh negotiated TLS with %s and reported %q for check %q. This is an "+
				"observed property of the live TLS handshake, not an inference from a config "+
				"file — whatever the server's configuration says, this is what it actually "+
				"offers to a client on the internet.", target, strings.TrimSpace(h.Finding), id)
		f.Subcategory = "tls"
		f.Engine = t.ID()
		f.CVE = splitCVEs(h.CVE)
		f.Evidence = []finding.Evidence{{
			Command: res.Command,
			Output:  fmt.Sprintf("%s [%s]: %s", id, strings.ToUpper(h.Severity), strings.TrimSpace(h.Finding)),
		}}
		f.Remediation = finding.Remediation{Op: "change_config",
			Summary: fmt.Sprintf("Fix the TLS setting behind testssl.sh check %q on %s "+
				"(usually the ssl_protocols / ssl_ciphers block of the web server or its TLS profile)", id, target)}
		if len(f.CVE) > 0 {
			f.Remediation = finding.Remediation{Op: "apply_patch",
				Summary: fmt.Sprintf("Patch the TLS library or server to a version not affected by %s",
					strings.Join(f.CVE, ", "))}
		}
		// Location carries the check id as well as the target: several checks
		// report against the same endpoint and must not collapse into one
		// fingerprint.
		out = append(out, f.WithLocation(target+"#"+id, finding.Component{}))
	}
	return out, nil
}

// testsslSeverity maps testssl.sh's vocabulary, which is wider than the shared
// one: it adds OK (a passed check, not a finding) and WARN (the tool could not
// complete a check — worth seeing, not worth ranking as a weakness).
func testsslSeverity(s string) (sev finding.Severity, skip bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "OK":
		return "", true
	case "FATAL":
		// The scan itself broke. Reported so the gap is visible.
		return finding.SevInfo, false
	case "WARN", "INFO", "":
		return finding.SevInfo, false
	}
	return severityFrom(s), false
}

// testsslTitle prefers the check id, which is stable and greppable, and adds
// the finding text only when it is short enough to stay readable.
func testsslTitle(id, text string) string {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 90 {
		return "TLS: " + id
	}
	return "TLS: " + id + " — " + text
}

// splitCVEs handles the space-separated list testssl.sh writes into one field.
func splitCVEs(s string) []string {
	var out []string
	for _, part := range strings.Fields(strings.ReplaceAll(s, ",", " ")) {
		if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
			out = append(out, strings.ToUpper(part))
		}
	}
	return out
}

// ------------------------------------------------------------------- Nuclei

// Nuclei wraps projectdiscovery/nuclei — template-driven detection of known
// web vulnerabilities, exposed panels, default credentials pages and leaked
// configuration files.
//
// Its value is that it tests rather than infers: a finding here means a request
// was sent and the response matched, which is a materially stronger claim than
// "the config file suggests this might be true".
type Nuclei struct{}

func (Nuclei) ID() string     { return "nuclei" }
func (Nuclei) Binary() string { return "nuclei" }

// WhyExpensive: measured at over eight minutes against one host and still
// running. See the Expensive interface for why that keeps it out of the
// default scan.
func (Nuclei) WhyExpensive() string {
	return "Nuclei runs roughly 13,500 templates per site. Measured: 15m36s for two public " +
		"hosts unfiltered, 76 seconds for a targeted tag set, and 75 minutes against a single " +
		"site behind an identity provider — where every template waits out a timeout on the " +
		"sign-in redirect and finds nothing. Enable it deliberately, and point it at surfaces " +
		"that answer without authentication."
}

func (Nuclei) InstallHint() string {
	return "https://github.com/projectdiscovery/nuclei — `brew install nuclei`"
}

// flexStrings accepts nuclei's `reference` field in either shape it ships in:
// a JSON array, or a bare string when a template lists exactly one reference.
//
// Without this, one line in a different shape fails to unmarshal and the
// finding is dropped — a silent loss, which is the failure mode this scanner
// exists to avoid.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var xs []string
		if err := json.Unmarshal(b, &xs); err != nil {
			return err
		}
		*f = xs
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s != "" {
		*f = []string{s}
	}
	return nil
}

type nucleiHit struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string      `json:"name"`
		Severity    string      `json:"severity"`
		Description string      `json:"description"`
		Reference   flexStrings `json:"reference"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

func (n Nuclei) Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error) {
	now := clock.Now()

	host := strings.TrimSpace(r.Target().Host)
	if host == "" {
		return nil, fmt.Errorf("no host name for this target — nuclei sends HTTP requests to a " +
			"remote name, and a local scan has none to point it at")
	}
	target := "https://" + host

	// -rate-limit and -severity are NOT tuning parameters. They are the reason
	// it is safe to point this at production.
	//
	// nuclei's default is 150 requests/second across a template set in the
	// thousands. Against a real site that is a load test nobody scheduled: it
	// will fill the access log, trip WAF and fail2ban rules (locking the
	// scanner out of the host it is meant to be assessing), and on anything
	// backed by a database it is a plausible way to cause the outage you were
	// scanning to prevent. 20/s with a 5-second per-request timeout keeps a
	// full run in the same order of magnitude as ordinary crawler traffic.
	//
	// The severity floor does the same job for the operator's attention:
	// nuclei's info-level templates are overwhelmingly fingerprinting ("this
	// is nginx", "this is WordPress"), which is inventory, not risk, and
	// hundreds of those entries bury the handful that are real.
	//
	// If you raise either of these, you are choosing to make the scanner
	// intrusive. Say so to whoever owns the host first.
	//
	// Measured runtime, so the next person does not have to rediscover it:
	// 15m36s for two public hosts unfiltered; 76s for a targeted tag set;
	// 75 minutes against one site behind an identity provider, where every
	// template waits out a timeout on the sign-in redirect and finds nothing.
	//
	// Worth recording what that 15-minute run actually returned on a
	// reasonably-kept estate: zero findings at critical/high/medium/low. Every
	// hit was info-severity hardening — missing isolation headers, weak SSH
	// MACs, absent subresource integrity — and the native collectors in this
	// scanner now cover all three, precisely because that run surfaced them.
	//
	// So nuclei's honest position here is: valuable as a periodic check for
	// what we have not thought to look for, and as the source of new native
	// checks. Not valuable as a routine engine on an estate it has already
	// taught us about. That is why it is opt-in rather than merely slow.
	res := r.Run(ctx, "nuclei",
		"-target", target,
		"-jsonl",
		"-silent",
		"-severity", "critical,high,medium",
		"-timeout", "5",
		"-rate-limit", "20")
	if res.Err != nil {
		return nil, res.Err
	}
	body := strings.TrimSpace(res.Stdout)
	if body == "" {
		// nuclei exits 0 with no output when nothing matched, which is the
		// common and good case. Empty output with a non-zero exit is a failed
		// run, and reading it as clean would let coverage close open findings.
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("nuclei produced no output (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
		}
		return nil, nil
	}

	hits, malformed := parseNucleiJSONL(body)

	// Dropping every line quietly would report "nuclei ran, found nothing",
	// which is the one answer we must never give when we do not know.
	if len(hits) == 0 && malformed > 0 {
		return nil, fmt.Errorf("nuclei produced %d output line(s), none of them parseable as "+
			"JSONL — check the installed version's -jsonl schema", malformed)
	}

	var out []finding.Finding
	for _, h := range hits {
		out = append(out, n.toFinding(a, h, res.Command, target, now))
	}
	return out, nil
}

// parseNucleiJSONL turns nuclei's JSONL stream into hits, returning how many
// lines could not be understood.
//
// Split out of Run so it can be exercised against output nuclei actually
// produced. The equivalent testssl parser was written from the documented shape
// and parsed nothing at all against the real tool; an adapter is a claim about
// another program's output, and the only honest way to hold that claim is a
// fixture captured from a live run.
func parseNucleiJSONL(body string) (hits []nucleiHit, malformed int) {
	sc := bufio.NewScanner(strings.NewReader(body))
	// Some templates embed large response extracts; the default 64KB token
	// limit would truncate mid-line and turn a real finding into a parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var h nucleiHit
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			malformed++
			continue
		}
		if strings.TrimSpace(h.TemplateID) == "" {
			malformed++
			continue
		}
		hits = append(hits, h)
	}
	return hits, malformed
}

func (n Nuclei) toFinding(a *finding.Asset, h nucleiHit, cmd, target string, now time.Time) finding.Finding {
	title := strings.TrimSpace(h.Info.Name)
	if title == "" {
		title = h.TemplateID
	}
	where := strings.TrimSpace(h.MatchedAt)
	if where == "" {
		where = target
	}

	f := finding.New(a.ID, finding.CatWeb, severityFrom(h.Info.Severity),
		"web.nuclei."+strings.ToLower(h.TemplateID), title, now)

	// nuclei's own description is written for the template, not for this host,
	// so it is framed with what the match actually establishes. The distinction
	// between "matched" and "might be present" is the whole reason this engine
	// outranks a config-file inference.
	desc := strings.TrimSpace(h.Info.Description)
	if desc != "" && !strings.HasSuffix(desc, ".") {
		desc += "."
	}
	f.Description = strings.TrimSpace(desc + fmt.Sprintf(
		" A nuclei template matched a live response at %s, so this was observed rather than "+
			"inferred. What the match does not tell you is whether the affected function is "+
			"actually used here — confirm that before deciding how urgently to act.", where))

	f.Subcategory = "nuclei/" + orNone2(h.Type, "http")
	f.Engine = n.ID()
	f.References = h.Info.Reference
	f.Evidence = []finding.Evidence{{
		Command: cmd,
		Output: fmt.Sprintf("template %s (%s) matched at %s",
			h.TemplateID, strings.ToLower(strings.TrimSpace(h.Info.Severity)), where),
	}}

	// nuclei names its CVE templates after the CVE, which is the only place the
	// identifier appears in the JSONL output.
	if cves := splitCVEs(h.TemplateID); len(cves) > 0 {
		f.CVE = cves
		f.Remediation = finding.Remediation{Op: "apply_patch",
			Summary: fmt.Sprintf("Patch the affected component to a version not affected by %s",
				strings.Join(cves, ", "))}
	} else {
		f.Remediation = finding.Remediation{Op: "manual",
			Summary: fmt.Sprintf("Review what nuclei template %q matched at %s and apply the "+
				"vendor's fix, or remove the exposed resource", h.TemplateID, where)}
	}
	return f.WithLocation(where+"#"+h.TemplateID, finding.Component{})
}

// orNone2 substitutes a default for an empty string. (orNone in engine.go
// renders "(no fix)", which is the wrong word here.)
func orNone2(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
