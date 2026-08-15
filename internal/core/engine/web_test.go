package engine

import (
	"os"
	"strings"
	"testing"
)

// Golden fixture: real `testssl.sh --jsonfile-pretty` output, captured from a
// live run against app.example.net.
//
// This test exists because the first implementation of the parser was written
// against the documented flat-array shape and parsed exactly nothing when
// pointed at the real tool. An adapter is a claim about another program's
// output format, and the only way to hold that claim honest is to check it
// against output that program actually produced.
func TestParseTestSSLRealOutput(t *testing.T) {
	body, err := os.ReadFile("testdata/testssl-real.json")
	if err != nil {
		t.Skip("fixture not present")
	}

	hits, err := parseTestSSL(string(body))
	if err != nil {
		t.Fatalf("real testssl.sh output failed to parse: %v", err)
	}
	// This particular capture is from a well-configured endpoint, so zero
	// entries is the CORRECT answer — the sections are present and empty. The
	// assertion that matters is that it parsed without error: an unrecognised
	// shape must error, a clean result must not.
	for _, h := range hits {
		if h.ID == "" {
			t.Errorf("entry with no id: %+v", h)
		}
	}
	t.Logf("parsed %d entries from real testssl.sh output (clean endpoint)", len(hits))
}

// TestParseTestSSLFlatArray keeps the other documented shape working, so an
// operator who switches to --jsonfile does not silently lose every finding.
func TestParseTestSSLFlatArray(t *testing.T) {
	flat := `[{"id":"BREACH","severity":"MEDIUM","finding":"potentially vulnerable","cve":"CVE-2013-3587"}]`
	hits, err := parseTestSSL(flat)
	if err != nil {
		t.Fatalf("flat array failed: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != "BREACH" {
		t.Errorf("got %+v", hits)
	}
}

// TestParseTestSSLRejectsGarbage: a parse failure must be an error the caller
// turns into "did not run, because X", never an empty success.
func TestParseTestSSLRejectsGarbage(t *testing.T) {
	// Note `{"scanResult":[{}]}`: a scanResult present but carrying none of the
	// expected sections means the format moved, which must error. An empty
	// section array means a clean scan, which must not — that case is covered
	// by TestParseTestSSLRealOutput.
	for _, in := range []string{"", "not json", "{}", `{"scanResult":[]}`, `{"scanResult":[{}]}`} {
		if _, err := parseTestSSL(in); err == nil {
			t.Errorf("parseTestSSL(%q) returned no error — an unparseable result must not "+
				"be reported as a clean scan", in)
		}
	}
}

// Golden fixture: real `nuclei -jsonl` output captured from a live run against
// host.example.net.
//
// Every record in it carries `"reference": null`, which is the detail worth
// having a fixture for — a parser that mishandles a null there rejects every
// line and the engine reports "ran, found nothing" while seeing everything.
func TestParseNucleiRealOutput(t *testing.T) {
	body, err := os.ReadFile("testdata/nuclei-real.jsonl")
	if err != nil {
		t.Skip("fixture not present")
	}

	hits, malformed := parseNucleiJSONL(string(body))
	if malformed > 0 {
		t.Errorf("%d line(s) of real nuclei output were rejected", malformed)
	}
	if len(hits) == 0 {
		t.Fatal("parsed zero hits from real nuclei output — the exact failure the " +
			"fixture exists to catch")
	}

	byID := map[string]nucleiHit{}
	for _, h := range hits {
		byID[h.TemplateID] = h
	}
	// Template ids present in the captured run against the two public hosts.
	// Asserting on specific ids rather than just a count is what would catch a
	// schema change that still produced parseable-but-empty records.
	for _, want := range []string{"ssh-sha1-hmac-algo", "http-missing-security-headers", "missing-sri"} {
		h, ok := byID[want]
		if !ok {
			t.Errorf("template %q missing from parsed output", want)
			continue
		}
		if h.Info.Name == "" {
			t.Errorf("%s: no info.name", want)
		}
		if h.Info.Severity == "" {
			t.Errorf("%s: no info.severity", want)
		}
	}
	t.Logf("parsed %d hits from real nuclei output", len(hits))
}

// TestParseNucleiTolerance: nuclei's `reference` ships as an array, a bare
// string, or null depending on the template. All three must survive, because a
// shape mismatch drops the whole record rather than just that field.
func TestParseNucleiTolerance(t *testing.T) {
	lines := `{"template-id":"a","info":{"name":"A","severity":"high","reference":["https://x"]}}
{"template-id":"b","info":{"name":"B","severity":"low","reference":"https://y"}}
{"template-id":"c","info":{"name":"C","severity":"info","reference":null}}
not json at all
{"template-id":"","info":{"name":"no id"}}`

	hits, malformed := parseNucleiJSONL(lines)
	if len(hits) != 3 {
		t.Errorf("got %d hits, want 3 (array, string and null references must all parse)", len(hits))
	}
	if malformed != 1 {
		t.Errorf("malformed = %d, want 1 (the id-less record; the non-JSON line is skipped, not counted)", malformed)
	}
}

// TestParseTestSSLRealOutputWithClientProblem is the shape that actually broke
// in production: a document carrying BOTH clientProblem1 and scanResult.
//
// The bug was not in the parser at all — testssl.sh was writing its JSON to
// /dev/stdout, where --quiet does not stop its ANSI-coloured console output
// from interleaving with the document, so the parse died on the first escape
// byte and TLS coverage was silently lost until the next scan reported the
// collector as not-run. The fix writes the JSON to a temp file. This fixture is
// the real output of that corrected invocation, sanitized.
func TestParseTestSSLRealOutputWithClientProblem(t *testing.T) {
	body, err := os.ReadFile("testdata/testssl-clientproblem.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	hits, err := parseTestSSL(string(body))
	if err != nil {
		t.Fatalf("real output with a clientProblem alongside scanResult must parse: %v", err)
	}
	// A clientProblem must not suppress the scan that did happen.
	t.Logf("parsed %d entries alongside a clientProblem", len(hits))
	if strings.Contains(string(body), "\x1b") {
		t.Error("fixture contains an ANSI escape — it was captured from a polluted stream")
	}
}

// TestParseTestSSLClientProblemNamesTheRightMachine covers the document
// testssl.sh emits when the problem is with the LOCAL openssl rather than with
// the target: an object carrying clientProblem1 and no scanResult.
//
// Without special handling this parses fine, yields no findings, and gets
// reported as "the target may not have completed a TLS handshake" — which sends
// the operator to investigate the wrong machine.
func TestParseTestSSLClientProblemNamesTheRightMachine(t *testing.T) {
	body := `{"clientProblem1":[{"id":"engine_problem","severity":"WARN",` +
		`"finding":"No engine or GOST support via engine with your /usr/bin/openssl"}]}`

	_, err := parseTestSSL(body)
	if err == nil {
		t.Fatal("a document with no scanResult must be an error, not an empty success")
	}
	if !strings.Contains(err.Error(), "THIS machine") {
		t.Errorf("error should say the scanner host is at fault, got: %v", err)
	}
	if !strings.Contains(err.Error(), "openssl") {
		t.Errorf("error should carry testssl's own explanation, got: %v", err)
	}
	if strings.Contains(err.Error(), "handshake") {
		t.Errorf("error must not blame the target's handshake, got: %v", err)
	}
}
