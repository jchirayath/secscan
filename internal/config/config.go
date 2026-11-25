// Package config is the ONLY place in the binary that reads the environment.
//
// Scattered os.Getenv calls with no boot-time validation are how a service
// reaches the state where nobody can answer "what configures this?" without
// grepping the whole tree. Here every key is declared once with type, default,
// required-ness,
// secret-ness and description; the process refuses to start if a required key
// is missing; `secscan config` prints the resolved set with secrets redacted
// and doubles as the documentation source (ARCHITECTURE.md — Configuration).
//
// `ci/guards.sh` fails the build on os.Getenv outside this package.
package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is the value type of a key, used for parsing and for `config` output.
type Kind int

const (
	KindString Kind = iota
	KindBool
	KindInt
	KindDuration
)

// Key is one declared configuration entry.
type Key struct {
	Name     string // env var name, always SECSCAN_-prefixed
	Kind     Kind
	Default  string
	Required bool // if true and unset (and no default), boot fails
	Secret   bool // redacted in output
	Desc     string
	// RequiredWhen makes a key conditionally required — evaluated against the
	// resolved config after all keys are read. Used so Entra keys are required
	// only in entra auth mode.
	RequiredWhen func(*Config) bool
}

// The registry. Adding configuration means adding a line here — there is no
// other way to introduce a knob.
var registry = []Key{
	{Name: "SECSCAN_HOME", Kind: KindString, Default: "", Desc: "State directory (default ~/.secscan)"},
	{Name: "SECSCAN_BIND", Kind: KindString, Default: "127.0.0.1:8788", Desc: "Listen address for `serve`"},
	{Name: "SECSCAN_AUTH_MODE", Kind: KindString, Default: "local", Desc: "entra | proxy | local"},
	{Name: "SECSCAN_BASE_URL", Kind: KindString, Default: "", Desc: "External base URL, e.g. https://scan.example.com"},

	{Name: "SECSCAN_ENTRA_TENANT_ID", Kind: KindString, Desc: "Entra directory (tenant) ID",
		RequiredWhen: func(c *Config) bool { return c.AuthMode == "entra" }},
	{Name: "SECSCAN_ENTRA_CLIENT_ID", Kind: KindString, Desc: "Entra application (client) ID",
		RequiredWhen: func(c *Config) bool { return c.AuthMode == "entra" }},
	{Name: "SECSCAN_ENTRA_CLIENT_SECRET", Kind: KindString, Secret: true, Desc: "Entra client secret",
		RequiredWhen: func(c *Config) bool { return c.AuthMode == "entra" }},
	{Name: "SECSCAN_SESSION_SECRET", Kind: KindString, Secret: true, Desc: "HMAC key for session cookies (>=32 bytes)",
		RequiredWhen: func(c *Config) bool { return c.AuthMode == "entra" }},
	{Name: "SECSCAN_SESSION_TTL", Kind: KindDuration, Default: "8h", Desc: "Session lifetime"},
	{Name: "SECSCAN_ALLOWED_DOMAINS", Kind: KindString, Default: "", Desc: "Comma-separated email domain allow-list"},
	{Name: "SECSCAN_ADMIN_EMAILS", Kind: KindString, Default: "", Desc: "Comma-separated emails granted admin"},

	{Name: "SECSCAN_TRUSTED_PROXIES", Kind: KindString, Default: "", Desc: "CIDRs allowed to assert identity headers (proxy mode)"},

	{Name: "SECSCAN_HTTP_TIMEOUT", Kind: KindDuration, Default: "30s", Desc: "Outbound HTTP timeout"},
	{Name: "SECSCAN_SCAN_TIMEOUT", Kind: KindDuration, Default: "5m", Desc: "Per-collector timeout"},
	{Name: "SECSCAN_SCAN_INTERVAL", Kind: KindDuration, Default: "0", Desc: "serve: scan every target this often (e.g. 24h); 0 disables"},
	{Name: "SECSCAN_SSH_TIMEOUT", Kind: KindDuration, Default: "20s", Desc: "SSH connect timeout"},
	{Name: "SECSCAN_LOG_LEVEL", Kind: KindString, Default: "info", Desc: "debug | info | warn | error"},
	{Name: "SECSCAN_SNAPSHOT_DIR", Kind: KindString, Default: "", Desc: "Where per-scan snapshots are written (default $SECSCAN_HOME/snapshots)"},
	{Name: "SECSCAN_SNAPSHOT_KEEP", Kind: KindInt, Default: "0", Desc: "Snapshots to retain per asset; 0 keeps everything"},
}

// Config is the resolved, validated configuration.
type Config struct {
	Home     string
	Bind     string
	AuthMode string
	BaseURL  string

	EntraTenantID     string
	EntraClientID     string
	EntraClientSecret string
	SessionSecret     string
	SessionTTL        time.Duration
	AllowedDomains    []string
	AdminEmails       []string

	TrustedProxies []string

	HTTPTimeout time.Duration
	ScanTimeout time.Duration
	// ScanInterval > 0 makes `serve` scan every target on that cadence.
	ScanInterval time.Duration
	SSHTimeout   time.Duration
	LogLevel     string

	SnapshotDir  string
	SnapshotKeep int

	raw map[string]string
}

// Load reads, parses and validates the environment. It is the only os.Getenv
// site in the binary.
func Load() (*Config, error) {
	raw := map[string]string{}
	for _, k := range registry {
		v := os.Getenv(k.Name) //nolint:forbidigo // the one permitted site
		if v == "" {
			v = k.Default
		}
		raw[k.Name] = v
	}

	c := &Config{raw: raw}
	var errs []string

	get := func(n string) string { return strings.TrimSpace(raw[n]) }
	dur := func(n string) time.Duration {
		d, err := time.ParseDuration(get(n))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %q is not a duration", n, get(n)))
			return 0
		}
		return d
	}
	list := func(n string) []string {
		s := get(n)
		if s == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}

	c.Home = get("SECSCAN_HOME")
	if c.Home == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			errs = append(errs, "SECSCAN_HOME unset and home directory undiscoverable")
		}
		c.Home = home + "/.secscan"
	}
	c.Bind = get("SECSCAN_BIND")
	c.AuthMode = strings.ToLower(get("SECSCAN_AUTH_MODE"))
	c.BaseURL = strings.TrimRight(get("SECSCAN_BASE_URL"), "/")

	c.EntraTenantID = get("SECSCAN_ENTRA_TENANT_ID")
	c.EntraClientID = get("SECSCAN_ENTRA_CLIENT_ID")
	c.EntraClientSecret = get("SECSCAN_ENTRA_CLIENT_SECRET")
	c.SessionSecret = get("SECSCAN_SESSION_SECRET")
	c.SessionTTL = dur("SECSCAN_SESSION_TTL")
	c.AllowedDomains = list("SECSCAN_ALLOWED_DOMAINS")
	c.AdminEmails = list("SECSCAN_ADMIN_EMAILS")
	c.TrustedProxies = list("SECSCAN_TRUSTED_PROXIES")
	c.HTTPTimeout = dur("SECSCAN_HTTP_TIMEOUT")
	c.ScanTimeout = dur("SECSCAN_SCAN_TIMEOUT")
	c.ScanInterval = dur("SECSCAN_SCAN_INTERVAL")
	if c.ScanInterval < 0 || (c.ScanInterval > 0 && c.ScanInterval < 10*time.Minute) {
		// A full scan takes minutes; anything tighter is a load test, not a schedule.
		errs = append(errs, "SECSCAN_SCAN_INTERVAL must be 0 (off) or at least 10m")
	}
	c.SSHTimeout = dur("SECSCAN_SSH_TIMEOUT")
	c.LogLevel = get("SECSCAN_LOG_LEVEL")

	c.SnapshotDir = get("SECSCAN_SNAPSHOT_DIR")
	if c.SnapshotDir == "" {
		c.SnapshotDir = c.Home + "/snapshots"
	}
	if v := get("SECSCAN_SNAPSHOT_KEEP"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errs = append(errs, "SECSCAN_SNAPSHOT_KEEP must be a non-negative integer")
		} else {
			c.SnapshotKeep = n
		}
	}

	switch c.AuthMode {
	case "entra", "proxy", "local":
	default:
		errs = append(errs, fmt.Sprintf("SECSCAN_AUTH_MODE: %q must be entra, proxy or local", c.AuthMode))
	}

	for _, k := range registry {
		missing := get(k.Name) == ""
		if !missing {
			continue
		}
		if k.Required || (k.RequiredWhen != nil && k.RequiredWhen(c)) {
			errs = append(errs, fmt.Sprintf("%s is required (%s)", k.Name, k.Desc))
		}
	}

	// A short session secret is a real weakness, not a style nit: it is the
	// only thing standing between a user and forging a session cookie.
	if c.AuthMode == "entra" && c.SessionSecret != "" && len(c.SessionSecret) < 32 {
		errs = append(errs, "SECSCAN_SESSION_SECRET must be at least 32 bytes")
	}
	// proxy mode without a trusted-peer list means anyone who can reach the
	// port can assert any identity via headers. Refuse to start.
	if c.AuthMode == "proxy" && len(c.TrustedProxies) == 0 {
		errs = append(errs, "SECSCAN_TRUSTED_PROXIES is required in proxy mode — "+
			"trusting identity headers from any peer is an authentication bypass")
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("configuration invalid:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return c, nil
}

// LoopbackOnly reports whether Bind is restricted to loopback. `local` auth
// mode is permitted only when this is true.
func (c *Config) LoopbackOnly() bool {
	host := c.Bind
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

// Example renders a .env template from the registry itself.
//
// Generated rather than hand-written: a checked-in example that drifts from
// the code is worse than none, because it tells an operator to set a variable
// that no longer does anything.
func Example() []string {
	keys := make([]Key, len(registry))
	copy(keys, registry)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })

	out := []string{
		"# secscan configuration.",
		"#",
		"# Generated by `secscan config -example` from the config registry, so this",
		"# file cannot drift from what the binary actually reads.",
		"#",
		"# Copy to .env (gitignored) and fill in. Never commit a filled-in copy:",
		"# the session and client secrets are what stand between a stranger and",
		"# your dashboard.",
		"",
	}
	for _, k := range keys {
		out = append(out, "# "+k.Desc)
		val := k.Default
		if k.Secret {
			val = "CHANGE_ME"
			out = append(out, "# SECRET — do not commit a real value")
		}
		if k.Required || k.RequiredWhen != nil {
			out = append(out, "# required"+requiredNote(k))
		}
		out = append(out, k.Name+"="+val, "")
	}
	return out
}

func requiredNote(k Key) string {
	if k.RequiredWhen != nil {
		return " when SECSCAN_AUTH_MODE=entra"
	}
	return ""
}

// Redacted renders the resolved configuration for `secscan config`, hiding
// secrets. Sorted so the output is diffable.
func (c *Config) Redacted() []string {
	keys := make([]Key, len(registry))
	copy(keys, registry)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v := c.raw[k.Name]
		switch {
		case v == "":
			v = "(unset)"
		case k.Secret:
			v = "(set, redacted)"
		}
		out = append(out, fmt.Sprintf("%-32s %-28s %s", k.Name, v, k.Desc))
	}
	return out
}
