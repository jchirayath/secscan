// Package exec is the command transport: local for the host we run on, SSH for
// remote targets.
//
// SSH shells out to the system `ssh` binary rather than vendoring a crypto
// stack (ARCHITECTURE.md — Transport). That keeps the dependency count at zero and
// inherits the operator's existing known_hosts, agent, jump hosts and per-host
// config — behaviour they have already audited. Host-key checking is on by
// default and turning it off is per-target, explicit, and logged.
//
// Every remote command is assembled by quoting each argv element (shellQuote),
// never by interpolating a format string, so a hostile target name or path
// cannot inject.
package exec

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Result is the outcome of one command.
type Result struct {
	Command  string
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// OK reports a clean exit. Many probes treat non-zero as "absent", not as a
// failure, so callers check this rather than Err.
func (r Result) OK() bool { return r.Err == nil && r.ExitCode == 0 }

// Target describes what we are scanning.
type Target struct {
	Name     string `json:"name"`           // stable asset id
	Host     string `json:"host,omitempty"` // empty ⇒ local
	User     string `json:"user,omitempty"`
	Port     int    `json:"port,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	Critical bool   `json:"critical,omitempty"`

	// InsecureHostKey disables host-key verification for this target only.
	// Explicit, per-target, and logged loudly at WARN — the fail-closed
	// fail-closed pattern.
	InsecureHostKey bool `json:"insecure_host_key,omitempty"`

	// UseSudo allows `sudo -n` for the small set of collectors that need it
	// (shadow policy, docker socket). Never required — collectors degrade.
	UseSudo bool `json:"use_sudo,omitempty"`

	// VirtualHosts are additional DNS names this host answers for. A reverse
	// proxy routes by Host header, so probing the IP alone only ever reaches
	// the default virtual host — every other site on the same port is invisible.
	// Listing them here lets the exposure probe check each one, which is how a
	// name-based vhost sitting behind an identity provider gets recognised as
	// protected instead of being scored as an open port.
	VirtualHosts []string `json:"virtual_hosts,omitempty"`
}

// IsLocal reports whether this target runs commands on the local machine.
func (t Target) IsLocal() bool { return t.Host == "" }

// Runner executes commands against a target.
//
// Has and ReadFile are on the interface rather than free functions because
// they differ fundamentally by transport: locally `command -v` is a shell
// builtin with no binary to exec, and reading a file is a syscall, not a
// `cat`. Pushing them into the implementations keeps callers transport-blind.
type Runner interface {
	Run(ctx context.Context, argv ...string) Result
	Has(ctx context.Context, cmd string) bool
	ReadFile(ctx context.Context, path string) (string, bool)
	Target() Target
}

// New returns the right Runner for the target.
func New(t Target, timeout time.Duration) Runner {
	if t.IsLocal() {
		return &localRunner{target: t, timeout: timeout}
	}
	if t.InsecureHostKey {
		slog.Warn("ssh host-key verification DISABLED for target — "+
			"this target is vulnerable to man-in-the-middle",
			slog.String("target", t.Name), slog.String("host", t.Host))
	}
	return &sshRunner{target: t, timeout: timeout}
}

// ---------- local ----------

type localRunner struct {
	target  Target
	timeout time.Duration
}

func (l *localRunner) Target() Target { return l.target }

func (l *localRunner) Run(ctx context.Context, argv ...string) Result {
	if len(argv) == 0 {
		return Result{Err: fmt.Errorf("empty command")}
	}
	argv = l.maybeSudo(argv)
	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	cmd := osexec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()

	return Result{
		Command:  strings.Join(argv, " "),
		Stdout:   out.String(),
		Stderr:   errb.String(),
		ExitCode: exitCode(err, cmd),
		Err:      classify(err),
	}
}

// Has uses LookPath: locally there is no `command` binary to exec.
func (l *localRunner) Has(_ context.Context, cmd string) bool {
	_, err := osexec.LookPath(cmd)
	return err == nil
}

// ReadFile reads directly, falling back to `sudo cat` only for the few paths
// that genuinely need it.
func (l *localRunner) ReadFile(ctx context.Context, path string) (string, bool) {
	if b, err := os.ReadFile(path); err == nil {
		return string(b), true
	}
	if !l.target.UseSudo || !needsPrivilege([]string{"cat", path}) {
		return "", false
	}
	res := l.Run(ctx, "cat", path)
	if !res.OK() {
		return "", false
	}
	return res.Stdout, true
}

func (l *localRunner) maybeSudo(argv []string) []string {
	if !l.target.UseSudo || argv[0] == "sudo" {
		return argv
	}
	if !needsPrivilege(argv) {
		return argv
	}
	return append([]string{"sudo", "-n"}, argv...)
}

// ---------- ssh ----------

type sshRunner struct {
	target  Target
	timeout time.Duration
}

func (s *sshRunner) Target() Target { return s.target }

func (s *sshRunner) Run(ctx context.Context, argv ...string) Result {
	if len(argv) == 0 {
		return Result{Err: fmt.Errorf("empty command")}
	}
	if s.target.UseSudo && needsPrivilege(argv) && argv[0] != "sudo" {
		argv = append([]string{"sudo", "-n"}, argv...)
	}

	// Each element is quoted independently, so nothing in a path or hostname
	// can escape into the remote shell.
	remote := make([]string, len(argv))
	for i, a := range argv {
		remote[i] = shellQuote(a)
	}

	// A scan issues dozens of commands. Without multiplexing each one pays a
	// full TCP + TLS-equivalent handshake, which measured at ~26s for a single
	// host; with a shared master connection the same scan is a few seconds.
	// The socket lives in the user's own runtime dir and expires on its own.
	ctlPath := filepath.Join(os.TempDir(),
		fmt.Sprintf("secscan-%d-%s", os.Getuid(), sanitizeForPath(s.target.Name)))

	ssh := []string{
		"ssh",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(s.timeout.Seconds())),
		"-o", "LogLevel=ERROR",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + ctlPath,
		"-o", "ControlPersist=60s",
	}
	if s.target.InsecureHostKey {
		ssh = append(ssh, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
	} else {
		ssh = append(ssh, "-o", "StrictHostKeyChecking=accept-new")
	}
	if s.target.KeyFile != "" {
		ssh = append(ssh, "-o", "IdentitiesOnly=yes", "-i", s.target.KeyFile)
	}
	if s.target.Port != 0 {
		ssh = append(ssh, "-p", fmt.Sprint(s.target.Port))
	}
	dest := s.target.Host
	if s.target.User != "" {
		dest = s.target.User + "@" + s.target.Host
	}
	ssh = append(ssh, dest, strings.Join(remote, " "))

	// The overall context gets a longer budget than the connect timeout: a
	// slow collector shouldn't be killed just because connecting is slow.
	ctx, cancel := context.WithTimeout(ctx, s.timeout+2*time.Minute)
	defer cancel()

	cmd := osexec.CommandContext(ctx, ssh[0], ssh[1:]...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()

	return Result{
		Command:  strings.Join(argv, " "),
		Stdout:   out.String(),
		Stderr:   errb.String(),
		ExitCode: exitCode(err, cmd),
		Err:      classify(err),
	}
}

// Has runs the shell builtin remotely — over SSH the command string is
// interpreted by the login shell, so `command -v` is available.
func (s *sshRunner) Has(ctx context.Context, cmd string) bool {
	return s.Run(ctx, "command", "-v", cmd).OK()
}

// ReadFile cats the file on the remote host.
func (s *sshRunner) ReadFile(ctx context.Context, path string) (string, bool) {
	res := s.Run(ctx, "cat", path)
	if !res.OK() {
		return "", false
	}
	return res.Stdout, true
}

// ---------- helpers ----------

// privilegedPaths are the reads that genuinely need root. Keeping the list
// explicit means `sudo` is never prepended speculatively — a scanner that runs
// everything as root is its own risk.
//
// sshd_config is here because distributions increasingly ship it 0600 (Ubuntu
// 24.04 does). Without sudo the SSHD collector reads nothing and would report
// "no SSH daemon" on a host we are literally connected to over SSH.
var privilegedPaths = []string{
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/var/log/auth.log",
}

// privilegedCommands need root for their *useful* output. `ss -p` silently
// omits the owning process for sockets the caller does not own, which would
// make every listener look ownerless.
var privilegedCommands = map[string]bool{
	"docker":          true, // the docker socket is root-owned
	"ss":              true, // process/user attribution
	"nft":             true,
	"iptables":        true,
	"fail2ban-client": true, // jail status: is SSH actually protected?
	"sshd":            true, // sshd -T resolves the EFFECTIVE config
	"/usr/sbin/sshd":  true,
}

func needsPrivilege(argv []string) bool {
	if privilegedCommands[argv[0]] {
		return true
	}
	joined := strings.Join(argv, " ")
	for _, p := range privilegedPaths {
		if strings.Contains(joined, p) {
			return true
		}
	}
	return false
}

// shellQuote renders s as a single POSIX shell word. Single quotes protect
// everything except a single quote itself, which is closed, escaped, reopened.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '=' || r == ',' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func exitCode(err error, cmd *osexec.Cmd) int {
	if err == nil {
		return 0
	}
	var ee *osexec.ExitError
	if ok := asExitError(err, &ee); ok {
		return ee.ExitCode()
	}
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return -1
}

func asExitError(err error, target **osexec.ExitError) bool {
	if ee, ok := err.(*osexec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// classify keeps a non-zero exit out of Err: for probes, "command not found"
// is information, not an error. Only transport-level failures become Err.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*osexec.ExitError); ok {
		return nil
	}
	return err
}

// sanitizeForPath keeps a target name safe to embed in a filesystem path, so a
// target called "../../etc/passwd" cannot steer the control socket.
func sanitizeForPath(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := b.String()
	// Control-socket paths are bounded by the sockaddr_un limit (~104 on
	// macOS); a long target name would silently break multiplexing.
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// Trim is a small convenience used throughout the collectors.
func Trim(s string) string { return strings.TrimSpace(s) }
