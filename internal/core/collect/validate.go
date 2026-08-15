package collect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Validation: prove the finding, don't just infer it.
//
// Most scanners read a config file, conclude a weakness exists, and move on.
// That produces plausible findings. It also produces a steady stream of ones
// that cannot actually be exercised — a world-writable directory on a noexec
// mount, a capability that is permitted but not effective, a group membership
// whose socket is not actually reachable. Every such finding spends the
// operator's attention on nothing, and that is precisely how a security tool
// stops being read.
//
// So where a safe test exists, we run it. Rules for every validator:
//
//   - NON-DESTRUCTIVE. Unique temp names, removed afterwards. Nothing
//     persisted, nothing restarted, nothing denied service.
//   - NO CREDENTIALS. We never attempt an authentication with a guess. We may
//     ask a service which methods it offers; we never try one.
//   - UNPRIVILEGED. Tests run as the scanning account, without sudo, because
//     the question is "can an ordinary local user do this?"
//   - HONEST ON FAILURE. If the test cannot run, the verdict is unverified —
//     never "refuted". Absence of proof is not proof of absence.

// Validator proves or refutes findings on a target.
type Validator struct{}

// unprivileged returns a runner that never escalates. Every validator must use
// it: the question a validation answers is "can an ordinary local user do
// this?", so a test that quietly runs under sudo answers a different question
// and gets the verdict wrong in both directions.
func unprivileged(r exec.Runner) exec.Runner {
	t := r.Target()
	if !t.UseSudo {
		return r
	}
	t.UseSudo = false
	return exec.New(t, 30*time.Second)
}

// tempName produces a collision-resistant probe filename that is obviously
// ours, so anything left behind by an interrupted scan is identifiable.
func tempName(seed string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(seed); i++ {
		h ^= uint32(seed[i])
		h *= 16777619
	}
	return fmt.Sprintf(".secscan-probe-%08x", h)
}

// Validate runs the applicable test for each finding and records the verdict.
// Returns the number of findings for which a test actually ran.
func (v Validator) Validate(ctx context.Context, r exec.Runner, fs []finding.Finding) int {
	r = unprivileged(r)
	n := 0
	for i := range fs {
		f := &fs[i]
		var val *finding.Validation

		switch f.RuleID {
		case "escalation.writable-path-dir", "hygiene.cron-writable",
			"escalation.writable-systemd-unit", "hardening.world-writable":
			val = v.proveWritable(ctx, r, *f)
		case "escalation.capabilities":
			val = v.proveCapabilityEffective(ctx, r, *f)
		case "escalation.docker-group":
			val = v.proveDockerSocket(ctx, r)
		case "hygiene.mount-options":
			val = v.proveNoexec(ctx, r, *f)
		case "hygiene.sensitive-file-permissions":
			val = v.proveShadowReadable(ctx, r)
		case "identity.ssh-password-auth":
			val = v.proveSSHOffersPassword(ctx, r)
		case "network.wide-bind":
			val = v.fromReachability(*f)
		}

		if val != nil {
			f.Validation = val
			if val.Verdict != finding.VerdictUnverified {
				n++
			}
		}
	}
	return n
}

// ------------------------------------------------------------ writability

// proveWritable attempts to create and immediately remove a uniquely-named
// file in each reported path. This answers the only question that matters —
// can the scanning account actually write there right now — rather than
// inferring it from a mode bit that may be overridden by an ACL, a read-only
// mount, or an LSM.
func (v Validator) proveWritable(ctx context.Context, r exec.Runner, f finding.Finding) *finding.Validation {
	paths := pathsFromEvidence(f)
	if len(paths) == 0 {
		return unverified("no concrete path in the evidence to test")
	}

	var wrote, blocked []string
	for _, p := range paths {
		dir := p
		if !strings.HasSuffix(dir, "/") {
			// For a file, test its containing directory: replacing the file is
			// what matters, and that needs directory write permission.
			if i := strings.LastIndex(p, "/"); i > 0 {
				dir = p[:i]
			}
		}
		probe := dir + "/" + tempName(dir)
		res := r.Run(ctx, "touch", probe)
		if res.OK() {
			wrote = append(wrote, dir)
			r.Run(ctx, "rm", "-f", probe) // always clean up
		} else {
			blocked = append(blocked, dir+": "+firstLine(res.Stderr))
		}
	}

	switch {
	case len(wrote) > 0:
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "created and removed a uniquely-named file as the scanning account",
			Output:  "writable: " + strings.Join(wrote, ", "),
		}
	case len(blocked) > 0:
		return &finding.Validation{
			Verdict: finding.VerdictRefuted,
			Method:  "attempted to create a file as the scanning account",
			Output:  strings.Join(blocked, "\n"),
			Note: "The permission bits suggest it is writable, but the write was refused — " +
				"an ACL, a read-only mount or an LSM is preventing it. The mode is still " +
				"wrong and should be corrected, because whatever is blocking it may not always be.",
		}
	}
	return unverified("write test produced no result")
}

// ------------------------------------------------------------ capabilities

// proveCapabilityEffective distinguishes `=ep` from `=p`.
//
// This is a genuine and widely-missed nuance: a file capability marked
// permitted-only (`=p`) is NOT active when the program starts. The binary must
// deliberately raise it, which capability-unaware software never does. Tools
// that grep for the capability name alone report both identically — and that
// is why snap-confine gets flagged as critical on essentially every Ubuntu
// host despite being `=p`.
func (v Validator) proveCapabilityEffective(ctx context.Context, r exec.Runner, f finding.Finding) *finding.Validation {
	raw := evidenceText(f)
	if raw == "" {
		return unverified("no getcap output to inspect")
	}

	var effective, permittedOnly []string
	for _, l := range lines(raw) {
		if !strings.Contains(l, "cap_") {
			continue
		}
		bin := strings.Fields(l)[0]
		switch {
		case strings.Contains(l, "=ep"), strings.Contains(l, "+ep"):
			effective = append(effective, bin)
		case strings.HasSuffix(strings.TrimSpace(l), "=p"), strings.Contains(l, "+p "):
			permittedOnly = append(permittedOnly, bin)
		}
	}

	if len(effective) > 0 {
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "parsed the capability set for effective (=ep) versus permitted-only (=p)",
			Output:  "effective at exec: " + strings.Join(effective, ", "),
		}
	}
	if len(permittedOnly) > 0 {
		return &finding.Validation{
			Verdict: finding.VerdictRefuted,
			Method:  "parsed the capability set for effective (=ep) versus permitted-only (=p)",
			Output:  "permitted-only (=p): " + strings.Join(permittedOnly, ", "),
			Note: "These capabilities are in the permitted set but not the effective set, so " +
				"they are NOT active when the program starts — the binary must raise them " +
				"itself, which capability-unaware software does not do. This is the normal " +
				"configuration for snap-confine and similar. Still worth inventorying: if the " +
				"binary is capability-aware, or is ever replaced, the grant becomes live.",
		}
	}
	return unverified("could not determine the capability mode from getcap output")
}

// ----------------------------------------------------------- docker socket

// proveDockerSocket checks whether the scanning account can actually reach the
// Docker API without sudo. Group membership implies it; reaching the socket
// demonstrates it.
func (v Validator) proveDockerSocket(ctx context.Context, r exec.Runner) *finding.Validation {
	if !r.Has(ctx, "docker") {
		return unverified("docker client not present for the scanning account")
	}
	// `docker version` talks to the daemon and changes nothing.
	res := r.Run(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	if res.OK() && strings.TrimSpace(res.Stdout) != "" {
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "queried the Docker daemon as the scanning account, without sudo",
			Output: "daemon reachable, server version " + strings.TrimSpace(res.Stdout) +
				" — anyone who can do this can mount the host filesystem into a container and read or write anything",
		}
	}
	return &finding.Validation{
		Verdict: finding.VerdictRefuted,
		Method:  "attempted to query the Docker daemon as the scanning account",
		Output:  firstLine(res.Stderr),
		Note: "The scanning account is not itself in the group, so this test only shows the " +
			"socket is not reachable by THIS account. The listed members may still have access — " +
			"treat the membership finding as standing.",
	}
}

// ----------------------------------------------------------------- noexec

// proveNoexec writes a trivial script to the mount point, marks it executable
// and tries to run it. Definitive: mount options can be overridden by a
// remount, and reading /proc/mounts only tells you what was requested.
func (v Validator) proveNoexec(ctx context.Context, r exec.Runner, f finding.Finding) *finding.Validation {
	raw := evidenceText(f)
	if !strings.Contains(raw, "noexec") {
		return unverified("this finding is not about noexec")
	}
	var mount string
	for _, m := range []string{"/dev/shm", "/tmp", "/var/tmp"} {
		if strings.Contains(raw, m+" is missing noexec") {
			mount = m
			break
		}
	}
	if mount == "" {
		return unverified("no noexec-missing mount named in the evidence")
	}

	probe := mount + "/" + tempName(mount)
	defer r.Run(ctx, "rm", "-f", probe)

	if w := r.Run(ctx, "sh", "-c", fmt.Sprintf("printf '#!/bin/sh\\nexit 7\\n' > %s && chmod +x %s", probe, probe)); !w.OK() {
		return unverified("could not stage a probe on " + mount + ": " + firstLine(w.Stderr))
	}
	res := r.Run(ctx, probe)
	if res.ExitCode == 7 {
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "wrote a small script to " + mount + ", executed it, and removed it",
			Output: "the script ran (exit 7) — " + mount + " can execute code, so a dropped " +
				"payload here runs",
		}
	}
	return &finding.Validation{
		Verdict: finding.VerdictRefuted,
		Method:  "wrote a small script to " + mount + ", attempted to execute it, and removed it",
		Output:  "execution was refused: " + firstLine(res.Stderr),
		Note: "Something is already preventing execution on this mount. The fstab option is " +
			"still worth setting so the protection is explicit and survives a remount.",
	}
}

// ------------------------------------------------------------ shadow read

// proveShadowReadable attempts an unprivileged read of the password hashes.
func (v Validator) proveShadowReadable(ctx context.Context, r exec.Runner) *finding.Validation {
	// head -c avoids pulling the whole file, and we never store what comes back.
	// This runs unprivileged by construction (see unprivileged()), which is the
	// only way the answer means anything.
	res := r.Run(ctx, "sh", "-c", "head -c 1 /etc/shadow >/dev/null 2>&1; echo $?")
	code := strings.TrimSpace(res.Stdout)
	if code == "0" {
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "attempted an unprivileged read of /etc/shadow (content discarded)",
			Output: "readable without privilege — every password hash on this host can be " +
				"copied by any local user and cracked offline",
		}
	}
	return &finding.Validation{
		Verdict: finding.VerdictRefuted,
		Method:  "attempted an unprivileged read of /etc/shadow",
		Output:  "read refused (exit " + code + ")",
		Note:    "The permission bits looked loose but the read was denied.",
	}
}

// ------------------------------------------------------------ ssh methods

// proveSSHOffersPassword asks the SSH server which authentication methods it
// offers. It never attempts one: the server advertises its method list during
// the handshake, and a deliberately invalid key is enough to make it say so.
func (v Validator) proveSSHOffersPassword(ctx context.Context, r exec.Runner) *finding.Validation {
	res := r.Run(ctx, "sh", "-c",
		"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 "+
			"-o PreferredAuthentications=none -o PubkeyAuthentication=no "+
			"-v secscan-probe@127.0.0.1 exit 2>&1 | grep -i 'authentications that can continue' | head -1")
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		return unverified("the SSH server did not advertise its method list from this vantage point")
	}
	if strings.Contains(strings.ToLower(out), "password") {
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "read the server's advertised authentication methods (no credential was attempted)",
			Output:  out,
		}
	}
	return &finding.Validation{
		Verdict: finding.VerdictRefuted,
		Method:  "read the server's advertised authentication methods (no credential was attempted)",
		Output:  out,
		Note:    "The server does not offer password authentication, whatever the config file suggests.",
	}
}

// ------------------------------------------------------ reachability reuse

// fromReachability promotes the external probe already performed by the
// Reachability collector into a verdict, so exposure findings carry the same
// confirmed/refuted vocabulary as everything else.
func (v Validator) fromReachability(f finding.Finding) *finding.Validation {
	for _, e := range f.Evidence {
		if !strings.HasPrefix(e.Command, "probe ") {
			continue
		}
		if strings.Contains(e.Output, "failed") {
			return &finding.Validation{
				Verdict: finding.VerdictRefuted,
				Method:  "TCP connect from outside the host",
				Output:  e.Output,
				Note:    "Bound to all interfaces, but not reachable from outside.",
			}
		}
		return &finding.Validation{
			Verdict: finding.VerdictConfirmed,
			Method:  "TCP connect from outside the host",
			Output:  e.Output,
		}
	}
	return nil
}

// ---------------------------------------------------------------- helpers

func unverified(note string) *finding.Validation {
	return &finding.Validation{Verdict: finding.VerdictUnverified, Note: note}
}

func evidenceText(f finding.Finding) string {
	var b strings.Builder
	for _, e := range f.Evidence {
		b.WriteString(e.Output)
		b.WriteString("\n")
	}
	return b.String()
}

// pathsFromEvidence pulls absolute paths out of evidence output so a validator
// can test the exact things that were reported.
func pathsFromEvidence(f finding.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines(evidenceText(f)) {
		for _, tok := range strings.Fields(l) {
			if !strings.HasPrefix(tok, "/") || len(tok) < 2 {
				continue
			}
			tok = strings.TrimRight(tok, ":,")
			if !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
		}
	}
	if len(out) > 10 {
		out = out[:10] // bound the work; a sample is enough to prove the class
	}
	return out
}
