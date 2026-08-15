package collect

import (
	"strings"
	"testing"
)

// These pin the false positives found while validating against a real Ubuntu
// 24.04 host. Each one made the scanner confidently wrong, which is worse than
// silent — an operator who is burned twice stops reading the output.

// TestSensitiveModeComparison: the mode check must allow stricter-than-required
// and reject only genuinely looser modes.
func TestSensitiveModeComparison(t *testing.T) {
	cases := []struct {
		mode     int
		max      int
		tooLoose bool
	}{
		{0o640, 0o640, false}, // exactly right
		{0o600, 0o640, false}, // stricter is fine
		{0o644, 0o640, true},  // world-readable shadow
		{0o666, 0o644, true},  // world-writable passwd
		{0o750, 0o750, false},
		{0o755, 0o750, true},
	}
	for _, c := range cases {
		got := c.mode&^c.max != 0
		if got != c.tooLoose {
			t.Errorf("mode %o against max %o: tooLoose=%v, want %v", c.mode, c.max, got, c.tooLoose)
		}
	}
}

func TestPermissionHelpers(t *testing.T) {
	if !worldReadable("644") || worldReadable("640") {
		t.Error("worldReadable is wrong")
	}
	if !groupOrWorldReadable("640") || groupOrWorldReadable("600") {
		t.Error("groupOrWorldReadable is wrong")
	}
	if !groupOrWorldWritable("664") || groupOrWorldWritable("644") {
		t.Error("groupOrWorldWritable is wrong")
	}
	// A symlink is always 0777. This is why the PATH check must dereference —
	// on any usrmerge system /bin and /sbin are symlinks and would otherwise
	// report as world-writable on every modern Ubuntu host.
	if !groupOrWorldWritable("777") {
		t.Error("777 must read as writable — the fix is to stat -L, not to ignore it")
	}
}

// TestExpectedSUID: reporting the whole standard SUID set would train people to
// ignore the check, so only unexpected binaries count.
func TestExpectedSUID(t *testing.T) {
	for _, p := range []string{"/usr/bin/sudo", "/bin/su", "/usr/bin/passwd", "/usr/bin/pkexec"} {
		if !expectedSUID(p) {
			t.Errorf("%s should be in the expected set", p)
		}
	}
	for _, p := range []string{"/tmp/rootshell", "/opt/vendor/helper", "/usr/local/bin/backup"} {
		if expectedSUID(p) {
			t.Errorf("%s should NOT be treated as expected", p)
		}
	}
}

// TestCountHolders: the sudo finding counts distinct accounts, not rules —
// "%sudo can do anything" is noise, "these two people can" is the useful fact.
func TestCountHolders(t *testing.T) {
	grants := []string{
		"%admin → alice  (/etc/sudoers)",
		"%sudo → alice, bob  (/etc/sudoers)",
	}
	if n := countHolders(grants); n != 2 {
		t.Errorf("countHolders = %d, want 2 distinct accounts (alice, bob)", n)
	}
	if n := countHolders(nil); n != 0 {
		t.Errorf("countHolders(nil) = %d, want 0", n)
	}
}

// TestDangerousCapsCoverKnownEscalationPaths guards the list against being
// trimmed to the point of uselessness.
func TestDangerousCapsCoverKnownEscalationPaths(t *testing.T) {
	for _, c := range []string{"cap_setuid", "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module"} {
		if _, ok := dangerousCaps[c]; !ok {
			t.Errorf("%s is a documented route to root and must be flagged", c)
		}
		if why := dangerousCaps[c]; !strings.Contains(why, " ") {
			t.Errorf("%s has no explanation; a capability name alone tells an operator nothing", c)
		}
	}
	// cap_net_raw is what ping carries. Flagging it would make the check noise.
	if _, ok := dangerousCaps["cap_net_raw"]; ok {
		t.Error("cap_net_raw is normal on ping and must not be flagged")
	}
}
