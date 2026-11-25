package exec

import "testing"

// TestRedactionTargetsContentNotMetadata is the check that keeps this feature
// from being either a disclosure risk or useless.
//
// Too little redaction and the scanner's own state file holds password hashes.
// Too much and it hides the mode bits that a permissions finding is *about* —
// protecting nothing while removing the evidence.
func TestRedactionTargetsContentNotMetadata(t *testing.T) {
	mustRedact := []string{
		"cat /etc/shadow",
		"sudo -n cat /etc/shadow",
		"head -c 1 /etc/shadow",
		"cat /home/u/.ssh/id_rsa",
		"grep secret /opt/app/.env",
		"cat /etc/gshadow",
	}
	mustKeep := []string{
		"stat -c %a %n /etc/shadow",      // the mode IS the finding
		"stat -Lc %a %U %n /etc/gshadow", //
		"find /root /home -name .ssh",    // paths, not key material
		"ls -1 /etc/sudoers.d",           //
		"test -s /var/lib/logrotate/status",
		"cat /etc/os-release", // content, but not secret
		"apt-get -s upgrade",
	}
	for _, c := range mustRedact {
		if !isSensitive(c) {
			t.Errorf("%q must be redacted — it reads secret content", c)
		}
	}
	for _, c := range mustKeep {
		if isSensitive(c) {
			t.Errorf("%q must NOT be redacted — it returns metadata or non-secret content, "+
				"and hiding it removes the evidence without protecting anything", c)
		}
	}
}

func TestRecorderBoundsOutput(t *testing.T) {
	long := make([]byte, maxOutput*2)
	for i := range long {
		long[i] = 'x'
	}
	got := truncate(string(long))
	if len(got) <= maxOutput || len(got) > maxOutput+40 {
		t.Errorf("truncate produced %d bytes; expected ~%d with a marker", len(got), maxOutput)
	}
}
