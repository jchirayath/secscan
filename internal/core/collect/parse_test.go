package collect

import "testing"

// Golden fixture: real `ss -tulpnH` output captured from a live host
// (Ubuntu 24.04.4). Committed so parser changes are checked against reality
// rather than against what we imagine the format to be — and so the test needs
// no network.
const ssSample = `udp   UNCONN 0      0            0.0.0.0:443        0.0.0.0:*    users:(("caddy",pid=1234,fd=9))
udp   UNCONN 0      0      127.0.0.54:53         0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=18))
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      4096            [::]:22           [::]:*    users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("caddy",pid=1234,fd=7))
tcp   LISTEN 0      4096       127.0.0.1:3306       0.0.0.0:*    users:(("mariadbd",pid=999,fd=21))
tcp   LISTEN 0      511             [::]:7681          [::]:*
`

func TestParseSS(t *testing.T) {
	got := parseSS(ssSample)
	if len(got) != 7 {
		t.Fatalf("parsed %d listeners, want 7", len(got))
	}

	byPort := map[int]Listener{}
	for _, l := range got {
		// Two rows share port 22 (v4 + v6); keep the first for the assertions.
		if _, seen := byPort[l.Port]; !seen || l.Proto == "tcp" {
			if _, seen := byPort[l.Port]; !seen {
				byPort[l.Port] = l
			}
		}
	}

	if l := byPort[22]; l.Addr != "0.0.0.0" || l.Process != "sshd" {
		t.Errorf("port 22: addr=%q process=%q, want 0.0.0.0/sshd", l.Addr, l.Process)
	}
	// The loopback bind must NOT be reported as wide — this is the distinction
	// the whole exposure model rests on.
	if l := byPort[3306]; wideBind(l.Addr) {
		t.Errorf("port 3306 bound to %q was treated as a wide bind", l.Addr)
	}
	if l := byPort[7681]; !wideBind(l.Addr) {
		t.Errorf("port 7681 bound to %q should be a wide bind", l.Addr)
	}
	// A row with no users:(()) tail must still parse rather than being dropped.
	if _, ok := byPort[7681]; !ok {
		t.Error("listener without a process tail was dropped")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"0.0.0.0:22", "0.0.0.0", 22, true},
		{"[::]:443", "::", 443, true},
		{"*:8080", "0.0.0.0", 8080, true},
		{"127.0.0.1:6379", "127.0.0.1", 6379, true},
		{"[fe80::1%eth0]:22", "fe80::1%eth0", 22, true},
		{"garbage", "", 0, false},
		{"host:notaport", "", 0, false},
	}
	for _, c := range cases {
		h, p, ok := splitHostPort(c.in)
		if ok != c.ok || (ok && (h != c.host || p != c.port)) {
			t.Errorf("splitHostPort(%q) = (%q,%d,%v), want (%q,%d,%v)",
				c.in, h, p, ok, c.host, c.port, c.ok)
		}
	}
}

func TestKVFile(t *testing.T) {
	// sshd_config style: space-separated, comments ignored, later wins —
	// which is how sshd_config.d overrides actually resolve.
	cfg := `
# comment
PermitRootLogin yes
PasswordAuthentication no
PermitRootLogin no
`
	kv := kvFile(cfg, " ")
	if kv["permitrootlogin"] != "no" {
		t.Errorf("later directive should win, got %q", kv["permitrootlogin"])
	}
	if kv["passwordauthentication"] != "no" {
		t.Errorf("got %q", kv["passwordauthentication"])
	}

	// os-release style: key=value with quotes stripped.
	rel := `PRETTY_NAME="Ubuntu 24.04.4 LTS"` + "\n" + `ID=ubuntu` + "\n" + `ID_LIKE=debian`
	kv2 := kvFile(rel, "=")
	if kv2["pretty_name"] != "Ubuntu 24.04.4 LTS" {
		t.Errorf("got %q", kv2["pretty_name"])
	}
	if familyOf(kv2["id_like"]) != "debian" {
		t.Errorf("familyOf(debian) = %q", familyOf(kv2["id_like"]))
	}
}
