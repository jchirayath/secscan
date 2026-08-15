package engine

import "testing"

// TestKernelPackageRecognition pins both directions of the kernel-package rule.
//
// The false-negative direction matters more than it looks: if a name stops
// matching, its findings quietly return to HIGH with nothing to indicate the
// rule lapsed. The false-positive direction matters because demoting a real
// userspace CVE to informational is exactly the kind of silent under-reporting
// this codebase treats as unforgivable.
func TestKernelPackageRecognition(t *testing.T) {
	kernel := []string{
		"linux-libc-dev",
		"linux-headers-6.12.69-1",
		"linux-image-6.12.0-amd64",
		"kernel-headers",
		"kernel-devel-5.14.0",
		"linux",
		"LINUX-LIBC-DEV", // case must not matter
		" linux-libc-dev ",
	}
	for _, p := range kernel {
		if !kernelPackage(p) {
			t.Errorf("kernelPackage(%q) = false, want true — its findings will be rated as if the container ran its own kernel", p)
		}
	}

	userspace := []string{
		"libssl3", "openssl", "libcrypto3", "stdlib", "axios",
		"golang.org/x/crypto", "linux-firmware", // ships blobs the HOST loads
		"libpq5", "bind-libs", "tar", "curl",
	}
	for _, p := range userspace {
		if kernelPackage(p) {
			t.Errorf("kernelPackage(%q) = true, want false — a reachable userspace CVE would be demoted to informational", p)
		}
	}
}
