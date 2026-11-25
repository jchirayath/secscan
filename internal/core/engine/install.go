package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/jchirayath/secscan/internal/core/exec"
)

// Installation is the one place in secscan that deliberately CHANGES the host
// it is pointed at. Everything else is read-only.
//
// Because of that it is: admin-only, explicitly requested per engine and per
// target, audited, and built from fixed commands defined here — never from
// anything a caller supplies. There is no `curl | sh` anywhere in this file:
// a security tool that installs itself by piping the internet into a shell is
// arguing against its own findings.

// InstallPlan is what would be run, shown to the operator before they confirm.
type InstallPlan struct {
	Engine    string   `json:"engine"`
	OSFamily  string   `json:"os_family"`
	Supported bool     `json:"supported"`
	Reason    string   `json:"reason,omitempty"`
	Steps     []string `json:"steps"`
	NeedsSudo bool     `json:"needs_sudo"`
}

// installRecipes are per-engine, per-OS-family command sequences. Each step is
// an argv, so nothing is shell-interpolated.
var installRecipes = map[string]map[string][][]string{
	"trivy": {
		"debian": {
			{"apt-get", "update", "-qq"},
			{"apt-get", "install", "-y", "-qq", "wget", "gnupg"},
			// Official Aqua apt repository, key pinned to keyring.
			{"sh", "-c", "wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg"},
			{"sh", "-c", `echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list`},
			{"apt-get", "update", "-qq"},
			{"apt-get", "install", "-y", "-qq", "trivy"},
		},
		"rhel": {
			{"sh", "-c", `cat > /etc/yum.repos.d/trivy.repo <<'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF`},
			{"dnf", "install", "-y", "trivy"},
		},
		"alpine": {
			{"apk", "add", "--no-cache", "trivy"},
		},
	},
	"gitleaks": {
		"debian": {{"sh", "-c", gitleaksInstall}},
		"rhel":   {{"sh", "-c", gitleaksInstall}},
		"alpine": {{"apk", "add", "--no-cache", "gitleaks"}},
	},
	"osv-scanner": {
		"debian": {{"sh", "-c", osvInstall}},
		"rhel":   {{"sh", "-c", osvInstall}},
	},
	"nuclei": {
		"debian": {{"sh", "-c", nucleiInstall}},
		"rhel":   {{"sh", "-c", nucleiInstall}},
	},
	"testssl": {
		"debian": {
			{"apt-get", "install", "-y", "-qq", "bsdextrautils"}, // testssl needs `hexdump`
			{"sh", "-c", testsslInstall},
		},
		"rhel": {{"sh", "-c", testsslInstall}},
	},
}

// Release-tarball installs, pinned to a version rather than "latest" so an
// install is reproducible and a compromised release channel cannot silently
// change what lands on the host.
//
// The `renovate:` markers let the update bot propose bumps as pull requests,
// and ci/engines.sh reads these same constants so CI's engine contract tests
// run the exact version a bump would ship. Keep each marker directly above its
// constant (the bot's match is line-anchored).
const (
	// renovate: datasource=github-releases depName=gitleaks/gitleaks
	gitleaksVersion = "8.21.2"
	// renovate: datasource=github-releases depName=google/osv-scanner
	osvVersion = "1.9.1"
	// renovate: datasource=github-releases depName=projectdiscovery/nuclei
	nucleiVersion = "3.11.1"
	// renovate: datasource=github-tags depName=testssl/testssl.sh
	testsslVersion = "3.2.4"

	gitleaksInstall = `set -e
arch=$(uname -m); case "$arch" in x86_64) a=x64;; aarch64|arm64) a=arm64;; *) echo "unsupported arch $arch"; exit 1;; esac
tmp=$(mktemp -d)
wget -qO "$tmp/g.tgz" "https://github.com/gitleaks/gitleaks/releases/download/v` + gitleaksVersion + `/gitleaks_` + gitleaksVersion + `_linux_${a}.tar.gz"
tar -xzf "$tmp/g.tgz" -C "$tmp" gitleaks
install -m 0755 "$tmp/gitleaks" /usr/local/bin/gitleaks
rm -rf "$tmp"`

	// nuclei ships a zip; unzip is not universally present, so it is installed
	// first rather than assumed.
	nucleiInstall = `set -e
arch=$(uname -m); case "$arch" in x86_64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "unsupported arch $arch"; exit 1;; esac
command -v unzip >/dev/null || (apt-get install -y -qq unzip || dnf install -y unzip)
tmp=$(mktemp -d)
wget -qO "$tmp/n.zip" "https://github.com/projectdiscovery/nuclei/releases/download/v` + nucleiVersion + `/nuclei_` + nucleiVersion + `_linux_${a}.zip"
unzip -q -o "$tmp/n.zip" nuclei -d "$tmp"
install -m 0755 "$tmp/nuclei" /usr/local/bin/nuclei
rm -rf "$tmp"`

	// testssl.sh is a shell script that needs the data files shipped alongside
	// it, so it is installed as a tree under /opt with a symlink on PATH rather
	// than as a lone binary. Dropping just the script would leave it unable to
	// find its cipher mapping and CA bundles.
	testsslInstall = `set -e
tmp=$(mktemp -d)
wget -qO "$tmp/t.tgz" "https://github.com/testssl/testssl.sh/archive/refs/tags/v` + testsslVersion + `.tar.gz"
rm -rf /opt/testssl.sh
mkdir -p /opt/testssl.sh
tar -xzf "$tmp/t.tgz" -C /opt/testssl.sh --strip-components=1
chmod 0755 /opt/testssl.sh/testssl.sh
ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
rm -rf "$tmp"`

	osvInstall = `set -e
arch=$(uname -m); case "$arch" in x86_64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "unsupported arch $arch"; exit 1;; esac
wget -qO /tmp/osv-scanner "https://github.com/google/osv-scanner/releases/download/v` + osvVersion + `/osv-scanner_linux_${a}"
install -m 0755 /tmp/osv-scanner /usr/local/bin/osv-scanner
rm -f /tmp/osv-scanner`
)

// PlanInstall describes what installing id on this OS family would do.
func PlanInstall(id, osFamily string) InstallPlan {
	p := InstallPlan{Engine: id, OSFamily: osFamily, NeedsSudo: true}
	// trivy-image is a second engine over the same binary; without this it
	// would show as installable in the UI and then refuse to plan.
	if id == "trivy-image" {
		id = "trivy"
	}
	recipes, ok := installRecipes[id]
	if !ok {
		p.Reason = "no install recipe for " + id
		return p
	}
	steps, ok := recipes[osFamily]
	if !ok {
		p.Reason = fmt.Sprintf("%s has no install recipe for OS family %q — install it manually", id, osFamily)
		return p
	}
	p.Supported = true
	for _, s := range steps {
		p.Steps = append(p.Steps, strings.Join(s, " "))
	}
	return p
}

// explainFailure turns a raw failure into something the operator can act on.
//
// The common case is the interesting one: a correctly-configured scan account
// has a narrow sudoers allow-list covering the handful of privileged *reads*
// it needs, and installing software is deliberately not on that list. Echoing
// "sudo: a password is required" leaves the reader to work that out; saying so
// plainly is the difference between a dead end and a next step.
func explainFailure(stderr string, step []string, code int) string {
	cmd := strings.Join(step, " ")
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "a password is required"), strings.Contains(s, "may not run"),
		strings.Contains(s, "not allowed to execute"):
		return fmt.Sprintf(
			"the scan account may not run %q as root. This is expected when the target uses a "+
				"least-privilege sudoers allow-list: scanning needs a few privileged reads, "+
				"installing needs far more. Either install the engine manually on the host, or "+
				"temporarily grant the scan account permission for the package manager.", cmd)
	case strings.Contains(s, "could not resolve"), strings.Contains(s, "temporary failure in name resolution"),
		strings.Contains(s, "network is unreachable"):
		return fmt.Sprintf("the target cannot reach the package source (step: %s). "+
			"An air-gapped or egress-filtered host needs the engine installed by other means.", cmd)
	case strings.Contains(s, "could not get lock"), strings.Contains(s, "unable to acquire the dpkg frontend lock"):
		return "another package operation is running on the target; retry once it finishes."
	}
	return fmt.Sprintf("step failed (exit %d): %s", code, cmd)
}

// InstallResult reports what happened.
type InstallResult struct {
	Engine    string   `json:"engine"`
	OK        bool     `json:"ok"`
	Installed bool     `json:"installed"` // verified present afterwards
	Output    []string `json:"output"`
	Error     string   `json:"error,omitempty"`
}

// Install runs the recipe on the target. The caller is responsible for having
// checked the capability and written the audit record — this function does the
// work, not the authorization.
func Install(ctx context.Context, r exec.Runner, id, osFamily string) InstallResult {
	res := InstallResult{Engine: id}

	plan := PlanInstall(id, osFamily)
	if !plan.Supported {
		res.Error = plan.Reason
		return res
	}
	var eng Engine
	for _, e := range All() {
		if e.ID() == id {
			eng = e
		}
	}
	if eng == nil {
		res.Error = "unknown engine " + id
		return res
	}
	if r.Has(ctx, eng.Binary()) {
		res.OK, res.Installed = true, true
		res.Output = append(res.Output, eng.Binary()+" is already installed")
		return res
	}
	if !r.Target().UseSudo {
		res.Error = "installation needs root: configure this target with -sudo, or install manually"
		return res
	}

	// trivy-image installs the trivy binary; alias to its recipe.
	recipeID := id
	if recipeID == "trivy-image" {
		recipeID = "trivy"
	}
	for _, step := range installRecipes[recipeID][osFamily] {
		argv := append([]string{"sudo", "-n"}, step...)
		out := r.Run(ctx, argv...)
		line := fmt.Sprintf("$ %s\n%s", strings.Join(step, " "),
			strings.TrimSpace(out.Stdout+"\n"+out.Stderr))
		res.Output = append(res.Output, strings.TrimSpace(line))
		if !out.OK() {
			res.Error = explainFailure(out.Stderr, step, out.ExitCode)
			return res
		}
	}

	// Verify rather than assume: a recipe that "succeeded" without producing a
	// working binary is a failure, and reporting otherwise would be exactly the
	// dishonesty this product is built to avoid.
	res.Installed = r.Has(ctx, eng.Binary())
	res.OK = res.Installed
	if !res.Installed {
		res.Error = "commands completed but " + eng.Binary() + " is still not on PATH"
	}
	return res
}
