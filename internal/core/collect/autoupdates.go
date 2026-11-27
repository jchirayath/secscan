package collect

import (
	"context"
	"regexp"
	"strings"

	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// Unattended security upgrades, detected as a compensating control.
//
// The catalogue has always offered "auto-updates" as a mitigation for pending
// patches, but nothing detected it, so Recommend suggested turning it on even
// on hosts where it was running. Same rule as every other control: configured
// AND able to run. A "1" in apt's config with the package removed, or with the
// systemd timer masked, applies nothing.

var aptUnattendedRe = regexp.MustCompile(`(?m)^\s*APT::Periodic::Unattended-Upgrade\s+"([^"]*)"\s*;`)

// aptUnattendedEnabled reports whether apt config text turns unattended
// upgrades on. apt treats any non-zero value as "run every N days"; the last
// assignment wins, as it does in apt.
func aptUnattendedEnabled(cfg string) bool {
	m := aptUnattendedRe.FindAllStringSubmatch(cfg, -1)
	if len(m) == 0 {
		return false
	}
	v := strings.TrimSpace(m[len(m)-1][1])
	return v != "" && v != "0"
}

const aptAutoUpgradesFile = "/etc/apt/apt.conf.d/20auto-upgrades"

// aptUnattendedConfig returns apt's EFFECTIVE setting when apt-config can say,
// so an override in a later apt.conf.d file counts; otherwise the usual file.
func aptUnattendedConfig(ctx context.Context, r exec.Runner) (cfg, source string, ok bool) {
	if res := r.Run(ctx, "apt-config", "dump", "APT::Periodic::Unattended-Upgrade"); res.OK() {
		return res.Stdout, res.Command, true
	}
	cfg, ok = r.ReadFile(ctx, aptAutoUpgradesFile)
	return cfg, aptAutoUpgradesFile, ok
}

// timerInactive is true only when systemd positively reports the timer not
// active. No systemctl (containers, non-systemd hosts) is not evidence either way.
func timerInactive(ctx context.Context, r exec.Runner, unit string) bool {
	if !r.Has(ctx, "systemctl") {
		return false
	}
	return !r.Run(ctx, "systemctl", "is-active", "--quiet", unit).OK()
}

func detectAutoUpdates(ctx context.Context, r exec.Runner) (Control, bool) {
	ctl := func(detail, cmd, out string) Control {
		return Control{
			ID: "auto-updates", Name: "Unattended security upgrades",
			Detail: detail, Factor: 0.8,
			Covers: []string{"patch.updates-pending"},
			Limits: "Closes known vulnerabilities only, and only after the vendor ships a fix. " +
				"It does not update container images, language packages or anything installed outside the package manager.",
			Evidence: finding.Evidence{Command: cmd, Output: out},
		}
	}

	// Debian / Ubuntu.
	if cfg, src, ok := aptUnattendedConfig(ctx, r); ok && aptUnattendedEnabled(cfg) {
		if !r.Has(ctx, "unattended-upgrade") {
			return Control{}, false
		}
		if timerInactive(ctx, r, "apt-daily-upgrade.timer") {
			return Control{}, false
		}
		return ctl("unattended-upgrades is installed, enabled in apt, and its timer is active",
			src, strings.TrimSpace(cfg)), true
	}

	// RHEL family. dnf-automatic-install.timer always applies; the plain
	// dnf-automatic.timer only downloads unless apply_updates is set.
	if r.Has(ctx, "systemctl") {
		if res := r.Run(ctx, "systemctl", "is-active", "--quiet", "dnf-automatic-install.timer"); res.OK() {
			return ctl("dnf-automatic-install.timer is active", res.Command, "active"), true
		}
		if res := r.Run(ctx, "systemctl", "is-active", "--quiet", "dnf-automatic.timer"); res.OK() {
			if conf, ok := r.ReadFile(ctx, "/etc/dnf/automatic.conf"); ok && dnfAppliesUpdates(conf) {
				return ctl("dnf-automatic.timer is active with apply_updates = yes",
					"/etc/dnf/automatic.conf", "apply_updates = yes"), true
			}
		}
	}
	return Control{}, false
}

var dnfApplyRe = regexp.MustCompile(`(?mi)^\s*apply_updates\s*=\s*(yes|true|1|on)\s*$`)

func dnfAppliesUpdates(conf string) bool { return dnfApplyRe.MatchString(conf) }
