package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/core/exec"
	"github.com/jchirayath/secscan/internal/core/finding"
)

// ---------------------------------------------------------------- TrivyImage

// TrivyImage scans the contents of the images that are actually running.
//
// The Containers collector answers "how is this container run?" — privileged,
// docker.sock mounted, host netns. This answers the other half: "what is inside
// it?". They are genuinely different failures. A container can be perfectly
// confined and still be serving a five-year-old OpenSSL, and `trivy rootfs /`
// on the host never sees it: the vulnerable packages live in image layers the
// host package manager knows nothing about.
//
// Scope is deliberately the running set, not every image on disk. A pulled but
// unused image is not attack surface, and ranking it alongside things serving
// traffic is how a CVE list stops being read.
type TrivyImage struct{}

func (TrivyImage) ID() string     { return "trivy-image" }
func (TrivyImage) Binary() string { return "trivy" }
func (TrivyImage) InstallHint() string {
	return "https://aquasecurity.github.io/trivy — `brew install trivy` or the distro package (same binary as the `trivy` engine)"
}

// maxImages bounds the work.
//
// Image scanning is not like the other engines: every image is unpacked and
// analysed layer by layer, and a handful of fat application images turns a
// two-minute scan into a twenty-minute one. A scan that takes twenty minutes
// gets run monthly instead of nightly, and that costs more coverage than the
// images we skip.
//
// Ten is the point where the marginal image is usually a sidecar rather than a
// service. When the cap bites it is reported as a finding — see coverageNote.
// Truncating quietly would let an operator read "no image CVEs" off a scan that
// never looked, which is the one failure mode this codebase treats as
// unforgivable.
const maxImages = 10

func (t TrivyImage) Run(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, error) {
	fs, _, err := t.RunPartial(ctx, r, a)
	return fs, err
}

// RunPartial is Run plus the running images it did not get to (past the cap)
// or could not read, so the store keeps those images' findings open rather
// than declaring them fixed.
func (t TrivyImage) RunPartial(ctx context.Context, r exec.Runner, a *finding.Asset) ([]finding.Finding, []string, error) {
	now := clock.Now()

	// Both dependencies fail as errors rather than as an empty result, so
	// RunAll renders them as "did not run, because X". A "found 0" from an
	// engine that never obtained a container list is a lie the operator has no
	// way to detect.
	if !r.Has(ctx, "docker") {
		return nil, nil, fmt.Errorf("docker is not installed on the target, so no running images could be enumerated")
	}
	ps := r.Run(ctx, "docker", "ps", "-q")
	if ps.Err != nil {
		return nil, nil, ps.Err
	}
	if !ps.OK() {
		return nil, nil, fmt.Errorf("docker is present but not queryable (daemon down, or the scan account lacks socket access): %s",
			firstLine(ps.Stderr))
	}

	// `docker ps -q` returns container IDs, and `docker inspect` resolves each
	// to its image. Both are commands a least-privilege scan account is
	// normally granted (the Containers collector uses exactly these two);
	// `docker ps --format ...` is a different command string and gets denied by
	// an exact-match sudoers allow-list, which is how this check silently
	// produced nothing on a correctly-hardened host.
	//
	// Ten containers commonly share one image; scanning it ten times is ten
	// times the runtime for identical output.
	images := resolveImages(ctx, r, ps.Stdout)
	if len(images) == 0 {
		return nil, nil, nil // nothing running — a real, honest zero
	}

	var out []finding.Finding
	scanned := images
	var notCovered []string
	if len(scanned) > maxImages {
		notCovered = append(notCovered, images[maxImages:]...)
		scanned = scanned[:maxImages]
		out = append(out, coverageNote(a, now, images, scanned))
	}

	var failed []string
	for _, img := range scanned {
		fs, err := t.scanImage(ctx, r, a, now, img)
		if err != nil {
			// One unreadable image must not cost the findings from the other
			// nine — but it must not vanish either, so it is collected here and
			// reported as its own finding below.
			failed = append(failed, fmt.Sprintf("%s — %v", img, err))
			notCovered = append(notCovered, img)
			continue
		}
		out = append(out, fs...)
	}
	if len(failed) > 0 {
		out = append(out, failureNote(a, now, failed))
	}
	return out, notCovered, nil
}

// scanImage runs Trivy against one image and converts the report to findings.
func (t TrivyImage) scanImage(ctx context.Context, r exec.Runner, a *finding.Asset, now time.Time, image string) ([]finding.Finding, error) {
	// --ignore-unfixed is the deliberate tradeoff in this engine.
	//
	// An image CVE with no published fix is not something the operator can act
	// on: they cannot patch a package upstream has not patched, and rebuilding
	// the image changes nothing. Including those entries typically triples the
	// list — base images carry a long tail of unfixed low-impact CVEs — and
	// buries the ones that a `docker pull` and a restart would actually close.
	//
	// The cost is real and worth naming: an unfixed CRITICAL in a reachable
	// service is still a genuine risk, and this engine will not report it. That
	// class of finding belongs to mitigation and exposure reduction rather than
	// patching, which is a different workflow; the host-level `trivy` engine,
	// which does not pass this flag, still surfaces unfixed CVEs for anything
	// installed outside a container.
	res := r.Run(ctx, "trivy", "image", "--quiet", "--scanners", "vuln",
		"--format", "json", "--severity", "CRITICAL,HIGH", "--ignore-unfixed", image)
	if res.Err != nil {
		return nil, res.Err
	}
	body := strings.TrimSpace(res.Stdout)
	if body == "" {
		return nil, fmt.Errorf("no output (exit %d): %s", res.ExitCode, firstLine(res.Stderr))
	}

	var rep trivyReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}

	// Deduplication is on CVE-within-image, not on the finding fingerprint.
	//
	// The fingerprint includes the component, so a CVE affecting two copies of
	// the same library at different paths or versions inside one image produced
	// two findings — which surfaced as "axios ×2, both in
	// louislam/uptime-kuma:1.23.17" and reads as a bug.
	//
	// Image-scoped is the right grain because the remediation is image-scoped:
	// one rebuild clears every copy, so two rows are two pieces of reading for
	// one piece of work. The same CVE in a DIFFERENT image stays separate —
	// that is genuinely a second thing to rebuild. Affected packages are still
	// listed in the evidence.
	seen := map[string]bool{}
	pkgsFor := map[string][]string{}
	var out []finding.Finding

	for _, result := range rep.Results {
		for _, v := range result.Vulnerabilities {
			title := v.Title
			if title == "" {
				title = fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName)
			}
			f := finding.New(a.ID, finding.CatContainer, severityFrom(v.Severity),
				"container.image-cve."+strings.ToLower(v.VulnerabilityID), title, now)
			f.Description = imageDescription(v.Description, image, v.PkgName)
			f.Subcategory = "image"
			f.Engine = t.ID()
			f.CVE = []string{v.VulnerabilityID}
			for _, c := range v.CVSS {
				if c.V3Score > f.CVSS {
					f.CVSS = c.V3Score
				}
			}
			if v.PrimaryURL != "" {
				f.References = []string{v.PrimaryURL}
			}
			f.Evidence = []finding.Evidence{{
				Command: res.Command,
				Output: fmt.Sprintf("%s: %s %s → fixed in %s (%s in image %s)",
					v.VulnerabilityID, v.PkgName, v.InstalledVersion,
					orNone(v.FixedVersion), result.Target, image),
			}}
			// No Command on the remediation on purpose. The honest fix depends
			// on how the image is produced: `docker pull` only helps a mutable
			// tag, a digest-pinned deployment needs the pin moved, and a
			// locally-built image needs a rebuild against a fresher base. A
			// generated one-liner would be wrong in two of those three cases,
			// and a wrong remediation is worse than none.
			// The Summary is scoped to the IMAGE, not the package, and that is
			// deliberate on two counts. First it is what an operator actually
			// does: you cannot apt-upgrade inside a running container, you
			// rebuild or re-pull the image and recreate the containers — one
			// action clears every CVE in it. Second, the remediation summary is
			// the key the posture score and the remediation plan group on, so a
			// per-package summary would make 800 CVEs behind a single rebuild
			// look like 800 separate pieces of work.
			//
			// The specific package and fixed version are not lost — they are in
			// Component and in the evidence, where the detail belongs.
			f.Remediation = finding.Remediation{
				Op:      "apply_patch",
				Summary: fmt.Sprintf("Rebuild or re-pull image %s, then recreate the containers using it", image),
			}

			// A kernel package inside a container image does not describe the
			// kernel that runs. Containers are namespaces over the HOST kernel,
			// so linux-libc-dev at 6.12.69 in an image tells you what headers
			// were available when it was built, not what the workload executes.
			// The host's actual kernel is assessed separately, by the patch
			// collector, against the version it is really running.
			//
			// This is re-rated rather than dropped. Suppressing it would hide a
			// real base-image staleness signal, and a scanner that silently
			// discards findings cannot be checked. It is demoted to
			// informational, with the reason attached, so it stops competing for
			// attention with vulnerabilities that can actually be reached.
			//
			// On one real host this single rule covered 53% of all container
			// findings — the difference between a list an operator reads and one
			// they give up on.
			if kernelPackage(v.PkgName) {
				f.Severity = finding.SevInfo
				f.Description = "Not exploitable through this image: " + v.PkgName +
					" is a kernel package, and a container does not run its own kernel — it " +
					"shares the host's. This version reflects the base image's age, not the " +
					"running kernel, so it is reported for base-image hygiene rather than as " +
					"an exposure. The host's real kernel is checked separately by the patch " +
					"collector.\n\n" + f.Description
			}

			comp := finding.Component{Name: v.PkgName, Version: v.InstalledVersion, FixedVersion: v.FixedVersion}
			f = f.WithLocation(image, comp)
			dedupeKey := image + "|" + v.VulnerabilityID
			pkgsFor[dedupeKey] = append(pkgsFor[dedupeKey],
				fmt.Sprintf("%s %s → %s", v.PkgName, v.InstalledVersion, orNone(v.FixedVersion)))
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true
			out = append(out, f)
		}
	}
	// Fold every affected package into the surviving finding, so the collapse
	// above loses nothing an operator would want.
	for k := range out {
		if len(out[k].CVE) == 0 {
			continue
		}
		key := image + "|" + out[k].CVE[0]
		if pkgs := pkgsFor[key]; len(pkgs) > 1 {
			out[k].Evidence = append(out[k].Evidence, finding.Evidence{
				Command: "trivy image " + image,
				Output: fmt.Sprintf("affects %d packages in this image:\n%s",
					len(pkgs), strings.Join(pkgs, "\n")),
			})
		}
	}

	return out, nil
}

// imageDescription states the consequence in the operator's terms. Trivy's own
// text describes the flaw in the library; what the reader needs first is that
// the flaw is running on their host right now, inside something they may
// believe is isolated.
func imageDescription(trivyDesc, image, pkg string) string {
	lead := fmt.Sprintf("The running image %s ships a vulnerable %s, and a fixed version exists. "+
		"Container isolation does not protect the process inside the container — anything that reaches "+
		"the service reaches this package. The image must be rebuilt or re-pulled; patching the host "+
		"does nothing, because this package came from an image layer.", image, pkg)
	if d := strings.TrimSpace(trivyDesc); d != "" {
		return lead + "\n\n" + d
	}
	return lead
}

// coverageNote reports that the cap truncated the scan.
//
// This is emitted as a finding rather than logged, because the operator reads
// findings and does not read logs. Severity is informational: incomplete
// coverage is not a vulnerability, it is a statement about what this scan can
// and cannot be used to conclude.
func coverageNote(a *finding.Asset, now time.Time, all, scanned []string) finding.Finding {
	skipped := all[len(scanned):]
	f := finding.New(a.ID, finding.CatContainer, finding.SevInfo,
		"container.image-scan-truncated",
		fmt.Sprintf("Image scanning covered %d of %d running images", len(scanned), len(all)), now)
	f.Description = fmt.Sprintf("This host runs %d distinct container images and image scanning is capped at %d "+
		"per scan to keep the run time usable. The %d image(s) not scanned have not been cleared — nothing is "+
		"known about their contents. Treat the container findings from this scan as partial coverage.",
		len(all), maxImages, len(skipped))
	f.Subcategory = "image"
	f.Engine = TrivyImage{}.ID()
	f.Evidence = []finding.Evidence{{
		Command: "docker ps -q + docker inspect",
		Output: fmt.Sprintf("scanned: %s\nnot scanned: %s",
			strings.Join(scanned, ", "), strings.Join(skipped, ", ")),
	}}
	f.Remediation = finding.Remediation{Op: "manual",
		Summary: "Scan the remaining images out of band: `trivy image --severity CRITICAL,HIGH --ignore-unfixed <image>`"}
	return f.WithLocation("container-images", finding.Component{})
}

// failureNote reports the images Trivy could not read. Same reasoning as
// coverageNote: an image that failed to scan is not an image with no CVEs, and
// only the finding list is in a position to say so.
func failureNote(a *finding.Asset, now time.Time, failed []string) finding.Finding {
	f := finding.New(a.ID, finding.CatContainer, finding.SevInfo,
		"container.image-scan-failed",
		fmt.Sprintf("%d running image(s) could not be scanned", len(failed)), now)
	f.Description = "Trivy failed on these images, so their contents are unknown rather than clean. The usual " +
		"causes are a private registry Trivy cannot authenticate to, an image no longer present locally, or a " +
		"vulnerability database that could not be fetched on an egress-filtered host."
	f.Subcategory = "image"
	f.Engine = TrivyImage{}.ID()
	f.Evidence = []finding.Evidence{{Output: strings.Join(failed, "\n")}}
	f.Remediation = finding.Remediation{Op: "manual",
		Summary: "Run `trivy image <image>` on the host to see the underlying error, then re-scan"}
	return f.WithLocation("container-images", finding.Component{})
}

// resolveImages turns container IDs into the deduplicated, sorted set of image
// references they run.
func resolveImages(ctx context.Context, r exec.Runner, idList string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range strings.Fields(idList) {
		res := r.Run(ctx, "docker", "inspect", id)
		if !res.OK() {
			continue
		}
		var insp []struct {
			Config struct {
				Image string `json:"Image"`
			} `json:"Config"`
		}
		if err := json.Unmarshal([]byte(res.Stdout), &insp); err != nil || len(insp) == 0 {
			continue
		}
		img := strings.TrimSpace(insp[0].Config.Image)
		if img == "" || seen[img] {
			continue
		}
		seen[img] = true
		out = append(out, img)
	}
	sort.Strings(out) // stable truncation choice across runs
	return out
}

// kernelPackage reports whether a package name is the kernel or its headers.
//
// The list is prefix-based because distributions version the name itself
// (linux-headers-6.12.69-1, kernel-devel-5.14), so an exact-match set would go
// stale on the next point release and silently stop matching — the failure mode
// being that findings quietly return to HIGH with no indication why.
//
// Deliberately NOT matched: userspace libraries whose names merely start with
// "lib", and packages like "linux-firmware", which ships blobs the host loads.
func kernelPackage(pkg string) bool {
	p := strings.ToLower(strings.TrimSpace(pkg))
	for _, prefix := range []string{
		"linux-libc-dev", // Debian/Ubuntu: kernel headers for userspace builds
		"linux-headers",
		"linux-image",
		"linux-kernel",
		"kernel-headers", // RHEL/Fedora family
		"kernel-devel",
		"kernel-core",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	// Alpine names the package plainly.
	return p == "linux" || p == "kernel"
}
