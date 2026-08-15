# Interpreting secscan results

A scanner that produces numbers nobody can explain gets ignored. This page
explains every number secscan shows, and — just as important — what each one
does **not** mean.

---

## Read this section first: what did not run

Every scan ends with a **Not run** list. A check that could not execute is
reported with its reason; it is never silently dropped.

```
Not run (1):
  testssl — engine not installed on the target
```

This matters more than any individual finding. **"Found nothing" and "never
looked" are different answers**, and a tool that renders them identically is
lying to you. If a check is missing, the correct reading is "unknown", not
"clean".

The same rule applies to the trend view: it plots coverage alongside the score,
because a score that improved because a check stopped running is not an
improvement.

---

## Severity vs. risk — they are not the same

| Column | What it is |
|---|---|
| **Severity** | How bad this class of problem is, in general |
| **Residual risk** | How bad *this instance* is, here, after everything secscan verified |

Ranking uses residual risk. Two identical CVEs can sit far apart in the list
because one is reachable from the internet and the other is on a loopback socket
behind a firewall.

### How the number is built

```
inherent risk  =  base(severity) × (1 + 2·EPSS) × KEV(2.0) × exposed(1.5) × critical_asset(1.3)
residual risk  =  inherent risk × mitigation_factor
```

Every multiplier that applied is listed on the finding page. *"Why is this at the
top?"* always has an answer you can read.

- **EPSS** — probability the vulnerability is exploited in the wild
- **KEV** — it is in CISA's Known Exploited Vulnerabilities catalogue: it is not
  theoretical, it is being used
- **exposed** — *verified* reachable from outside, not merely bound to `0.0.0.0`
- **critical asset** — you marked the target `-critical`

---

## Exposure is tested, not assumed

A socket on `0.0.0.0` is only *potentially* exposed. secscan probes each
wide-bound port from outside the host and reclassifies it:

| Verdict | Meaning | Effect on the finding |
|---|---|---|
| **exposed** | TCP connect succeeds and content is served anonymously | ×1.5 |
| **behind authentication** | reachable, but anonymous requests get 401/403 or bounce to an identity provider | severity down one step |
| **blocked upstream** | TCP connect fails — a firewall or cloud security group drops it | dropped to `info`, exposure cleared |

Where a host serves several names, each is probed separately. A reverse proxy
routes by `Host` header, so probing the IP alone reaches only the default vhost —
which is how a protected site gets scored as wide open. Declare the names with
`-vhosts`.

**What this does not prove:** the probe runs from wherever secscan runs. "Blocked
upstream" means blocked *from here*. If your scanner sits inside the same VPC as
the target, it says nothing about the internet.

---

## Compensating controls

Where a control is verified active, it reduces risk rather than clearing the
finding:

```
inherent 8.4  →  ×0.4 controls  →  residual 3.4
```

Each control states what it does **not** cover, and that limitation is shown
every time:

> **fail2ban (SSH brute-force protection)** — rate-limits repeated failed logins.
> Does not cover: a vulnerability in sshd itself, a stolen or leaked private key,
> a valid credential obtained elsewhere, or a slow distributed guessing attack
> below the ban threshold.

Three rules keep this honest:

1. **Controls reduce risk; they never clear it.** The reduction is capped —
   nothing drops below a floor.
2. A control counts only if it is **verified running and scoped to that service**.
   An installed-but-inactive fail2ban mitigates nothing.
3. The **inherent** figure is always shown. That is what the risk returns to if
   the control is removed, fails, or turns out to be misconfigured.

---

## Validation: proved, refuted, or unverified

Where a safe test exists, secscan runs it rather than inferring from a config
file.

| Verdict | Meaning |
|---|---|
| **confirmed** | the condition was demonstrated on the host |
| **refuted** | it was tested and does not hold — risk ×0.25, kept visible |
| **unverified** | no safe test exists, or the test could not run |

Validators are non-destructive, never attempt authentication with a guessed
credential, and run **unprivileged** — the question is "can an ordinary local
user do this?", so a test that quietly ran under sudo would answer a different
question and get the verdict wrong in both directions.

**Absence of proof is never recorded as proof of absence.** A test that could not
run yields `unverified`, not `refuted`.

---

## The posture score

A single 0–100 number, higher is better.

```
penalty  = Σ per-finding weight, grouped by remediation action, with diminishing returns
score    = 100 / (1 + penalty/40)
```

The grouping is the important part. 800 CVEs cleared by one `docker pull` are
**one piece of work**, not 800, so the first finding in a group costs full weight
and the rest decay. Without that, a host with 900 container CVEs and a host with
3,000 both score ~0 and the number stops distinguishing anything.

### Known limitation — read this before tracking the score

**The curve compresses badly at the low end.** On a host with a large backlog,
clearing most of the outstanding work barely moves the number:

| Work done | Score |
|---|---|
| starting point | 5.0 |
| rebuild image 1 (clears 493 findings) | 5.8 |
| + image 2 | 6.7 |
| + image 3 | 7.7 |
| + images 4 and 5 | 10.0 |

That is five rebuilds and ~724 findings cleared to move 5.0 → 10.0. If you are
using the score to judge whether a week of work mattered, it will tell you
almost nothing.

**Track the critical+high count and the trend diff instead.** They move
proportionally to the work. The score is most useful for comparing hosts at a
point in time, and least useful as a progress bar on a host with a big backlog.

---

## Container findings need a second look

Two systematic effects to know about:

**Kernel packages are re-rated.** A container does not run its own kernel — it
shares the host's. So `linux-libc-dev` in an image describes what headers were
available when it was built, not what the workload executes. These are demoted to
**informational** with the reason attached. They are not deleted: base-image
staleness is real, and a scanner that silently discards findings cannot be
checked. On one real host this covered 53% of all container findings.

**"Re-pull the image" often fixes nothing.** The remediation says to rebuild or
re-pull, and for a digest-pinned or already-current tag that is a no-op. Check
before you schedule downtime:

```bash
docker image inspect IMAGE --format '{{index .RepoDigests 0}}'
docker buildx imagetools inspect IMAGE | grep Digest
```

Identical digests mean re-pulling downloads nothing. The real fix is then either
a newer upstream version or a rebuild against a fresher base — and sometimes
upstream has no fix, in which case the honest answer is that the finding stays.

> One caution from practice: moving to a newer major version can *increase* CVE
> count sharply if the new image bundles something large. Check the image size
> and contents before deploying a major bump, and re-scan afterwards to confirm
> the direction of travel.

---

## Provenance

Every API response and dashboard view is labelled:

| Label | Meaning |
|---|---|
| `live` | from this scan |
| `cached` | from stored state |
| `partial` | some collectors could not run |
| `unavailable` | no data yet |
| `demo` | fabricated sample data — **never** a real scan |

The dashboard cannot render stale or demo data without the banner.

---

## A worked reading

```
13.0  CRITICAL  Step CA: unauthenticated certificate issuance via SCEP
```

Ask, in order:

1. **Did the checks run?** Look at Not-run first.
2. **Is it exposed?** Verified reachable, or just bound wide?
3. **What is the inherent vs residual figure?** If they differ, a control is
   doing work — and you should read what that control does not cover.
4. **Was it validated?** `refuted` means tested and not holding.
5. **What is the change-risk of fixing it?** A green fix can go now; amber and
   red need a window and a human.
6. **How many findings does that one action clear?** The Plan page groups by
   action, which is the only view that reflects the work rather than the row
   count.

Steps 1 and 6 are the ones people skip, and they are the two that decide whether
the list is worth reading.
