# Using secscan

Everything the dashboard can show, the CLI can produce, and vice versa. They
read the same state and neither is a second-class citizen.

```
secscan scan [name...]    scan targets;  -report FILE writes a Markdown assessment
secscan serve             start the web dashboard
secscan targets           list targets;  targets add <name> [user@host] [-key F] [-sudo] [-critical]
secscan plan [name]       remediation plan;  -script to emit a shell script
secscan trend [name]      posture over time from snapshots;  -diff to compare the last two
secscan fix [target]      classify fixes by change-risk;  -apply runs the green ones
secscan config            print resolved configuration;  -example emits a .env template
secscan version
```

> Scan only systems you own or are authorised to test. The web engines send real
> traffic to live services.

---

## Targets

```bash
secscan targets add web01 scan@web01.example.net -key ~/.ssh/id_ed25519
secscan targets add db01  scan@db01.example.net  -key ~/.ssh/id_ed25519 -sudo -critical
secscan targets add local                        # the machine secscan runs on
secscan targets
secscan targets rm web01
```

`add` is an **upsert**: re-running it with an existing name replaces that target
in place and prints `updated target` rather than `added target`. That is how you
edit a target — there is no `targets edit`. Flags come from the new invocation,
so repeat any you still want:

```bash
secscan targets add web01 scan@10.0.0.9 -key ~/.ssh/id_ed25519 -sudo -critical
```

`rm` removes **every** entry with the given name.

| Flag | Effect |
|---|---|
| `-key FILE` | SSH private key for this target |
| `-sudo` | allow `sudo -n` for the small set of checks that need it |
| `-critical` | mark the asset business-critical — multiplies risk by 1.3 |

### Virtual hosts

A reverse proxy routes by `Host` header, so probing an IP only ever reaches the
default virtual host. Every other site on that port is invisible to the exposure
check — and a name-based vhost sitting behind an identity provider gets scored as
a wide-open port when it is actually protected.

List the names a host answers for so each is probed properly:

```bash
secscan targets add web01 scan@web01.example.net -vhosts app.example.net,status.example.net
```

---

## Scanning

```bash
secscan scan                       # every configured target
secscan scan web01                 # one target
secscan scan web01 -no-engines     # native collectors only — fast, no external tools
secscan scan web01 -report out.md  # also write a Markdown assessment
secscan scan web01 -json           # full result as JSON, for piping
```

A scan prints the posture score, severity counts, the highest-risk findings, the
new/fixed delta since last run, and — importantly — a **Not run** section.

**Read the Not-run section first.** A check that did not execute is reported
with its reason, never silently omitted. A score that improved because a check
stopped running is not an improvement, and this is the only way to tell the
difference.

### Choosing which checks run

`nuclei` and `testssl.sh` are off by default: they take minutes per endpoint and
send real traffic to live services. Enable them in the dashboard's **Checks**
page, or run without engines entirely using `-no-engines`.

---

## The dashboard

```bash
SECSCAN_AUTH_MODE=local SECSCAN_BIND=127.0.0.1:8788 secscan serve
```

| Page | Answers |
|---|---|
| **Overview** | Score, exposure, and findings by category. Click any tile to drill in. |
| **Assets** | Per-host posture. |
| **Plan** | Findings collapsed into the minimum ordered set of actions. |
| **Trend** | Posture over time, with coverage plotted alongside it. |
| **Checks & results** | Every check, whether it ran, what it found, and the raw command output behind it. |
| **Checks** | Turn expensive engines on and off. |
| **Audit** | Who did what, with role and source address. |

Every finding page shows the risk factors that produced its ranking, the raw
evidence, any compensating controls, and — where a reviewed fix exists — the
change-risk of applying it.

---

## Reports

```bash
secscan scan web01 -report assessment.md
secscan plan                       # ordered remediation plan
secscan plan -script > fix.sh      # emit a reviewed shell script — read it before running
```

`-script` writes commands for a human to review and run. It is not executed for
you; see **Remediation** below for what secscan will and will not run itself.

---

## Trend

Every scan writes a compressed snapshot of all findings plus which checks ran.

```bash
secscan trend            # posture over time
secscan trend -diff      # what changed between the last two scans
secscan scan -snapshot-dir /mnt/backup/secscan-snapshots
secscan scan -no-snapshot
```

The diff names findings that appeared and cleared, and separately reports
**coverage lost** — checks that ran in the earlier snapshot but not the later
one. A posture can improve because a problem was fixed or because the check that
found it stopped running, and only one of those is good news.

Snapshots are written `0700` and gzipped. They contain every finding for a host,
which is a map of its weaknesses — treat them as sensitive.

---

## Remediation

secscan can apply a small set of fixes, and refuses to apply the rest. The
distinction is **change-risk**: how bad it would be if the *fix* went wrong,
which is a different question from how severe the finding is.

A CRITICAL finding can have a trivial fix (send a header). A LOW one can have a
fix that locks you out of the machine you are fixing (`sshd_config`, firewall
rules, PAM).

| Flag | Meaning | Runs? |
|---|---|---|
| 🟢 **green** | reversible, idempotent, no restart, cannot affect the path that keeps you able to reach and repair the host | yes |
| 🟠 **amber** | restarts a service, changes behaviour for everyone, or can break an app that depended on the old setting | no |
| 🔴 **red** | can remove your own access, is hard to reverse, or needs a reboot | no |

```bash
secscan fix                 # classify every open finding, grouped by fix
secscan fix -dry-run        # show the exact steps for green fixes, run nothing
secscan fix -sudoers        # print the exact sudoers entries the green fixes need
secscan fix -apply          # run the green fixes
```

Amber and red are not "run with a warning" — they are not runnable at all, from
the CLI or the API. Applying them is a human job, done with a console open.

### What running a fix actually does

```
canary → backup → apply → canary → verify → rollback-on-failure
```

The second canary is the one that earns its place: if a fix cost you the host,
you find out while you are watching, not at the next scan. **Verification tests
the condition on the host** — mirroring the check that raised the finding — not
the exit code of the fix, which only tells you the command ran.

Fixes come from a hand-written catalogue. Nothing is generated from a finding's
own remediation text: generating shell from a finding and running it as root is
how a scanner becomes the incident.

### Privilege for fixes

Apply and rollback steps run under `sudo -n`; **backup and verify never do.**
Verification is stronger from the same vantage point the original check had — a
verify that only passes as root proves nothing about what an ordinary account
can still see.

`secscan fix -sudoers` generates exact-match sudoers lines, resolving each
binary's absolute path on the target. Review them, validate with
`visudo -c -f`, then install. No wildcard is ever emitted.

### From the dashboard

Finding pages show the change-risk badge, the full plan, and — for green fixes,
to holders of the `remediate.apply` capability (admin only) — **Dry run** and
**Apply** buttons. Applying requires explicit confirmation and is audited before
and after, so a run that hangs still leaves a record of what was started and by
whom.

---

## Accepting a risk

Findings you have consciously accepted can be suppressed with a reason and an
expiry. Suppression is a first-class, audited action — not a delete. The finding
stays visible with its justification, and returns when the suppression lapses.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | completed |
| `1` | an error occurred (scan failure, persistence failure, a fix that failed) |

Next: [INTERPRETING-RESULTS.md](INTERPRETING-RESULTS.md)
