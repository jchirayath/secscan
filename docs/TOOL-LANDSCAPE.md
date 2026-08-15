# Tool landscape — what already exists, and what we should not rebuild

Research date: **2026-08-09**. Licenses noted because this project ships as open
source; re-verify each at integration time (several projects have relicensed
in the last three years).

The question this document answers: *for each layer of a full posture
assessment, is there already an open-source engine good enough that writing our
own would be a waste?*

---

## 1. The three candidate strategies

| | What it means | Cost to reach coverage | Ongoing cost | Verdict |
|---|---|---|---|---|
| **A. Fully custom** | Write our own CVE matching, port scanner, check engine, feeds | Months | We own vuln-feed accuracy forever — the hardest, least differentiated work in security tooling | ❌ |
| **B. Deploy existing platforms** | Stand up Wazuh + Greenbone/OpenVAS + DefectDojo, write glue | Days | Three UIs, ~16 GB RAM, heavy agents; it's a *deployment*, not a project | ❌ as the product |
| **C. Hybrid orchestrator** | Custom core owns the model, correlation, scoring and dashboard; shells out to best-in-class engines as pluggable adapters | Weeks | Adapters break occasionally when engine output changes — cheap, contained | ✅ **chosen** |

The reason C wins is a clean split of concerns:

- **Commodity, and expensive to maintain:** vulnerability feeds, CVE↔package
  matching, 10k+ web templates, TLS cipher logic, CIS rule content. Trivy,
  Grype, OSV, Nuclei, Lynis and OpenSCAP already do this and update daily. We
  will never beat them, and every hour spent trying is an hour not spent on the
  part users actually see.
- **Genuinely missing, and where the value is:** a *single* normalized finding
  model across all those engines, cross-engine dedup, exposure-aware risk
  scoring (is this vulnerable package actually reachable?), a remediation plan,
  posture trend over time, and a drill-down dashboard a non-specialist can read.
  Every existing OSS tool hands you a wall of raw findings in its own format.

So: **we do not write scanners. We write the thing that makes many scanners
usable.**

---

## 2. Layer-by-layer

### 2.1 Host OS vulnerabilities & missing patches

| Tool | License | Notes |
|---|---|---|
| **Trivy** | Apache-2.0 | `trivy rootfs /` covers OS packages *and* language deps, secrets, and IaC misconfig in one binary. Broadest single-tool coverage. Chosen as **primary**. |
| **Grype** (+ **Syft**) | Apache-2.0 | Curated `grype-db`, precise version matching, low false positives, ~30–40% faster on pure vuln matching. Independent DB from Trivy → running both widens real coverage. Chosen as **second opinion**. |
| **Vuls** | GPL-3.0 | Agentless over SSH, parses changelogs and distro OVAL to answer *"is a fix actually available?"* — a question Trivy answers less directly. Optional deep mode. |
| **osv-scanner** | Apache-2.0 | Google's OSV database, language-ecosystem focused. Good third signal for app deps. |
| **Wazuh** | GPL-2.0 | Agent collects packages, compares to CVE feeds. Excellent, but pulls in an entire SIEM (manager + indexer + dashboard, 8 vCPU / 8–16 GB). Wrong weight class for a standalone scanner. |
| **Greenbone / OpenVAS** | GPL-2.0 | The only OSS peer to Nessus/Qualys for *network-side* authenticated VA — 100k+ NVTs. Heavy (feed sync, gvmd, GSA). Support as an **optional adapter**, not a dependency. |

**Decision:** Trivy primary, Grype for a second opinion on high-value hosts,
Vuls and Greenbone as optional deep-scan adapters.

### 2.2 Host hardening / CIS compliance

| Tool | License | Notes |
|---|---|---|
| **Lynis** | GPL-3.0 | ~300 hardening tests, single shell script, no deps, runs anywhere. Best effort-to-signal ratio. **Primary.** |
| **OpenSCAP** + **SCAP Security Guide** | LGPL-2.1 / BSD-3 | Authoritative CIS/STIG profiles, machine-readable XCCDF/ARF results and a real compliance score. Use where `oscap` is available. **Primary for scored CIS.** |
| **Wazuh SCA** | GPL-2.0 | CIS-derived YAML policies — good content, but coupled to the agent. Worth mining the policy content for our own pack. |
| **CIS-CAT Pro** | Commercial | Not free. Out of scope. |
| **mSCP** (`usnistgov/macos_security`) | Public domain | NIST/CIS macOS baselines as YAML → audit scripts. The right answer *if* macOS targets are added later. |

### 2.3 Network exposure & ports

| Tool | License | Notes |
|---|---|---|
| **Nmap** | **NPSL — not OSI-approved, GPL-incompatible** | Best-in-class, but the license explicitly exists to block bundling into other products. ⚠️ **Never vendor it.** Detect on `PATH`, use if present, document that it's the user's own install. |
| **naabu** | MIT | ProjectDiscovery's fast port scanner. Freely redistributable — our **default** sweeper. |
| `ss -tulpn` / `/proc` | n/a | Our own local collector. Gives what no external scanner can: the listening socket **plus the owning process, user, and bind address**. |

The interesting signal here isn't the port list — it's the **delta**: what binds
`0.0.0.0` internally vs. what actually answers from outside vs. what the router
forwards. That correlation is ours to build (see §3).

### 2.4 Web services, TLS, and outdated libraries

| Tool | License | Notes |
|---|---|---|
| **httpx** | MIT | Probe + tech/version fingerprint. Discovery stage. |
| **Nuclei** | MIT | ~10k community templates: CVEs, exposed panels, default logins, misconfigs, takeovers. The single highest-value web adapter. |
| **testssl.sh** | GPL-2.0 | Thorough TLS/cipher/cert/protocol audit, JSON output. **Primary for TLS.** |
| **sslyze** | AGPL-3.0 | Python-native alternative. AGPL — fine to shell out to, note it. |
| **retire.js** | Apache-2.0 | Detects vulnerable **client-side JS libraries** on a live page and emits an SBOM. Directly answers "web services using old libraries". |
| **OWASP ZAP** | Apache-2.0 | Real active DAST. Heavy and intrusive — opt-in `deep` profile only. |
| **Nikto** | GPL-2.0 | Dated, but cheap breadth on web servers. Optional. |
| **Wappalyzer** | ⚠️ No longer OSS | Relicensed to source-available. **Avoid** — use httpx/Nuclei tech detection instead. |

### 2.5 Containers

| Tool | License | Notes |
|---|---|---|
| **Trivy** (`image`, `config`) | Apache-2.0 | Image CVEs + Dockerfile/Compose misconfig + secrets. **Primary.** |
| **Syft** / **Grype** | Apache-2.0 | One SBOM, two matchers. Second opinion on critical images. |
| **Docker Bench for Security** | Apache-2.0 | CIS Docker Benchmark as a script. Good, but partly stale — mine it, then implement as our own pack for better output. |
| **kube-bench**, **Kubescape** | Apache-2.0 | Only if k8s appears. Deferred. |

Runtime posture (root user, `--privileged`, host network/PID, `docker.sock`
mounted, no resource limits, `:latest` instead of a digest, image age) is a
**custom pack** — it's cheap for us and Trivy doesn't do it.

### 2.6 Identity, accounts & credentials

This is the layer with the most legal and ethical care required, and the least
usable OSS.

| Approach | Tool | Notes |
|---|---|---|
| **Policy audit** (default ON) | ours | `/etc/login.defs`, PAM `pwquality`, password aging, **empty password fields in shadow**, non-root UID-0 accounts, stale/unused accounts, shell assignment, `authorized_keys` perms and key types/ages, `sudoers` `NOPASSWD`, `PermitRootLogin`. Catches most real weakness with zero risk. |
| **SSH config/algorithm audit** (ON) | **ssh-audit** (MIT) | Weak KEX/cipher/MAC, host key type/size, known-bad versions. |
| **Default-credential probe** (opt-in) | **Nuclei** default-login templates; `changeme` (verify license) | Only against declared, owned targets; rate-limited; requires explicit authorization flag. |
| **Offline hash audit** (opt-in, off) | **John the Ripper** (GPL-2.0) | Against a *local* `/etc/shadow` copy only, wordlist mode, never network. Reports "N accounts crack in under X" — never the plaintext. Requires `--i-am-authorized` and is logged. |

**Explicitly out of scope:** online password spraying/brute force against
anything, credential attacks against hosts not in the declared target file.

### 2.7 Secrets

**gitleaks** (MIT) and **Trivy secret** (Apache-2.0) — both permissive, both
good. **trufflehog** (AGPL-3.0) has the best detector set (700+ with live
verification); shell-out only, opt-in.

### 2.8 Aggregation & dashboards

| Tool | License | Notes |
|---|---|---|
| **DefectDojo** | BSD-3 | The gold standard: 200+ parsers, dedup, SLA tracking, compliance mapping. But it's a large Django app aimed at AppSec teams and CI pipelines — not "run this on your box and see your risk". |
| **Faraday** | GPL-3.0 | 80+ tool integrations, built for pentest engagements and live collaboration. Wrong shape for continuous self-assessment. |
| **ArcherySec** | — | Small surface area, less active. |

**Decision:** build our own dashboard — that *is* the user-facing ask — but
**export to DefectDojo, SARIF, and OCSF** so anyone who already runs DefectDojo
can pipe our output in rather than choose between us.

### 2.9 Normalization schema

- **SARIF** (OASIS) — the CI/static-analysis interchange standard. GitHub code
  scanning ingests it. Good for the `ci` profile, weak for infra findings.
- **OCSF** (Linux Foundation) — vendor-neutral schema; since 1.1 it splits
  findings into **Vulnerability Finding**, **Compliance Finding**, **Detection
  Finding**, **Incident Finding** — which maps almost exactly onto our
  categories.

**Decision:** internal model **aligned to OCSF 1.x** finding classes; emit
**both** OCSF and SARIF. Free enrichment feeds: **CISA KEV** (JSON) and
**FIRST EPSS** (API/CSV).

---

## 3. What we build that nothing above does

1. **One model, many engines.** Trivy, Nuclei, Lynis, testssl and ssh-audit all
   emit incompatible shapes. Normalizing them into one severity-comparable
   finding — with stable fingerprints so "new since last scan" works — is real
   work nobody has done for the small-fleet case.
2. **Exposure-aware risk.** A critical CVE in a package bound to `127.0.0.1`
   behind a firewall is not the same risk as one on a port the router forwards
   from the internet. Joining *internal listener map* × *external scan result* ×
   *router port-forward table* × *KEV/EPSS* produces a ranking that raw CVSS
   never will. This is the single best idea in the project.
3. **Remediation plan, not a finding dump.** Group findings into the minimum set
   of actions (`apt upgrade X`, bump this image, close this port, rotate this
   key) ordered by risk cleared per action.
4. **Posture over time.** Score per category, trend line, new vs. fixed vs.
   accepted, with suppressions and VEX-style justifications that survive rescans.
5. **A dashboard a non-specialist can read.** Category tiles → drill to asset →
   drill to finding → raw engine evidence and a concrete fix.
6. **Asset inventory reuse.** `netinventory` already discovers every device on
   this network and scrapes the router. SecurityScanner should consume its
   device list as an asset feed rather than rediscovering the LAN.

---

## Sources

- [Wiz — Best Vulnerability Management Tools 2026](https://www.wiz.io/academy/vulnerability-management/oss-vulnerability-management-tools)
- [eSecurityPlanet — Top Open-Source Vulnerability Scanners](https://www.esecurityplanet.com/networks/open-source-vulnerability-scanners/)
- [Greenbone OpenVAS alternatives, compared](https://www.cybersectool.com/tools/greenbone-openvas/alternatives)
- [TuxCare — 11 Best Open Source Security Tools in 2026](https://tuxcare.com/blog/open-source-security-tools/)
- [TuxCare — Best Linux Vulnerability Scanners 2026](https://tuxcare.com/blog/linux-vulnerability-scanner/)
- [Vuls — agentless vulnerability scanner](https://vuls.io/)
- [Help Net Security — Vuls](https://www.helpnetsecurity.com/2025/05/05/vuls-open-source-agentless-vulnerability-scanner/)
- [Nmap Public Source License](https://nmap.org/npsl/) · [annotated](https://nmap.org/npsl/npsl-annotated.html) · [LWN on the license change](https://lwn.net/Articles/842436/)
- [NIST — macOS Security Compliance Project](https://pages.nist.gov/macos_security/) · [repo](https://github.com/usnistgov/macos_security)
- [Wazuh — Security Configuration Assessment](https://wazuh.com/resources/use-cases/security-configuration-assessment/) · [Platform overview](https://wazuh.com/platform/overview/)
- [DefectDojo — Top 11 Open Source Vulnerability Management Tools for 2026](https://defectdojo.com/blog/top-11-open-source-vulnerability-management-tools-for-2026) · [vs Faraday](https://defectdojo.com/blog/defectdojo-pro-vs-faraday-security-in-2026)
- [Trivy vs Grype 2026](https://lucaberton.com/blog/trivy-vs-grype-2026/) · [Syft vs Trivy](https://appsecsanta.com/sca-tools/syft-vs-trivy)
- [OCSF schema](https://schema.ocsf.io/) · [vulnerability_finding class](https://github.com/ocsf/ocsf-schema/blob/main/events/findings/vulnerability_finding.json)
- [Sonar — complete guide to SARIF](https://www.sonarsource.com/resources/library/sarif/)
- [retire.js](https://github.com/retirejs/retire.js/)
- [OWASP — Testing for Default Credentials](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
- [changeme — default credential scanner](https://github.com/ztgrace/changeme)
