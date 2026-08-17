# Installing secscan

secscan is a single static Go binary with **no runtime dependencies**: no
database, no Node, no Python, no container. Building it needs Go 1.24+ and
nothing else — the module has an empty `require` block and CI fails the build if
a dependency is ever added.

---

## 1. Build from source

```bash
git clone https://github.com/jchirayath/secscan.git
cd secscan
go build -o secscan ./cmd/secscan
./secscan version
```

Cross-compile for the machine you intend to run it on:

```bash
GOOS=linux  GOARCH=amd64 go build -o secscan-linux-amd64  ./cmd/secscan
GOOS=linux  GOARCH=arm64 go build -o secscan-linux-arm64  ./cmd/secscan
GOOS=darwin GOARCH=arm64 go build -o secscan-darwin-arm64 ./cmd/secscan
```

The result is statically linked and runs on any kernel of that architecture —
there is no glibc version to match.

---

## 2. Decide where it runs

secscan scans a target either **locally** (the machine it runs on) or **over
SSH**. It never installs an agent on the target.

| Mode | When to use it | What the target needs |
|---|---|---|
| Local | Scanning the box secscan sits on | nothing |
| SSH | Scanning other hosts from a workstation or a jump box | an SSH account and the standard `ssh` client on *your* side |

SSH transport shells out to your system `ssh` binary rather than vendoring a
crypto stack. That is deliberate: it inherits your existing `known_hosts`, agent,
jump hosts and per-host config — configuration you have already audited — and
keeps the dependency count at zero.

---

## 3. Create a scanning account on the target

**Do not scan as root.** secscan is designed to degrade honestly without
privilege: a check that cannot run is reported as not-run, never as a silent
pass. Most checks work unprivileged.

```bash
# on the target
sudo useradd -m -s /bin/bash scan
sudo mkdir -p /home/scan/.ssh
sudo tee /home/scan/.ssh/authorized_keys < ~/.ssh/id_ed25519.pub
sudo chown -R scan:scan /home/scan/.ssh
sudo chmod 700 /home/scan/.ssh && sudo chmod 600 /home/scan/.ssh/authorized_keys
```

### Optional: a narrow sudoers grant

A few checks read root-only files (`/etc/shadow`, `sshd_config` on distributions
that ship it `0600`) or need process attribution from `ss`. Without them those
checks report "could not run", which is honest but less useful.

Grant **exactly** these commands and nothing more:

```
scan ALL=(root) NOPASSWD: /usr/bin/cat /etc/shadow, \
                          /usr/bin/cat /etc/sudoers, \
                          /usr/bin/cat /etc/sudoers.d/*, \
                          /usr/bin/cat /etc/ssh/sshd_config, \
                          /usr/bin/cat /etc/ssh/sshd_config.d/*, \
                          /usr/bin/ss -tulpnH, \
                          /usr/sbin/nft list ruleset, \
                          /usr/sbin/iptables -S, \
                          /usr/bin/docker ps -q, \
                          /usr/bin/docker inspect *, \
                          /usr/sbin/sshd -T, \
                          /usr/bin/fail2ban-client status, \
                          /usr/bin/fail2ban-client status *
```

Install it safely — `visudo -c` first, always:

```bash
sudo visudo -c -f /tmp/secscan.sudoers && \
sudo install -m 440 /tmp/secscan.sudoers /etc/sudoers.d/secscan
```

> **Never** write `NOPASSWD: ALL`, and never use a wildcard on `sh -c`.
> `/usr/bin/sh -c *` is not a narrower grant than `ALL` — it is the same grant
> spelled longer.

If you later enable remediation, `secscan fix -sudoers` generates the additional
exact-match lines it needs, resolving each binary's absolute path *on the target*.
Review them before installing; see [USAGE.md](USAGE.md#remediation).

---

## 4. Optional scanning engines

secscan works with none of these installed. Each one that is missing is reported
as a not-run check with an install hint — coverage is never silently reduced.

Install them **on the target** (they run where the filesystem is):

| Engine | Adds | Install |
|---|---|---|
| [Trivy](https://trivy.dev) | OS package CVEs, container image CVEs, language dependencies | `apt install trivy` / `brew install trivy` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | committed secrets in checked-out repos | `brew install gitleaks` |
| [osv-scanner](https://github.com/google/osv-scanner) | lockfile vulnerabilities | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | web-layer misconfigurations | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [testssl.sh](https://testssl.sh) | TLS protocol, cipher and named-vulnerability checks | clone the repo — it is one shell script |

`nuclei` and `testssl.sh` are **expensive** (minutes per endpoint) and send
traffic to a live service. They are off by default; enable them per-scan or in
the dashboard's Checks page. See [USAGE.md](USAGE.md#choosing-which-checks-run).

A scan reports every engine that did not run, and why, so you can confirm what
is actually installed by running one:

```bash
./secscan scan web01
```

---

## 5. Configuration

Every setting is an environment variable declared in one registry. Generate a
template that cannot drift from what the binary actually reads:

```bash
./secscan config -example > .env
./secscan config                 # show resolved values, secrets redacted
```

`.env` is gitignored. Never commit a filled-in copy — the session and client
secrets are what stand between a stranger and your dashboard.

State lives in `$SECSCAN_HOME` (default `~/.secscan`): `state.json`,
`history.jsonl`, `audit.jsonl` and `snapshots/`. **These are scan output and
must never be committed** — a snapshot is a complete map of a host's weaknesses,
which is a worse disclosure than any credential. The shipped `.gitignore` and a
CI guard both enforce this.

---

## 6. Running the dashboard

### Local mode — loopback only, no authentication

```bash
SECSCAN_AUTH_MODE=local SECSCAN_BIND=127.0.0.1:8788 ./secscan serve
```

secscan **refuses to start** in local mode on a non-loopback bind. That is not a
warning you can click through: an unauthenticated dashboard of your estate's
weaknesses on a routable address is the worst outcome this tool can produce.

### Entra ID (Microsoft) mode

```bash
SECSCAN_AUTH_MODE=entra
SECSCAN_BASE_URL=https://scan.example.com
SECSCAN_ENTRA_TENANT_ID=...
SECSCAN_ENTRA_CLIENT_ID=...
SECSCAN_ENTRA_CLIENT_SECRET=...
SECSCAN_SESSION_SECRET=$(openssl rand -base64 48)   # >= 32 bytes, enforced
SECSCAN_ALLOWED_DOMAINS=example.com
SECSCAN_ADMIN_EMAILS=you@example.com
```

Register an app in Entra ID with redirect URI
`https://scan.example.com/auth/callback`, and grant the delegated `openid`,
`profile` and `email` scopes. Authorization-code flow with PKCE; the session is
an HMAC-signed cookie.

### Behind a reverse proxy

```bash
SECSCAN_AUTH_MODE=proxy
SECSCAN_TRUSTED_PROXIES=10.0.0.0/8
```

`SECSCAN_TRUSTED_PROXIES` is **required** in proxy mode and secscan refuses to
start without it. Trusting identity headers from any peer is an authentication
bypass, not a configuration preference.

#### The proxy must strip the identity headers on the way in

`SECSCAN_TRUSTED_PROXIES` checks **which peer** may assert an identity. It does
not, and cannot, check **where the header value came from**. A forged header
that arrives through a trusted proxy is still trusted — so if your proxy passes
client headers through untouched, proxy mode is wide open:

```
curl -H 'X-MS-CLIENT-PRINCIPAL-NAME: admin@example.com' https://scan.example.com/
```

The proxy must therefore **delete these headers from the inbound request before
it authenticates**, and set them only from the authentication response:

```
X-MS-CLIENT-PRINCIPAL-NAME
X-MS-CLIENT-PRINCIPAL-ROLES
X-MS-CLIENT-PRINCIPAL-ID
X-MS-CLIENT-PRINCIPAL
```

Strip first, authenticate, then set. Any other order is a bypass. Verify it from
outside with the `curl` above: a correct deployment still bounces you to the
identity provider.

---

## 7. Deploying as a container behind an identity-aware proxy

A worked example of the layout above: Caddy terminating TLS and running an
Entra gate via oauth2-proxy, with secscan reachable only through it.

**Dockerfile** — the binary is cross-compiled outside and copied in, so there is
no toolchain in the runtime image:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache openssh-client ca-certificates tzdata \
 && adduser -D -u 1001 -h /home/secscan secscan
COPY secscan /usr/local/bin/secscan
USER secscan
WORKDIR /home/secscan
EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/secscan"]
CMD ["serve"]
```

`openssh-client` is required, not incidental: secscan shells out to the system
`ssh` rather than vendoring a crypto stack, so without it every remote scan
fails at the first target.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' \
  -o secscan ./cmd/secscan
```

**Compose service** — note there are no published ports. The dashboard is an
inventory of an estate's weaknesses; it should never listen anywhere the
internet can reach it directly.

```yaml
  secscan:
    build: ./secscan
    restart: unless-stopped
    environment:
      SECSCAN_AUTH_MODE: proxy
      SECSCAN_TRUSTED_PROXIES: "172.18.0.0/16"   # the compose bridge only
      SECSCAN_BIND: "0.0.0.0:8788"
      SECSCAN_BASE_URL: "https://scan.example.com"
      SECSCAN_ADMIN_EMAILS: "you@example.com"
    volumes:
      - ./secscan/state:/home/secscan/.secscan    # JSON doc + JSONL history
      - ./secscan/ssh:/home/secscan/.ssh:ro       # its own scanning keypair
    expose:
      - "8788"
    security_opt: [ no-new-privileges:true ]
    cap_drop: [ ALL ]
```

Generate the service's keypair **on the server**, rather than copying in a key
you already use from a workstation: two callers with two credentials means
either can be revoked without disturbing the other.

**Caddy site block** — strip, authenticate, rename, forward:

```caddyfile
scan.example.com {
	# 1. distrust anything the client claims about its identity
	request_header -X-MS-CLIENT-PRINCIPAL-NAME
	request_header -X-MS-CLIENT-PRINCIPAL-ROLES
	request_header -X-MS-CLIENT-PRINCIPAL-ID
	request_header -X-MS-CLIENT-PRINCIPAL

	# 2. authenticate, and set the identity from the AUTH RESPONSE.
	#    copy_headers renames oauth2-proxy's header to the one secscan reads.
	forward_auth oauth2-proxy:4180 {
		uri /oauth2/auth
		copy_headers X-Auth-Request-Email>X-MS-CLIENT-PRINCIPAL-NAME
		@unauth status 401
		handle_response @unauth {
			redir * https://scan.example.com/oauth2/start?rd={scheme}%3A%2F%2F{host}{uri}
		}
	}

	# 3. scans of remote hosts take minutes; the default read timeout would
	#    cut one off mid-flight and surface it as a proxy error.
	reverse_proxy secscan:8788 {
		transport http { read_timeout 600s  write_timeout 600s }
	}
}
```

**oauth2-proxy must be started with `--set-xauthrequest=true`.** Without it the
`/oauth2/auth` response contains no `X-Auth-Request-*` headers at all, so
`copy_headers` copies nothing and every request reaches secscan anonymous. The
symptom is a clean sign-in followed by:

```json
{"error":{"code":"unauthorized","message":"authentication required"}}
```

which reads like a secscan bug and is actually a proxy that forwarded no
identity. It fails closed, which is the right direction, but it is easy to
misdiagnose.

Also make sure the identity the proxy sends is the one in
`SECSCAN_ADMIN_EMAILS`. oauth2-proxy with `--oidc-email-claim=preferred_username`
sends the directory UPN (`you@corp.example`), not a personal address — a
mismatch authenticates fine and then silently drops you to the lowest role,
where the scan controls are simply absent.

secscan still answers `401` to a request with no identity header even from a
trusted peer, so the proxy failing open does not silently expose the dashboard.
Confirm both halves after deploying:

```bash
curl -o /dev/null -w '%{http_code}\n' https://scan.example.com/          # 302 → IdP
curl -o /dev/null -w '%{http_code}\n' \
     -H 'X-MS-CLIENT-PRINCIPAL-NAME: admin@example.com' \
     https://scan.example.com/                                           # 302, not 200
```

---

## 8. Verify the install

```bash
go test ./...      # unit tests and golden fixtures
./ci/guards.sh     # architecture and disclosure guards

./secscan targets add web01 scan@web01.example.net -key ~/.ssh/id_ed25519
./secscan scan web01
```

The scan output ends with a **Not run** section listing any check that could not
execute and the reason. An empty list means full coverage; anything listed is
coverage you do not have.

Next: [USAGE.md](USAGE.md) · [INTERPRETING-RESULTS.md](INTERPRETING-RESULTS.md)
