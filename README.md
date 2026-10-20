# Nawasara Agent

Security monitoring agent for Linux servers. It tails web-server access logs
(Nginx, Apache, Caddy/FrankenPHP, Traefik), the SSH auth log and, optionally,
Laravel logs; matches them against detection rules; scans web roots for
webshells and SEO spam; and reports incidents, findings and host metrics to the
Nawasara Dashboard (`nawasara/secscan`, https://nawasara.ponorogo.go.id).

The Dashboard decides what happens next. Incidents from an **approved** agent
feed the auto-block Decision Engine, which can block the source IP on
Cloudflare. The agent itself never blocks anything on its own initiative.

Current release: **v0.13.0**.

## What it does

| Area | Details |
|---|---|
| Web logs | Combined / vhost_combined (Nginx, Apache), JSON (Caddy, FrankenPHP, Traefik). Log rotation aware; per-vhost glob tailing |
| Target domain | From the `$host` field (vhost_combined, Caddy, Traefik) or the per-domain log filename (WHM/cPanel domlogs) |
| SSH | Failed logins and accepted root logins from `auth.log` / `secure` |
| Detection | 13 built-in rules with per-IP sliding-window scoring; custom YAML rules |
| File scanner | Webshell, backdoor, exploit-artifact and SEO-spam signatures; file integrity hashing |
| Plugins | Laravel log, Docker container health, TLS certificate expiry |
| Metrics | CPU, memory, disk in every heartbeat (default 60s) |
| Offline buffer | SQLite queue when the Dashboard is unreachable, retried automatically |
| Remote actions | Optional executor for admin-approved commands (off by default) |

## Requirements

- Linux amd64 or arm64, systemd
- Root (to read logs and, if the executor is enabled, to run iptables/systemctl)
- Outbound HTTPS to the Dashboard

## Install

### 1. Create an enrollment token

In the Dashboard open **Keamanan > Agen** and press **Buat Token** (needs
`secscan.agent.enroll` and a sudo confirmation). The token (`nwe_...`) is shown
once, is single-use, and expires after 1 hour to 7 days.

Since the 15 October 2026 security audit the Dashboard refuses registration
without a token. Before that, anyone on the internet could register an agent and
submit fake incidents that blocked arbitrary IPs on Cloudflare.

### 2. Run the installer on the server

```bash
curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | sudo NAWASARA_ENROLLMENT_TOKEN=nwe_xxx bash
```

The script is served by the Dashboard. It:

1. Downloads the binary from `/agent/download/latest/linux/<arch>/nawasara-agent`
   (the Dashboard redirects to the latest GitHub Release asset)
2. Registers with `POST /api/agent/register`, sending the token in `X-Enrollment-Token`
3. Writes `/etc/nawasara-agent/config.yaml` with the returned `agent_id` and `api_key` (mode 600)
4. Installs and starts the `nawasara-agent` systemd service

The agent name is the server's hostname. Re-running the installer keeps the
existing config and credentials and only updates the binary.

> **Pipe or file, not both.** `curl ... | bash </dev/null` makes bash read
> `/dev/null` instead of the script. In automation, download the script to a
> file first, then run `bash install.sh`.

### 3. Approve the agent

The new agent appears as **Menunggu persetujuan**. Until an admin chooses
**Setujui agen** in its row menu (sudo), its incidents are stored and visible
but cannot trigger an IP block.

Approve only after checking the first incidents. An agent that reads traffic
from shared IPs (mobile carrier NAT, the office proxy) can otherwise get many
legitimate users blocked at once.

### 4. Check the default config

The installer writes `web_server: auto`, which only finds logs at the usual
host paths. If the web server runs in a container, or logs elsewhere, set the
path explicitly (see [Web servers inside containers](#web-servers-inside-containers)),
then `systemctl restart nawasara-agent`.

## Manual install

```bash
ARCH=amd64   # or arm64
curl -fsSL https://github.com/nawasara/agent/releases/latest/download/nawasara-agent-linux-$ARCH \
  -o /usr/local/bin/nawasara-agent
chmod +x /usr/local/bin/nawasara-agent
mkdir -p /etc/nawasara-agent /var/lib/nawasara-agent /var/log/nawasara-agent
chmod 700 /etc/nawasara-agent /var/lib/nawasara-agent

# Register once with an enrollment token and keep the response
curl -sS -X POST https://nawasara.ponorogo.go.id/api/agent/register \
  -H 'Content-Type: application/json' \
  -H 'X-Enrollment-Token: nwe_xxx' \
  -d '{"name":"web-01","hostname":"web-01","os":"linux","arch":"x86_64"}'

cp config.example.yaml /etc/nawasara-agent/config.yaml
# set dashboard_url, agent_name, agent_id and api_key from the response
chmod 600 /etc/nawasara-agent/config.yaml

cp scripts/nawasara-agent.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now nawasara-agent
```

`scripts/nawasara-agent.service` caps the agent at 10% CPU and 128 MB of
memory. The unit written by the Dashboard installer does not set these limits
yet.

> **Self-registration does not work any more.** When `agent_id` is empty the
> binary still calls `/api/agent/register` without a token, which the
> Dashboard rejects. Always register with the installer or the `curl` call
> above and put `agent_id` / `api_key` in the config. This includes the Docker
> deployment in `deploy/docker`.

## Configuration

File: `/etc/nawasara-agent/config.yaml`. Every option is documented in
[`config.example.yaml`](config.example.yaml); there are also ready-made
examples for WHM (`config.whm.example.yaml`) and Apache + Laravel
(`config.apache-laravel.example.yaml`).

| Field | Default | Notes |
|---|---|---|
| `dashboard_url` | | Required |
| `agent_id`, `api_key` | | From registration; every request sends both (`X-Agent-Id` is required) |
| `agent_name` | hostname | Display name |
| `collector.web_server` | `auto` | `auto`, `nginx`, `apache`, `caddy`, `frankenphp`, `traefik` |
| `collector.log_paths.<server>.access` / `vhosts` | per server | Explicit access log and optional per-vhost glob |
| `collector.ssh_log` | `auto` | `auto` or a path |
| `reporter.heartbeat_interval` | `60s` | The Dashboard marks the agent offline after about 3 minutes without one |
| `analyzer.correlation_window` | `5m` | Per-IP score lifetime |
| `plugins.enabled` | `[nginx, ssh]` | Add `laravel`, `docker`, `ssl` |
| `scanner.enabled` | `false` | File scanner |
| `executor.enabled` | `false` | Remote actions |

## Web servers inside containers

The agent runs on the host, so it needs a log **file on the host**. A web
server inside a container that logs to stdout is invisible to it.

### Nginx in a container (the Nawasara pattern)

Nawasara's own server (LXC 140) runs nginx inside the app container and logs
JSON to stdout. A second access log is written for the agent in
vhost_combined format to a folder bind-mounted from the host:

```nginx
log_format agent_vhost '$host $remote_addr - $remote_user [$time_local] '
    '"$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/nawasara-web/access.log agent_vhost;
```

```yaml
# compose: app service
volumes:
  - /var/log/nawasara-web:/var/log/nawasara-web
```

```yaml
# agent config
collector:
  web_server: nginx
  log_paths:
    nginx:
      access: /var/log/nawasara-web/access.log
```

Rotate the host file with logrotate using `copytruncate`: nginx in the
container keeps the file open, and a plain rename leaves it writing to the old
file. `$remote_addr` must be the real client IP (nginx `realip` behind
Cloudflare), or every incident points at the proxy.

### Traefik

Make Traefik write a JSON access log to a host-mounted path:

```yaml
# traefik.yml
accessLog:
  filePath: /var/log/traefik/access.log
  format: json
  fields:
    headers:
      defaultMode: keep   # keeps User-Agent and X-Forwarded-For
```

```yaml
collector:
  web_server: traefik
  log_paths:
    traefik:
      access: /var/log/traefik/access.log
```

The client IP is taken from the client-most `X-Forwarded-For` hop, falling
back to `ClientHost`.

## Detection rules

Built in, no configuration needed. A rule fires when the per-IP score reaches
its threshold within the window.

| Rule | Category | Severity | Fires on |
|---|---|---|---|
| Dotenv file access | `vulnerability_scan` | high | `/.env`, `/.env.bak`, `/.env.old`, `/.env.example` |
| Git config access | `vulnerability_scan` | high | `/.git/config`, `/.git/HEAD` |
| PHPInfo access | `vulnerability_scan` | medium | `phpinfo`, `test.php` in the path |
| Directory traversal | `directory_traversal` | critical | `../`, `..%2F`, `%2e%2e%2f` |
| SQL injection in URL | `sql_injection` | critical | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `SLEEP(`, `BENCHMARK(` ... in the query |
| XSS probe | `xss` | medium | `<script`, `javascript:`, `onerror=`, `onload=` in the query |
| Known scanner bot | `scanner_bot` | high | User-Agent of sqlmap, nikto, nuclei and similar tools, including load testers |
| PHP webshell upload | `webshell_upload` | critical | POST of a `.php` file under upload/media/tmp paths |
| HTTP login brute force | `brute_force` | high | 10 POSTs to a login path from one IP in 60s |
| HTTP 4xx storm | `4xx_storm` | medium | 50 responses 4xx from one IP in 30s |
| HTTP request flood | `request_flood` | high | 300 requests from one IP in 60s |
| SSH brute force | `brute_force` | high | 10 failed logins from one IP in 5 minutes |
| SSH root login accepted | `ssh_root_login` | critical | Any successful root login |

Which categories can lead to an automatic block, and the whitelist (office
range, private and Cloudflare ranges), are decided by the Dashboard's
Decision Engine, not by the agent.

### Custom rules

YAML files in `/etc/nawasara-agent/rules/`, reloaded every 6 hours or on
restart:

```yaml
- id: rule_custom_wp_admin_scan
  name: WordPress Admin Scan
  category: vulnerability_scan
  severity: high
  score: 10
  threshold: 10
  conditions:
    source: web_log
    path_contains:
      - /wp-admin/
      - /wp-login.php
```

Conditions: `source` (`web_log` | `ssh_log`), `method`, `path_equals`,
`path_contains`, `path_regex`, `query_regex`, `ua_contains`, `status_min`,
`status_max`, `event_type`, `per_ip`, `window_seconds`.

## File scanner

Off by default. When `scanner.enabled: true` the agent scans `web_dirs` every
`scan_interval` (default 6h) and pushes findings to
`POST /api/agent/scan-findings`.

| Category | Signatures |
|---|---|
| Webshell | c99, r57, WSO, b374k, IndoXploit, Priv8, mini PHP shell, generic upload shell |
| Backdoor | eval + base64, hex-encoded eval, `create_function`, system/exec on user input, dynamic file write, PHP mail spammer |
| Exploit artifact | WP File Manager (CVE-2020-25213), phpMyAdmin LFI, Log4Shell JNDI payloads |
| SEO spam | Online gambling (judol), illegal abortion-drug spam |
| Integrity | Hash changes of watched files (`.env`, `composer.json`, `wp-config.php` ...) |

Decisions worth knowing before changing this:

- **Integrity checking skips volatile paths** (page caches, logs, sessions,
  compiled templates), because there a changed hash is the application
  working. The signature scan still reads those files, so a webshell hidden in
  a cache folder is still reported. WordPress core and plugin folders are
  deliberately NOT skipped: that is where backdoors are planted.
- **Each signature finding carries a few lines of surrounding code**, so staff
  can judge it in the Dashboard without SSH. Credential values (database
  passwords in `wp-config.php`, `.env` secrets) are blanked before anything
  leaves the host. There is intentionally no "read this file" command: it
  would let whoever compromises the Dashboard pull every `wp-config.php` on
  every server.

A custom signature database (same JSON structure as the built-in one) can be
placed at `scanner.signatures_db`.

## Plugins

| Plugin | Purpose | Key settings |
|---|---|---|
| `laravel` | Incidents for EMERGENCY/ALERT/CRITICAL and serious ERROR entries (DB exceptions, OOM, class not found) | `plugins.laravel.log_paths` (glob; empty = auto-detect) |
| `docker` | OOM kills, non-zero exits and unhealthy containers via `docker events` + periodic `docker ps` | `plugins.docker.check_interval` |
| `ssl` | Certificate expiry of listed hosts | `plugins.ssl.hosts`, `warn_days`, `crit_days` |

## Executor (remote actions)

Off by default. With `executor.enabled: true` the agent polls
`GET /api/agent/commands/pending` every 30s and runs commands that admins
approved in the Dashboard.

Three gates, all required:

1. An admin with `secscan.agent.command` issues the command.
2. **A different** admin with `secscan.agent.command.approve` approves it
   (self-approval is refused unless the Dashboard sets
   `SECSCAN_AGENT_COMMAND_SELF_APPROVE=true`).
3. The action is in the agent's own `executor.allowed_actions`, whatever the
   Dashboard says.

| Action | Effect |
|---|---|
| `block_ip` / `unblock_ip` | iptables/nftables DROP for `ip` |
| `restart_nginx` / `reload_nginx` | systemctl |
| `restart_apache` / `reload_apache` | systemctl (apache2 or httpd) |
| `restart_php_fpm` / `reload_php_fpm` | systemctl, PHP version auto-detected |
| `restart_mysql` | systemctl (mysql, mysqld or mariadb) |
| `artisan_queue_restart`, `artisan_optimize_clear` | `php artisan ...` |

## CLI

```bash
nawasara-agent run [--config /etc/nawasara-agent/config.yaml] [--debug]
nawasara-agent status [--config ...]   # prints agent_id, name, dashboard, plugins
nawasara-agent version
```

Logs: `/var/log/nawasara-agent/agent.log` (Dashboard installer) or
`journalctl -u nawasara-agent` (manual unit).

## Troubleshooting

| Symptom | Cause |
|---|---|
| Installer: `Registration failed` with 401 | Token missing, expired, revoked or already used. Create a new one |
| Agent online but no web incidents | `web_server: auto` found no host log. Set `log_paths` explicitly; a containerised web server needs a host log file |
| Incidents appear, no IP is ever blocked | Agent still pending approval, the category is not blockable, or the IP is whitelisted |
| `ssh_root_login` from a 10.x / jump-host address | Your own admin login. Private IPs are never blocked |
| `version` prints `0.8.0` | Local build; release builds get the tag through ldflags |

## Building and releasing

```bash
go build -o nawasara-agent ./cmd/agent            # Go 1.23+
go test ./...
```

Release: push a tag `vX.Y.Z`. The `release` workflow cross-compiles
linux/amd64 and linux/arm64 with the version injected
(`-X github.com/nawasara/agent/internal/reporter.Version=<tag>`), writes
`checksums.txt` and publishes a GitHub Release. The Dashboard's download route
redirects to the latest release, so new installs pick it up immediately.
Existing agents are not updated automatically: re-run the installer on each
server.

## Architecture

```
cmd/agent/          CLI (run, status, version) and wiring
internal/collector/ Log tailers and parsers (nginx/apache, caddy, traefik, ssh), metrics
internal/analyzer/  Rule engine, per-IP sliding windows, built-in + YAML rules
internal/reporter/  Heartbeats, incidents, SQLite offline buffer, registration
internal/scanner/   File scanner: signatures, integrity hashes, volatile paths, code context
internal/plugin/    laravel, docker, ssl
internal/executor/  Command polling, allowlist, actions
internal/health/    Agent health score
internal/config/    YAML config load/save
deploy/docker/      Sidecar deployment (see its README)
```

## Uninstall

```bash
systemctl disable --now nawasara-agent
rm /etc/systemd/system/nawasara-agent.service && systemctl daemon-reload
rm /usr/local/bin/nawasara-agent
rm -rf /etc/nawasara-agent /var/lib/nawasara-agent /var/log/nawasara-agent
```

Then revoke the agent in the Dashboard (Keamanan > Agen) so its API key stops
working.

## Roadmap

- Self-registration with an enrollment token from config, so the Docker
  deployment can register without a manual `curl`
- Resource limits in the unit written by the Dashboard installer
- Telling WordPress updates apart from tampering via WordPress checksums,
  instead of path lists
- Automatic agent updates from the Dashboard

## Author

Pringgo J. Saputro, Diskominfo Kabupaten Ponorogo
