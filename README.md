# Nawasara Agent

Lightweight security monitoring agent for Linux VMs. Reads Nginx/Apache access logs and SSH auth logs in realtime, detects attack patterns, and reports incidents to the [Nawasara Dashboard](https://nawasara.ponorogo.go.id).

## Features

- Real-time log tailing with log-rotation awareness
- 12 built-in attack detection rules (SQL injection, XSS, brute force, webshell upload, scanner bots, SSH attacks, and more)
- Per-IP sliding window score accumulation — fires incident only when threshold is reached
- SQLite offline buffer — incidents queued locally when Dashboard is unreachable, retried automatically
- Heartbeat every 60s with CPU/memory/disk metrics
- Auto-detects OS, web server, and SSH log path
- Self-registers with Dashboard on first run (no manual API key setup needed)
- Glob watcher for per-vhost nginx logs
- Runs as a systemd service with CPU/memory limits

## Requirements

- Linux (amd64 or arm64)
- systemd
- Root access (for log reading)

## Install (one-liner)

```bash
curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
```

Non-interactive (for automation/Ansible):

```bash
NAWASARA_API_KEY=nwa_xxx \
NAWASARA_URL=https://nawasara.ponorogo.go.id \
NAWASARA_AGENT_NAME=web-prod-01 \
bash <(curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh)
```

The installer:
1. Detects OS and architecture
2. Downloads the binary from the Dashboard (falls back to GitHub Releases)
3. Writes `/etc/nawasara-agent/config.yaml`
4. Calls `/api/agent/register` — agent ID and API key are saved to config automatically
5. Installs and starts a systemd service

## Manual Install

```bash
# Download binary (replace VERSION and ARCH as needed)
curl -fsSL https://github.com/nawasara/agent/releases/latest/download/nawasara-agent-linux-amd64 \
  -o /usr/local/bin/nawasara-agent
chmod +x /usr/local/bin/nawasara-agent

# Create directories
mkdir -p /etc/nawasara-agent/rules /etc/nawasara-agent/plugins/available
mkdir -p /var/lib/nawasara-agent
chmod 700 /etc/nawasara-agent /var/lib/nawasara-agent

# Create config
cp config.example.yaml /etc/nawasara-agent/config.yaml
# Edit dashboard_url and agent_name:
nano /etc/nawasara-agent/config.yaml

# Install systemd service
cp scripts/nawasara-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nawasara-agent

# Check status
nawasara-agent status
journalctl -u nawasara-agent -f
```

On first `run`, if `agent_id` is empty in config, the agent calls `/api/agent/register` automatically and writes the returned `agent_id` and `api_key` back to the config file.

## Configuration

Config file: `/etc/nawasara-agent/config.yaml`

See [`config.example.yaml`](config.example.yaml) for all options with documentation.

Key fields:

| Field | Default | Description |
|---|---|---|
| `dashboard_url` | — | Nawasara Dashboard base URL (required) |
| `agent_name` | hostname | Display name in Dashboard |
| `collector.web_server` | `auto` | `auto`, `nginx`, or `apache` |
| `collector.ssh_log` | `auto` | `auto`, or explicit path |
| `reporter.heartbeat_interval` | `60s` | Dashboard marks agent offline after 3× this |
| `reporter.buffer_db` | `/var/lib/nawasara-agent/buffer.db` | SQLite offline queue |
| `analyzer.correlation_window` | `5m` | Per-IP score TTL |
| `plugins.enabled` | `[nginx, ssh]` | Active collectors |

## CLI

```bash
# Run the daemon
nawasara-agent run [--config /path/to/config.yaml] [--debug]

# Print version
nawasara-agent version

# Print current config values (reads config, does not start daemon)
nawasara-agent status
```

## Detection Rules

Built-in rules (no config needed):

| Rule | Category | Severity | Trigger |
|---|---|---|---|
| Dotenv file access | `vulnerability_scan` | High | GET `/.env`, `/.git/config` |
| PHPInfo access | `vulnerability_scan` | Medium | GET `*phpinfo*` |
| Directory traversal | `directory_traversal` | Critical | `../` in path |
| SQL injection (URL) | `sql_injection` | Critical | `UNION SELECT`, `OR 1=1`, `SLEEP()` etc. in query |
| XSS probe | `xss` | Medium | `<script>`, `javascript:` in query |
| Scanner bot | `scanner_bot` | High | UA contains `sqlmap`, `nikto`, `nuclei`, etc. |
| PHP webshell upload | `webshell_upload` | Critical | POST to `/upload*` path with `.php` extension |
| HTTP brute force | `brute_force` | High | 10+ POST `/login` from same IP in 60s |
| HTTP 4xx storm | `4xx_storm` | Medium | 50+ 4xx responses from same IP in 30s |
| SSH brute force | `brute_force` | High | 10+ failed SSH logins from same IP in 5m |
| SSH root login | `ssh_root_login` | Critical | Successful SSH login as root |

### Custom Rules

Place YAML files in `/etc/nawasara-agent/rules/`. Reloaded every 6 hours (or on agent restart).

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

Available condition fields: `source` (`web_log`|`ssh_log`), `method`, `path_equals`, `path_contains`, `path_regex`, `query_regex`, `ua_contains`, `status_min`, `status_max`, `event_type`, `per_ip`, `window_seconds`.

## Building from Source

```bash
git clone https://github.com/nawasara/agent
cd agent
go mod tidy

# Build for current platform
go build -o nawasara-agent ./cmd/agent

# Cross-compile for Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags="-s -w" \
  -o dist/nawasara-agent-linux-amd64 ./cmd/agent
```

Requires Go 1.23+.

## Phase 2 — Executor (Remote Actions)

When `executor.enabled: true`, the agent polls `GET /api/agent/commands/pending` every 30 seconds and executes approved commands.

**All commands require admin approval on the Dashboard before being sent to the agent.** The agent also enforces its own allowlist — any command not in `executor.allowed_actions` is refused regardless of Dashboard approval.

Enable in config:

```yaml
executor:
  enabled: true
  poll_interval: 30s
  allowed_actions:
    - block_ip
    - unblock_ip
    - restart_nginx
    - restart_php_fpm
    - artisan_queue_restart
    - artisan_optimize_clear
```

Available actions:

| Action | Description |
|---|---|
| `block_ip` | Add IP to iptables/nftables INPUT DROP (params: `ip`) |
| `unblock_ip` | Remove IP from block (params: `ip`) |
| `restart_nginx` | `systemctl restart nginx` |
| `reload_nginx` | `systemctl reload nginx` |
| `restart_apache` | `systemctl restart apache2/httpd` |
| `reload_apache` | `systemctl reload apache2/httpd` |
| `restart_php_fpm` | `systemctl restart php*-fpm` (auto-detects version) |
| `reload_php_fpm` | `systemctl reload php*-fpm` |
| `restart_mysql` | `systemctl restart mysql/mysqld/mariadb` |
| `artisan_queue_restart` | `php artisan queue:restart` |
| `artisan_optimize_clear` | `php artisan optimize:clear` |

## Phase 2 — Plugins

Enable additional monitoring plugins via `plugins.enabled`:

### SSL Certificate Monitor (`ssl`)

Probes TLS certificate expiry on configured hostnames.

```yaml
plugins:
  enabled:
    - nginx
    - ssh
    - ssl
  ssl:
    hosts:
      - nawasara.ponorogo.go.id
      - app.ponorogo.go.id:8443
    check_interval: 12h
    warn_days: 30    # emit "high" incident
    crit_days: 7     # emit "critical" incident
```

### Docker Monitor (`docker`)

Monitors container health via `docker events` (real-time) and periodic `docker ps` snapshots. Emits incidents for OOM kills, non-zero exits, and unhealthy health checks.

```yaml
plugins:
  enabled:
    - nginx
    - ssh
    - docker
  docker:
    check_interval: 5m
```

### Laravel Log Monitor (`laravel`)

Tails Laravel log files and emits incidents for `EMERGENCY`, `ALERT`, `CRITICAL` entries, and significant `ERROR` patterns (DB exceptions, OOM, class not found). Auto-detects common log paths.

```yaml
plugins:
  enabled:
    - nginx
    - ssh
    - laravel
  laravel:
    log_paths:  # empty = auto-detect
      - /var/www/html/storage/logs/laravel.log
```

## Architecture

```
collector/          Read and parse log lines
  tailer.go         tail -F with log-rotation detection
  glob_tailer.go    Watch a glob pattern, add new files automatically
  nginx.go          Combined Log Format parser (nginx + apache)
  ssh.go            sshd auth log parser
  metrics_linux.go  /proc CPU/mem/disk sampler

analyzer/           Match events against rules, emit incidents
  engine.go         Rule matching (path/query/UA/status conditions)
  window.go         Per-IP sliding-window score accumulator
  rules.go          Built-in default rules + YAML loader

reporter/           Send incidents and heartbeats to Dashboard
  reporter.go       HTTP POST with SQLite offline buffer + retry loop

executor/           Phase 2 — poll + execute admin-approved commands
  executor.go       Poll loop, allowlist enforcement, result reporting
  actions.go        block_ip (iptables/nftables), systemctl, artisan

plugin/             Plugin manager + runtime plugins
  manager.go        Plugin loader from YAML files
  ssl.go            TLS cert expiry monitor
  docker.go         Container health via docker events + docker ps
  laravel.go        Laravel log tailer (CRITICAL/ERROR patterns)

health/             Calculate agent health score (0-100)
config/             YAML config load + Save() for agent_id persist
```

## Uninstall

```bash
systemctl stop nawasara-agent
systemctl disable nawasara-agent
rm /etc/systemd/system/nawasara-agent.service
systemctl daemon-reload
rm /usr/local/bin/nawasara-agent
rm -rf /etc/nawasara-agent /var/lib/nawasara-agent
```
