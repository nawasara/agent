# Nawasara Agent on Docker

Two ways to run the agent in Docker, both self-registering via env vars — no
manual key handling.

| File | Pattern | Use when |
|---|---|---|
| `docker-compose.yml` | **One agent per host** — monitors host logs + web dirs | You have a few Docker hosts and want one agent each |
| `docker-compose.sidecar.yml` | **One agent per app** — a sidecar watching just that app | Your stack is dockerized and you want per-app isolation |

## How registration works

On first start the agent finds `agent_id` empty, calls `POST /api/agent/register`
on the Dashboard, and writes the returned `agent_id` + `api_key` into the
`*-config` volume. Restarts reuse that identity. **Nothing to paste** — just set
`NAWASARA_URL` and a unique `NAWASARA_AGENT_NAME`.

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `NAWASARA_URL` | yes | — | Dashboard base URL, no trailing slash |
| `NAWASARA_AGENT_NAME` | yes | hostname | **Must be unique** per agent |
| `NAWASARA_WEB_SERVER` | no | `auto` | `auto` \| `nginx` \| `apache` |
| `NAWASARA_SCANNER_ENABLED` | no | `false` | `true` turns on the file scanner |
| `NAWASARA_AGENT_ID` / `NAWASARA_API_KEY` | no | — | Pre-provision instead of self-registering |

Everything else (scan interval, plugins, rules) still comes from
`config.yaml` if you mount one; env vars only cover identity + connection.

## Quick start (host-wide)

```bash
cd deploy/docker
# edit NAWASARA_AGENT_NAME in docker-compose.yml
docker compose up -d --build
docker compose logs -f          # look for: registered as agent_id=...
```

The agent appears in the Dashboard → Agents within ~30s.

## Sidecar (per app)

Copy the `myapp` + `myapp-agent` block in `docker-compose.sidecar.yml` for each
app, giving each a unique `NAWASARA_AGENT_NAME`. The app and its agent share
`*-logs` and `*-web` volumes; the agent mounts them read-only.

## Using a released binary instead of building

The compose files build from source (`context: ../..`). To skip building and use
a published release binary, replace the `build:` block with an image that bakes
in the downloaded binary, or mount it:

```yaml
services:
  nawasara-agent:
    image: alpine:3.20
    # download the binary into a volume once, then run it
    entrypoint: ["/usr/local/bin/nawasara-agent", "run", "--config", "/etc/nawasara-agent/config.yaml"]
    volumes:
      - ./nawasara-agent:/usr/local/bin/nawasara-agent:ro   # from GitHub Releases
```

(Once the agent image is published to a registry, point `image:` at it directly.)

## What to mount

The agent only sees what you mount:

- **Logs** (`/var/log:ro` or a shared `*-logs` volume) — SSH brute force, web
  attacks. Without this, no log-based incidents.
- **Web roots** (`/var/www:ro`, `/home:ro`, or a shared `*-web` volume) — the
  file scanner looks here for webshells/backdoors/SEO-spam. Needs
  `NAWASARA_SCANNER_ENABLED=true`.
- **`/var/run/docker.sock:ro`** (optional) — only if you enable the `docker`
  plugin to watch container health.

## Resource footprint

Capped at 0.25 CPU / 128 MB in the compose files. The first scan builds a hash
baseline of every file under the web roots, so it's I/O-heavy once; subsequent
scans only diff hashes.
