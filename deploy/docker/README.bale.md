# Nawasara Agent — Bale Stack (Traefik → Caddy → FrankenPHP)

This stack has no nginx/apache. Caddy (and FrankenPHP, which embeds Caddy) logs
in **JSON**, and Traefik sits in front so the real client IP arrives in
`X-Forwarded-For`. Agent v0.8.0+ handles both natively — you only need to make
Caddy write its access log to a **file** the agent can read.

## Step 1 — Caddy writes a JSON access log to a shared volume

Caddy/FrankenPHP log to stdout by default; the agent tails files. Point the
access log at a file on a shared volume. In your Caddyfile:

```caddyfile
# global options (or per-site)
{
    log access-log {
        output file /var/log/caddy/access.log {
            roll_size 50MiB
            roll_keep 5
        }
        format json          # default; the agent parses Caddy JSON
    }
}
```

FrankenPHP uses the same Caddyfile syntax. If you run multiple sites, either log
them all to `access.log` or use per-site files matching `/var/log/caddy/*.log`
(the agent's default vhost glob).

> Keep `format json` — the agent parses Caddy's JSON, extracts the real client
> IP from `X-Forwarded-For`, and falls back to `remote_ip`.

## Step 2 — Make sure Traefik forwards the client IP

Traefik forwards `X-Forwarded-For` by default. Just ensure Caddy trusts it — if
your Caddy is configured with `trusted_proxies`, include Traefik's network so
Caddy keeps the header. (The agent reads the header regardless, but this keeps
Caddy's own logs correct too.)

## Step 3 — Run the agent as a sidecar

Add this to the Bale `docker-compose.yml`. It shares the Caddy log volume and
the app's web root (for the file scanner).

```yaml
services:
  # ... your existing caddy / frankenphp service, e.g.:
  app:
    image: your-frankenphp-image
    volumes:
      - caddy-logs:/var/log/caddy          # Caddy writes access.log here
      - app-web:/app/public                # FrankenPHP document root
    # ... traefik labels, etc.

  nawasara-agent:
    image: ghcr.io/nawasara/agent:latest    # or build from source (see README.md)
    container_name: bale-nawasara-agent
    restart: unless-stopped
    environment:
      NAWASARA_URL: https://nawasara.ponorogo.go.id
      NAWASARA_AGENT_NAME: bale-production   # unique name in the Dashboard
      NAWASARA_WEB_SERVER: caddy             # <-- key: use the Caddy collector
      NAWASARA_SCANNER_ENABLED: "true"
      TZ: Asia/Jakarta
    volumes:
      - agent-config:/etc/nawasara-agent     # persists agent identity
      - agent-data:/var/lib/nawasara-agent
      - caddy-logs:/var/log/caddy:ro         # SAME volume as Caddy, read-only
      - app-web:/app/public:ro               # scan the app's files
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: "0.25"
          memory: 128M
    command: ["run", "--config", "/etc/nawasara-agent/config.yaml"]

volumes:
  caddy-logs:
  app-web:
  agent-config:
  agent-data:
```

## Step 4 — Bring it up + verify

```bash
docker compose up -d nawasara-agent
docker compose logs -f nawasara-agent
```

Look for:
- `nawasara-agent 0.8.0 started (agent=bale-production ...)`
- `[collector] caddy:/var/log/caddy/access.log started`
- `registered as agent_id=...`

Then generate a request that trips a rule (e.g. hit `/wp-login.php` a few times,
or `curl -A sqlmap https://your-site/`) and confirm an incident appears in the
Dashboard for **bale-production** with the real client IP (not the Traefik
address).

## Notes for this stack

- **`NAWASARA_WEB_SERVER: caddy` is required** — auto-detect also works if
  `/var/log/caddy/access.log` exists, but setting it explicitly is clearer.
- The agent scans `/app/public` (FrankenPHP docroot) for webshells / backdoors /
  SEO-spam — adjust the path to your image's document root.
- Everything runs unprivileged and read-only against your app; the agent only
  tails logs and reads files.
- If your app scales to multiple replicas, run one agent that mounts the shared
  log volume — not one per replica — to avoid duplicate incidents.
