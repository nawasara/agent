# Deploy Nawasara Agent — Bale Production Stack

Panduan lengkap memasang Nawasara Agent di stack **Traefik → Caddy →
FrankenPHP** (semua container). Agent berjalan sebagai **sidecar**: memantau log
akses Caddy (deteksi serangan) dan memindai file web (webshell/backdoor/SEO
spam), lalu melapor ke dashboard Nawasara.

File contoh siap pakai ada di folder [`bale/`](bale/):
- [`bale/docker-compose.yml`](bale/docker-compose.yml) — stack + sidecar agent
- [`bale/Caddyfile`](bale/Caddyfile) — konfigurasi log Caddy yang dibutuhkan

---

## Prasyarat

- Stack Bale sudah jalan (Traefik + Caddy/FrankenPHP dalam Docker Compose).
- Server bisa menjangkau `https://nawasara.ponorogo.go.id` (untuk registrasi +
  lapor). Cek: `curl -sI https://nawasara.ponorogo.go.id | head -1`.
- Arsitektur amd64 atau arm64 (image multi-arch, otomatis cocok).

Tidak perlu clone repo atau build apa pun — image ditarik dari GHCR.

---

## Langkah 1 — Caddy menulis access log JSON ke file

Caddy/FrankenPHP default log ke stdout; agent membaca **file**. Arahkan access
log ke file JSON di volume bersama. Di Caddyfile Anda tambahkan blok `log`
(lihat [`bale/Caddyfile`](bale/Caddyfile) untuk contoh utuh):

```caddyfile
bale.ponorogo.go.id {
    log {
        output file /var/log/caddy/access.log {
            roll_size 50MiB
            roll_keep 5
        }
        format json          # WAJIB json — agent mem-parse JSON Caddy
    }

    root * /app/public
    php_server
}
```

Dan di blok global, percayai Traefik supaya IP asli tetap di `X-Forwarded-For`:

```caddyfile
{
    servers {
        trusted_proxies static 172.16.0.0/12 10.0.0.0/8   # ganti dgn CIDR network Traefik Anda
    }
}
```

> **Kenapa:** stack ini tak ada nginx/apache. Caddy log JSON (bukan Combined Log
> Format), dan Traefik di depan menaruh IP penyerang asli di `X-Forwarded-For`.
> Agent v0.8.0+ mengerti keduanya — ia ambil IP dari `X-Forwarded-For` (fallback
> ke `remote_ip`).

---

## Langkah 2 — Tambahkan volume mount ke service app

Service Caddy/FrankenPHP Anda perlu meng-expose dua hal ke agent lewat **named
volume**:

```yaml
services:
  app:                          # service FrankenPHP Anda yang sudah ada
    volumes:
      - caddy-logs:/var/log/caddy      # Caddy menulis access.log ke sini
      - app-web:/app/public            # docroot yang dipindai agent
```

`/app/public` = document root FrankenPHP — sesuaikan kalau image Anda beda.

---

## Langkah 3 — Tambahkan service agent

Tempel service `nawasara-agent` ke `docker-compose.yml` Anda (dari
[`bale/docker-compose.yml`](bale/docker-compose.yml)):

```yaml
  nawasara-agent:
    image: ghcr.io/nawasara/agent:latest
    container_name: bale-nawasara-agent
    restart: unless-stopped
    depends_on:
      - app
    environment:
      NAWASARA_URL: https://nawasara.ponorogo.go.id
      NAWASARA_AGENT_NAME: bale-production    # nama UNIK di dashboard
      NAWASARA_WEB_SERVER: caddy              # collector Caddy JSON
      NAWASARA_SCANNER_ENABLED: "true"
      TZ: Asia/Jakarta
    volumes:
      - agent-config:/etc/nawasara-agent      # simpan agent_id + api_key
      - agent-data:/var/lib/nawasara-agent
      - caddy-logs:/var/log/caddy:ro          # volume SAMA dgn app, read-only
      - app-web:/app/public:ro                # pindai file app
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: "0.25"
          memory: 128M
    command: ["run", "--config", "/etc/nawasara-agent/config.yaml"]
```

Lalu daftarkan volume-nya:

```yaml
volumes:
  caddy-logs:
  app-web:
  agent-config:
  agent-data:
```

---

## Langkah 4 — Reload Caddy + jalankan agent

```bash
# Terapkan perubahan Caddyfile (reload tanpa downtime)
docker compose exec app caddy reload --config /etc/frankenphp/Caddyfile 2>/dev/null \
  || docker compose restart app

# Jalankan agent
docker compose up -d nawasara-agent
docker compose logs -f nawasara-agent
```

**Log yang benar** menandakan sukses:

```
nawasara-agent 0.8.0 started (agent=bale-production dashboard=https://nawasara.ponorogo.go.id ...)
[collector] caddy:/var/log/caddy/access.log started
registered as agent_id=... (saved to config)
[scanner] file scanner started ...
```

Agent muncul di **Dashboard → Agents** dalam ~30 detik sebagai `bale-production`.

---

## Langkah 5 — Verifikasi deteksi bekerja

Picu satu aturan deteksi, lalu cek dashboard:

```bash
# Dari luar (lewat Traefik) — simulasi scanner bot
curl -A "sqlmap/1.5" "https://bale.ponorogo.go.id/?id=1' OR '1'='1"

# atau beberapa kali hit login (brute-force)
for i in $(seq 1 5); do curl -s -o /dev/null "https://bale.ponorogo.go.id/wp-login.php"; done
```

Di dashboard, insiden untuk **bale-production** harus muncul dengan **IP asli
Anda** (bukan alamat internal Traefik). Kalau IP-nya alamat internal (`10.x` /
`172.x`), berarti `trusted_proxies` / `X-Forwarded-For` belum benar di
Langkah 1.

---

## Update agent ke versi baru

```bash
docker compose pull nawasara-agent
docker compose up -d nawasara-agent
```

Identitas (`agent_id`) tersimpan di volume `agent-config`, jadi update tak
mendaftarkan ulang. Baseline hash scanner di `agent-data` juga tetap.

---

## Troubleshooting

| Gejala | Penyebab & solusi |
|---|---|
| `pull access denied` | Image publik; pastikan tak ada typo `ghcr.io/nawasara/agent:latest`. Jaringan server bisa akses ghcr.io? |
| Log agent `caddy:...started` tapi tak ada insiden | Caddy belum nulis ke `/var/log/caddy/access.log` (masih stdout), atau `format` bukan `json`. Cek `docker compose exec app ls -la /var/log/caddy/`. |
| Insiden muncul tapi IP = `10.x`/`172.x` | `X-Forwarded-For` tak sampai. Set `trusted_proxies` di Caddy (Langkah 1). |
| `registration failed` di log | Server tak bisa menjangkau `NAWASARA_URL`. Cek firewall/DNS: `docker compose exec nawasara-agent wget -qO- https://nawasara.ponorogo.go.id/up`. |
| Scanner tak menemukan file | Path docroot salah. Sesuaikan `app-web:/app/public` ke docroot image Anda. |

---

## Catatan

- Semua akses agent **read-only** ke app Anda — hanya tail log + baca file.
- Kalau app di-scale ke banyak replika, jalankan **satu** agent yang mount
  volume log bersama (bukan satu per replika) agar insiden tak dobel.
- Agent dibatasi 0.25 CPU / 128 MB. Scan pertama membangun baseline hash seluruh
  docroot (I/O berat sekali), scan berikutnya hanya banding hash.
- Butuh format lain (mis. app log ke stdout, bukan file)? Belum didukung —
  hubungi tim Nawasara; bisa ditambah dukungan baca `docker logs` via
  docker.sock.
