# Deploying the fleet on one laptop (Docker only)

Everything — sensor, collector and the Cloudflare tunnel connector — runs on a
single Windows/macOS/Linux laptop behind Docker Compose. No VPS, no router
port-forwarding, no published ports. Cloudflare's edge is the only way in.

```
                internet
                   │  (edge TLS, wildcard cert *.hudaw.lol)
     ┌─────────────▼───────────┐  tunnel (outbound only)
     │  cloudflared (laptop)   │──────────── Cloudflare edge
     └───────────┬─────────┘
                 │  internal network "fleet" (internal: true, no NAT egress)
     ┌───────────▼─────────┐   ┌─────────────────────┐
     │  sensor :8080       │──▶│  collector :9443    │──▶ /data (volume)
     │  (no egress at all) │   │  (never published)  │
     └─────────────────────┘   └─────────────────────┘
```

Topology facts, enforced by `docker-compose.yml`:

- The `fleet` network is `internal: true`: the sensor and the collector have
  no NAT egress at all — captured payloads cannot pivot through the laptop.
- `cloudflared` is attached both to `fleet` (to reach the sensor) and to the
  normal bridge (for its *outbound* tunnel connection). It is the only
  internet-facing component.
- The sensor and collector publish no ports. The collector is operated with
  `docker compose exec`; its data lives on the `collector-data` volume at
  `/data`.
- Decoy source identity: `PHPTOPWN_CLIENT_IP_HEADER=CF-Connecting-IP`, so
  `client.ip` in records is the real client and the tunnel peer is kept in
  `client.peer_ip` (see docs/SCHEMA.md).

## 0. Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine + Compose v2.
- Access to the registrar where hudaw.lol is registered, and to Vercel where
  its DNS is hosted today.
- A Cloudflare account (the free plan is enough).

## 1. Move the hudaw.lol DNS zone from Vercel to Cloudflare

The tunnel hostname must live in a Cloudflare zone. The zone can only be in
one DNS host at a time.

1. Cloudflare dashboard → *Add a domain* → `hudaw.lol` → plan **Free**.
2. Cloudflare scans existing Vercel records and imports them. Verify every
   record that matters survived the import (the public site record pointing
   at Vercel, any MX/SPF/DKIM records) before switching.
3. Cloudflare shows two nameservers, e.g. `dana.ns.cloudflare.com` and
   `greg.ns.cloudflare.com`. At the registrar (or in Vercel's DNS settings,
   if the domain is managed there), replace the current nameservers with the
   Cloudflare pair. Proxy status for now does not matter; keep the imported
   records as Cloudflare gave them.
4. Wait for propagation (usually minutes, up to 24h) until the dashboard
   says the zone is *Active*. Until then, nothing below works.

> The public site hosting stays on Vercel — only DNS hosting moves.

## 2. Create the tunnel and route the decoy hostname

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a
   tunnel → Cloudflared**. Name it e.g. `php2shell-laptop`.
2. Copy the **tunnel token** — a long `eyJ...` string.
3. In the tunnel's *Public Hostname* tab add one route:
   - Subdomain `files` (or any plain, boring name — wildcard
     `*.hudaw.lol` is covered by the zone's edge certificate, so the choice
     is free and no per-subdomain CRT-log enumeration reveals the decoy),
     domain `hudaw.lol`,
   - Service `HTTP`, URL `sensor:8080`.
   - Do **not** add a route for the collector. The collector must never have
     a public hostname.
4. Cloudflare creates a CNAME `<name>.hudaw.lol → <tunnel-id>.cfargotunnel.com`
   automatically for you. If you ever manage the tunnel locally
   (credentials-file mode with `cloudflared tunnel login/create`), no CNAME
   is created for you: add it manually —
   CNAME `files.hudaw.lol → <tunnel-id>.cfargotunnel.com`, proxied (orange
   cloud).
5. Zone `hudaw.lol` → **SSL/TLS → Edge Certificates** → enable **Always Use
   HTTPS**, so the decoy surface is HTTPS-only like the built-in TLS listener
   would be.

## 3. Local configuration

```bash
cp .env.example .env
$EDITOR .env
```

Fill in:

| variable | meaning |
| --- | --- |
| `FLEET_TOKEN` | shared sensor↔collector token, ≥32 chars, no whitespace |
| `NODE_ID` | sensor id, `[a-z0-9-]` (e.g. `laptop-node-1`) |
| `REGION` | sensor region label, `[a-z0-9-]` (e.g. `laptop-local`) |
| `DECOY_HOSTNAME` | the decoy hostname routed in step 2 (e.g. `files.hudaw.lol`) |
| `TUNNEL_TOKEN` | the Zero Trust tunnel token from step 2 |

`.env` is git-ignored; do not commit it.

## 4. Bring-up (3 commands)

```bash
cp .env.example .env && $EDITOR .env          # 1. identity + tokens
docker compose --profile tunnel up -d --build # 2. build & start everything
scripts/e2e_laptop.py                         # 3. end-to-end verification
```

`docker compose ps` should show `sensor`, `collector` and `cloudflared` up
(health green). `cloudflared` logs show
`Registered tunnel connection ... loc=<edge>` once the tunnel is live.

Omitting `--profile tunnel` leaves the connector out (sensor + collector
only) — useful before the tunnel exists. The e2e helper profile services
(`driver`, `probe`) are installed on demand by `scripts/e2e_laptop.py` and
exit after use; they share no published ports.

> Note: the E2E script drives traffic against `sensor:8080` *inside* the
> fleet network — it never needs the tunnel or an open route.

## 5. Verification after DNS/tunnel

From any device outside the laptop:

```bash
curl -sS https://files.hudaw.lol/ | head        # decoy index page
curl -sSI https://files.hudaw.lol/phpinfo.php   # Apache/PHP decoy headers
```

Then confirm capture on the collector (exec'd into the container, no
published port):

```bash
docker compose exec collector tail -1 /data/raw/$(date -u +%Y%m%d).jsonl
# "client": {"ip": "<your-public-ip>", "peer_ip": "<cloudflared/edge peer>", ...}
```

`client.ip` must show the visiting device's public IP, `client.peer_ip` the
tunnel-side peer — the identity split working end to end.

## 6. Daily operation

```bash
docker compose logs -f sensor                  # follow sensor logs
docker compose exec collector sh -c 'wc -l /data/raw/*.jsonl'
docker compose exec collector phptopwn-collect ioc \
    --config /tmp/collect.toml --day $(date -u +%Y%m%d) --out /data/ioc-exports
docker compose down                            # volumes persist
```

IOC artefacts land in the volume under `/data/ioc-exports/` and can be pulled
out with `docker compose cp collector:/data/ioc-exports/ioc-<day>.csv .`.

## 7. Troubleshooting

- **`cloudflared` crash-loops** — wrong/expired `TUNNEL_TOKEN`, or the tunnel
  was deleted. Re-copy the token, `docker compose up -d cloudflared`.
- **Decoy reachable but collector sees nothing** — check the sensor logged
  `fleet forwarding enabled` at boot; then
  `docker compose logs collector`. A `401`/`403` from the ingest endpoint
  means `FLEET_TOKEN`/`NODE_ID` mismatch: both sides read the same `.env`,
  and the collector's `[nodes]` map is rendered from them at startup —
  restart both containers after changing `.env`
  (`docker compose up -d --force-recreate`).
- **`client.ip` shows the connector IP instead of the client** — someone
  reached the sensor without the edge header (direct fleet-network access);
  expected inside the network, wrong if seen from a public `https://...`
  visit (then the route is sending traffic past Cloudflare's proxy).
- **Zone not Active yet** — the tunnel_Public-Hostname route needs the zone;
  until propagation finishes `files.hudaw.lol` will 5xx or NXDOMAIN.
