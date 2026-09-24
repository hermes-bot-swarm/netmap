# netmap — crowdsourced map of the internet, one LAN at a time

A tiny, fully self-hostable stack that turns volunteer network scans into a public,
layered map of the internet: **every network that reports in becomes a point on the
world map** (geolocated by its public IP), with its LAN contents attached — devices,
MAC addresses, vendors, hostnames, IPv6 — and every traceroute becomes **ISP path
edges** between hops. Enough scanners → a bottom-up picture of real ISP topologies,
home/office LAN shapes, and the global internet.

Completely public: the map and API are open, the data is crowd-contributed.

```
┌──────────────────────────┐        HTTPS POST /api/v1/scan       ┌─────────────────────────────┐
│ netmap_agent.py          │ ───────────────────────────────────► │ ingest.py on VPS            │
│ (runs on volunteer PCs)  │        JSON scan record              │  · validate + rate-limit    │
│  · interface discovery   │                                      │  · public-IP geolocation    │
│  · ARP / ping / IPv6 ND  │                                      │    (cached, ip-api batch)   │
│  · hostname + OUI vendor │                                      │  · SQLite (WAL): scans,     │
│  · traceroute → hop list │                                      │    devices, nodes, edges    │
└──────────────────────────┘                                      └──────────┬──────────────────┘
                                                                             │ GET /api/v1/map
                                                                             ▼
                                                                  ┌─────────────────────────────┐
                                                                  │ web/index.html              │
                                                                  │ Leaflet + OSM/Carto tiles   │
                                                                  │  · network dots (device n)  │
                                                                  │  · ISP hop paths (edges)    │
                                                                  │  · per-LAN drilldown        │
                                                                  └─────────────────────────────┘
```

## Contents

| Path | What it is |
|---|---|
| `agent/netmap_agent.py` | The scanner. Single file, **Python 3.8+ stdlib only** — no pip. Windows / macOS / Linux. |
| `server/ingest.py` | Ingest API + map host. Python 3.9 stdlib only (http.server + sqlite3). |
| `server/schema.sql` | Database schema. |
| `web/index.html` | The public map (Leaflet, dark tiles, layered). |
| `deploy/netmap-ingest.service` | systemd **user** unit for the VPS. |
| `deploy/install.sh` | One-shot VPS deploy (firewall, sysctl, unit). |

## Run the agent (volunteers)

```
python3 netmap_agent.py                     # scan my networks, submit to the public map
python3 netmap_agent.py --dry-run           # scan, print JSON, submit nothing
python3 netmap_agent.py --no-traceroute     # skip ISP path discovery
python3 netmap_agent.py --interval 3600     # keep scanning every hour
python3 netmap_agent.py --lat 51.5 --lon -0.1 --alt 35 --label home   # optional precise placement
python3 netmap_agent.py --ports 22,80,443,445,3389,8080   # light port fingerprint of LAN hosts
```

What it gathers (all from the machine you run it on, nothing privileged):

- **Interfaces / subnets** — every IPv4 + global IPv6, prefix lengths, interface names, own MACs
- **LAN devices** — via ping sweep + UDP/9 ARP-poke + the OS neighbor table (finds hosts even when
  they drop ICMP), MAC address, OUI vendor (builtin table + cached IEEE oui.txt), mDNS/reverse-DNS
  hostname (best effort), optional TCP port fingerprint
- **Gateway** — default route IP + MAC + hostname
- **Traceroute** — hop-by-hop path to the internet (gateway → carrier NAT → ISP core → backbones);
  this is what draws the ISP lines on the map
- **Public identity** — your public IPv4/IPv6 (via ipify); the **server** geolocates it (city level)
- **Location** — server-side IP geolocation by default; pass `--lat/--lon/--alt` for precision.
  Nothing auto-geolocates your device without your say-so.

## API

| Endpoint | Purpose |
|---|---|
| `GET /` | The map (also `GET /api/v1/map` for its raw JSON: stats + networks + hops + edges) |
| `POST /api/v1/scan` | Submit a scan record (JSON, ≤2 MB, ≤60/min per source IP) |
| `GET /api/v1/network/<netkey>` | Full detail of one LAN: devices, vendors, hostnames, hops |
| `GET /api/v1/lookup?ip=<ip\|netkey>` | Locate one node on the map |
| `GET /api/v1/stats` | Totals |
| `GET /api/v1/recent` | Recent scans |
| `GET /healthz` | Liveness |

## Privacy & ethics — read this

- **Only scan networks you own or have explicit permission to scan.** The agent is passive-grade:
  ICMP/UDP pokes, neighbor-table reads, unprivileged traceroute. No stealth scans, no root.
- The agent **never sends your Wi-Fi password or any credentials anywhere**.
- LAN device data (private IPs like `192.168.x.x`, MACs of devices on that LAN) is only meaningful
  inside that LAN and is how the "what do LANs look like" layer works. If a hostname embeds a
  person's name, it will be uploaded — review with `--dry-run` first.
- **Location**: the public IP is geolocated server-side (city-level, that's the resolution the map
  has). Don't pass `--lat/--lon` unless you want your dot exactly there.
- Every scan is attributed to the submitting IP and the map is public — submit from networks you're
  authorized to represent.

## Honest limitations (MVP scope)

- Devices that block ICMP **and** fail the UDP ARP-poke won't appear (AP-isolation Wi-Fi, some IoT).
- Carrier-grade NAT (100.64/10) and ISP-internal hops are stored but can't be geolocated — the map
  draws only edges where both hop IPs geolocate; MPLS/ICMP-rate-limited tracers show gaps.
- IP geolocation is city-level and sometimes wrong; that's a property of geo-IP, not this stack.
- Altitude is optional and client-supplied (`--alt`); nothing infers it automatically yet.

## Deploy your own server

See `deploy/install.sh` (Oracle Linux-flavoured; adapt the firewall lines). The server is one
stdlib Python process + one SQLite file — a $0 VPS handles tens of thousands of scans.

## License

MIT — see `LICENSE`.
