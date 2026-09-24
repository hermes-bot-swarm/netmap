#!/usr/bin/env python3
"""
ingest.py — netmap ingest API + public map host.

Python 3.9 stdlib only. One process serves:
  GET  /                   the map (web/index.html)
  POST /api/v1/scan        scan records from agents (<= 2 MB, <= 60/min/IP)
  GET  /api/v1/map         map JSON: stats, networks, hops, ISP edges
  GET  /api/v1/network/N   one LAN in detail
  GET  /api/v1/lookup?ip=  locate a node
  GET  /api/v1/stats       totals
  GET  /api/v1/recent      recent scans
  GET  /healthz            liveness

Design notes:
  * SQLite in WAL mode; every write wrapped in one short transaction.
  * Public IPs are geolocated server-side via ip-api.com free batch endpoint
    (45 req/min, 100 addrs/batch) and cached in the `geo` table forever.
    Fields used: lat, lon, city, country, as, org. Nothing else is stored.
  * LAN data (private IPs, MACs) is stored as submitted — it only has meaning
    inside that LAN; the public map shows networks as single dots, device
    details only in the per-network drilldown.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_INDEX = os.path.join(ROOT, "web", "index.html")

DB_PATH = "/home/opc/var/lib/netmap/netmap.db"
PORT = 80
MAX_BODY = 2 * 1024 * 1024
UA = "netmap-ingest/1.0"

# ---------------------------------------------------------------- database

_db_local = threading.local()


def db():
    conn = getattr(_db_local, "conn", None)
    if conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=15000")
        _db_local.conn = conn
    return conn


def init_db():
    schema_path = os.path.join(ROOT, "server", "schema.sql")
    with open(schema_path) as f:
        db().executescript(f.read())
    db().commit()


# ---------------------------------------------------------------- geolocation

_geo_lock = threading.Lock()
_geo_missing = {}          # ip -> ts of last failed attempt
GEO_RETRY = 24 * 3600.0


def geo_lookup(ips):
    """Geolocate a list of public IPs (cache-first, ip-api batch for misses).
    Returns dict ip -> node geo dict (lat/lon/city/country/asn/org)."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result = {}
    missing = []

    import ipaddress

    def _is_public(ip):
        # RFC1918 / CGNAT / link-local / ULA are not geolocatable
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    want = [ip for ip in dict.fromkeys(ips) if ip and _is_public(ip)]

    with _geo_lock:
        for ip in want:
            row = db().execute("SELECT * FROM geo WHERE ip=?", (ip,)).fetchone()
            if row:
                result[ip] = {"lat": row["lat"], "lon": row["lon"],
                              "city": row["city"], "country": row["country"],
                              "asn": row["asn"], "org": row["org"]}
            else:
                ts = _geo_missing.get(ip, 0)
                if time.time() - ts > GEO_RETRY:
                    missing.append(ip)

    # ip-api batch: 100 per call, 45 calls/min — we stay far below
    for i in range(0, len(missing), 100):
        batch = missing[i:i + 100]
        payload = json.dumps(batch).encode()
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,lat,lon,city,country,as,org,query",
                data=payload, headers={"Content-Type": "application/json",
                                       "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=12) as r:
                rows = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            sys.stderr.write("[geo] batch failed: %s\n" % e)
            for ip in batch:
                _geo_missing[ip] = time.time()
            continue
        with _geo_lock:
            for row in rows:
                ip = row.get("query")
                if not ip:
                    continue
                if row.get("status") != "success":
                    _geo_missing[ip] = time.time()
                    continue
                asn = None
                as_str = row.get("as") or ""
                m = re.match(r"AS(\d+)", as_str)
                if m:
                    asn = int(m.group(1))
                rec = {"lat": row.get("lat"), "lon": row.get("lon"),
                       "city": row.get("city"), "country": row.get("country"),
                       "asn": asn, "org": row.get("org") or as_str[:80] or None}
                result[ip] = rec
                db().execute(
                    "INSERT OR REPLACE INTO geo(ip,lat,lon,city,country,asn,org,fetched_at)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (ip, rec["lat"], rec["lon"], rec["city"], rec["country"],
                     rec["asn"], rec["org"], now))
            db().commit()
    return result


# ---------------------------------------------------------------- ingest

def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def handle_scan(record, source_ip):
    now = iso_now()
    networks = record.get("networks") or []
    if isinstance(networks, dict):
        networks = list(networks.values())
    lat = record.get("lat") if isinstance(record.get("lat"), (int, float)) else None
    lon = record.get("lon") if isinstance(record.get("lon"), (int, float)) else None

    # geo-locate the public IP (server-side, cached)
    pub4 = record.get("public_ipv4")
    pub6 = record.get("public_ipv6")
    geo = geo_lookup([ip for ip in (pub4, pub6) if ip]) if (pub4 or pub6) else {}
    primary = pub4 or pub6
    g = geo.get(primary) or {}
    if lat is None and g.get("lat") is not None:
        lat, lon = g["lat"], g["lon"]

    conn = db()
    with conn:
        cur = conn.execute(
            "INSERT INTO scans(received_at,source_ip,agent_version,agent_os,"
            "agent_platform,public_ipv4,public_ipv6,lat,lon,alt_m,label)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (now, source_ip, record.get("agent_version"), record.get("agent_os"),
             record.get("agent_platform"), pub4, pub6,
             record.get("lat"), record.get("lon"),
             record.get("alt_m") if isinstance(record.get("alt_m"), (int, float)) else None,
             (record.get("label") or "")[:80] or None))
        scan_id = cur.lastrowid

        for net in networks:
            if not isinstance(net, dict) or not net.get("netkey"):
                continue
            netkey = str(net["netkey"])[:64]
            devices = net.get("devices") or []
            conn.execute(
                "INSERT OR REPLACE INTO networks(scan_id,netkey,ifname,ipv4,prefix,"
                "gateway,gateway_mac,hosts_total,device_count,ipv6_global) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (scan_id, netkey, net.get("ifname"), net.get("ipv4"),
                 net.get("prefix"), net.get("gateway"), net.get("gateway_mac"),
                 net.get("hosts_total"), len(devices),
                 json.dumps(net.get("ipv6") or [])))
            for d in devices:
                if not isinstance(d, dict):
                    continue
                conn.execute(
                    "INSERT INTO devices(scan_id,netkey,ipv4,ipv6,mac,hostname,"
                    "vendor,alive,open_ports,discovered_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, netkey, d.get("ipv4"), d.get("ipv6"),
                     d.get("mac"), (d.get("hostname") or "")[:120] or None,
                     (d.get("vendor") or "")[:80] or None,
                     1 if d.get("alive") else 0,
                     json.dumps(d.get("open_ports") or []) if d.get("open_ports") else None,
                     now))

        # nodes: one per network (a LAN point) + one per public traceroute hop
        for net in networks:
            if not isinstance(net, dict) or not net.get("netkey"):
                continue
            netkey = str(net["netkey"])[:64]
            node_lat, node_lon = lat, lon
            node_city, node_country = g.get("city"), g.get("country")
            conn.execute(
                "INSERT INTO nodes(kind,identifier,ip,lat,lon,city,country,asn,org,"
                "geo_at,attrs,first_seen,last_seen,scans) VALUES"
                "('network',?,?,?,?,?,?,?,?,?,?,?,?,'1')"
                " ON CONFLICT(kind,identifier) DO UPDATE SET"
                " ip=excluded.ip, lat=excluded.lat, lon=excluded.lon,"
                " city=excluded.city, country=excluded.country, asn=excluded.asn,"
                " org=excluded.org, geo_at=excluded.geo_at, attrs=excluded.attrs,"
                " last_seen=excluded.last_seen, scans=scans+1",
                (netkey, pub4, node_lat, node_lon, node_city, node_country,
                 g.get("asn"), g.get("org"), now if (node_lat is not None) else None,
                 json.dumps({"device_count": len(net.get("devices") or []),
                             "gateway": net.get("gateway"),
                             "gateway_vendor": (net.get("gateway_mac") or "")[:8],
                             "ifname": net.get("ifname"),
                             "prefix": net.get("prefix"),
                             "label": record.get("label")}),
                 now, now))

        for tr in record.get("traceroutes") or []:
            hops = tr.get("hops") or []
            import ipaddress

            def _glob(ip):
                try:
                    return ipaddress.ip_address(ip).is_global
                except ValueError:
                    return False
            pub_hops = [h for h in hops if h.get("ip") and _glob(h["ip"])]
            geo_h = geo_lookup([h["ip"] for h in pub_hops])
            for h in pub_hops:
                ip = h["ip"]
                gh = geo_h.get(ip) or {}
                conn.execute(
                    "INSERT INTO nodes(kind,identifier,ip,lat,lon,city,country,asn,"
                    "org,geo_at,attrs,first_seen,last_seen,scans) VALUES"
                    "('hop',?,?,?,?,?,?,?,?,?,?,?,?, '1')"
                    " ON CONFLICT(kind,identifier) DO UPDATE SET"
                    " ip=excluded.ip, lat=COALESCE(excluded.lat,lat),"
                    " lon=COALESCE(excluded.lon,lon),"
                    " city=COALESCE(excluded.city,city),"
                    " country=COALESCE(excluded.country,country),"
                    " asn=COALESCE(excluded.asn,asn), org=COALESCE(excluded.org,org),"
                    " geo_at=COALESCE(excluded.geo_at,geo_at),"
                    " last_seen=excluded.last_seen, scans=scans+1",
                    (ip, ip, gh.get("lat"), gh.get("lon"), gh.get("city"),
                     gh.get("country"), gh.get("asn"), gh.get("org"),
                     now if gh.get("lat") is not None else None,
                     json.dumps({"ms": h.get("ms"), "target": tr.get("target")}),
                     now, now))
            # ISP edges: consecutive hops in the path
            for i in range(1, len(hops)):
                a, b = hops[i - 1], hops[i]
                if not a.get("ip") or not b.get("ip") or a["ip"] == b["ip"]:
                    continue
                conn.execute(
                    "INSERT INTO edges(src,dst,ttl,first_seen,last_seen,seen_count)"
                    " VALUES(?,?,?,?,?,1)"
                    " ON CONFLICT(src,dst,ttl) DO UPDATE SET"
                    " last_seen=excluded.last_seen, seen_count=seen_count+1",
                    (a["ip"], b["ip"], b.get("ttl") or i, now, now))

    n_hops = sum(len((t or {}).get("hops") or []) for t in record.get("traceroutes") or [])
    return {"ok": True, "scan_id": scan_id, "networks": len(networks),
            "devices_stored": sum(len(n.get("devices") or []) for n in networks),
            "hops": n_hops}


# ---------------------------------------------------------------- reads

def jdump(obj):
    return json.dumps(obj).encode("utf-8")


def map_payload():
    conn = db()
    stats = {
        "scans": conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"],
        "networks": conn.execute(
            "SELECT COUNT(DISTINCT netkey) c FROM networks").fetchone()["c"],
        "devices": conn.execute(
            "SELECT COUNT(DISTINCT netkey || '|' || COALESCE(mac, ipv4, ipv6)) c "
            "FROM devices").fetchone()["c"],
        "nodes": conn.execute("SELECT COUNT(*) c FROM nodes").fetchone()["c"],
        "edges": conn.execute("SELECT COUNT(*) c FROM edges").fetchone()["c"],
        "last_scan": conn.execute(
            "SELECT received_at FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone(),
    }
    if stats["last_scan"]:
        stats["last_scan"] = stats["last_scan"]["received_at"]

    networks = []
    for r in conn.execute(
            "SELECT * FROM nodes WHERE kind='network' AND lat IS NOT NULL "
            "ORDER BY last_seen DESC LIMIT 5000"):
        attrs = {}
        try:
            attrs = json.loads(r["attrs"] or "{}")
        except Exception:
            pass
        networks.append({
            "id": r["identifier"], "ip": r["ip"], "lat": r["lat"], "lon": r["lon"],
            "city": r["city"], "country": r["country"], "org": r["org"],
            "asn": r["asn"], "last_seen": r["last_seen"],
            "devices": attrs.get("device_count"), "label": attrs.get("label"),
            "gateway": attrs.get("gateway"), "prefix": attrs.get("prefix")})

    hops = []
    for r in conn.execute(
            "SELECT * FROM nodes WHERE kind='hop' AND lat IS NOT NULL "
            "ORDER BY last_seen DESC LIMIT 20000"):
        hops.append({"ip": r["identifier"], "lat": r["lat"], "lon": r["lon"],
                     "city": r["city"], "country": r["country"], "asn": r["asn"],
                     "org": r["org"]})

    hopset = {h["ip"] for h in hops}
    edges = []
    for r in conn.execute(
            "SELECT src,dst,ttl,seen_count FROM edges "
            "ORDER BY seen_count DESC LIMIT 60000"):
        if r["src"] in hopset and r["dst"] in hopset:
            edges.append([r["src"], r["dst"], r["ttl"], r["seen_count"]])

    return {"stats": stats, "networks": networks, "hops": hops, "edges": edges}


def network_detail(netkey):
    conn = db()
    latest = conn.execute(
        "SELECT * FROM networks WHERE netkey=? ORDER BY scan_id DESC LIMIT 1",
        (netkey,)).fetchone()
    if not latest:
        return None
    devices = [dict(d) for d in conn.execute(
        "SELECT ipv4,ipv6,mac,hostname,vendor,alive,open_ports FROM devices "
        "WHERE netkey=? AND scan_id=? ORDER BY ipv4",
        (netkey, latest["scan_id"]))]
    for d in devices:
        try:
            d["open_ports"] = json.loads(d["open_ports"]) if d["open_ports"] else []
        except Exception:
            d["open_ports"] = []
    out = dict(latest)
    out["devices"] = devices
    return out


# ---------------------------------------------------------------- http

_rate = {}
_rate_lock = threading.Lock()


def rate_ok(ip):
    now = time.time()
    with _rate_lock:
        bucket = _rate.setdefault(ip, [])
        bucket[:] = [t for t in bucket if now - t < 60]
        if len(bucket) >= 60:
            return False
        bucket.append(now)
        if len(_rate) > 10000:
            _rate.clear()
        return True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "netmap/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[http] %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, jdump(obj), "application/json")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if path in ("/", "/index.html", "/map"):
                with open(WEB_INDEX, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/healthz":
                return self._json(200, {"ok": True, "time": iso_now()})
            if path == "/api/v1/map":
                return self._json(200, map_payload())
            if path == "/api/v1/stats":
                return self._json(200, map_payload()["stats"])
            if path == "/api/v1/recent":
                rows = [dict(r) for r in db().execute(
                    "SELECT scan_id,received_at,source_ip,agent_os,public_ipv4,"
                    "public_ipv6,label FROM scans ORDER BY scan_id DESC LIMIT 50")]
                return self._json(200, {"scans": rows})
            if path.startswith("/api/v1/network/"):
                key = urllib.parse.unquote(path[len("/api/v1/network/"):])
                det = network_detail(key)
                return self._json(200, det) if det else self._json(404, {"error": "unknown network"})
            if path == "/api/v1/lookup":
                q = (qs.get("ip") or [None])[0]
                if not q:
                    return self._json(400, {"error": "ip query param required"})
                row = db().execute(
                    "SELECT * FROM nodes WHERE identifier=? OR ip=? ORDER BY last_seen DESC LIMIT 1",
                    (q, q)).fetchone()
                if not row:
                    return self._json(404, {"error": "not found"})
                return self._json(200, dict(row))
            return self._json(404, {"error": "not found"})
        except BrokenPipeError:
            pass
        except Exception as e:
            sys.stderr.write("[http] GET error: %r\n" % e)
            try:
                self._json(500, {"error": "internal"})
            except Exception:
                pass

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/v1/scan":
            return self._json(404, {"error": "not found"})
        src = self.client_address[0]
        if not rate_ok(src):
            return self._json(429, {"error": "rate limited (60/min)"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return self._json(413, {"error": "body must be 1B..2MB"})
        body = self.rfile.read(n)
        try:
            record = json.loads(body.decode("utf-8"))
        except Exception:
            return self._json(400, {"error": "invalid JSON"})
        if not isinstance(record, dict) or not record.get("networks"):
            return self._json(400, {"error": "record.networks required"})
        try:
            result = handle_scan(record, src)
            return self._json(200, result)
        except Exception as e:
            sys.stderr.write("[ingest] error: %r\n" % e)
            return self._json(500, {"error": "ingest failed"})


def main():
    global DB_PATH, PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    DB_PATH, PORT = args.db, args.port
    init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    sys.stderr.write("[ingest] listening on :%d db=%s\n" % (PORT, DB_PATH))
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
