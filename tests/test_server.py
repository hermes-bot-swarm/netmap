#!/usr/bin/env python3
"""e2e test for the netmap server: start on :8099, POST synthetic scans, verify reads."""
import json, subprocess, sys, tempfile, time, urllib.request, os, signal

tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "test.db")
port = 8099
proc = subprocess.Popen(
    [sys.executable, "/home/opc/netmap/server/ingest.py", "--port", str(port), "--db", db],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
base = "http://127.0.0.1:%d" % port

def req(method, path, body=None):
    r = urllib.request.Request(base + path, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        return resp.status, json.loads(resp.read().decode())

try:
    # health
    for _ in range(30):
        try:
            s, j = req("GET", "/healthz"); break
        except Exception: time.sleep(0.3)
    else: raise SystemExit("server never came up")
    assert s == 200 and j["ok"] is True, (s, j)
    print("PASS healthz:", j)

    # synthetic scan 1: two LANs + a traceroute with public hops
    scan1 = {
        "agent_version": "test", "agent_os": "Test OS 1.0",
        "networks": [{
            "netkey": "192.168.1.0/24", "ifname": "eth0", "ipv4": "192.168.1.0",
            "prefix": 24, "gateway": "192.168.1.1", "gateway_mac": "aa:bb:cc:dd:ee:ff",
            "hosts_total": 254,
            "devices": [
                {"ipv4": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "TP-Link",
                 "hostname": "router.lan", "alive": True, "open_ports": [80, 443]},
                {"ipv4": "192.168.1.105", "mac": "dc:a6:32:11:22:33", "vendor": "Raspberry Pi",
                 "hostname": "raspberrypi.lan", "alive": True, "open_ports": None},
                {"ipv4": "192.168.1.120", "mac": None, "vendor": None,
                 "hostname": None, "alive": False, "open_ports": None}]},
            {"netkey": "10.0.0.0/24", "ifname": "wlan0", "ipv4": "10.0.0.0",
             "prefix": 24, "gateway": "10.0.0.1", "hosts_total": 254,
             "devices": [{"ipv4": "10.0.0.1", "mac": "00:0c:29:aa:bb:cc",
                          "vendor": "VMware", "hostname": None, "alive": True,
                          "open_ports": [22, 80]}]}],
        "traceroutes": [{"target": "1.1.1.1", "hops": [
            {"ttl": 1, "ip": "192.168.1.1", "ms": 1.2},
            {"ttl": 2, "ip": "100.64.0.1", "ms": 9.1},
            {"ttl": 3, "ip": "81.2.21.1", "ms": 12.3},
            {"ttl": 4, "ip": "1.1.1.1", "ms": 13.0}]}],
        "public_ipv4": "81.2.21.1",
        "lat": None, "lon": None, "label": "test-a"}

    # scan 2 shares one LAN and one hop to exercise upserts + edge counts
    scan2 = dict(scan1)
    scan2["networks"] = [scan1["networks"][0]]
    scan2["traceroutes"] = scan1["traceroutes"]

    for k, scan in (("1", scan1), ("2", scan2)):
        s, j = req("POST", "/api/v1/scan", scan)
        assert s == 200 and j["ok"], (s, j)
        print("PASS ingest scan%s -> %s" % (k, j))

    # geo was called server-side (ip-api) — the test box has internet; accept either
    s, j = req("GET", "/api/v1/map")
    assert s == 200
    st = j["stats"]
    print("map stats:", json.dumps(st))
    assert st["scans"] == 2, st
    assert st["networks"] == 2, st
    assert st["devices"] == 4, st
    assert st["nodes"] >= 4, st          # >= 3 hop IPs + networks (geo may fail offline)
    assert st["edges"] == 3, st          # three distinct (src,dst,ttl)
    print("PASS map aggregates (network dots geo-located: %d, hop dots: %d)" %
          (len(j["networks"]), len(j["hops"])))
    # edges resolve only if hops geo-located; report rather than fail
    resolvable = sum(1 for e in j["edges"] if e[0] in {h["ip"] for h in j["hops"]} and e[1] in {h["ip"] for h in j["hops"]})
    print("PASS edges stored=%d, geo-resolvable=%d" % (len(j["edges"]), resolvable))

    s, j = req("GET", "/api/v1/network/192.168.1.0%2F24")
    assert s == 200 and len(j["devices"]) == 3, (s, j)
    assert j["devices"][0]["open_ports"] == [80, 443]
    print("PASS network detail: gateway=%s gw_mac=%s devices=%d" %
          (j["gateway"], j["gateway_mac"], len(j["devices"])))

    s, j = req("GET", "/api/v1/lookup?ip=1.1.1.1")
    print("lookup 1.1.1.1:", {k: j.get(k) for k in ("kind", "identifier", "city", "org")})
    assert s == 200 and j["identifier"] == "1.1.1.1"

    # garbage is rejected (must run BEFORE the rate-limit test exhausts the bucket)
    for bad, why in [({"networks": []}, "empty networks"), ({"nope": 1}, "missing key")]:
        try:
            req("POST", "/api/v1/scan", bad)
            raise SystemExit("should have failed: " + why)
        except urllib.error.HTTPError as e:
            assert e.code == 400, e.code
    print("PASS malformed records rejected with 400")

    # rate limit: fire 60 more posts quickly, expect a 429 eventually
    codes = []
    try:
        for i in range(70):
            s, j = req("POST", "/api/v1/scan", scan1); codes.append(s)
    except urllib.error.HTTPError as e:
        codes.append(e.code)
    assert 429 in codes, codes[:5]
    print("PASS rate limit bites (429 at post #%d)" % (codes.index(429) + 1))

    # index page served
    with urllib.request.urlopen(base + "/", timeout=10) as r:
        html = r.read().decode()
    assert "netmap" in html and "leaflet" in html.lower()
    print("PASS map HTML served (%d bytes)" % len(html))

    print("\nALL SERVER TESTS PASSED")
finally:
    proc.send_signal(signal.SIGTERM)
    try:
        out = proc.communicate(timeout=5)[0]
        tail = out.strip().splitlines()[-8:]
        print("--- server log tail ---")
        for ln in tail: print("   ", ln)
    except Exception:
        proc.kill()
