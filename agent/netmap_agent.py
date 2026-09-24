#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netmap_agent.py — crowdsourced network scanner for the public internet map.

Single file, Python 3.8+ STANDARD LIBRARY ONLY (no pip). Works on Windows,
macOS and Linux by shelling out to each OS's native tools and reading
/proc, /sys, ip, arp, route, netsh and getmac.

What it does:
  1. Discovers every local interface: IPv4, global IPv6, MAC, prefix.
  2. Maps each IPv4 LAN: ping sweep + UDP/9 "wake" packets to farm ARP,
     then reads the OS neighbor table -> live hosts, MACs, OUI vendors,
     mDNS/reverse-DNS hostnames, optional light TCP port fingerprint.
  3. Finds the default gateway (IP + MAC + hostname).
  4. Traceroutes to the internet (UDP probes, OS par UDP-TTL or parse
     traceroute/tracepath/tracert output) -> hop-by-hop ISP path.
  5. Discovers the public IPv4/IPv6 (ipify), submits everything as one
     JSON record to the netmap server, which geolocates the public IP.

Nothing privileged is required: no raw sockets, no root, no admin.
Only run this on networks you own or have permission to scan.
"""

import argparse
import concurrent.futures
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.request

__version__ = "1.0.0"

DEFAULT_SERVER = "http://193.123.176.104"
USER_AGENT = "netmap-agent/" + __version__

# --------------------------------------------------------------------------
# tiny utils
# --------------------------------------------------------------------------

def log(msg):
    sys.stderr.write("[netmap] %s\n" % msg)
    sys.stderr.flush()


def run(cmd, timeout=8):
    """Run a command, return stdout ('' on any failure). Never raises."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout)
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def ping_sweep(hosts, timeout=0.6, workers=64):
    """Threaded ping sweep — returns set of hosts that answered."""
    alive = set()

    def _one(h):
        return h if ping(h, timeout=timeout) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(_one, hosts):
            if r:
                alive.add(r)
    return alive


def ping(host, timeout=1.0, size=32):
    """One ICMP ping via the OS binary. Returns True if it answered."""
    sysname = platform.system()
    if sysname == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, round(timeout)))), host]
    out = run(cmd, timeout=timeout + 2)
    # some hosts reply with 'unreachable' text; require an actual reply line
    if sysname == "Windows":
        return ("TTL=" in out) or ("ttl=" in out)
    return ("bytes from" in out) or ("time=" in out)


def safe_ip(s):
    """Light sanity check for an IPv4/IPv6 string."""
    if not s or len(s) > 45:
        return None
    if not re.match(r"^[0-9a-fA-F.:]+$", s):
        return None
    return s


def mac_norm(s):
    if not s:
        return None
    s = s.strip().lower().replace("-", ":")
    if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", s):
        return s
    return None


# --------------------------------------------------------------------------
# OUI vendor lookup (small builtin table + optional cached IEEE list)
# --------------------------------------------------------------------------

_BUILTIN_OUI = {
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:d8": "Google",
    "00:1b:63": "Apple", "ac:de:48": "Apple", "f0:18:98": "Apple",
    "a4:83:e7": "Apple", "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:0c:29": "VMware", "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5d": "Microsoft (Hyper-V)", "00:03:93": "Parallels",
    "b8:ca:3a": "ABIT", "00:1a:2b": "Ayecom",
    "00:50:f1": "Netgear", "a0:40:a0": "Netgear", "9c:3d:cf": "Netgear",
    "00:18:4d": "Netgear", "b0:39:56": "Netgear",
    "c8:d7:19": "TP-Link", "50:c7:bf": "TP-Link", "ac:84:c6": "TP-Link",
    "f4:ec:38": "ASUSTek", "04:d4:c4": "ASUSTek", "14:dd:a9": "ASUSTek",
    "00:1f:33": "Netgear", "24:4b:fe": "ASUSTek", "ac:9e:17": "ASUSTek",
    "84:16:f9": "TP-Link", "98:da:c4": "TP-Link", "ec:08:6b": "ASUSTek",
    "00:26:5a": "Gamma Solution", "00:1f:5b": "Apple",
    "3c:22:fb": "Apple", "8c:85:90": "Apple", "d0:03:4b": "Apple",
    "44:d9:e7": "Intel", "3c:97:0e": "Wistron", "00:0d:3a": "Microsoft (Azure)",
    "00:1d:7e": "Cisco", "00:23:04": "Cisco", "f8:66:f2": "D-Link",
    "00:05:69": "VMware", "00:1c:14": "VMware", "d8:bb:c1": "AzureWave",
    "00:e0:4c": "Realtek", "52:11:22": "Locally administered",
    "02:42:ac": "Docker", "02:11:32": "Locally administered",
}

_oui_cache = {"loaded": False, "table": {}}


def _load_oui_file():
    """Load a cached IEEE oui.txt (created on first successful download)."""
    if _oui_cache["loaded"]:
        return
    _oui_cache["loaded"] = True
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt")
    table = {}
    try:
        if os.path.exists(path) and os.path.getsize(path) > 100000:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    m = re.match(r"^\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    if m:
                        table[m.group(1).replace("-", ":").lower()] = m.group(2).strip()[:60]
    except Exception:
        pass
    _oui_cache["table"] = table


def vendor_for(mac):
    if not mac:
        return None
    prefix = mac[:8]
    _load_oui_file()
    v = _oui_cache["table"].get(prefix) or _BUILTIN_OUI.get(prefix)
    if not v and int(mac[0:2], 16) & 0x02:
        v = "Locally administered"
    return v


# --------------------------------------------------------------------------
# interface discovery
# --------------------------------------------------------------------------

def _linux_interfaces():
    out = {}

    # names via /sys/class/net
    try:
        names = os.listdir("/sys/class/net")
    except Exception:
        names = []
    for name in names:
        mac = None
        try:
            with open("/sys/class/net/%s/address" % name) as f:
                mac = mac_norm(f.read().strip())
        except Exception:
            pass
        out[name] = {"ifname": name, "mac": mac, "ipv4": None, "prefix": None,
                     "ipv6": []}

    # addresses via /proc/net (fIB truncates v6 but flags global vs link-local ok)
    try:
        with open("/proc/net/fib_trie") as f:
            cur = None
            for line in f:
                m = re.match(r"\s+--\s+(\S+)(?:/(\d+))?", line)
                if m:
                    ip = safe_ip(m.group(1))
                    if ip and ":" not in ip:
                        cur = (ip, int(m.group(2) or 32))
                    continue
                m = re.match(r"\s+\|--\s+(\S+)", line)
                if m and m.group(1) in ("LOCAL", "link"):
                    pass
    except Exception:
        pass

    # prefer `ip -j` when available (v4 + v6 + prefix, reliable)
    if shutil.which("ip"):
        js = run(["ip", "-j", "-4", "addr"], 6)
        try:
            for itf in json.loads(js):
                name = itf.get("ifname")
                if name not in out:
                    out[name] = {"ifname": name, "mac": mac_norm(itf.get("address")),
                                 "ipv4": None, "prefix": None, "ipv6": []}
                for a in itf.get("addr_info", []):
                    ip = safe_ip(a.get("local"))
                    if ip:
                        out[name]["ipv4"] = ip
                        out[name]["prefix"] = a.get("prefixlen", 24)
        except Exception:
            pass
        js = run(["ip", "-j", "-6", "addr"], 6)
        try:
            for itf in json.loads(js):
                name = itf.get("ifname")
                if name in out:
                    for a in itf.get("addr_info", []):
                        ip = safe_ip(a.get("local"))
                        if ip and not ip.startswith("fe80"):
                            out[name]["ipv6"].append(
                                {"ip": ip, "prefix": a.get("prefixlen", 64)})
        except Exception:
            pass
    else:
        # fallback: /proc/net parsing
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) > 8 and p[1] == "00000000":
                        ipn = struct.unpack("<I", bytes.fromhex(p[7]))[0]
                        ip = socket.inet_ntoa(struct.pack("!I", ipn))
                        if p[0] in out:
                            out[p[0]]["ipv4"] = ip
                            out[p[0]]["prefix"] = None
        except Exception:
            pass
        try:
            with open("/proc/net/if_inet6") as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 4:
                        ipn = bytes.fromhex(p[0])
                        ip = socket.inet_ntop(socket.AF_INET6, ipn)
                        if not ip.startswith("fe80") and p[5] != "1" and p[0] in out:
                            out[p[5]]["ipv6"].append(
                                {"ip": safe_ip(ip), "prefix": int(p[2])})
        except Exception:
            pass

    return [v for v in out.values()]


def _macos_interfaces():
    out = []
    # IPv4 via ifconfig parsing
    txt = run(["ifconfig"], 6)
    cur = None
    for line in txt.splitlines():
        m = re.match(r"^(\S+):\s+flags", line)
        if m:
            cur = {"ifname": m.group(1), "mac": None, "ipv4": None,
                   "prefix": None, "ipv6": []}
            out.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"ether\s+([0-9a-fA-F:]{17})", line)
        if m:
            cur["mac"] = mac_norm(m.group(1))
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+.*\s+0x([0-9a-fA-F]+)\s*$", line)
        if m:
            cur["ipv4"] = safe_ip(m.group(1))
            try:
                mask = int(m.group(2), 16)
                cur["prefix"] = bin(mask & 0xFFFFFFFF).count("1")
            except Exception:
                cur["prefix"] = 24
        m = re.search(r"inet6\s+(\S+)%?\S*\s+prefixlen\s+(\d+)", line)
        if m and not m.group(1).startswith("fe80"):
            cur["ipv6"].append({"ip": safe_ip(m.group(1)), "prefix": int(m.group(2))})
    return out


def _windows_interfaces():
    out = []
    txt = run(["ipconfig", "/all"], 10)
    cur = None
    for line in txt.splitlines():
        if not line.strip():
            continue
        m = re.match(r"^(.*?)adapter (.*?):\s*$", line)
        if not m:
            m = re.match(r"^(\S.*):\s*$", line)
        if m and ("adapter" in line or line.endswith(":")):
            cur = {"ifname": m.group(1).strip(), "mac": None, "ipv4": None,
                   "prefix": 24, "ipv6": []}
            out.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"([0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5})", line)
        if m and "physical" in line.lower():
            cur["mac"] = mac_norm(m.group(1))
        m = re.search(r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            m = re.search(r"IP Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            cur["ipv4"] = safe_ip(m.group(1))
        m = re.search(r"IPv6 Address[.\s]*:\s*([0-9a-fA-F:]+)", line)
        if m and not m.group(1).lower().startswith("fe80"):
            cur["ipv6"].append({"ip": safe_ip(m.group(1)), "prefix": 64})
    return [o for o in out if o.get("ipv4") or o.get("ipv6") or o.get("mac")]


def discover_interfaces():
    sysname = platform.system()
    if sysname == "Linux":
        itfs = _linux_interfaces()
    elif sysname == "Darwin":
        itfs = _macos_interfaces()
    else:
        itfs = _windows_interfaces()
    res = []
    for i in itfs:
        if not i.get("ipv4") and not i.get("ipv6"):
            continue
        i.setdefault("ipv6", [])
        res.append(i)
    return res


# --------------------------------------------------------------------------
# ARP / neighbor table (the LAN device workhorse)
# --------------------------------------------------------------------------

def read_neighbor_table():
    """Return dict ip -> mac from the OS ARP/neighbor table."""
    table = {}
    sysname = platform.system()

    if sysname == "Linux" and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 6:
                        ip = safe_ip(p[0])
                        mac = mac_norm(p[3])
                        if ip and mac:
                            table[ip] = mac
        except Exception:
            pass
    if shutil.which("ip"):
        js = run(["ip", "-j", "neigh"], 6)
        try:
            for n in json.loads(js):
                ip = safe_ip(n.get("dst"))
                mac = mac_norm(n.get("lladdr") or "")
                if ip and mac:
                    table[ip] = mac
        except Exception:
            pass

    if sysname == "Darwin" or (sysname != "Windows" and not table):
        out = run(["arp", "-an"], 6)
        for m in re.finditer(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+([0-9a-fA-F:]{17})", out):
            table[safe_ip(m.group(1))] = mac_norm(m.group(2))

    if sysname == "Windows":
        out = run(["arp", "-a"], 10)
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5})", out):
            table[safe_ip(m.group(1))] = mac_norm(m.group(2))

    return table


def arp_poke(host):
    """Send UDP packets to a closed port -> forces an ARP resolution."""
    for port in (9, 139, 5000):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.2)
            s.sendto(b"netmap-probe", (host, port))
            s.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# hostnames (mDNS / reverse DNS / NetBIOS)
# --------------------------------------------------------------------------

_hostname_cache = {}


def hostname_for(ip, quick=False):
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    name = None
    # gethostbyaddr has no timeout knob -> bound it with a worker thread
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            name = fut.result(timeout=2.5)[0]
    except Exception:
        name = None
    if not name:
        # mDNS / avahi / NetBIOS best effort
        if shutil.which("avahi-resolve"):
            out = run(["avahi-resolve", "-a", ip], 4)
            m = re.search(r"\s(\S+)\s*$", out.strip())
            if m:
                name = m.group(1)
        if not name and shutil.which("nmblookup"):
            out = run(["nmblookup", "-A", ip], 4)
            names = re.findall(r"\t(\S+)\s+<00>", out)
            for n in names:
                if n.lower() not in ("workgroup", "__msbrowse__"):
                    name = n
                    break
    _hostname_cache[ip] = name
    return name


# --------------------------------------------------------------------------
# default gateways
# --------------------------------------------------------------------------

def default_gateways():
    gws = []  # list of {"ifname":..., "ip":...}
    sysname = platform.system()
    if sysname == "Windows":
        out = run(["route", "print", "-4"], 8)
        for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)",
                             out, re.M):
            gws.append({"ifname": m.group(2), "ip": safe_ip(m.group(1))})
    elif shutil.which("ip"):
        js = run(["ip", "-j", "route"], 6)
        try:
            for r in json.loads(js):
                if r.get("dst") == "default":
                    gws.append({"ifname": r.get("dev"),
                                "ip": safe_ip(r.get("gateway"))})
        except Exception:
            pass
        if not gws:
            out = run(["ip", "route", "show", "default"], 6)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+) dev (\S+)", out)
            if m:
                gws.append({"ifname": m.group(2), "ip": safe_ip(m.group(1))})
    else:
        out = run(["route", "-n", "get", "default"], 6)
        m = re.search(r"gateway:\s+(\d+\.\d+\.\d+\.\d+)", out)
        n = re.search(r"interface:\s+(\S+)", out)
        if m:
            gws.append({"ifname": n.group(1) if n else None,
                        "ip": safe_ip(m.group(1))})
    seen, res = set(), []
    for g in gws:
        if g["ip"] and g["ip"] not in seen:
            seen.add(g["ip"])
            res.append(g)
    return res


# --------------------------------------------------------------------------
# LAN mapping
# --------------------------------------------------------------------------

PRIVATE_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)")


def is_private_v4(ip):
    return bool(ip and PRIVATE_RE.match(ip))


def net_and_broadcast(ip, prefix):
    """Very small IPv4 prefix math (prefix <= 32)."""
    try:
        packed = socket.inet_aton(ip)
        n = struct.unpack("!I", packed)[0]
        if prefix <= 0 or prefix > 32:
            prefix = 24
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net = n & mask
        bc = net | (~mask & 0xFFFFFFFF)
        fmt = lambda x: socket.inet_ntoa(struct.pack("!I", x))
        return fmt(net), fmt(bc), prefix
    except Exception:
        return None, None, 24


def expand_hosts(net_ip, prefix, cap=1024):
    """All candidate host IPs for a subnet, capped for huge prefixes."""
    n = struct.unpack("!I", socket.inet_aton(net_ip))[0]
    total = 1 << (32 - prefix)
    if total > cap + 2:
        # too big to sweep: just probe common low offsets + our own IP neighborhood
        candidates = [n + i for i in (1, 2, 3, 100, 101, 254)]
        return [socket.inet_ntoa(struct.pack("!I", c)) for c in candidates]
    return [socket.inet_ntoa(struct.pack("!I", n + i)) for i in range(1, total - 1)]


def scan_lan(ipv4, prefix, ifname, deep_ports, do_trace):
    """Full sweep of one IPv4 subnet. Returns a network dict."""
    net_ip, bc, prefix = net_and_broadcast(ipv4, prefix)
    if not net_ip:
        return None
    hosts = [h for h in expand_hosts(net_ip, prefix)
             if h != ipv4 and is_private_v4(h)]
    total = len(hosts)
    log("LAN %s/%d (%s): probing %d addresses..." % (net_ip, prefix, ifname, total))

    neigh_before = read_neighbor_table()

    # wake pass: sequential quick pokes (UDP, ~instant)
    for i, h in enumerate(hosts):
        arp_poke(h)
        if i % 32 == 31:
            time.sleep(0.05)  # tiny pacing

    # threaded ping pass (finds hosts that drop gratuitous ARP)
    alive = ping_sweep(hosts[:1024], timeout=0.6)

    time.sleep(1.0)  # let ARP entries settle
    neigh = read_neighbor_table()

    found = {}
    for ip, mac in neigh.items():
        if is_private_v4(ip) and ip != ipv4 and ip != bc and ip != net_ip:
            found[ip] = mac
    # keep prior knowledge too
    for ip, mac in neigh_before.items():
        found.setdefault(ip, mac)

    devices = []
    for ip in sorted(found, key=lambda x: tuple(int(o) for o in x.split("."))):
        mac = found.get(ip)
        dev = {
            "ipv4": ip,
            "ipv6": None,
            "mac": mac,
            "vendor": vendor_for(mac),
            "hostname": hostname_for(ip),
            "alive": ip in neigh and neigh.get(ip) == mac,
            "open_ports": None,
        }
        devices.append(dev)

    if deep_ports:
        for dev in devices:
            ports = tcp_probe(dev["ipv4"], deep_ports)
            if ports:
                dev["open_ports"] = ports

    # router usually answers ping even when silent in ARP dump
    return {
        "netkey": "%s/%d" % (net_ip, prefix),
        "ifname": ifname,
        "ipv4": net_ip,
        "prefix": prefix,
        "hosts_total": total,
        "devices": devices,
        "gateway": None,   # filled by caller
        "gateway_mac": None,
    }


def tcp_probe(ip, ports, timeout=0.35):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


# --------------------------------------------------------------------------
# traceroute (ISP path discovery)
# --------------------------------------------------------------------------

def traceroute(target="1.1.1.1", max_hops=15, timeout=2):
    """Traceroute using OS tools; returns list of hop dicts (private hops kept,
    marked so the server can classify them)."""
    hops = []
    sysname = platform.system()
    if sysname == "Windows":
        out = run(["tracert", "-d", "-h", str(max_hops), "-w",
                   str(int(timeout * 1000)), target], 60)
        for line in out.splitlines():
            m = re.match(r"^\s*(\d{1,2})\s+(\d+\S*\s+\d+\S*\s+\d+\S*)\s+(\S+)", line)
            if not m:
                m = re.match(r"^\s*(\d{1,2})\s+\*+\s+(\S+)", line)
                if m:
                    hops.append({"ttl": int(m.group(1)), "ip": None, "ms": None})
                continue
            rtt = None
            times = re.findall(r"(\d+)\s*ms", m.group(2))
            if times:
                rtt = min(int(t) for t in times)
            hops.append({"ttl": int(m.group(1)), "ip": safe_ip(m.group(3)), "ms": rtt})
    else:
        for tool, args in (("tracepath", ["-n", "-m", str(max_hops), target]),
                           ("traceroute", ["-n", "-m", str(max_hops), "-w", "2", target])):
            if not shutil.which(tool):
                continue
            out = run([tool] + args, 60)
            for line in out.splitlines():
                m = re.match(r"^\s*(\d{1,2})[:.]?\s+(.*)$", line)
                if not m:
                    continue
                ttl = int(m.group(1))
                rest = m.group(2)
                ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
                ms = None
                tms = re.findall(r"([0-9.]+)\s*ms", rest)
                if tms:
                    ms = min(float(t) for t in tms)
                ip = safe_ip(ipm.group(1)) if ipm else None
                if ttl <= max_hops:
                    hops.append({"ttl": ttl, "ip": ip, "ms": ms})
            if hops:
                break
    # dedupe consecutive duplicates, cap length
    cleaned = []
    for h in hops:
        if cleaned and cleaned[-1]["ip"] == h["ip"] and h["ip"] is None:
            continue
        cleaned.append(h)
        if len(cleaned) >= max_hops:
            break
    return cleaned


# --------------------------------------------------------------------------
# public IP discovery
# --------------------------------------------------------------------------

def http_get(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def public_ips():
    v4 = v6 = None
    try:
        v4 = safe_ip(http_get("https://api.ipify.org", 8).strip())
    except Exception:
        pass
    try:
        v6 = safe_ip(http_get("https://api64.ipify.org", 8).strip())
        if v6 and ":" not in v6:
            v6 = None
    except Exception:
        pass
    if v4 and ":" in v4:
        v4 = None
    return v4, v6


# --------------------------------------------------------------------------
# payload assembly + submission
# --------------------------------------------------------------------------

def build_payload(args):
    sysname = platform.system()
    record = {
        "agent_version": __version__,
        "agent_os": "%s %s" % (platform.system(), platform.release()),
        "agent_platform": platform.platform()[:120],
        "timestamp": int(time.time()),
        "interfaces": [],
        "networks": [],
        "traceroutes": [],
        "public_ipv4": None,
        "public_ipv6": None,
        "lat": args.lat,
        "lon": args.lon,
        "alt_m": args.alt,
        "label": args.label,
    }

    interfaces = discover_interfaces()
    record["interfaces"] = interfaces

    gateways = default_gateways()
    neigh = read_neighbor_table()

    seen_netkeys = set()
    for gw in gateways:
        gw_ip = gw["ip"]
        iface = next((i for i in interfaces
                      if i.get("ipv4") and is_private_v4(i["ipv4"])
                      and (gw.get("ifname") == i.get("ifname") or not gw.get("ifname"))),
                     None)
        if not iface:
            # gateway without a matching private interface: attach to first private
            iface = next((i for i in interfaces
                          if i.get("ipv4") and is_private_v4(i["ipv4"])), None)
        if not iface:
            continue
        pre = net_and_broadcast(iface["ipv4"], iface.get("prefix") or 24)
        if not pre or not pre[0]:
            continue
        candidate = "%s/%d" % (pre[0], pre[2])
        if candidate in seen_netkeys:
            continue
        net = scan_lan(iface["ipv4"], iface.get("prefix") or 24,
                       iface["ifname"], args.ports, do_trace=args.no_traceroute is False)
        if not net:
            continue
        seen_netkeys.add(net["netkey"])
        net["gateway"] = gw_ip
        net["gateway_mac"] = neigh.get(gw_ip) or read_neighbor_table().get(gw_ip)
        net["gateway_hostname"] = hostname_for(gw_ip)
        if gw_ip and not any(d["ipv4"] == gw_ip for d in net["devices"]):
            net["devices"].insert(0, {
                "ipv4": gw_ip, "ipv6": None, "mac": net["gateway_mac"],
                "vendor": vendor_for(net["gateway_mac"]),
                "hostname": net.get("gateway_hostname"),
                "alive": True, "open_ports": None, "role": "gateway"})
        record["networks"].append(net)

    # any remaining private IPv4 interfaces not already covered via the gateway loop
    for iface in interfaces:
        if not iface.get("ipv4") or not is_private_v4(iface["ipv4"]):
            continue
        pre = net_and_broadcast(iface["ipv4"], iface.get("prefix") or 24)
        if not pre or not pre[0]:
            continue
        candidate = "%s/%d" % (pre[0], pre[2])
        if candidate in seen_netkeys:
            continue
        net = scan_lan(iface["ipv4"], iface.get("prefix") or 24,
                       iface["ifname"], [], do_trace=False)
        if net:
            seen_netkeys.add(net["netkey"])
            record["networks"].append(net)

    if not args.no_traceroute:
        for target in args.trace_targets:
            tr = {"target": target, "hops": traceroute(target, args.max_hops)}
            record["traceroutes"].append(tr)

    if not args.no_public_ip:
        v4, v6 = public_ips()
        record["public_ipv4"] = v4
        record["public_ipv6"] = v6

    return record


def submit(server, record, dry=False):
    data = json.dumps(record).encode()
    if dry:
        print(json.dumps(record, indent=2))
        return 0
    url = server.rstrip("/") + "/api/v1/scan"
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "replace")
    log("server: %s" % body[:300])
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="netmap agent — scan YOUR network and contribute it to the public map")
    p.add_argument("--server", default=os.environ.get("NETMAP_SERVER", DEFAULT_SERVER),
                   help="netmap ingest server base URL")
    p.add_argument("--dry-run", action="store_true",
                   help="scan and print the payload, submit nothing")
    p.add_argument("--interval", type=int, default=0,
                   help="keep scanning every N seconds")
    p.add_argument("--no-traceroute", action="store_true")
    p.add_argument("--no-public-ip", action="store_true")
    p.add_argument("--max-hops", type=int, default=15)
    p.add_argument("--trace-targets", nargs="*", default=["1.1.1.1", "8.8.8.8"],
                   help="traceroute destinations (ISP path discovery)")
    p.add_argument("--ports", default="",
                   help="comma list of TCP ports to probe on LAN devices (light fingerprint)")
    p.add_argument("--lat", type=float, default=None, help="optional exact latitude")
    p.add_argument("--lon", type=float, default=None, help="optional exact longitude")
    p.add_argument("--alt", type=float, default=None, help="optional altitude (meters)")
    p.add_argument("--label", default=None, help="optional label for this location")
    a = p.parse_args(argv)
    if a.ports:
        a.ports = [int(x) for x in a.ports.split(",") if x.strip().isdigit()]
    else:
        a.ports = []
    return a


def one_cycle(args):
    t0 = time.time()
    record = build_payload(args)
    n_dev = sum(len(n.get("devices") or []) for n in record["networks"])
    n_hops = sum(len(t.get("hops") or []) for t in record["traceroutes"])
    log("scan done in %.1fs: %d network(s), %d device(s), %d trace hops, public %s"
        % (time.time() - t0, len(record["networks"]), n_dev, n_hops,
           record["public_ipv4"] or "?"))
    return submit(args.server, record, dry=args.dry_run)


def main(argv=None):
    args = parse_args(argv)
    print("netmap agent v%s — scans YOUR networks and contributes them to the "
          "public map at %s" % (__version__, args.server))
    print("Only run this on networks you own or have permission to scan.\n")
    while True:
        try:
            one_cycle(args)
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            log("cycle failed: %s" % e)
        if args.interval <= 0:
            break
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
