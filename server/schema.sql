-- netmap ingest schema (applied idempotently on server boot)

CREATE TABLE IF NOT EXISTS scans (
  scan_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at    TEXT NOT NULL,
  source_ip      TEXT,
  agent_version  TEXT,
  agent_os       TEXT,
  agent_platform TEXT,
  public_ipv4    TEXT,
  public_ipv6    TEXT,
  lat            REAL,
  lon            REAL,
  alt_m          REAL,
  label          TEXT
);

CREATE TABLE IF NOT EXISTS networks (
  scan_id      INTEGER NOT NULL,
  netkey       TEXT NOT NULL,
  ifname       TEXT,
  ipv4         TEXT,
  prefix       INTEGER,
  gateway      TEXT,
  gateway_mac  TEXT,
  hosts_total  INTEGER,
  device_count INTEGER,
  ipv6_global  TEXT,            -- JSON array
  PRIMARY KEY (scan_id, netkey)
);
CREATE INDEX IF NOT EXISTS idx_networks_netkey ON networks(netkey, scan_id);

CREATE TABLE IF NOT EXISTS devices (
  scan_id        INTEGER NOT NULL,
  netkey         TEXT NOT NULL,
  ipv4           TEXT,
  ipv6           TEXT,
  mac            TEXT,
  hostname       TEXT,
  vendor         TEXT,
  alive          INTEGER DEFAULT 0,
  open_ports     TEXT,           -- JSON array
  discovered_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_netkey ON devices(netkey, scan_id);

-- mappable points: kind='network' (one per submitted LAN) and kind='hop' (public traceroute IPs)
CREATE TABLE IF NOT EXISTS nodes (
  kind       TEXT NOT NULL,
  identifier TEXT NOT NULL,
  ip         TEXT,
  lat        REAL, lon REAL,
  city       TEXT, country TEXT,
  asn        INTEGER, org TEXT,
  geo_at     TEXT,
  attrs      TEXT,               -- JSON blob (LAN summary etc.)
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  scans      INTEGER DEFAULT 1,
  PRIMARY KEY (kind, identifier)
);
CREATE INDEX IF NOT EXISTS idx_nodes_ip ON nodes(ip);

-- ISP path edges: consecutive public traceroute hops
CREATE TABLE IF NOT EXISTS edges (
  src        TEXT NOT NULL,
  dst        TEXT NOT NULL,
  ttl        INTEGER NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  seen_count INTEGER DEFAULT 1,
  PRIMARY KEY (src, dst, ttl)
);

-- public-IP geolocation cache (negative results cached too, retried after 24h)
CREATE TABLE IF NOT EXISTS geo (
  ip         TEXT PRIMARY KEY,
  lat        REAL, lon REAL,
  city       TEXT, country TEXT,
  asn        INTEGER, org TEXT,
  fetched_at TEXT NOT NULL
);
