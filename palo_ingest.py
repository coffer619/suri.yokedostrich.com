#!/usr/bin/env python3
"""
palo_ingest.py
--------------
Palo Alto NGFW syslog -> DuckDB ingester for the "Firewall" dashboard page.

Two run modes
-------------
* ``--mock``     Generate synthetic PAN-OS-like rows and load them into the
                 DuckDB file. Used to seed the dashboard mockup before the
                 real syslog feed is configured on the NGFW. Idempotent-ish:
                 appends generated rows with new timestamps each run unless
                 ``--reset`` is passed (which drops & recreates the schema).

* ``--tail``     Tail a PAN-OS syslog file (default /var/log/palo-alto.log,
                 overridable with ``--syslog``) and parse the standard ICS
                 (comma-separated) syslog format into the typed tables.
                 Resume via an offset file (``<db>.offset``), idempotent
                 INSERT OR IGNORE on the per-table event PK.

Conventions mirror eve_tail2duckdb.py:
* qmark ``?`` placeholders with positional param lists.
* Bulk COPY via temp JSONL + INSERT ... SELECT FROM read_json_auto().
* Only one read-write connection at a time; the dashboard opens read-only.
* Deferred checkpointing so con.close() is fast on a large DB.

Schema
------
Tables (all with a SHA1-based ``event_id`` PK so re-ingests are idempotent):

  traffic : per-session traffic logs (TRAFFIC type)
  threat  : threat-prevention hits (THREAT type: spyware/virus/vulnerability/...)
  url     : URL filtering logs (URL type)
  system  : system logs (SYSTEM type)
  metrics : SNMP-polled health metrics (cpu/mem/sessions/throughput/ha_state)
            populated by a separate SNMP poller (skeleton here via --mock).

Run examples
------------
    # Seed mock data for the dashboard mockup:
    python3 palo_ingest.py --db /home/suricata/palo.duckdb --mock --hours 24

    # Run the real syslog tailer (via systemd: palo_ingest.service):
    python3 palo_ingest.py --db /home/suricata/palo.duckdb --tail \
        --syslog /var/log/palo-alto.log --batch 5000 --read-gap 1.0 --reopen-every 1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone

import duckdb

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_DB = os.environ.get("PALO_DUCKDB", "/home/suricata/palo.duckdb")
DEFAULT_SYSLOG = "/var/log/palo-alto.log"

# Same conservative checkpoint policy as the eve ingester: don't let close()
# trigger a multi-second full checkpoint on a large DB.
CHECKPOINT_THRESHOLD = "100GB"
WAL_AUTOCHECKPOINT = "100GB"

LOCAL_TZ = "America/Chicago"


# ---------------------------------------------------------------------------
# DB open / schema
# ---------------------------------------------------------------------------

def open_db(db_path: str, retries: int = 600, wait: float = 0.1) -> duckdb.DuckDBPyConnection:
    """Open a read-write DuckDB connection, retrying on lock conflicts.

    Retry is essential because the tailer closes and reopens the DB on every
    batch (--reopen-every 1) so the dashboard can read between flushes. The
    OS-level lock isn't released the instant con.close() returns, so an
    immediate reopen can race with the lock release. Without retries the
    service crash-loops; with retries it just waits ~10-50ms and succeeds.
    """
    import duckdb as _ddb
    last = None
    for _ in range(retries):
        try:
            con = _ddb.connect(db_path)
            con.execute(f"PRAGMA checkpoint_threshold='{CHECKPOINT_THRESHOLD}'")
            con.execute(f"PRAGMA wal_autocheckpoint='{WAL_AUTOCHECKPOINT}'")
            return con
        except (_ddb.IOException, _ddb.ConnectionException) as exc:
            last = exc
            time.sleep(wait)
    raise last


def create_schema(con: duckdb.DuckDBPyConnection, reset: bool = False) -> None:
    """Create (or recreate) the NGFW tables + helpful indexes."""
    if reset:
        for t in ("traffic", "threat", "url", "system", "metrics"):
            con.execute(f"DROP TABLE IF EXISTS {t}")

    con.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            event_id      VARCHAR PRIMARY KEY,
            timestamp     TIMESTAMPTZ NOT NULL,
            serial        VARCHAR,
            src_ip        VARCHAR,
            src_zone      VARCHAR,
            src_port      INTEGER,
            dest_ip       VARCHAR,
            dest_zone     VARCHAR,
            dest_port     INTEGER,
            app           VARCHAR,
            action        VARCHAR,
            bytes_sent    BIGINT,
            bytes_recv    BIGINT,
            packets       BIGINT,
            session_id    BIGINT,
            proto         VARCHAR,
            rule          VARCHAR,
            user          VARCHAR,
            app_category     VARCHAR,
            app_subcategory  VARCHAR,
            app_technology   VARCHAR,
            app_risk         INTEGER
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS threat (
            event_id      VARCHAR PRIMARY KEY,
            timestamp     TIMESTAMPTZ NOT NULL,
            serial        VARCHAR,
            src_ip        VARCHAR,
            dest_ip       VARCHAR,
            app           VARCHAR,
            threat_name   VARCHAR,
            threat_type   VARCHAR,
            severity      VARCHAR,
            action        VARCHAR,
            category      VARCHAR,
            subcategory   VARCHAR,
            session_id    BIGINT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS url (
            event_id      VARCHAR PRIMARY KEY,
            timestamp     TIMESTAMPTZ NOT NULL,
            serial        VARCHAR,
            src_ip        VARCHAR,
            dest_ip       VARCHAR,
            app           VARCHAR,
            category      VARCHAR,
            url           VARCHAR,
            action        VARCHAR,
            risk          INTEGER,
            user          VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS system (
            event_id      VARCHAR PRIMARY KEY,
            timestamp     TIMESTAMPTZ NOT NULL,
            serial        VARCHAR,
            severity      VARCHAR,
            event_name    VARCHAR,
            module        VARCHAR,
            description   VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            ts                TIMESTAMPTZ NOT NULL,
            cpu_pct           DOUBLE,
            mem_pct           DOUBLE,
            dp_cpu_pct        DOUBLE,
            active_sessions   BIGINT,
            session_util_pct  DOUBLE,
            throughput_in     BIGINT,
            throughput_out    BIGINT,
            ha_state          VARCHAR
        )
    """)

    # ---- Lightweight migrations: add columns that may be missing on DBs
    # created before the column existed. ALTER TABLE ADD COLUMN is a no-op if
    # the column is already present (we catch the error and ignore it). This
    # avoids needing --reset on every schema change.
    def _add_column(table: str, col: str, dtype: str) -> None:
        try:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {dtype}")
        except Exception:
            pass  # column already exists
    _add_column("threat", "subcategory", "VARCHAR")
    _add_column("traffic", "app_category", "VARCHAR")
    _add_column("traffic", "app_subcategory", "VARCHAR")
    _add_column("traffic", "app_technology", "VARCHAR")
    _add_column("traffic", "app_risk", "INTEGER")


    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_traffic_ts   ON traffic(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_traffic_src  ON traffic(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_traffic_act  ON traffic(action)",
        "CREATE INDEX IF NOT EXISTS idx_threat_ts    ON threat(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_threat_type  ON threat(threat_type)",
        "CREATE INDEX IF NOT EXISTS idx_url_ts       ON url(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_url_act      ON url(action)",
        "CREATE INDEX IF NOT EXISTS idx_system_ts    ON system(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_metrics_ts   ON metrics(ts)",
    ):
        con.execute(stmt)


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------

def _event_id(*parts) -> str:
    """Stable SHA1 id from the parts that make a row unique per table."""
    return hashlib.sha1(
        "|".join(str(p) for p in parts).encode("utf-8", "replace")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Mock data generator
# ---------------------------------------------------------------------------

MOCK_APPS = ["web-browsing", "ssl", "dns", "google-services", "youtube",
             "microsoft-office-365", "ssh", "smtp", "smb", "netflix"]
MOCK_ACTIONS = ["allow", "allow", "allow", "allow", "deny", "drop"]
MOCK_USERS = ["jdoe", "asmith", "rlee", "kwang", "mgarcia", "system"]
MOCK_ZONES = ["trust", "untrust", "dmz", "inside", "outside"]
MOCK_RULES = ["allow-trust-to-untrust", "allow-internal", "deny-malware",
              "drop-tor", "allow-dmz-inbound", "default-deny"]
MOCK_THREAT_TYPES = ["spyware", "virus", "vulnerability", "url"]
MOCK_THREAT_NAMES = {
    "spyware": ["Palo Alto Malware", "Phishing Domain", "C2 Callback"],
    "virus": ["Win32/Emotet", "JS/Obfuscation", "PE/Genetic"],
    "vulnerability": ["MS-RPC DCOM RCE", "OpenSSL Heartbleed", "Apache Log4Shell"],
    "url": ["Suspicious Domain", "Newly Registered Domain", "Dynamic DNS"],
}
MOCK_URL_CATEGORIES = ["malware", "phishing", "command-and-control", "gun-violence",
                       "hacking", "newly-registered-domain", "low-risk", "medium-risk"]
MOCK_URLS = ["bad-c2.example.com/login", "phish-paypal.example.com/x",
             "newreg.xyz/buy", "shady-ddns.net/payload", "h4x0r.io/exploit"]
MOCK_SYSTEM = [
    ("configuration committed", "configuration", "admin jdoe committed config"),
    ("HA peer alive", "ha", "Peer heartbeats resumed"),
    ("log forwarding restart", "log", "logfwd-reason reconnect"),
    ("global-protect gateway up", "global-protect", "gp-gw portal users: 12"),
    ("system restart", "system", "dataplane restart after upgrade"),
]


def _ip(rng, base):
    return f"{base}.{rng.randint(2, 250)}"


def gen_mock(con, hours: int = 24, seed: int = 1337) -> None:
    """Generate and bulk-load synthetic PAN-OS rows spanning the last `hours`."""
    import random
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    n_traffic = max(2000, hours * 400)
    n_threat = max(100, hours * 20)
    n_url = max(200, hours * 40)
    n_system = max(20, hours * 2)
    n_metrics = hours * 12  # every 5 min

    traffic, threat, urls, system, metrics = [], [], [], [], []

    for _ in range(n_traffic):
        t = start + timedelta(seconds=rng.randint(0, int(hours * 3600)))
        app = rng.choice(MOCK_APPS)
        action = rng.choice(MOCK_ACTIONS)
        src = _ip(rng, "10.0.0")
        dst = _ip(rng, "10.0.0" if rng.random() < 0.3 else "203.0.113")
        sp = rng.randint(1024, 65535)
        dp = rng.choice([443, 80, 53, 22, 25, 445, 8080, 514])
        bs = rng.randint(200, 5_000_000) if action == "allow" else 0
        br = rng.randint(200, 20_000_000) if action == "allow" else 0
        sid = rng.randint(100000, 999999)
        eid = _event_id("traffic", sid, t.isoformat(), src, dst, sp, dp)
        traffic.append({
            "event_id": eid, "timestamp": t.isoformat(), "serial": "PA-VM-001",
            "src_ip": src, "src_zone": "trust", "src_port": sp,
            "dest_ip": dst, "dest_zone": "untrust", "dest_port": dp,
            "app": app, "action": action, "bytes_sent": bs, "bytes_recv": br,
            "packets": rng.randint(2, 4000), "session_id": sid,
            "proto": rng.choice(["tcp", "udp", "tcp", "tcp"]),
            "rule": rng.choice(MOCK_RULES), "user": rng.choice(MOCK_USERS),
        })

    for _ in range(n_threat):
        t = start + timedelta(seconds=rng.randint(0, int(hours * 3600)))
        tt = rng.choice(MOCK_THREAT_TYPES)
        name = rng.choice(MOCK_THREAT_NAMES[tt])
        action = rng.choice(["drop", "alert", "reset-both", "block-ip"])
        eid = _event_id("threat", t.isoformat(), name, tt, action,
                        rng.randint(1, 10**9))
        threat.append({
            "event_id": eid, "timestamp": t.isoformat(), "serial": "PA-VM-001",
            "src_ip": _ip(rng, "10.0.0"),
            "dest_ip": _ip(rng, "203.0.113"),
            "app": rng.choice(MOCK_APPS), "threat_name": name, "threat_type": tt,
            "severity": rng.choice(["informational", "low", "medium", "high", "critical"]),
            "action": action, "category": tt, "session_id": rng.randint(100000, 999999),
        })

    for _ in range(n_url):
        t = start + timedelta(seconds=rng.randint(0, int(hours * 3600)))
        cat = rng.choice(MOCK_URL_CATEGORIES)
        u = rng.choice(MOCK_URLS)
        action = rng.choice(["block", "alert", "allow", "block", "continue"])
        risk = rng.choice([1, 2, 2, 3, 3, 4, 5])
        eid = _event_id("url", t.isoformat(), u, cat, action, rng.randint(1, 10**9))
        urls.append({
            "event_id": eid, "timestamp": t.isoformat(), "serial": "PA-VM-001",
            "src_ip": _ip(rng, "10.0.0"),
            "dest_ip": _ip(rng, "203.0.113"),
            "app": "web-browsing", "category": cat, "url": u, "action": action,
            "risk": risk, "user": rng.choice(MOCK_USERS),
        })

    for i in range(n_system):
        t = start + timedelta(seconds=int(i * hours * 3600 / max(1, n_system)))
        name, mod, desc = rng.choice(MOCK_SYSTEM)
        eid = _event_id("system", t.isoformat(), name, desc, i)
        system.append({
            "event_id": eid, "timestamp": t.isoformat(), "serial": "PA-VM-001",
            "severity": rng.choice(["informational", "low", "medium", "high"]),
            "event_name": name, "module": mod, "description": desc,
        })

    # SNMP-style metrics, every 5 minutes, with realistic-ish wandering.
    cpu = mem = dp = 35.0
    sess = 4500
    for i in range(n_metrics):
        t = start + timedelta(minutes=5 * i)
        cpu = max(2, min(98, cpu + rng.uniform(-4, 4)))
        mem = max(10, min(95, mem + rng.uniform(-2, 2)))
        dp = max(2, min(99, dp + rng.uniform(-6, 6)))
        sess = max(100, min(20000, sess + int(rng.uniform(-300, 320))))
        metrics.append({
            "ts": t.isoformat(), "cpu_pct": round(cpu, 1),
            "mem_pct": round(mem, 1), "dp_cpu_pct": round(dp, 1),
            "active_sessions": sess,
            "session_util_pct": round(100 * sess / 20000, 1),
            "throughput_in": int(rng.uniform(50e6, 900e6)),
            "throughput_out": int(rng.uniform(50e6, 900e6)),
            "ha_state": rng.choice(["active", "active", "active", "passive"]),
        })

    _bulk_insert(con, "traffic", traffic)
    _bulk_insert(con, "threat", threat)
    _bulk_insert(con, "url", urls)
    _bulk_insert(con, "system", system)
    _bulk_insert_metrics(con, metrics)
    con.execute("CHECKPOINT")
    print(f"[mock] loaded traffic={len(traffic)} threat={len(threat)} "
          f"url={len(urls)} system={len(system)} metrics={len(metrics)}")


# ---------------------------------------------------------------------------
# Bulk insert (mirrors eve_tail2duckdb._bulk_copy)
# ---------------------------------------------------------------------------

# Reserved-word identifiers per table that must be quoted in the COPY SELECT.
RESERVED = {"user"}  # 'user' is reserved in some contexts; quote to be safe

COLUMNS = {
    "traffic": ["event_id", "timestamp", "serial", "src_ip", "src_zone",
                "src_port", "dest_ip", "dest_zone", "dest_port", "app",
                "action", "bytes_sent", "bytes_recv", "packets", "session_id",
                "proto", "rule", "user",
                "app_category", "app_subcategory", "app_technology", "app_risk"],
    "threat": ["event_id", "timestamp", "serial", "src_ip", "dest_ip", "app",
               "threat_name", "threat_type", "severity", "action", "category",
               "subcategory", "session_id"],
    "url": ["event_id", "timestamp", "serial", "src_ip", "dest_ip", "app",
            "category", "url", "action", "risk", "user"],
    "system": ["event_id", "timestamp", "serial", "severity", "event_name",
               "module", "description"],
}

TYPES = {
    "traffic": ["VARCHAR", "TIMESTAMPTZ", "VARCHAR", "VARCHAR", "VARCHAR",
                "INTEGER", "VARCHAR", "VARCHAR", "INTEGER", "VARCHAR",
                "VARCHAR", "BIGINT", "BIGINT", "BIGINT", "BIGINT", "VARCHAR",
                "VARCHAR", "VARCHAR",
                "VARCHAR", "VARCHAR", "VARCHAR", "INTEGER"],
    "threat": ["VARCHAR", "TIMESTAMPTZ", "VARCHAR", "VARCHAR", "VARCHAR",
               "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR",
               "VARCHAR", "VARCHAR", "BIGINT"],
    "url": ["VARCHAR", "TIMESTAMPTZ", "VARCHAR", "VARCHAR", "VARCHAR",
            "VARCHAR", "VARCHAR", "VARCHAR", "VARCHAR", "INTEGER", "VARCHAR"],
    "system": ["VARCHAR", "TIMESTAMPTZ", "VARCHAR", "VARCHAR", "VARCHAR",
               "VARCHAR", "VARCHAR"],
}


def _bulk_insert(con, table: str, rows: list[dict]) -> int:
    """Write rows to a temp JSONL then INSERT OR IGNORE via read_json_auto."""
    if not rows:
        return 0
    cols = COLUMNS[table]
    types = TYPES[table]
    sel = ", ".join(
        f"CAST({c} AS {t})" if t != "TIMESTAMPTZ" else f"CAST({c} AS TIMESTAMPTZ)"
        for c, t in zip(cols, types)
    )
    # DuckDB's read_json "columns" parameter takes a SQL struct literal of
    # name->type pairs, NOT a JSON array. Build it as a string.
    cols_struct = "{" + ", ".join(
        f"'{c}': '{t}'" for c, t in zip(cols, types)
    ) + "}"
    tmp = f"/tmp/palo_{table}_{os.getpid()}.jsonl"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r, default=str) + "\n")
    try:
        sql = (
            f"INSERT OR IGNORE INTO {table} ({', '.join(cols)}) "
            f"SELECT {sel} FROM read_json_auto(?, columns={cols_struct})"
        )
        con.execute(sql, [tmp])
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return len(rows)


def _bulk_insert_metrics(con, rows: list[dict]) -> None:
    if not rows:
        return
    tmp = f"/tmp/palo_metrics_{os.getpid()}.jsonl"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r, default=str) + "\n")
    try:
        con.execute("""
            INSERT INTO metrics
            SELECT CAST(ts AS TIMESTAMPTZ), cpu_pct, mem_pct, dp_cpu_pct,
                   active_sessions, session_util_pct, throughput_in,
                   throughput_out, ha_state
            FROM read_json_auto(?)
        """, [tmp])
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# PAN-OS ICS syslog parser (for --tail mode)
# ---------------------------------------------------------------------------
#
# PAN-OS syslog format (verified against a PA-440 running PAN-OS 11.x,
# BSD syslog framing). The ICS payload is identical for BSD and IETF framing
# — only the outer syslog wrapper differs. The payload always begins with a
# leading ``1,`` followed by ``receive_time,serial,type,subtype,...``.
#
# A real BSD-framed TRAFFIC line looks like:
#   Jul  5 07:54:21 PA-440 1,2026/07/05 07:54:19,021201110142,TRAFFIC,end,2818,
#       2026/07/05 07:54:19,10.0.0.109,10.0.1.108,0.0.0.0,0.0.0.0,
#       Allow_pihole,,,dns-base,vsys1,trust,DMZ,ethernet1/2,ethernet1/3,
#       suri-syslog,2026/07/05 07:54:21,156854,1,63600,53,0,0,0x1c,tcp,allow,
#       754,406,348,11,2026/07/05 07:54:06,...
#
# Field indices (0-based, into the CSV-parsed payload starting at "1,"):
#   0  leading "1"            1  receive_time        2  serial
#   3  type (TRAFFIC/...)      4  subtype             5  config_version
#   6  generated_time         7  src_ip              8  dest_ip
#   9  nat_src_ip            10  nat_dest_ip        11  rule
#  12  src_user              13  dest_user           14  app
#  15  vsys                  16  src_zone            17  dest_zone
#  18  src_interface         19  dest_interface      20  log_forward_profile
#  21  start_time            22  session_id (short)  23  repeat_count
#  24  src_port              25  dest_port           26  nat_src_port
#  27  nat_dest_port         28  flags               29  proto
#  30  action                31  bytes_total         32  bytes_sent
#  33  bytes_recv            34  packets             35  session_start_time
#  36  duration              37  url_category        ...
#
# CRITICAL: PAN-OS quotes fields that contain commas (e.g. the app
# characteristics field: "used-by-malware,has-known-vulnerability,..."). A
# naive str.split(",") would split that quoted field and shift every later
# index. We use csv.reader() to respect quotes. For TRAFFIC we only read
# fields up to index 34, which are all unquoted, so even split() would work
# for traffic — but csv is needed for THREAT/URL where the URL/threat-name
# can appear earlier and be quoted.

import csv as _csv
import re as _re

# Match the start of the ICS payload: "1,YYYY/MM/DD HH:MM:SS,". The leading
# `(?<![0-9])` avoids matching a "1," that happens to appear inside a version
# number elsewhere. This works for BOTH framings:
#   BSD:  "Jul  5 ... PA-440 1,2026/07/05 ..."
#   IETF: "<14>1 2026-07-05T... PA-440 ... 1,2026/07/05 ..."
_PAYLOAD_START = _re.compile(r"(?<![0-9])1,(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}),")

# Where to append lines we could not parse (for debugging field positions).
UNPARSED_LOG = "/home/suricata/palo_unparsed.log"


def _parse_pano_dt(s: str) -> str:
    """Parse 'YYYY/MM/DD HH:MM:SS' (PAN-OS local time) -> tz-aware ISO string."""
    s = (s or "").strip()
    try:
        dt = datetime.strptime(s, "%Y/%m/%d %H:%M:%S")
        import zoneinfo
        dt = dt.replace(tzinfo=zoneinfo.ZoneInfo(LOCAL_TZ))
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _extract_payload(line: str) -> str | None:
    """Strip syslog framing and return the ICS payload starting at '1,...'."""
    line = line.strip()
    if not line:
        return None
    # Strip <PRI> if present (BSD-with-PRI and IETF both start with <PRI>).
    if line.startswith("<"):
        gt = line.find(">")
        if gt > 0:
            line = line[gt + 1:]
    m = _PAYLOAD_START.search(line)
    if not m:
        return None
    return line[m.start():]


def _log_unparsed(line: str) -> None:
    """Append a line we couldn't parse to the debug file (best effort)."""
    try:
        with open(UNPARSED_LOG, "a") as f:
            f.write(line if line.endswith("\n") else line + "\n")
    except Exception:
        pass


def parse_pano_syslog(line: str) -> dict | None:
    """Parse one PAN-OS ICS syslog line into a row dict for its table.

    Returns None for unparseable / unhandled lines (and appends the line to
    /home/suricata/palo_unparsed.log for debugging). Handles both BSD (RFC
    3164) and IETF (RFC 5424) syslog framing — only the ICS payload matters.
    """
    payload = _extract_payload(line)
    if payload is None:
        return None

    # CSV-parse the payload so quoted fields containing commas are preserved.
    rows = list(_csv.reader([payload]))
    if not rows:
        return None
    f = rows[0]
    if len(f) < 7:
        _log_unparsed(line)
        return None

    # Common prefix: 0=indicator, 1=receive_time, 2=serial, 3=type,
    # 4=subtype, 5=config_version, 6=generated_time.
    log_type = f[3]
    serial = f[2]
    ts = _parse_pano_dt(f[6]) if len(f) > 6 and f[6] else _parse_pano_dt(f[1])

    def g(i: int) -> str:
        return f[i] if i < len(f) else ""

    # ---- TRAFFIC (verified against real PA-440 PAN-OS 11.x sample) ----
    # App metadata (category/subcategory/technology/risk) lives at the tail:
    # idx 105=subcategory, 106=category, 107=technology, 108=risk (1-5).
    # These are only present in longer lines; older/shorter logs may omit them.
    if log_type == "TRAFFIC" and len(f) >= 35:
        src_ip, dest_ip = g(7), g(8)
        rule, app, action = g(11), g(14), g(30)
        src_zone, dest_zone = g(16), g(17)
        src_port, dest_port = _int(g(24)), _int(g(25))
        proto, user = g(29), g(12)
        bytes_sent, bytes_recv, packets = _int(g(32)), _int(g(33)), _int(g(34))
        session_id = _int(g(22))
        app_subcategory = g(105) if len(f) > 105 else ""
        app_category    = g(106) if len(f) > 106 else ""
        app_technology  = g(107) if len(f) > 107 else ""
        app_risk        = _int(g(108)) if len(f) > 108 else 0
        eid = _event_id("traffic", ts, session_id, src_ip, dest_ip,
                        src_port, dest_port)
        return {
            "table": "traffic", "event_id": eid, "timestamp": ts,
            "serial": serial, "src_ip": src_ip, "src_zone": src_zone,
            "src_port": src_port, "dest_ip": dest_ip, "dest_zone": dest_zone,
            "dest_port": dest_port, "app": app, "action": action,
            "bytes_sent": bytes_sent, "bytes_recv": bytes_recv,
            "packets": packets, "session_id": session_id,
            "proto": proto, "rule": rule, "user": user,
            "app_category": app_category, "app_subcategory": app_subcategory,
            "app_technology": app_technology, "app_risk": app_risk,
        }

    # ---- THREAT (verified against a real PA-440 PAN-OS 11.x sample).
    # CRITICAL: the field layout differs by subtype. The ``url`` subtype has
    # an extra numeric field at idx 32 (a risk/category-id like '(9999)')
    # that pushes category to idx 33 and severity to idx 34. The other
    # subtypes (spyware / virus / vulnerability) put category at idx 32 and
    # severity at idx 33.
    #   common: 7=src_ip 8=dest_ip 11=rule 14=app 22=session_id 29=proto
    #           30=action  31=threat_name (URL for the url subtype)
    #   url:        32=numeric-id  33=category  34=severity
    #   spyware/...:               32=category  33=severity
    #   subtype itself is at idx 4 (threat_type).
    if log_type == "THREAT" and len(f) >= 35:
        src_ip, dest_ip = g(7), g(8)
        app, action = g(14), g(30)
        threat_name = g(31)
        threat_type, session_id = g(4), _int(g(22))
        if threat_type == "url":
            category, severity = g(33), g(34)
        else:
            category, severity = g(32), g(33)
        # Subcategory: PAN-OS puts a combined "<category>,<subcategory>" field
        # at idx 75 for the url subtype (e.g. "online-storage-and-backup,medium-risk").
        # Extract just the subcategory part after the comma. For other subtypes
        # this field may be absent/empty — leave subcategory blank then.
        subcategory = ""
        combo = g(75) if len(f) > 75 else ""
        if combo and "," in combo:
            subcategory = combo.split(",", 1)[1].strip()
        eid = _event_id("threat", ts, threat_name, threat_type, action,
                        session_id, src_ip, dest_ip)
        return {
            "table": "threat", "event_id": eid, "timestamp": ts,
            "serial": serial, "src_ip": src_ip, "dest_ip": dest_ip,
            "app": app, "threat_name": threat_name, "threat_type": threat_type,
            "severity": severity, "action": action, "category": category,
            "subcategory": subcategory, "session_id": session_id,
        }

    # ---- URL (PAN-OS documented field order; NOT yet verified). ----
    # 7=src_ip 8=dest_ip 11=rule 14=app 22=session_id 30=action
    # 31=category 32=url  (risk is further out; using a best-effort index)
    if log_type == "URL" and len(f) >= 33:
        src_ip, dest_ip = g(7), g(8)
        app, action = g(14), g(30)
        category, url = g(31), g(32)
        user = g(12)
        risk = _int(g(34)) if len(f) > 34 else 0
        eid = _event_id("url", ts, url, category, action, src_ip, dest_ip)
        return {
            "table": "url", "event_id": eid, "timestamp": ts,
            "serial": serial, "src_ip": src_ip, "dest_ip": dest_ip,
            "app": app, "category": category, "url": url, "action": action,
            "risk": risk, "user": user,
        }

    # ---- SYSTEM (PAN-OS documented field order; NOT yet verified). ----
    # 7=event_name 8=severity 9=module 10=description  (type=SYSTEM, subtype at 4)
    if log_type == "SYSTEM" and len(f) >= 11:
        event_name, severity, module, desc = g(7), g(8), g(9), g(10)
        eid = _event_id("system", ts, event_name, desc)
        return {
            "table": "system", "event_id": eid, "timestamp": ts,
            "serial": serial, "severity": severity, "event_name": event_name,
            "module": module, "description": desc,
        }

    # Unhandled log type (CONFIG, HIPMATCH, GLOBALPROTECT, ...) or too-short
    # line. Log it so we can extend the parser if needed.
    _log_unparsed(line)
    return None


def _int(s: str) -> int:
    try:
        return int(s) if s and s != "" else 0
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Parse-test mode (no DB writes) — used to verify the parser against a real
# syslog file before starting the ingester.
# ---------------------------------------------------------------------------

def parse_test(path: str, limit: int = 0) -> None:
    """Parse a syslog file and report per-type counts without writing to the DB."""
    counts: dict[str, int] = {}
    unparsed = 0
    samples: dict[str, str] = {}
    n = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                n += 1
                row = parse_pano_syslog(line)
                if row is None:
                    unparsed += 1
                    continue
                t = row["table"]
                counts[t] = counts.get(t, 0) + 1
                if t not in samples:
                    # Trim to one representative row for display.
                    samples[t] = ", ".join(f"{k}={v}" for k, v in row.items()
                                            if k != "event_id")
                if limit and sum(counts.values()) >= limit:
                    break
    except FileNotFoundError:
        print(f"[parse-test] file not found: {path}")
        return
    print(f"[parse-test] read {n} lines from {path}")
    print(f"[parse-test] parsed: {counts}")
    print(f"[parse-test] unparsed/skipped: {unparsed}")
    for t, s in samples.items():
        print(f"[parse-test] sample {t}: {s[:200]}...")
    if unparsed:
        print(f"[parse-test] unparsed lines logged to {UNPARSED_LOG}")


# ---------------------------------------------------------------------------
# Tail mode
# ---------------------------------------------------------------------------

def tail_syslog(con, syslog_path: str, offset_path: str,
                batch: int, read_gap: float, reopen_every: int) -> None:
    """Tail the PAN-OS syslog file and ingest parsed rows in batches.

    Correctness notes:
    * The offset file is advanced AFTER a successful flush, not before. A
      crash mid-flush therefore re-processes the same lines on restart — safe
      because INSERT OR IGNORE on event_id is idempotent. (Advancing offset
      before flush would lose the in-flight batch on crash.)
    * The row buffer is only cleared after the flush succeeds, so a failed
      insert is retried on the next iteration rather than dropped.
    * open_db() retries on lock conflict, so the close/reopen cycle
      (--reopen-every 1) doesn't crash-loop when the OS lock release lags.
    """
    pos = _read_offset(offset_path)
    buf: dict[str, list[dict]] = {"traffic": [], "threat": [], "url": [], "system": []}
    pending_pos = pos  # file offset corresponding to the not-yet-flushed buffer

    def flush():
        """Insert all buffered rows + checkpoint. Raises on failure (caller
        leaves the buffer intact for retry)."""
        for tbl, rows in buf.items():
            if rows:
                _bulk_insert(con, tbl, rows)
        con.execute("CHECKPOINT")
        # Only clear + advance offset after a fully successful flush.
        for tbl in buf:
            buf[tbl] = []
        _write_offset(offset_path, pending_pos)

    iters = 0
    while True:
        try:
            with open(syslog_path, "r", errors="replace") as f:
                # Detect log rotation / truncation: if our saved offset is
                # past the current file size, the file was truncated (by
                # logrotate's copytruncate) or replaced. Reset to the start
                # so we don't silently read nothing forever. Re-reading from
                # 0 is safe because INSERT OR IGNORE on event_id is idempotent.
                current_size = f.seek(0, 2)  # seek to end to get size
                if pos > current_size:
                    print(f"[tail] log rotation detected: offset {pos} > "
                          f"file size {current_size}, resetting to 0")
                    pos = 0
                    pending_pos = 0
                f.seek(pos)
                lines = f.readlines()
                new_pos = f.tell()
            if lines:
                for line in lines:
                    row = parse_pano_syslog(line)
                    if row and row["table"] in buf:
                        buf[row["table"]].append(row)
                pos = new_pos
                pending_pos = new_pos
            total = sum(len(v) for v in buf.values())
            if total >= batch:
                flush()
            iters += 1
            if reopen_every and iters % reopen_every == 0:
                # Reopen the DB periodically so the dashboard's read-only open
                # doesn't starve (same reason as the eve ingester). open_db()
                # retries on the lock-release race.
                if any(buf.values()):
                    flush()
                con.close()
                con = open_db(con_path_for_reopen)
            time.sleep(read_gap)
        except FileNotFoundError:
            # Syslog file not created yet (NGFW not sending). Wait for it.
            time.sleep(read_gap)


# Module-level holder so the reopen branch can re-open with the same path.
con_path_for_reopen: str = ""


def _read_offset(path: str) -> int:
    try:
        with open(path) as f:
            return int(f.read().strip() or 0)
    except (FileNotFoundError, ValueError):
        return 0


def _write_offset(path: str, pos: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(pos))
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    global con_path_for_reopen
    p = argparse.ArgumentParser(description="Palo Alto NGFW syslog -> DuckDB ingester")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--syslog", default=DEFAULT_SYSLOG,
                   help="Path to the PAN-OS syslog file (tail mode)")
    p.add_argument("--mock", action="store_true",
                   help="Generate synthetic data and load into the DB")
    p.add_argument("--reset", action="store_true",
                   help="(mock mode) Drop & recreate tables before loading")
    p.add_argument("--tail", action="store_true",
                   help="Tail the syslog file and ingest real PAN-OS events")
    p.add_argument("--parse-test", action="store_true",
                   help="Parse the syslog file and report per-type counts without writing to the DB. "
                        "Use this to verify the parser before starting --tail.")
    p.add_argument("--limit", type=int, default=0,
                   help="(parse-test mode) Stop after this many parsed rows (0 = whole file)")
    p.add_argument("--hours", type=int, default=24,
                   help="(mock mode) How many hours of synthetic data to span")
    p.add_argument("--batch", type=int, default=5000)
    p.add_argument("--read-gap", type=float, default=1.0)
    p.add_argument("--reopen-every", type=int, default=1)
    args = p.parse_args()

    con_path_for_reopen = args.db

    # --parse-test does NOT open or write to the DB — it's a dry run.
    if args.parse_test:
        parse_test(args.syslog, limit=args.limit)
        return

    con = open_db(args.db)
    create_schema(con, reset=args.reset)

    if args.mock:
        gen_mock(con, hours=args.hours)
        print(f"[mock] wrote {args.db}")
        return

    if args.tail:
        offset_path = args.db + ".offset"
        print(f"[tail] following {args.syslog} -> {args.db} (offset {offset_path})")
        tail_syslog(con, args.syslog, offset_path,
                    args.batch, args.read_gap, args.reopen_every)
        return

    p.print_help()


if __name__ == "__main__":
    main()
