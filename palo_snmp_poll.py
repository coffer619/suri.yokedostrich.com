#!/usr/bin/env python3
"""
palo_snmp_poll.py — SNMP poller for the Palo Alto NGFW.

Polls the NGFW's management interface every N seconds via SNMPv2c and inserts
the results into the `metrics` table of palo.duckdb. The Firewall dashboard's
"System performance (SNMP)" section reads this table.

Run as a systemd service (setup/palo_snmp_poll.service) or standalone:
    python3 palo_snmp_poll.py --host YOUR_NGFW_IP --community YOUR_COMMUNITY --interval 300

PAN-OS SNMP OIDs (PAN-OS 9.x/10.x/11.x, enterprise 25461.2.1.2.3):
  * panSessionActive               1.3.6.1.4.1.25461.2.1.2.3.3.1.0
  * panfwGaugeMgmtCpuUtil          ...2.3.1.3.1.2.3.1.1.1   (mgmt CPU %)
  * panfwGaugeDataplaneCpuUtil     ...2.3.1.3.1.2.3.1.1.2   (dataplane CPU %)
  * panfwGaugeMemUtil              ...2.3.1.3.1.2.3.1.1.3   (memory %)
  * entPhySensorValue (CPU/mem on some PAN-OS versions use ENTITY-SENSOR-MIB)

This poller uses a defensive set of OIDs and inserts whatever it can read —
unavailable OIDs are skipped (None) rather than crashing the poll. HA state
is read from pan redundancy sub-agent if present, else 'unknown'.

The session utilization % is computed as (active_sessions / max_sessions * 100).
max_sessions is platform-dependent (PA-440 ~20000); pass --max-sessions to
override. Throughput (bps in/out) comes from the ifInOctets/ifOutOctets
delta between polls on the external interface — pass --ext-ifindex to set
which interface index to sample (default: auto-detect the highest-speed
interface).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from datetime import datetime, timezone

import duckdb

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_DB = os.environ.get("PALO_DUCKDB", "/home/suricata/palo.duckdb")
# The SNMP poller writes to a SEPARATE DB file to avoid lock contention with
# the syslog ingester (which holds the write lock on palo.duckdb). The dashboard
# opens this file read-only alongside palo.duckdb.
DEFAULT_METRICS_DB = os.environ.get("PALO_METRICS_DUCKDB", "/home/suricata/palo_metrics.duckdb")
LOCAL_TZ = "America/Chicago"
CHECKPOINT_THRESHOLD = "100GB"

# PAN-OS SNMP OIDs (SNMPv2c, community-based).
# Verified against a PA-440 running PAN-OS 11.1, cross-referenced with the
# PAN-11.1 SNMP MIB modules (PAN-COMMON-MIB.my).
#
# OID tree: enterprises(25461) → panModules(2) → panCommonMib(1)
#   panCommonMib → panCommonObjs(2) → panSys(1), panSession(3), panHrStorage(?)
#
# panSession (25461.2.1.2.3.3):
#   .1 = panSessionUtilization (%)
#   .2 = panSessionMax
#   .3 = panSessionActive, .4 = TCP, .5 = UDP, .6 = ICMP
#   .7 = SSL proxy active, .8 = SSL proxy util %, .12 = CPS
#
# panSys (25461.2.1.2.1):
#   .11 = panSysHAState (DisplayString: "active"/"passive"/"disabled")
#   .12 = panSysHAPeerState
#
# CPU: HOST-RESOURCES-MIB hrProcessorLoad (standard, not PAN-specific)
#   .1 = core 1 (management), .2 = core 2 (dataplane on PA-440)
#
# Memory + Dataplane packet buffers: HOST-RESOURCES-MIB hrStorageTable
#   .1010 = DP-0 Packet Descriptors
#   .1011 = DP-0 Hardware Packet Buffers
#   .1012 = DP-0 Software Packet Buffers
#   .1020 = Slot-1 Management Memory (RAM)
#   Utilization = hrStorageUsed / hrStorageSize * 100
OIDS = {
    "session_util":    "1.3.6.1.4.1.25461.2.1.2.3.1.0",    # panSessionUtilization (%)
    "session_max":     "1.3.6.1.4.1.25461.2.1.2.3.2.0",    # panSessionMax
    "active_sessions": "1.3.6.1.4.1.25461.2.1.2.3.3.0",   # panSessionActive (scalar .0)
    "sess_tcp":        "1.3.6.1.4.1.25461.2.1.2.3.4.0",   # panSessionActiveTcp
    "sess_udp":        "1.3.6.1.4.1.25461.2.1.2.3.5.0",   # panSessionActiveUdp
    "sess_icmp":       "1.3.6.1.4.1.25461.2.1.2.3.6.0",   # panSessionActiveICMP
    "sess_ssl_proxy":  "1.3.6.1.4.1.25461.2.1.2.3.7.0",   # panSessionActiveSslProxy
    "ssl_proxy_util":  "1.3.6.1.4.1.25461.2.1.2.3.8.0",   # panSessionSslProxyUtilization
    "cps":             "1.3.6.1.4.1.25461.2.1.2.3.12.0",  # panSessionCps
    "mgmt_cpu":        "1.3.6.1.2.1.25.3.3.1.2.1",      # hrProcessorLoad.1
    "dp_cpu":          "1.3.6.1.2.1.25.3.3.1.2.2",      # hrProcessorLoad.2
    "mem_used":        "1.3.6.1.2.1.25.2.3.1.6.1020",   # hrStorageUsed (mgmt memory)
    "mem_size":        "1.3.6.1.2.1.25.2.3.1.5.1020",   # hrStorageSize (mgmt memory)
    "pkt_desc_used":   "1.3.6.1.2.1.25.2.3.1.6.1010",   # DP-0 Packet Descriptors used
    "pkt_desc_size":   "1.3.6.1.2.1.25.2.3.1.5.1010",   # DP-0 Packet Descriptors size
    "hw_buf_used":     "1.3.6.1.2.1.25.2.3.1.6.1011",   # DP-0 Hardware Packet Buffers used
    "hw_buf_size":     "1.3.6.1.2.1.25.2.3.1.5.1011",   # DP-0 Hardware Packet Buffers size
    "sw_buf_used":     "1.3.6.1.2.1.25.2.3.1.6.1012",   # DP-0 Software Packet Buffers used
    "sw_buf_size":     "1.3.6.1.2.1.25.2.3.1.5.1012",   # DP-0 Software Packet Buffers size
    "ha_state":        "1.3.6.1.4.1.25461.2.1.2.1.11.0", # panSysHAState (string)
    "if_in_octets":    "1.3.6.1.2.1.2.2.1.10",   # + .ifindex
    "if_out_octets":   "1.3.6.1.2.1.2.2.1.16",   # + .ifindex
}


# ---------------------------------------------------------------------------
# SNMP helpers (pysnmp)
# ---------------------------------------------------------------------------

def _snmp_get(host, community, oid, port=161, timeout=5, retries=1):
    """Single SNMPv2c GET. Returns (value_as_int_or_str, None) on success,
    (None, error_str) on failure. Uses pysnmp 7.x v1arch async API."""
    from pysnmp.hlapi.v1arch.asyncio import SnmpDispatcher, CommunityData, UdpTransportTarget, ObjectType, ObjectIdentity
    from pysnmp.hlapi.v1arch.asyncio import cmdgen

    async def _do():
        with SnmpDispatcher() as dispatcher:
            transport = await UdpTransportTarget.create(
                (host, port), timeout=timeout, retries=retries)
            try:
                # pysnmp 7.x v1arch.get_cmd returns a 4-tuple:
                # (error_indication, error_status_idx, error_idx, var_binds)
                result = await cmdgen.get_cmd(
                    dispatcher,
                    CommunityData(community, mpModel=1),  # SNMPv2c
                    transport,
                    ObjectType(ObjectIdentity(oid)),
                )
                error_indication, error_status, _err_idx, var_binds = result
            except Exception as exc:
                return None, str(exc)
            if error_indication:
                return None, str(error_indication)
            if error_status:
                return None, str(error_status)
            for var_bind in var_binds:
                val = var_bind[1]
                try:
                    return int(val), None
                except (ValueError, TypeError):
                    return str(val), None
            return None, "no var_binds"

    try:
        return asyncio.run(_do())
    except Exception as exc:
        return None, str(exc)


def _snmp_walk_ifnames(host, community, port=161, timeout=5, retries=1):
    """Walk ifName to map ifIndex → interface name. Returns {ifindex: name}."""
    from pysnmp.hlapi.v1arch.asyncio import SnmpDispatcher, CommunityData, UdpTransportTarget, ObjectType, ObjectIdentity
    from pysnmp.hlapi.v1arch.asyncio import cmdgen

    BASE = "1.3.6.1.2.1.31.1.1.1.1"

    async def _do():
        result = {}
        with SnmpDispatcher() as dispatcher:
            transport = await UdpTransportTarget.create(
                (host, port), timeout=timeout, retries=retries)
            try:
                current = [ObjectType(ObjectIdentity(BASE))]
                for _ in range(100):  # max 100 iterations
                    result_tuple = await cmdgen.next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1),
                        transport,
                        *current,
                    )
                    error_indication, error_status, _err_idx, var_binds = result_tuple
                    if error_indication or error_status:
                        break
                    next_oids = []
                    stop = False
                    for var_bind in var_binds:
                        oid_str = str(var_bind[0])
                        # Stop if we've walked past the ifName subtree.
                        if not oid_str.startswith(BASE + "."):
                            stop = True
                            break
                        oid_tail = oid_str.split(".")[-1]
                        try:
                            ifindex = int(oid_tail)
                        except ValueError:
                            continue
                        result[ifindex] = str(var_bind[1])
                        next_oids.append(ObjectType(ObjectIdentity(oid_str)))
                    if stop or not next_oids:
                        break
                    current = next_oids
            except Exception:
                pass
        return result

    try:
        return asyncio.run(_do())
    except Exception:
        return {}


def detect_ext_ifindex(host, community, port=161):
    """Auto-detect the external-interface ifIndex by looking for 'ethernet1/1'
    or 'ethernet1/2' in ifName. Returns an ifIndex int or None."""
    names = _snmp_walk_ifnames(host, community, port=port)
    for ifindex, name in names.items():
        low = name.lower().strip()
        # PAN-OS external is typically ethernet1/1.
        if low == "ethernet1/1":
            return ifindex
    for ifindex, name in names.items():
        if "ethernet1/1" in name.lower().strip():
            return ifindex
    for ifindex, name in names.items():
        if "ethernet" in name.lower().strip():
            return ifindex
    return None


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def open_db(db_path, retries=600, wait=0.5):
    """Open a read-write DuckDB connection, retrying on lock conflicts.

    The ingester holds the write lock while processing batches; the SNMP
    poller needs write access too (to INSERT into metrics). Retry for up to
    5 minutes so the poller rides out the ingester's lock instead of crashing.
    """
    last = None
    for _ in range(retries):
        try:
            con = duckdb.connect(db_path)
            con.execute(f"PRAGMA checkpoint_threshold='{CHECKPOINT_THRESHOLD}'")
            con.execute(f"PRAGMA wal_autocheckpoint='{CHECKPOINT_THRESHOLD}'")
            # Ensure the metrics table exists.
            con.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    ts                TIMESTAMPTZ NOT NULL,
                    cpu_pct           DOUBLE,
                    mem_pct           DOUBLE,
                    dp_cpu_pct        DOUBLE,
                    active_sessions   BIGINT,
                    session_util_pct  DOUBLE,
                    sess_tcp          BIGINT,
                    sess_udp          BIGINT,
                    sess_icmp         BIGINT,
                    sess_ssl_proxy    BIGINT,
                    ssl_proxy_util    DOUBLE,
                    cps               BIGINT,
                    pkt_desc_pct      DOUBLE,
                    hw_buf_pct        DOUBLE,
                    sw_buf_pct        DOUBLE,
                    throughput_in     BIGINT,
                    throughput_out    BIGINT,
                    ha_state          VARCHAR
                )
            """)
            return con
        except (duckdb.IOException, duckdb.ConnectionException) as exc:
            last = exc
            time.sleep(wait)
    raise last


def insert_metric(con, m):
    """Insert one metrics row from the poll_once() dict. No CHECKPOINT."""
    import zoneinfo
    ts = datetime.now(timezone.utc).astimezone(zoneinfo.ZoneInfo(LOCAL_TZ))
    con.execute(
        "INSERT INTO metrics (ts, cpu_pct, mem_pct, dp_cpu_pct, active_sessions, "
        "session_util_pct, sess_tcp, sess_udp, sess_icmp, sess_ssl_proxy, "
        "ssl_proxy_util, cps, pkt_desc_pct, hw_buf_pct, sw_buf_pct, "
        "throughput_in, throughput_out, ha_state) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [ts, m["cpu_pct"], m["mem_pct"], m["dp_cpu_pct"],
         m["active_sessions"], m["session_util_pct"],
         m.get("sess_tcp"), m.get("sess_udp"), m.get("sess_icmp"),
         m.get("sess_ssl_proxy"), m.get("ssl_proxy_util"), m.get("cps"),
         m.get("pkt_desc_pct"), m.get("hw_buf_pct"), m.get("sw_buf_pct"),
         m.get("throughput_in"), m.get("throughput_out"), m["ha_state"]],
    )


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------

HA_STATE_MAP = {"1": "active", "2": "passive", "3": "candidate",
                "4": "primary", "5": "secondary"}


def poll_once(host, community, port, ext_ifindex, max_sessions):
    """Poll all OIDs once. Returns a dict of metric values (None if unavailable)."""
    vals = {}
    # CPU / mem / sessions / HA
    for key in ("session_util", "session_max", "active_sessions",
                "sess_tcp", "sess_udp", "sess_icmp", "sess_ssl_proxy",
                "ssl_proxy_util", "cps",
                "mgmt_cpu", "dp_cpu", "mem_used", "mem_size",
                "pkt_desc_used", "pkt_desc_size",
                "hw_buf_used", "hw_buf_size",
                "sw_buf_used", "sw_buf_size",
                "ha_state"):
        v, err = _snmp_get(host, community, OIDS[key], port=port)
        vals[key] = v
        if err and key == "active_sessions":
            # active_sessions is the most important; log if it fails.
            print(f"[poll] active_sessions OID failed: {err}", file=sys.stderr)

    # Interface octets for throughput (delta-based).
    tp_in = tp_out = None
    if ext_ifindex:
        v_in, _ = _snmp_get(host, community, f"{OIDS['if_in_octets']}.{ext_ifindex}", port=port)
        v_out, _ = _snmp_get(host, community, f"{OIDS['if_out_octets']}.{ext_ifindex}", port=port)
        vals["if_in_octets"] = v_in
        vals["if_out_octets"] = v_out

    # Normalize. Guard against empty strings / non-numeric values — some
    # PAN-OS versions return '' for OIDs that aren't applicable.
    def _to_float(v):
        if v is None or v == "":
            return None
        try:
            return float(v)
        except (ValueError, TypeError):
            return None

    def _to_int(v):
        if v is None or v == "":
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    cpu = _to_float(vals.get("mgmt_cpu"))
    dp = _to_float(vals.get("dp_cpu"))
    # Memory % = used / size * 100
    mem_used = _to_float(vals.get("mem_used"))
    mem_size = _to_float(vals.get("mem_size"))
    mem = (100.0 * mem_used / mem_size) if (mem_used is not None and mem_size) else None
    sessions = _to_int(vals.get("active_sessions"))
    # Prefer the NGFW's own session utilization % if available; else compute.
    sess_util = _to_float(vals.get("session_util"))
    if sess_util is None and sessions is not None and max_sessions:
        sess_util = 100.0 * sessions / max_sessions
    # Session protocol breakdown
    sess_tcp = _to_int(vals.get("sess_tcp"))
    sess_udp = _to_int(vals.get("sess_udp"))
    sess_icmp = _to_int(vals.get("sess_icmp"))
    sess_ssl = _to_int(vals.get("sess_ssl_proxy"))
    ssl_proxy_util = _to_float(vals.get("ssl_proxy_util"))
    cps = _to_int(vals.get("cps"))
    # Dataplane packet buffer utilization (%)
    def _pct(used_key, size_key):
        u = _to_float(vals.get(used_key))
        s = _to_float(vals.get(size_key))
        return (100.0 * u / s) if (u is not None and s) else None
    pkt_desc_pct = _pct("pkt_desc_used", "pkt_desc_size")
    hw_buf_pct = _pct("hw_buf_used", "hw_buf_size")
    sw_buf_pct = _pct("sw_buf_used", "sw_buf_size")
    # HA state is a DisplayString ("active"/"passive"/"disabled").
    ha_raw = vals.get("ha_state")
    ha = str(ha_raw).strip().lower() if ha_raw not in (None, "") else "unknown"
    return {
        "cpu_pct": cpu, "mem_pct": mem, "dp_cpu_pct": dp,
        "active_sessions": sessions, "session_util_pct": sess_util,
        "sess_tcp": sess_tcp, "sess_udp": sess_udp,
        "sess_icmp": sess_icmp, "sess_ssl_proxy": sess_ssl,
        "ssl_proxy_util": ssl_proxy_util, "cps": cps,
        "pkt_desc_pct": pkt_desc_pct, "hw_buf_pct": hw_buf_pct,
        "sw_buf_pct": sw_buf_pct,
        "if_in_octets": _to_int(vals.get("if_in_octets")),
        "if_out_octets": _to_int(vals.get("if_out_octets")),
        "ha_state": ha,
    }


def run_loop(host, community, port, db_path, interval, ext_ifindex, max_sessions):
    # Auto-detect the external interface if not specified (done once, before
    # the loop — doesn't need a DB connection).
    if ext_ifindex is None:
        ext_ifindex = detect_ext_ifindex(host, community, port=port)
        if ext_ifindex is not None:
            print(f"[snmp] auto-detected external interface ifIndex={ext_ifindex}")
        else:
            print("[snmp] WARNING: could not auto-detect external interface; "
                  "throughput will be unavailable. Pass --ext-ifindex manually.",
                  file=sys.stderr)

    prev_in = prev_out = None
    while True:
        # Open the DB connection fresh on each poll, insert, then close — so
        # the dashboard can acquire a read-only connection between polls.
        # (Holding the write lock continuously would block the dashboard.)
        try:
            m = poll_once(host, community, port, ext_ifindex, max_sessions)
            # Throughput = octets delta / interval (bps). On the first poll we
            # have no prior sample, so throughput is None until the second poll.
            tp_in = tp_out = None
            cur_in = m.pop("if_in_octets", None)
            cur_out = m.pop("if_out_octets", None)
            if cur_in is not None and prev_in is not None and interval > 0:
                tp_in = max(0, (cur_in - prev_in) * 8 // interval)
            if cur_out is not None and prev_out is not None and interval > 0:
                tp_out = max(0, (cur_out - prev_out) * 8 // interval)
            prev_in, prev_out = cur_in, cur_out

            # Write the row: open, insert, close (release the lock immediately).
            con = open_db(db_path)
            try:
                # Add throughput to the dict before inserting.
                m["throughput_in"] = tp_in
                m["throughput_out"] = tp_out
                insert_metric(con, m)
            finally:
                con.close()
            print(f"[snmp] {datetime.now().strftime('%H:%M:%S')} "
                  f"cpu={m['cpu_pct']} mem={m['mem_pct']} dp={m['dp_cpu_pct']} "
                  f"sessions={m['active_sessions']} ha={m['ha_state']} "
                  f"tp_in={tp_in} tp_out={tp_out}")
        except Exception as exc:
            print(f"[snmp] poll error: {exc}", file=sys.stderr)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Palo Alto NGFW SNMP poller")
    p.add_argument("--host", required=True, help="NGFW management IP")
    p.add_argument("--community", default="public", help="SNMPv2c community string")
    p.add_argument("--port", type=int, default=161)
    p.add_argument("--db", default=DEFAULT_METRICS_DB,
                   help="Path to the metrics DuckDB file (default: separate from palo.duckdb "
                        "to avoid lock contention with the syslog ingester)")
    p.add_argument("--interval", type=int, default=300,
                   help="Poll interval in seconds (default 300 = 5 min)")
    p.add_argument("--ext-ifindex", type=int, default=None,
                   help="External interface ifIndex for throughput (auto-detect if omitted)")
    p.add_argument("--max-sessions", type=int, default=20000,
                   help="Platform max sessions for utilization %% (PA-440 ~20000)")
    p.add_argument("--test", action="store_true",
                   help="Poll once and print, then exit (no DB write)")
    args = p.parse_args()

    if args.test:
        # Auto-detect interface for the test.
        ifi = args.ext_ifindex or detect_ext_ifindex(args.host, args.community, port=args.port)
        if ifi:
            print(f"[test] external interface ifIndex={ifi}")
        m = poll_once(args.host, args.community, args.port, ifi, args.max_sessions)
        print("[test] poll result:")
        for k, v in m.items():
            print(f"  {k}: {v}")
        return

    print(f"[snmp] polling {args.host}:{args.port} every {args.interval}s "
          f"-> {args.db}")
    run_loop(args.host, args.community, args.port, args.db, args.interval,
             args.ext_ifindex, args.max_sessions)


if __name__ == "__main__":
    main()
