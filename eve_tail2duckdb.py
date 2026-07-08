#!/usr/bin/env python3
"""
eve_tail2duckdb.py
------------------
Tail Suricata's /var/log/suricata/eve.json and index each event into a
lightweight DuckDB database.

Features
--------
* Resumable: persists the last byte offset in a sidecar file so restarts
  continue where it left off (no re-ingest).
* Rotation-aware: if eve.json is truncated/rotated (size shrinks or inode
  changes), it reopens from the beginning.
* Idempotent: primary key is a hash of the raw JSON line, so re-reading a
  line is a harmless no-op (INSERT OR IGNORE).
* Normalized: common fields are typed columns; nested `dns` and `flow`
  objects are split into companion tables for fast querying.
* Batched inserts for throughput.

Usage
-----
    python3 eve_tail2duckdb.py [--eve PATH] [--db PATH] [--batch N] [--poll S]

    --eve   path to eve.json        (default: /var/log/suricata/eve.json)
    --db    path to duckdb file     (default: ./eve.duckdb)
    --batch flush every N lines     (default: 1000)
    --poll  seconds between polls   (default: 1.0)
"""

import argparse
import hashlib
import json
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

import duckdb

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
# Main events table. `event_hash` is the PK (sha1 of the raw line) -> makes
# re-ingest idempotent. `raw` keeps the full original JSON for any field we
# didn't pull out into a column.
SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS events (
        event_hash      VARCHAR PRIMARY KEY,
        timestamp       TIMESTAMPTZ,
        flow_id         BIGINT,
        in_iface        VARCHAR,
        event_type      VARCHAR,
        vlan            INTEGER[],
        src_ip          VARCHAR,
        src_port        INTEGER,
        dest_ip         VARCHAR,
        dest_port       INTEGER,
        ip_v            SMALLINT,
        proto           VARCHAR,
        app_proto       VARCHAR,
        pkt_src         VARCHAR,
        raw             VARCHAR,
        ingested_at     TIMESTAMPTZ DEFAULT now()
    )
    """,
    # DNS events (one row per dns event; queries flattened to a JSON array col)
    """
    CREATE TABLE IF NOT EXISTS dns_events (
        event_hash      VARCHAR PRIMARY KEY,
        timestamp       TIMESTAMPTZ,
        flow_id         BIGINT,
        src_ip          VARCHAR,
        dest_ip         VARCHAR,
        dns_type        VARCHAR,          -- request | response
        tx_id           INTEGER,
        id              INTEGER,
        flags           VARCHAR,
        rcode           VARCHAR,
        opcode          INTEGER,
        rrname          VARCHAR,          -- first query name (for fast filtering)
        rrtype          VARCHAR,          -- first query type
        queries         VARCHAR           -- full queries array as JSON text
    )
    """,
    # Flow events
    """
    CREATE TABLE IF NOT EXISTS flow_events (
        event_hash      VARCHAR PRIMARY KEY,
        timestamp       TIMESTAMPTZ,
        flow_id         BIGINT,
        src_ip          VARCHAR,
        dest_ip         VARCHAR,
        pkts_toserver   BIGINT,
        pkts_toclient   BIGINT,
        bytes_toserver  BIGINT,
        bytes_toclient  BIGINT,
        start           TIMESTAMPTZ,
        "end"            TIMESTAMPTZ,
        age             INTEGER,
        state           VARCHAR,
        reason          VARCHAR,
        alerted         BOOLEAN,
        tx_cnt          INTEGER,
        app_proto       VARCHAR
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_flow_id   ON events(flow_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_src       ON events(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_dest      ON events(dest_ip)",
    "CREATE INDEX IF NOT EXISTS idx_dns_rrname       ON dns_events(rrname)",
    "CREATE INDEX IF NOT EXISTS idx_flow_state       ON flow_events(state)",
]


def init_db(con: duckdb.DuckDBPyConnection) -> None:
    for stmt in SCHEMA:
        con.execute(stmt)


def open_db(db_path: Path, read_only: bool = False,
            retries: int = 20, wait: float = 0.3) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB connection, retrying briefly on lock conflicts.

    DuckDB allows multiple read-only connections OR a single read-write
    connection, never both at once. A live dashboard holding a read-only
    lock can transiently block the ingester's write connection (and vice
    versa); retrying resolves the race.
    """
    last = None
    for _ in range(retries):
        try:
            con = duckdb.connect(str(db_path), read_only=read_only)
            if not read_only:
                # Defer checkpointing so con.close() doesn't trigger a slow
                # full checkpoint (which can take ~19s on a multi-GB DB and
                # holds the write lock the whole time). The WAL still gets
                # flushed; the big merge is deferred until an explicit
                # CHECKPOINT or shutdown.
                try:
                    con.execute("SET checkpoint_threshold='100GB'")
                    con.execute("SET wal_autocheckpoint='100GB'")
                except Exception:
                    pass
            return con
        except duckdb.IOException as exc:
            last = exc
            time.sleep(wait)
    raise last


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def first_query(dns: dict):
    """Return (rrname, rrtype) of the first query, or (NULL, NULL)."""
    qs = dns.get("queries") or []
    if qs:
        q = qs[0]
        return q.get("rrname"), q.get("rrtype")
    return None, None


def build_rows(line: str):
    """Parse one raw JSON line into the rows we want to insert.

    Returns (events_row, dns_row_or_None, flow_row_or_None) or None if the
    line is not valid JSON.
    """
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return None

    raw = line.rstrip("\n")
    event_hash = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    # Typed alert fields (extracted from the nested alert object so we don't
    # need to store the full raw JSON line).
    alert = e.get("alert") or {}
    alert_signature = alert.get("signature")
    alert_severity = alert.get("severity")

    vlan = e.get("vlan")
    # DuckDB wants a Python list for INTEGER[]
    if isinstance(vlan, list):
        vlan = [int(v) for v in vlan]
    elif vlan is not None:
        vlan = [int(vlan)]
    else:
        vlan = None

    ev_row = (
        event_hash,
        e.get("timestamp"),
        e.get("flow_id"),
        e.get("in_iface"),
        e.get("event_type"),
        vlan,
        e.get("src_ip"),
        e.get("src_port"),
        e.get("dest_ip"),
        e.get("dest_port"),
        e.get("ip_v"),
        e.get("proto"),
        e.get("app_proto"),
        e.get("pkt_src"),
        alert_signature,
        alert_severity,
    )

    dns_row = None
    flow_row = None

    if e.get("event_type") == "dns" and "dns" in e:
        d = e["dns"]
        rrname, rrtype = first_query(d)
        dns_row = (
            event_hash,
            e.get("timestamp"),
            e.get("flow_id"),
            e.get("src_ip"),
            e.get("dest_ip"),
            d.get("type"),
            d.get("tx_id"),
            d.get("id"),
            d.get("flags"),
            d.get("rcode"),
            d.get("opcode"),
            rrname,
            rrtype,
            json.dumps(d.get("queries") or []),
        )
    elif e.get("event_type") == "flow" and "flow" in e:
        f = e["flow"]
        flow_row = (
            event_hash,
            e.get("timestamp"),
            e.get("flow_id"),
            e.get("src_ip"),
            e.get("dest_ip"),
            f.get("pkts_toserver"),
            f.get("pkts_toclient"),
            f.get("bytes_toserver"),
            f.get("bytes_toclient"),
            f.get("start"),
            f.get("end"),
            f.get("age"),
            f.get("state"),
            f.get("reason"),
            bool(f.get("alerted")) if f.get("alerted") is not None else None,
            f.get("tx_cnt"),
            e.get("app_proto"),
        )

    return ev_row, dns_row, flow_row


# ---------------------------------------------------------------------------
# Tail logic
# ---------------------------------------------------------------------------
class Tailer:
    def __init__(self, path: Path, state_file: Path):
        self.path = path
        self.state_file = state_file
        self.fp = None
        self.inode = None

    def _load_offset(self) -> int:
        try:
            return int(self.state_file.read_text().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_offset(self, offset: int) -> None:
        self.state_file.write_text(str(offset))

    def open(self) -> bool:
        """Open the file and seek to the saved offset. Handle rotation.

        Returns True if the file is open and ready to read.
        """
        if not self.path.exists():
            return False
        st = self.path.stat()
        offset = self._load_offset()

        # Rotation / truncation detection: if the file got smaller, or the
        # inode changed, start from the beginning.
        if self.fp is not None and (st.st_size < self.tell() or st.st_ino != self.inode):
            self.fp.close()
            self.fp = None
            offset = 0

        if self.fp is None:
            self.fp = open(self.path, "r", encoding="utf-8", errors="replace")
            self.inode = st.st_ino
            if offset > st.st_size:
                offset = 0
            self.fp.seek(offset)

        return True

    def tell(self) -> int:
        return self.fp.tell() if self.fp else 0

    def readlines(self):
        """Yield raw lines that are currently available (non-blocking)."""
        if self.fp is None:
            return
        while True:
            pos = self.fp.tell()
            line = self.fp.readline()
            if not line:
                # No more data right now; rewind to start of partial line so
                # the next poll re-reads it whole.
                self.fp.seek(pos)
                break
            yield line

    def checkpoint(self):
        self._save_offset(self.tell())

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
RUNNING = True


def _stop(signum, frame):
    global RUNNING
    RUNNING = False


def main():
    ap = argparse.ArgumentParser(description="Tail eve.json into DuckDB")
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--db", default=str(Path(__file__).with_suffix(".duckdb")))
    ap.add_argument("--batch", type=int, default=1000, help="flush every N lines")
    ap.add_argument("--poll", type=float, default=1.0, help="seconds between polls")
    ap.add_argument("--read-gap", type=float, default=1.0,
                    help="seconds to hold the write lock open (no connection) "
                         "after closing it, so the dashboard can read. The lock "
                         "is released at --reopen-every intervals and on idle.")
    ap.add_argument("--reopen-every", type=int, default=1,
                    help="close the write connection every N flushes so the "
                         "dashboard can acquire the read lock. 1 (default) "
                         "releases after every batch. 0=never close during "
                         "active ingest (dashboard blocked until idle).")
    ap.add_argument("--from-start", action="store_true",
                    help="ignore saved offset and read from the start once")
    args = ap.parse_args()

    eve_path = Path(args.eve)
    db_path = Path(args.db)
    state_file = db_path.with_suffix(db_path.suffix + ".offset")

    if args.from_start and state_file.exists():
        state_file.unlink()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    # Open the schema once with a persistent write connection. Bulk COPY is
    # ~100-400x faster than executemany, but it needs a persistent connection
    # to amortize the open cost. Strategy: keep the write connection open only
    # while we have data to ingest; close it when idle so the dashboard can
    # open read-only. (DuckDB forbids RO+RW coexisting at all, so the only way
    # the dashboard reads is when no writer exists.)
    con = open_db(db_path, read_only=False)
    init_db(con)
    flush_count = 0
    con_open = True

    tailer = Tailer(eve_path, state_file)

    ev_buf, dns_buf, flow_buf = [], [], []
    last_checkpoint = time.time()
    total = 0

    print(f"[eve_tail2duckdb] eve={eve_path} db={db_path} batch={args.batch}",
          flush=True)

    while RUNNING:
        if not tailer.open():
            # file doesn't exist yet
            time.sleep(args.poll)
            continue

        lines_read = 0
        for line in tailer.readlines():
            lines_read += 1
            parsed = build_rows(line)
            if parsed is None:
                continue
            ev_row, dns_row, flow_row = parsed
            ev_buf.append(ev_row)
            if dns_row is not None:
                dns_buf.append(dns_row)
            if flow_row is not None:
                flow_buf.append(flow_row)

            if len(ev_buf) >= args.batch:
                _flush(con, db_path, ev_buf, dns_buf, flow_buf)
                total += len(ev_buf)
                ev_buf.clear(); dns_buf.clear(); flow_buf.clear()
                tailer.checkpoint()
                last_checkpoint = time.time()
                print(f"[eve_tail2duckdb] indexed {total} events "
                      f"(offset={tailer.tell()})", flush=True)
                flush_count += 1
                # Periodically close the write connection so the dashboard can
                # open read-only (DuckDB forbids RO+RW coexisting). With
                # deferred checkpointing, close is ~2-3s instead of ~19s, and
                # --read-gap gives the dashboard a window before we reopen.
                if args.reopen_every and flush_count % args.reopen_every == 0:
                    con.close()
                    con_open = False
                    time.sleep(args.read_gap)
                else:
                    time.sleep(args.read_gap)

        if lines_read == 0:
            # Idle (no new lines this poll). Flush any pending buffer so data
            # is queryable, then CLOSE the write connection so the dashboard
            # can open read-only. We reopen on demand when new data arrives.
            if ev_buf and (time.time() - last_checkpoint) >= max(args.poll, 2.0):
                _flush(con, db_path, ev_buf, dns_buf, flow_buf)
                total += len(ev_buf)
                ev_buf.clear(); dns_buf.clear(); flow_buf.clear()
                tailer.checkpoint()
                last_checkpoint = time.time()
                print(f"[eve_tail2duckdb] indexed {total} events "
                      f"(offset={tailer.tell()})", flush=True)
            if con_open:
                con.close()
                con_open = False
            time.sleep(args.poll)
            # Reopen on the next loop iteration only if there's new data; if
            # there isn't, we stay closed and the dashboard can read.
            # (The reopen happens lazily below.)

        elif lines_read < args.batch and con_open:
            # Live-tail trickle: we read some lines but not enough to fill a
            # batch, so we're not in a backlog flood. Release the write lock
            # now so the dashboard can read between polls, then sleep. The
            # pending buffer is kept and flushed once it fills or on idle.
            con.close()
            con_open = False
            time.sleep(args.read_gap)

        # Lazy reopen: if we previously closed the connection and we're about
        # to need it (buffer has data to flush, or there are pending rows),
        # reopen now. This keeps the writer absent during idle periods. If the
        # dashboard is holding a long read query, retry for a while; if we still
        # can't get the lock, skip this cycle (keep the buffer) and try again on
        # the next poll rather than crashing.
        if not con_open and (ev_buf or lines_read > 0):
            try:
                con = open_db(db_path, read_only=False, retries=120, wait=0.5)
                con_open = True
            except duckdb.IOException:
                # Dashboard still holding the read lock; try again next poll.
                con_open = False

    # graceful shutdown: flush remainder + final checkpoint
    if not con_open:
        con = open_db(db_path, read_only=False)
        con_open = True
    if ev_buf:
        _flush(con, db_path, ev_buf, dns_buf, flow_buf)
        total += len(ev_buf)
    tailer.checkpoint()
    final_offset = tailer.tell()
    tailer.close()
    try:
        con.execute("CHECKPOINT")  # merge WAL into main DB on clean shutdown
    except Exception:
        pass
    con.close()
    print(f"[eve_tail2duckdb] stopped. total indexed={total} "
          f"offset={final_offset}", flush=True)


def _flush(con, db_path, ev_buf, dns_buf, flow_buf):
    """Bulk-load buffers into DuckDB via COPY from temp JSONL files.

    This is ~100-400x faster than executemany() on this VM. Re-reading a
    line after a crash/rotation is harmless because event_hash is the PK
    and we use INSERT OR IGNORE.
    """
    _bulk_copy(con, ev_buf,
               "events",
               "event_hash,timestamp,flow_id,in_iface,event_type,vlan,"
               "src_ip,src_port,dest_ip,dest_port,ip_v,proto,app_proto,"
               "pkt_src,alert_signature,alert_severity",
               16)
    if dns_buf:
        _bulk_copy(con, dns_buf,
                   "dns_events",
                   "event_hash,timestamp,flow_id,src_ip,dest_ip,dns_type,"
                   "tx_id,id,flags,rcode,opcode,rrname,rrtype,queries",
                   14)
    if flow_buf:
        _bulk_copy(con, flow_buf,
                   "flow_events",
                   "event_hash,timestamp,flow_id,src_ip,dest_ip,"
                   "pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,"
                   "start,\"end\",age,state,reason,alerted,tx_cnt,app_proto",
                   17)


def _bulk_copy(con, rows, table, columns, ncols):
    """Write `rows` (tuples of length ncols) to a temp JSONL file and
    INSERT OR IGNORE via read_json_auto. Columns with reserved names
    (e.g. "end") are quoted in the SELECT list."""
    if not rows:
        return
    # Build the temp JSONL. Each row is a JSON object keyed by column name.
    col_names = [c.strip().strip('"') for c in columns.split(",")]
    # SELECT identifiers: quote any that are DuckDB/SQL reserved words.
    RESERVED = {"end", "start", "order", "group", "select", "from", "where",
                "type", "id", "state", "age", "reason", "source", "location"}
    sel = ", ".join(f'"{c}"' if c in RESERVED else c for c in col_names)
    fd, path = tempfile.mkstemp(suffix=".jsonl", prefix=f"eve_{table}_")
    os.close(fd)
    try:
        with open(path, "w") as f:
            for row in rows:
                obj = {col_names[i]: row[i] for i in range(ncols)}
                f.write(json.dumps(obj, default=str) + "\n")
        con.execute(
            f"INSERT OR IGNORE INTO {table} ({columns}) "
            f"SELECT {sel} FROM read_json_auto('{path}')"
        )
    finally:
        try: os.remove(path)
        except OSError: pass


if __name__ == "__main__":
    main()
