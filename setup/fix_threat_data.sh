#!/usr/bin/env bash
# fix_threat_data.sh — clear mis-parsed threat rows and re-ingest with the
# subtype-aware parser.
#
# Background: an earlier parser bug mapped category/severity to the wrong
# fields for the `url` THREAT subtype (category got '(9999)'). The parser is
# now fixed, but INSERT OR IGNORE on event_id keeps the old bad rows because
# they collide with the corrected rows' IDs. We must DELETE the bad rows,
# reset the ingest offset, and let the ingester re-parse the syslog file.
#
# This script is safe to re-run. It verifies the DELETE actually happened
# before restarting the ingester.
set -euo pipefail

DB=/home/suricata/palo.duckdb
OFFSET=/home/suricata/palo.duckdb.offset

echo "==> [1/5] Stop the ingester so we can take the write lock"
sudo systemctl stop palo_ingest.service
# Wait for the process to actually exit and release the DuckDB lock.
for i in $(seq 1 30); do
    if ! systemctl is-active --quiet palo_ingest.service; then break; fi
    sleep 0.5
done
sleep 1  # extra grace for OS lock release

echo "==> [2/5] DELETE all threat rows (retry on lock) + verify"
python3 - <<'PY'
import time, duckdb, sys
for attempt in range(120):
    try:
        c = duckdb.connect('/home/suricata/palo.duckdb')  # read-write
        break
    except (duckdb.IOException, duckdb.ConnectionException) as e:
        if attempt == 0:
            print(f"  waiting for write lock (ingester may still be releasing it)...")
        time.sleep(0.5)
else:
    print("ERROR: could not acquire write lock after 60s"); sys.exit(1)
c.execute("DELETE FROM threat")
c.execute("CHECKPOINT")
n = c.execute("SELECT count(*) FROM threat").fetchone()[0]
c.close()
print(f"  threat rows after DELETE: {n}")
if n != 0:
    print("ERROR: DELETE did not clear the table — aborting"); sys.exit(1)
print("  OK — threat table is empty")
PY

echo "==> [3/5] Remove the ingest offset so syslog is re-parsed from the start"
rm -f "$OFFSET"
echo "  removed $OFFSET"

echo "==> [4/5] Restart the ingester (re-parses syslog with the fixed parser)"
sudo systemctl start palo_ingest.service

echo "==> [5/5] Wait for re-ingest, then verify"
sleep 12
python3 - <<'PY'
import time, duckdb, sys
for attempt in range(60):
    try:
        c = duckdb.connect('/home/suricata/palo.duckdb', read_only=True); break
    except Exception:
        time.sleep(0.5)
else:
    print("  (ingester still holding lock after 30s — try again in a moment)"); sys.exit(0)
total = c.execute("SELECT count(*) FROM threat").fetchone()[0]
bad   = c.execute("SELECT count(*) FROM threat WHERE category='(9999)'").fetchone()[0]
good  = c.execute("SELECT count(*) FROM threat WHERE category NOT LIKE '(%' AND category <> ''").fetchone()[0]
print(f"  threat total: {total}   bad((9999)): {bad}   good: {good}")
print("  sample by subtype/category/severity:")
for r in c.execute("SELECT threat_type, category, severity, action, count(*) FROM threat GROUP BY 1,2,3,4 ORDER BY 5 DESC LIMIT 8").fetchall():
    print("   ", r)
c.close()
if bad == 0:
    print("\n✅ FIXED — no (9999) rows remain.")
else:
    print(f"\n⚠️  {bad} bad rows still present — re-run this script.")
PY

echo
echo "==> Restart streamlit to pick up the widget changes:"
echo "   sudo systemctl restart streamlit.service"
