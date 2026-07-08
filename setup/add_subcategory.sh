#!/usr/bin/env bash
# add_subcategory.sh — add the subcategory column to the threat table and
# re-ingest threat rows so the URL filtering widget can show subcategories.
#
# The ingester's create_schema() now runs ALTER TABLE threat ADD COLUMN
# subcategory VARCHAR on startup (no-op if already present). But existing
# threat rows won't have subcategory populated (INSERT OR IGNORE on event_id
# keeps the old rows). So we DELETE the threat rows + reset the offset and
# let the ingester re-parse the syslog with the subcategory-extracting parser.
set -euo pipefail

echo "==> [1/4] Stop the ingester so we can take the write lock"
sudo systemctl stop palo_ingest.service
for i in $(seq 1 30); do
    if ! systemctl is-active --quiet palo_ingest.service; then break; fi
    sleep 0.5
done
sleep 1

echo "==> [2/4] Clear threat rows + reset offset (so syslog is re-parsed)"
python3 - <<'PY'
import time, duckdb, sys
for attempt in range(120):
    try:
        c = duckdb.connect('/home/suricata/palo.duckdb'); break
    except (duckdb.IOException, duckdb.ConnectionException):
        time.sleep(0.5)
else:
    print("ERROR: write lock busy after 60s"); sys.exit(1)
# Add the column now if missing (the ingester would do it too, but doing it
# here means the re-ingest populates it immediately).
try:
    c.execute("ALTER TABLE threat ADD COLUMN subcategory VARCHAR")
    print("  added subcategory column")
except Exception:
    print("  subcategory column already present")
c.execute("DELETE FROM threat")
c.execute("CHECKPOINT")
n = c.execute("SELECT count(*) FROM threat").fetchone()[0]
c.close()
print(f"  threat rows after DELETE: {n}")
PY
rm -f /home/suricata/palo.duckdb.offset

echo "==> [3/4] Restart the ingester (re-parses syslog, populates subcategory)"
sudo systemctl start palo_ingest.service

echo "==> [4/4] Restart streamlit to pick up the widget changes"
sudo systemctl restart streamlit.service

echo
echo "Wait ~10s, then verify subcategory is populated:"
echo "  python3 -c \"import duckdb,time; \\
echo '   ', [r for r in duckdb.connect('/home/suricata/palo.duckdb',read_only=True).execute('SELECT category,subcategory,count(*) FROM threat WHERE threat_type=\\'url\\' GROUP BY 1,2 ORDER BY 3 DESC LIMIT 8').fetchall()]\""
