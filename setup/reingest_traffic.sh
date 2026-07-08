#!/usr/bin/env bash
# reingest_traffic.sh — clear traffic rows and re-ingest so the new
# app_category/app_subcategory/app_technology/app_risk columns are populated
# for all existing rows. (INSERT OR IGNORE won't update existing rows, so we
# must DELETE + reset offset + re-parse the syslog.)
#
# NOTE: the systemctl calls need sudo, but the python3 DB operations MUST run
# as the suricata user (not root) because duckdb is installed in the suricata
# user's pip dir — `sudo python3` would use root's python with no duckdb.
set -euo pipefail

echo "==> [1/4] Stop the ingester so we can take the write lock"
sudo systemctl stop palo_ingest.service
for i in $(seq 1 30); do
    if ! systemctl is-active --quiet palo_ingest.service; then break; fi
    sleep 0.5
done
sleep 1

echo "==> [2/4] Add new columns if missing + clear traffic + reset offset"
# Run python3 as the suricata user (NOT root) so it can import duckdb from
# the user's pip install. `sudo -u suricata` preserves the user environment.
sudo -u suricata /usr/bin/python3 - <<'PY'
import time, duckdb, sys
for attempt in range(120):
    try:
        c = duckdb.connect('/home/suricata/palo.duckdb'); break
    except (duckdb.IOException, duckdb.ConnectionException):
        time.sleep(0.5)
else:
    print("ERROR: write lock busy after 60s"); sys.exit(1)
for col, dtype in [("app_category","VARCHAR"),("app_subcategory","VARCHAR"),
                   ("app_technology","VARCHAR"),("app_risk","INTEGER")]:
    try:
        c.execute(f"ALTER TABLE traffic ADD COLUMN {col} {dtype}")
        print(f"  added {col}")
    except Exception:
        print(f"  {col} already present")
c.execute("DELETE FROM traffic")
c.execute("CHECKPOINT")
n = c.execute("SELECT count(*) FROM traffic").fetchone()[0]
c.close()
print(f"  traffic rows after DELETE: {n}")
PY
sudo -u suricata rm -f /home/suricata/palo.duckdb.offset

echo "==> [3/4] Restart the ingester (re-parses syslog with app metadata)"
sudo systemctl start palo_ingest.service

echo "==> [4/4] Wait for re-ingest, then verify app metadata is populated"
sleep 12
sudo -u suricata /usr/bin/python3 - <<'PY'
import time, duckdb, sys
for attempt in range(60):
    try:
        c = duckdb.connect('/home/suricata/palo.duckdb', read_only=True); break
    except Exception:
        time.sleep(0.5)
else:
    print("  (ingester still holding lock — try again in a moment)"); sys.exit(0)
total = c.execute("SELECT count(*) FROM traffic").fetchone()[0]
with_cat = c.execute("SELECT count(*) FROM traffic WHERE app_category IS NOT NULL AND app_category <> ''").fetchone()[0]
print(f"  traffic total: {total}   with app_category: {with_cat}")
print("  sample app metadata:")
for r in c.execute("SELECT app, app_category, app_subcategory, app_technology, app_risk, count(*) FROM traffic WHERE app_category <> '' GROUP BY 1,2,3,4,5 ORDER BY 6 DESC LIMIT 8").fetchall():
    print("  ", r)
c.close()
if with_cat > 0:
    print("\n✅ app metadata populated.")
else:
    print("\n⚠️  no app metadata yet — re-run this script.")
PY
