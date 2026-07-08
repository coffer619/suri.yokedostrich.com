#!/usr/bin/env bash
# install.sh — one-time setup for the Firewall dashboard syslog target + services.
#
# Run with:  bash /home/suricata/setup/install.sh
# (It will sudo internally and prompt for your password.)
#
# Idempotent: safe to re-run. Does NOT touch eve.duckdb or the existing
# eve_tail2duckdb.service. After this, point the NGFW at this VM per
# /home/suricata/NGFW_SETUP.md.
set -euo pipefail

SETUP_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Setup dir: $SETUP_DIR"

echo "==> [1/7] Install rsyslog PAN-OS receiver (UDP 5140 -> /var/log/palo-alto.log)"
sudo install -m 0644 -o root -g root "$SETUP_DIR/49-palo.conf" /etc/rsyslog.d/49-palo.conf
# Pre-create the log file owned by suricata so the ingester can read it even
# before the first PAN-OS message arrives.
sudo install -d -o suricata -g adm -m 0755 /var/log
sudo touch /var/log/palo-alto.log
sudo chown suricata:adm /var/log/palo-alto.log
sudo chmod 0644 /var/log/palo-alto.log
sudo systemctl restart rsyslog.service
sudo systemctl enable --now rsyslog.service >/dev/null 2>&1 || true

echo "==> [2/7] Install logrotate for /var/log/palo-alto.log"
sudo install -m 0644 -o root -g root "$SETUP_DIR/palo-alto.logrotate" /etc/logrotate.d/palo-alto

echo "==> [3/7] Open UDP 5140 in ufw for the NGFW syslog feed"
if command -v ufw >/dev/null 2>&1; then
    if sudo ufw status | grep -q "Status: active"; then
        sudo ufw allow 5140/udp comment 'PAN-OS syslog'
        echo "    ufw active — added 5140/udp."
    else
        echo "    ufw inactive — no rule added (fine if no host firewall)."
    fi
else
    echo "    ufw not installed — skipping."
fi

echo "==> [4/7] Install palo_ingest.service (syslog -> palo.duckdb)"
sudo install -m 0644 -o root -g root "$SETUP_DIR/palo_ingest.service" /etc/systemd/system/palo_ingest.service
sudo systemctl daemon-reload

echo "==> [5/7] Seed mock data so the Firewall page renders immediately"
if [ ! -f /home/suricata/palo.duckdb ] || [ "${1:-}" = "--reseed" ]; then
    /usr/bin/python3 /home/suricata/palo_ingest.py \
        --db /home/suricata/palo.duckdb --mock --hours 24 --reset
fi

echo "==> [6/7] Update streamlit.service to run app.py (left-side menu)"
sudo install -m 0644 -o root -g root "$SETUP_DIR/streamlit.service" /etc/systemd/system/streamlit.service
sudo systemctl daemon-reload

echo "==> [7/7] Restart streamlit + enable (but don't start) the palo ingester"
sudo systemctl restart streamlit.service
# Don't auto-start palo_ingest yet — it will spin idly until the NGFW sends.
# Start it manually once syslog is confirmed flowing:
#   sudo systemctl enable --now palo_ingest.service
sudo systemctl enable palo_ingest.service >/dev/null 2>&1 || true

echo
echo "Done. Verify:"
echo "  sudo systemctl status streamlit.service"
echo "  curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:8765   # expect 200"
echo "  https://your-dashboard.example.com   -> left menu: Local Network / Firewall"
echo
echo "When the NGFW syslog feed is configured (see ~/NGFW_SETUP.md):"
echo "  sudo systemctl enable --now palo_ingest.service"
