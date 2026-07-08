#!/usr/bin/env bash
# fix_rsyslog.sh — apply the corrected PAN-OS rsyslog receiver.
#
# Two fixes vs the original install:
#   1. Named input (name="palo_imudp") + match on $inputname, so routing is
#      deterministic (the bare `imudp` match could silently never fire on
#      rsyslog 8.2112, leaving /var/log/palo-alto.log empty).
#   2. Drop fileOwner/fileGroup (rsyslog can't chown to suricata after
#      privilege drop) and use fileCreateMode=0664 so the syslog user (in the
#      adm group) can append to the suricata:adm file.
#   3. chmod the existing log file to 0664 so appending works immediately.
set -euo pipefail

SETUP_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Install corrected rsyslog config"
sudo install -m 0644 -o root -g root "$SETUP_DIR/49-palo.conf" /etc/rsyslog.d/49-palo.conf

echo "==> Ensure /var/log/palo-alto.log is group-writable by adm (syslog is in adm)"
sudo touch /var/log/palo-alto.log
sudo chown suricata:adm /var/log/palo-alto.log
sudo chmod 0664 /var/log/palo-alto.log

echo "==> Validate rsyslog config (rsyslogd -N1)"
sudo rsyslogd -N1 2>&1 || { echo "CONFIG VALIDATION FAILED"; exit 1; }

echo "==> Restart rsyslog"
sudo systemctl restart rsyslog.service
sleep 1
sudo systemctl is-active rsyslog.service

echo
echo "Done. Now generate/send some PAN-OS syslog and check:"
echo "  sudo tcpdump -ni ens160 udp port 5140 -c 5    # confirm packets to-us"
echo "  tail -f /var/log/palo-alto.log                # should now show PAN-OS lines"
echo
echo "If lines appear, start the ingester:"
echo "  sudo systemctl enable --now palo_ingest.service"
echo "  journalctl -u palo_ingest.service -n 30 --no-pager"
