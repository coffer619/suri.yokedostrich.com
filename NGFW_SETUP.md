# NGFW Dashboard — Setup Guide

This adds a **Firewall** page to the Streamlit dashboard (left-side menu:
*Local Network* = existing Suricata eve dashboard, *Firewall* = new Palo Alto
NGFW dashboard). The existing Suricata dashboard is unchanged.

---

## Architecture

```
Palo Alto NGFW  --UDP/5140 syslog-->  rsyslog on VM  --> /var/log/palo-alto.log
                                                                  |
                                                                  v
                                              palo_ingest.py (systemd) --tail
                                                                  |
                                                                  v
                                                          palo.duckdb (read-only for dashboard)
                                                                  |
                                                                  v
                                          Streamlit "Firewall" page (app.py nav)

(VM)  --SNMP GET-->  Palo Alto NGFW  (future: poller fills `metrics` table)
```

Files added on the VM:

| File | Purpose |
| --- | --- |
| `/home/suricata/app.py` | New Streamlit entry point with left-side nav (Local Network / Firewall) |
| `/home/suricata/pages/local_network.py` | Nav page wrapping the existing Suricata dashboard (unchanged behavior) |
| `/home/suricata/pages/firewall.py` | The NGFW dashboard mockup (KPIs, traffic, threats, URL filtering, SNMP gauges, system events) |
| `/home/suricata/palo_ingest.py` | PAN-OS syslog → DuckDB ingester. `--mock` seeds synthetic data; `--tail` parses real syslog. |
| `/home/suricata/palo.duckdb` | The NGFW DuckDB file (created by `--mock` or the tailer) |
| `/home/suricata/setup/49-palo.conf` | rsyslog receiver config (UDP 5140 → `/var/log/palo-alto.log`) |
| `/home/suricata/setup/palo_ingest.service` | systemd unit for the ingester |
| `/home/suricata/setup/streamlit.service` | Updated systemd unit (runs `app.py` instead of `suri_dashboard.py`) |
| `/home/suricata/setup/install.sh` | One-time installer (rsyslog, logrotate, ufw, services, mock seed) |

`suri_dashboard.py` was refactored minimally: `render_local_network_page()`
was extracted from `main()` so it can be reused as a nav page. Running
`streamlit run suri_dashboard.py` directly still works as a standalone
fallback.

---

## 1. On the VM: run the installer (one time)

```bash
bash /home/suricata/setup/install.sh
```

This:
1. Installs the rsyslog receiver (UDP 5140 → `/var/log/palo-alto.log`, owned by `suricata`).
2. Installs logrotate (daily, 14-day retention, `copytruncate` so the tailer keeps following).
3. Opens UDP 5140 in ufw (if ufw is active).
4. Installs `palo_ingest.service`.
5. Seeds **mock data** into `palo.duckdb` so the Firewall page renders immediately.
6. Switches `streamlit.service` to run `app.py` (left-side menu) and restarts it.

Verify:
```bash
sudo systemctl status streamlit.service
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8765   # expect 200
```
Visit https://your-dashboard.example.com — you should see a left menu with
**Local Network** and **Firewall**. The Firewall page will show the mockup
data (synthetic 24h of PAN-OS traffic/threats/URL/metrics).

The VM's syslog target is:
- **IP:** `YOUR_VM_IP` (the Suricata VM)
- **Transport:** UDP
- **Port:** `5140`
- **Format:** ICS (comma-separated, the PAN-OS default "Syslog" format). Do **not** use CEF / BSD leatherboard — the parser in `palo_ingest.py` expects the standard ICS payload (the `1,date,time,serial,type,...` body).

---

## 2. On the Palo Alto NGFW: create the syslog profile

### a) Syslog Server Profile
**Device → Server Profiles → Syslog → Add**

| Field | Value |
| --- | --- |
| Name | `suri-vm-syslog` |
| Servers → Name | `suri-vm` |
| Servers → Server | `YOUR_VM_IP` |
| Servers → Transport | `UDP` |
| Servers → Port | `5140` |
| Servers → Facility | `LOG_USER` (any — rsyslog routes by port, not facility) |
| Format | **ICS** (the default comma-separated format) |

### b) Log forwarding (attach the profile to the log types you want)
For each log type you want on the dashboard, add a log-forwarding profile
entry pointing at `suri-vm-syslog`. The ingester parses these types:
**TRAFFIC, THREAT, URL, SYSTEM**. (CONFIG and others are ignored for now.)

Example — **Objects → Log Forwarding → Add** (`fw-to-suri`):
- Traffic log → forward `all` (or `traffic-allowed` + `traffic-denied`) to `suri-vm-syslog`
- Threat log  → forward `all` to `suri-vm-syslog`
- URL log     → forward `all` to `suri-vm-syslog`  *(requires URL filtering license)*
- System log  → forward `all` to `suri-vm-syslog`

Then attach `fw-to-suri` to the relevant **Security policies** and the
**default** Log Forwarding setting under **Device → Setup → Management →
Logging**. Enable "Log at Session Start/End" for traffic.

### c) Verify the feed reaches the VM
After committing on the NGFW, generate some traffic and check:
```bash
sudo tcpdump -ni any udp port 5140 -c 5          # see packets arriving
tail -f /var/log/palo-alto.log                    # see parsed lines
```
A PAN-OS ICS line looks like:
```
<14>Jul  5 12:00:00 palo 1,2026/07/05 12:00:00,01234567890,TRAFFIC,0,2300,...
```

### d) Start the ingester
```bash
sudo systemctl enable --now palo_ingest.service
sudo systemctl status palo_ingest.service
journalctl -u palo_ingest.service -n 30 --no-pager
```
The ingester tails `/var/log/palo-alto.log`, parses ICS lines, and loads them
into `palo.duckdb` (idempotent on `event_id`, resume via
`palo.duckdb.offset`). Re-run the mock seeder anytime to top up demo data:
```bash
python3 /home/suricata/palo_ingest.py --db /home/suricata/palo.duckdb --mock --hours 24 --reset
```

---

## 3. SNMP (optional, for the performance gauges)

The **System performance (SNMP)** section of the Firewall page reads the
`metrics` table. Today it's populated only by `--mock`. For live SNMP
polling, a small poller needs to be written (e.g. `palo_snmp_poll.py` using
`pysnmp` or `easysnmp`) that polls the NGFW every ~5 min and inserts rows
into `palo.duckdb.metrics` with columns:

```
ts, cpu_pct, mem_pct, dp_cpu_pct, active_sessions,
session_util_pct, throughput_in, throughput_out, ha_state
```

Standard PAN-OS SNMP OIDs (under `1.3.6.1.4.1.25461.2.1.2.3.3`):
- `panSessionActive.0` — active sessions
- `panSessionUtilization.0` — session utilization %
- `panfwGaugeMgmtCpuUtil.0` — management CPU %
- `panfwGaugeDataplaneCpuUtil.0` — dataplane CPU %
- `panfwGaugeMemUtil.0` — memory %
- `haState.0` — HA state

On the NGFW, enable SNMP under **Device → Setup → Management →
SNMP** (community string + the VM's IP `YOUR_VM_IP` as an allowed
client, or SNMPv3 credentials). The VM polls outbound — no inbound firewall
rule needed on the VM for SNMP.

This SNMP poller is **not yet built** — say the word and I'll add
`palo_snmp_poll.py` + a `palo_snmp_poll.service` unit.

---

## 4. DuckDB schema (what the Firewall page queries)

All tables use a SHA1 `event_id` PK (idempotent re-ingest). `timestamp` is
TIMESTAMPTZ; display converts to `America/Chicago` like the eve dashboard.

```
traffic : event_id, timestamp, serial, src_ip, src_zone, src_port, dest_ip,
          dest_zone, dest_port, app, action, bytes_sent, bytes_recv, packets,
          session_id, proto, rule, "user"
threat  : event_id, timestamp, serial, src_ip, dest_ip, app, threat_name,
          threat_type, severity, action, category, session_id
url     : event_id, timestamp, serial, src_ip, dest_ip, app, category, url,
          action, risk, "user"
system  : event_id, timestamp, serial, severity, event_name, module, description
metrics : ts, cpu_pct, mem_pct, dp_cpu_pct, active_sessions, session_util_pct,
          throughput_in, throughput_out, ha_state   (SNMP-polled)
```

Indexes on `timestamp`, `src_ip`, `action`, `threat_type` per table.

---

## 5. Conventions (same as the eve side)

- qmark `?` placeholders, positional param lists.
- Read-only dashboard connection with lock-conflict retry (safe alongside the running ingester).
- Bulk COPY ingest via temp JSONL + `read_json_auto` (same speed trick as the eve ingester).
- Deferred checkpointing (`checkpoint_threshold=100GB`) so `con.close()` is fast.
- Resume via `palo.duckdb.offset`; idempotent `INSERT OR IGNORE` on `event_id`.
- No live polling — use **↻ Refresh now**.

---

## 6. Troubleshooting

| Symptom | Check |
| --- | --- |
| Firewall page shows "not found" warning | Run `bash ~/setup/install.sh` (seeds `palo.duckdb`). |
| No new rows after NGFW commit | `sudo tcpdump -ni any udp port 5140` — packets arriving? If not, check the NGFW syslog profile + that the NGFW can route to `YOUR_VM_IP`. |
| `/var/log/palo-alto.log` empty | `sudo systemctl status rsyslog`; confirm `49-palo.conf` is installed and rsyslog restarted. |
| Ingestor not parsing | `journalctl -u palo_ingest -n 50`; the parser expects ICS format with the `,1,date,time,...` marker. If you configured CEF, switch the NGFW profile to ICS. |
| `palo.duckdb` lock errors | The tailer holds the write lock briefly between batches (`--reopen-every 1`); the dashboard retries. If it persists, restart `palo_ingest.service`. |
