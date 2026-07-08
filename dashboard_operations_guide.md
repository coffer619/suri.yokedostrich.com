# Network & Security Dashboard — Operations & Reference Guide

This document is the operational reference for the combined Suricata IDS +
Palo Alto NGFW dashboard deployment on this VM. It covers the running
services, file locations, common tasks, troubleshooting, and reboot behavior.

The dashboard is reachable at: **https://your-dashboard.example.com**

---

## Architecture at a glance

```
browser ──HTTPS──> Cloudflare edge (TLS + DNS + Access auth)
                       │
                       │  (outbound QUIC tunnel, UDP 7844)
                       │  initiated by cloudflared on this VM
                       ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Suricata VM  (YOUR_VM_IP, management on ens160)       │
   │                                                              │
   │  SURICATA / LOCAL NETWORK page:                              │
   │  suricata.service ──writes──> /var/log/suricata/eve.json    │
   │  eve_tail2duckdb.service ──tails──> eve.json                │
   │     └── indexes into /home/suricata/eve.duckdb              │
   │                                                              │
   │  PALO ALTO / FIREWALL page:                                  │
   │  rsyslog (UDP 5140) ──writes──> /var/log/palo-alto.log      │
   │  palo_ingest.service ──tails──> palo-alto.log               │
   │     └── indexes into /home/suricata/palo.duckdb             │
   │  palo_snmp_poll.service ──polls──> NGFW via SNMPv2c         │
   │     └── writes into /home/suricata/palo_metrics.duckdb      │
   │                                                              │
   │  streamlit.service (app.py) ──reads──> all 3 DuckDB files    │
   │     └── serves 127.0.0.1:8765 (multipage: Local Network +   │
   │         Firewall)                                            │
   │                                                              │
   │  cloudflared.service ──proxies──> 127.0.0.1:8765            │
   │     └── outbound tunnel to Cloudflare                        │
   └──────────────────────────────────────────────────────────────┘
```

Key properties:
- **No inbound firewall rules.** The tunnel is outbound-only (QUIC/UDP 7844).
  The Palo Alto only sees normal outbound traffic.
- **TLS is automatic** at the Cloudflare edge (cert renewed by Cloudflare).
- **Auth** is Cloudflare Access (per-email allow-list / SSO) at the Cloudflare edge; the dashboard has no own login gate.
- **All services start on boot** and restart on crash (systemd).
- **Three DuckDB files** — `eve.duckdb` (Suricata logs), `palo.duckdb` (NGFW syslog logs), `palo_metrics.duckdb` (SNMP metrics). The metrics DB is separate to avoid lock contention with the syslog ingester.

---

## Services

All services are systemd units, enabled (start on boot) and active.

| Service                    | Purpose                                          | Runs as   |
| -------------------------- | ------------------------------------------------ | --------- |
| `suricata.service`         | Suricata IDS — writes `eve.json`                 | root      |
| `eve_tail2duckdb.service`  | Tails `eve.json` → indexes into `eve.duckdb`     | suricata  |
| `rsyslog.service`          | Receives PAN-OS syslog on UDP 5140 → `palo-alto.log` | root  |
| `palo_ingest.service`      | Tails `palo-alto.log` → indexes into `palo.duckdb` | suricata |
| `palo_snmp_poll.service`   | Polls NGFW via SNMPv2c → writes `palo_metrics.duckdb` | suricata |
| `streamlit.service`        | Dashboard app (app.py) on `127.0.0.1:8765`       | suricata  |
| `cloudflared.service`      | Cloudflare Tunnel — exposes dashboard publicly   | suricata  |

### Boot ordering

```
suricata.service  →  eve_tail2duckdb.service  (After=suricata.service)
rsyslog.service   →  palo_ingest.service      (After=rsyslog.service)
palo_snmp_poll.service  (independent)
cloudflared.service     (independent)
streamlit.service       (independent)
```

The Suricata ingester waits for Suricata so `eve.json` exists before tailing.
The PAN-OS ingester waits for rsyslog so `palo-alto.log` exists before tailing.
The tunnel and dashboard start independently in parallel.

---

## Service management commands

### Status

```bash
sudo systemctl status cloudflared.service
sudo systemctl status streamlit.service
sudo systemctl status eve_tail2duckdb.service
sudo systemctl status palo_ingest.service
sudo systemctl status palo_snmp_poll.service
sudo systemctl status suricata.service
```

### Restart (after editing config/code)

```bash
# After editing app.py, pages/firewall.py, or suri_dashboard.py:
sudo systemctl restart streamlit.service

# After editing eve_tail2duckdb.py:
sudo systemctl restart eve_tail2duckdb.service

# After editing palo_ingest.py:
sudo systemctl restart palo_ingest.service

# After editing palo_snmp_poll.py:
sudo systemctl restart palo_snmp_poll.service

# After editing suricata.yaml (Suricata config):
sudo systemctl restart suricata.service

# After editing ~/.cloudflared/config.yml:
sudo systemctl restart cloudflared.service

# After editing /etc/rsyslog.d/49-palo.conf:
sudo systemctl restart rsyslog.service
```

### View logs (live)

```bash
journalctl -u streamlit.service -f
journalctl -u eve_tail2duckdb.service -f
journalctl -u palo_ingest.service -f
journalctl -u palo_snmp_poll.service -f
journalctl -u suricata.service -f
journalctl -u cloudflared.service -f
```

---

## File locations

### Application code

| File                                   | Purpose                                  |
| -------------------------------------- | ---------------------------------------- |
| `/home/suricata/app.py`                | Streamlit entry point — multipage nav (Local Network + Firewall) |
| `/home/suricata/suri_dashboard.py`     | Local Network page (Suricata eve dashboard) |
| `/home/suricata/pages/local_network.py`| Nav page wrapper for `suri_dashboard.py` |
| `/home/suricata/pages/firewall.py`     | Firewall page (Palo Alto NGFW dashboard) |
| `/home/suricata/eve_tail2duckdb.py`    | Suricata eve.json → DuckDB ingester      |
| `/home/suricata/palo_ingest.py`        | PAN-OS syslog → DuckDB ingester          |
| `/home/suricata/palo_snmp_poll.py`     | PAN-OS SNMP poller → metrics DuckDB      |

### Data

| File                                   | Purpose                                  |
| -------------------------------------- | ---------------------------------------- |
| `/home/suricata/eve.duckdb`            | Suricata DuckDB (events, dns_events, flow_events) |
| `/home/suricata/eve.duckdb.offset`     | Suricata ingester's byte position in eve.json |
| `/home/suricata/palo.duckdb`           | NGFW syslog DuckDB (traffic, threat, url, system) |
| `/home/suricata/palo.duckdb.offset`    | NGFW ingester's byte position in palo-alto.log |
| `/home/suricata/palo_metrics.duckdb`   | NGFW SNMP metrics (CPU, mem, sessions, CPS, etc.) |
| `/var/log/suricata/eve.json`           | Suricata's live event log                |
| `/var/log/palo-alto.log`               | PAN-OS syslog sink (rsyslog UDP 5140)    |

### Config

| File                                   | Purpose                                  |
| -------------------------------------- | ---------------------------------------- |
| `/home/suricata/.cloudflared/config.yml` | Cloudflare tunnel config               |
| `/etc/rsyslog.d/49-palo.conf`          | rsyslog PAN-OS receiver (UDP 5140)       |
| `/etc/logrotate.d/palo-alto`           | Log rotation for palo-alto.log           |
| `/home/suricata/setup/`                | Install scripts + systemd unit source copies |

### systemd unit files

| File                                                | Purpose                  |
| --------------------------------------------------- | ------------------------ |
| `/etc/systemd/system/streamlit.service`             | Streamlit service unit   |
| `/etc/systemd/system/eve_tail2duckdb.service`       | Suricata ingester unit   |
| `/etc/systemd/system/palo_ingest.service`           | NGFW syslog ingester unit |
| `/etc/systemd/system/palo_snmp_poll.service`        | NGFW SNMP poller unit    |
| `/etc/systemd/system/cloudflared.service`           | cloudflared service unit |

Source copies of unit files and install scripts live in `/home/suricata/setup/`.
The active copies are in `/etc/systemd/system/`. If you edit a unit file, edit
the source copy in `setup/`, re-copy it to `/etc/systemd/system/`, then
`sudo systemctl daemon-reload`.

---

## Dashboard pages

### Local Network (Suricata eve dashboard)

The original Suricata IDS dashboard. Preserved from the original single-page
app with these enhancements:
- **Protocol-filter presets** — All / No DNS / Alerts only / Web / Custom
- **IP drilldown fragment** — search + dropdown wrapped in `@st.fragment` for instant typing (opens its own read-only DB connection)
- **Shared time window** — honors `st.session_state["global_window"]` set on either page

### Firewall (Palo Alto NGFW dashboard)

- **KPI row** — Active sessions, Threats blocked, URL blocks, Traffic in window; deltas vs previous window with "compared to what" caption; security badges (🔴/🟢)
- **Throughput (bytes over time)** — stacked area chart (TX/RX), bucket selector + source-IP filter
- **Traffic summary** — top 25 sources/destinations/apps; selectable rows for IP focus; Bytes (MB) numeric column
- **Application usage** — overall risk score (traffic-weighted), top app, total traffic, detailed table (Application/Category/Subcategory/Technology/Risk/Sessions/Bytes)
- **URL filtering** — KPIs, top categories table with subcategory, top URLs, action distribution
- **Threat prevention** — threats by type, over time, top signatures
- **System performance (SNMP)** — CPU/mem/DP CPU/sessions/HA gauges, session breakdown (TCP/UDP/ICMP/SSL proxy/CPS), sessions+CPS history chart
- **System events** — recent system log table
- **Unified toolbar** — time window + auto-refresh toggle + last-updated + ↻ Refresh
- **IP focus** — selecting a row in Top sources opens a focus panel and filters Threat/URL/Application widgets to that IP
- **Shared time window** — sets `st.session_state["global_window"]` honored by both pages

---

## Tunnel details

| Property               | Value                                              |
| ---------------------- | -------------------------------------------------- |
| Public URL             | https://your-dashboard.example.com                       |
| Tunnel UUID            | `<YOUR-TUNNEL-UUID>`             |
| Transport              | QUIC (UDP 7844, outbound)                          |
| Backed service         | `http://localhost:8765` (Streamlit app.py)         |

The tunnel config forces `protocol: quic` because the upstream firewall resets
TCP 7844 (HTTP/2 path). Do not change to `http2` unless the firewall is
modified to allow TCP 7844.

---

## Authentication

The dashboard is gated by **Cloudflare Access** (per-email allow-list / SSO)
in front of the Cloudflare Tunnel. The dashboard has no own login gate.

- **Who can access:** determined by the Cloudflare Access policy on
  `your-dashboard.example.com` (managed in the Cloudflare Zero Trust dashboard).
- **To add/remove users:** edit the Access policy's email allow-list in the
  Cloudflare dashboard. No VM-side change needed.
- **Do not re-add a password gate** to the dashboard — it would double-prompt.

---

## Database details

### eve.duckdb (Suricata)

| Property               | Value                                              |
| ---------------------- | -------------------------------------------------- |
| Tables                 | `events`, `dns_events`, `flow_events`              |
| Primary key            | `event_hash` (SHA1 of the raw eve.json line)       |
| `raw` column           | dropped (saved ~8.5 GB)                            |

### palo.duckdb (NGFW syslog)

| Table    | Key fields |
| -------- | ---------- |
| `traffic` | event_id, timestamp, src_ip, dest_ip, app, action, bytes_sent, bytes_recv, session_id, rule, app_category, app_subcategory, app_technology, app_risk |
| `threat`  | event_id, timestamp, src_ip, dest_ip, threat_name, threat_type, severity, action, category, subcategory |
| `url`     | (empty — URL filtering hits are logged as THREAT/url rows) |
| `system`  | event_id, timestamp, severity, event_name, module, description |
| `metrics` | (not in this DB — see palo_metrics.duckdb) |

Note: PAN-OS logs URL-filtering hits as THREAT log entries with subtype `url`.
The `url` table is for a separate URL log type that is not forwarded in this
config. The Firewall dashboard's URL filtering widget reads from `threat`
where `threat_type='url'`.

### palo_metrics.duckdb (SNMP metrics)

Separate DB file to avoid lock contention with the syslog ingester. The SNMP
poller writes here (one row every 5 min); the dashboard reads read-only.

| Columns | ts, cpu_pct, mem_pct, dp_cpu_pct, active_sessions, session_util_pct, sess_tcp, sess_udp, sess_icmp, sess_ssl_proxy, ssl_proxy_util, cps, pkt_desc_pct, hw_buf_pct, sw_buf_pct, throughput_in, throughput_out, ha_state |

### DuckDB concurrency

DuckDB allows **multiple read-only connections OR one read-write connection**
per DB file, never both at once. The ingesters release the write lock between
batches (`--reopen-every 1`, `--read-gap 1.0`). The dashboard opens read-only
with retry loops. The SNMP poller opens, inserts one row, and closes on each
cycle (every 5 min) so the dashboard can read between polls.

---

## Ingester details

### Suricata ingester (eve_tail2duckdb)

| Property               | Value                                              |
| ---------------------- | -------------------------------------------------- |
| Input                  | `/var/log/suricata/eve.json`                       |
| Output                 | `/home/suricata/eve.duckdb`                        |
| Resume mechanism       | Byte offset in `eve.duckdb.offset`                 |
| Idempotency            | `INSERT OR IGNORE` on `event_hash` primary key     |
| Batch size             | 50,000 events                                      |
| Lock release           | After every batch (`--reopen-every 1`) + 1s gap    |

### PAN-OS syslog ingester (palo_ingest)

| Property               | Value                                              |
| ---------------------- | -------------------------------------------------- |
| Input                  | `/var/log/palo-alto.log` (rsyslog UDP 5140)        |
| Output                 | `/home/suricata/palo.duckdb`                       |
| Resume mechanism       | Byte offset in `palo.duckdb.offset`                |
| Idempotency            | `INSERT OR IGNORE` on `event_id` primary key       |
| Batch size             | 5,000 events                                       |
| Lock release           | After every batch (`--reopen-every 1`) + 1s gap    |
| Log format             | PAN-OS ICS (BSD syslog framing), CSV-parsed        |
| Log types parsed       | TRAFFIC, THREAT (incl. url subtype), SYSTEM        |

### SNMP poller (palo_snmp_poll)

| Property               | Value                                              |
| ---------------------- | -------------------------------------------------- |
| Target                 | NGFW management IP (YOUR_NGFW_IP) via SNMPv2c    |
| Community              | `suricata`                                         |
| Poll interval          | 300 seconds (5 min)                                |
| Output                 | `/home/suricata/palo_metrics.duckdb` (separate file) |
| Lock handling          | Open → insert → close per cycle (no held lock)     |
| OIDs                   | PAN-COMMON-MIB (sessions, HA) + HOST-RESOURCES-MIB (CPU, memory, packet buffers) + IF-MIB (throughput) |
| Auto-detect            | External interface (ethernet1/1) for throughput    |

---

## NGFW syslog + SNMP configuration

### Syslog (NGFW → VM)

- **NGFW syslog server profile:** target `YOUR_VM_IP`, UDP port `5140`, format ICS
- **VM rsyslog:** `/etc/rsyslog.d/49-palo.conf` — dedicated UDP 5140 → `/var/log/palo-alto.log`
- **Log forwarding:** TRAFFIC, THREAT, URL, SYSTEM types forwarded
- **Denied traffic:** deny/drop rules must have "Log at Session Start" enabled (denied sessions have no "end")

### SNMP (VM → NGFW)

- **NGFW SNMP config:** Device → Setup → Management → SNMP, SNMPv2c, community `suricata`, allowed client `YOUR_VM_IP`
- **VM poller:** `palo_snmp_poll.py --host YOUR_NGFW_IP --community suricata --interval 300`
- **Test:** `python3 /home/suricata/palo_snmp_poll.py --host YOUR_NGFW_IP --community suricata --test`

See `/home/suricata/NGFW_SETUP.md` for detailed setup instructions.

---

## Reboot behavior

On reboot, systemd brings up the services automatically:

1. `suricata.service` → begins writing `eve.json`
2. `eve_tail2duckdb.service` (After=suricata) → resumes tailing from saved offset
3. `rsyslog.service` → begins receiving PAN-OS syslog on UDP 5140
4. `palo_ingest.service` (After=rsyslog) → resumes tailing from saved offset
5. `palo_snmp_poll.service` → begins polling NGFW every 5 min
6. `cloudflared.service` → reconnects the tunnel (~10s)
7. `streamlit.service` → dashboard available

After ~2 minutes post-reboot, https://your-dashboard.example.com should be live
and both dashboard pages should show fresh data.

---

## Common tasks

### Edit the dashboard code

```bash
# Firewall page:
nano /home/suricata/pages/firewall.py
# Local Network page:
nano /home/suricata/suri_dashboard.py
# Nav entry point:
nano /home/suricata/app.py
sudo systemctl restart streamlit.service
```

### Check ingester progress

```bash
# Suricata:
echo "eve offset: $(cat /home/suricata/eve.duckdb.offset) / $(stat -c %s /var/log/suricata/eve.json)"

# PAN-OS:
echo "palo offset: $(cat /home/suricata/palo.duckdb.offset) / $(stat -c %s /var/log/palo-alto.log)"
```

### Check DB row counts

```bash
python3 - <<'EOF'
import duckdb, time

def count(db, tables):
    c = None
    for _ in range(20):
        try:
            c = duckdb.connect(db, read_only=True); break
        except Exception: time.sleep(0.5)
    if c is None: print(f"  {db}: locked"); return
    for t in tables:
        try:
            n = c.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            print(f"  {db} → {t}: {n:,}")
        except Exception as e:
            print(f"  {db} → {t}: ({e})")
    c.close()

count("/home/suricata/eve.duckdb", ["events", "dns_events", "flow_events"])
count("/home/suricata/palo.duckdb", ["traffic", "threat", "url", "system"])
count("/home/suricata/palo_metrics.duckdb", ["metrics"])
EOF
```

### Test the SNMP poller

```bash
python3 /home/suricata/palo_snmp_poll.py --host YOUR_NGFW_IP --community suricata --test
```

### Re-ingest PAN-OS traffic (after schema changes)

If the `palo_ingest.py` parser is updated with new fields:

```bash
sudo systemctl stop palo_ingest.service
python3 -c "import duckdb; c=duckdb.connect('palo.duckdb'); c.execute('DELETE FROM traffic'); c.execute('CHECKPOINT'); c.close()"
rm -f /home/suricata/palo.duckdb.offset
sudo systemctl start palo_ingest.service
```

### Stop public access temporarily

```bash
sudo systemctl stop cloudflared.service
# To resume:
sudo systemctl start cloudflared.service
```

---

## Troubleshooting

| Symptom                                  | Likely cause / fix                                  |
| ---------------------------------------- | --------------------------------------------------- |
| Dashboard unreachable (DNS error)        | Tunnel down. `sudo systemctl status cloudflared.service`. |
| 502 Bad Gateway from Cloudflare          | Streamlit isn't running. `sudo systemctl status streamlit.service`. |
| Local Network page stale                 | Suricata ingester stopped. `sudo systemctl status eve_tail2duckdb.service`. |
| Firewall page stale                      | PAN-OS ingester stopped. `sudo systemctl status palo_ingest.service`. |
| System performance (SNMP) shows no data  | SNMP poller stopped or NGFW SNMP not enabled. `sudo systemctl status palo_snmp_poll.service`. Test: `python3 palo_snmp_poll.py --host YOUR_NGFW_IP --community suricata --test` |
| "Database busy" in dashboard             | Ingester holding write lock during flush. Hit ↻ Refresh. |
| Ingester crash-looping (lock errors)     | Another process holding the DuckDB write lock. Check `ps aux \| grep duckdb` and `ps aux \| grep palo`. The SNMP poller writes to a separate DB (`palo_metrics.duckdb`) — if it's writing to `palo.duckdb`, the service unit hasn't been updated. |
| PAN-OS syslog not arriving               | Check NGFW syslog profile targets `YOUR_VM_IP:5140/UDP`. Check rsyslog: `sudo systemctl status rsyslog`. Check: `tail /var/log/palo-alto.log`. |
| Denied traffic not showing in dashboard  | NGFW deny rules need "Log at Session Start" enabled. "Log at Session End" alone never fires for denied sessions. |
| URL filtering widget empty               | PAN-OS logs URL hits as THREAT/url, not a separate URL log type. The widget reads `threat WHERE threat_type='url'`. Ensure THREAT log forwarding is enabled. |
| SNMP poller "No SNMP response" timeout   | NGFW SNMP not enabled, or VM IP not in allowed-clients. Check Device → Setup → Management → SNMP on the NGFW. |
| `palo_metrics.duckdb` locked             | SNMP poller holding write lock. It should open/insert/close per cycle. If stuck, restart: `sudo systemctl restart palo_snmp_poll.service`. |
| IP drilldown "Connection already closed" | The `@st.fragment` should open its own read-only connection. If this errors, check `suri_dashboard.py` `ip_drilldown` — the fragment must not use the parent `con`. |

### Verify the full stack

```bash
# All services running?
sudo systemctl status cloudflared streamlit eve_tail2duckdb palo_ingest palo_snmp_poll suricata rsyslog

# Tunnel connected?
journalctl -u cloudflared.service -n 20 --no-pager | grep -i "registered\|protocol"

# Ingesters keeping up?
echo "eve:  $(cat /home/suricata/eve.duckdb.offset) / $(stat -c %s /var/log/suricata/eve.json)"
echo "palo: $(cat /home/suricata/palo.duckdb.offset) / $(stat -c %s /var/log/palo-alto.log)"

# SNMP poller writing?
journalctl -u palo_snmp_poll.service -n 5 --no-pager

# Dashboard responding?
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8765/
```

---

## Backups

```bash
# Stop ingesters first (release write locks)
sudo systemctl stop eve_tail2duckdb.service palo_ingest.service palo_snmp_poll.service

# Copy the DBs
cp /home/suricata/eve.duckdb /path/to/backup/eve.duckdb.$(date +%Y%m%d)
cp /home/suricata/palo.duckdb /path/to/backup/palo.duckdb.$(date +%Y%m%d)
cp /home/suricata/palo_metrics.duckdb /path/to/backup/palo_metrics.duckdb.$(date +%Y%m%d)

# Restart ingesters
sudo systemctl start eve_tail2duckdb.service palo_ingest.service palo_snmp_poll.service
```

---

## See also

- `/home/suricata/NGFW_SETUP.md` — detailed NGFW syslog + SNMP setup guide
- `/home/suricata/cloudflare_tunnel_setup.md` — Cloudflare tunnel step-by-step setup
- `/home/suricata/pi-suri-yokedostrich-context.md` — project context for pi coding sessions
- `/home/suricata/setup/` — install scripts, systemd unit source copies, rsyslog config
