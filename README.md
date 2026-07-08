# Suricata + Palo Alto NGFW Dashboard

A unified network security dashboard combining **Suricata IDS** event data
and **Palo Alto NGFW** syslog + SNMP metrics into a single Streamlit
application with two pages:

- **Local Network** — Suricata eve.json events (alerts, DNS, traffic, protocol usage, per-IP drilldown)
- **Firewall** — Palo Alto NGFW traffic/threat/URL-filtering logs + SNMP system health metrics

![Architecture](docs/architecture.md)

---

## What it does

### Local Network page (Suricata IDS)

- KPI row: events, DNS events, alerts
- Top Talkers (by source/dest IP, with IP-substring filter)
- Alert distribution (signatures + severity pie)
- Protocol usage (L3/L4 + application protocol)
- Throughput over time (TX/RX bytes from flow events)
- DNS query details
- Per-IP drilldown (searchable, sortable, with protocol/app/dest breakdown)
- Protocol-filter presets (All / No DNS / Alerts only / Web / Custom)
- Time window selector (1m – 7d / All)

### Firewall page (Palo Alto NGFW)

- KPI row with deltas vs previous window + security badges
- Throughput (bytes over time) — stacked area, bucket selector, source-IP filter
- Traffic summary — top 25 sources/destinations/apps, selectable rows for IP focus
- Application usage — overall risk score (traffic-weighted), app category/subcategory/technology/risk table
- URL filtering — category/subcategory breakdown, top URLs, action distribution
- Threat prevention — threats by type, over time, top signatures
- System performance (SNMP) — CPU/memory/dataplane CPU, session breakdown (TCP/UDP/ICMP/SSL proxy/CPS), sessions+CPS history chart
- System events table
- Unified toolbar: time window + auto-refresh toggle + last-updated + manual refresh
- IP focus: selecting a source IP filters Threat/URL/Application widgets to that IP
- Shared time window across both pages

---

## Architecture

```
                          ┌─────────────────────────────────┐
                          │  Streamlit Dashboard (app.py)    │
                          │  127.0.0.1:8765                  │
                          │  ┌──────────┐  ┌──────────────┐  │
                          │  │ Local    │  │ Firewall     │  │
                          │  │ Network  │  │ (NGFW)       │  │
                          │  └────┬─────┘  └───┬────┬─────┘  │
                          └───────┼────────────┼────┼────────┘
                                  │            │    │
                     ┌────────────┘            │    └──────────────┐
                     ▼                         ▼                   ▼
              ┌─────────────┐          ┌─────────────┐     ┌──────────────┐
              │ eve.duckdb  │          │ palo.duckdb │     │palo_metrics  │
              │             │          │             │     │  .duckdb     │
              └──────┬──────┘          └──────┬──────┘     └──────┬───────┘
                     │                        │                   │
                     ▼                        ▼                   ▼
              ┌─────────────┐          ┌─────────────┐     ┌──────────────┐
              │eve_tail2    │          │palo_ingest  │     │palo_snmp_poll│
              │duckdb.py    │          │.py          │     │.py           │
              │(tails eve)  │          │(tails log)  │     │(polls SNMP)  │
              └──────┬──────┘          └──────┬──────┘     └──────┬───────┘
                     │                        │                   │
                     ▼                        ▼                   ▼
              ┌─────────────┐          ┌─────────────┐     ┌──────────────┐
              │eve.json     │          │palo-alto.log│     │  NGFW SNMP   │
              │(Suricata)   │          │(rsyslog)    │     │  v2c         │
              └──────┬──────┘          └──────┬──────┘     └──────────────┘
                     │                        │
                ┌────┴────┐              ┌────┴────┐
                │Suricata │              │  Palo   │
                │  IDS    │              │  Alto   │
                └─────────┘              │  NGFW   │
                                         └─────────┘
```

**Three DuckDB files** (one writer each, dashboard reads all three read-only):
- `eve.duckdb` — Suricata events (from `eve_tail2duckdb.py`)
- `palo.duckdb` — NGFW syslog logs (from `palo_ingest.py`)
- `palo_metrics.duckdb` — NGFW SNMP metrics (from `palo_snmp_poll.py`, separate file to avoid lock contention)

**Public access** is via a Cloudflare Tunnel (outbound QUIC) with Cloudflare
Access authentication. The dashboard has no own login gate.

---

## Requirements

- **Python 3.10+** with: `streamlit`, `duckdb`, `pandas`, `plotly`, `pysnmp`
- **Suricata** (for the Local Network page)
- **Palo Alto NGFW** with syslog + SNMP enabled (for the Firewall page)
- **rsyslog** (to receive PAN-OS syslog on a dedicated UDP port)
- **Cloudflare account** (free tier) for the tunnel + Access auth (optional but recommended)

---

## Quick start

### 1. Install Python dependencies

```bash
pip install --user streamlit duckdb pandas plotly pysnmp
```

### 2. Clone and configure

```bash
git clone https://github.com/coffer619/suri.yokedostrich.com.git
cd suri.yokedostrich.com
```

### 3. Set up Suricata (Local Network page)

Install Suricata on your VM and configure it to write `eve.json`:
```bash
sudo apt install suricata
# Edit /etc/suricata/suricata.yaml to set your interface and home nets
sudo systemctl enable --now suricata
```

Install the eve ingester service:
```bash
# Edit config-examples/eve_tail2duckdb.service: replace YOUR_USER
sudo cp config-examples/eve_tail2duckdb.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now eve_tail2duckdb.service
```

Seed the DB (optional, for testing):
```bash
python3 eve_tail2duckdb.py --eve /var/log/suricata/eve.json --db ~/eve.duckdb --once
```

### 4. Set up Palo Alto syslog (Firewall page)

**On the NGFW:**
- Create a Syslog Server Profile targeting your VM's IP, UDP port 5140, ICS format
- Create a Log Forwarding profile forwarding TRAFFIC, THREAT, URL, SYSTEM log types
- Attach the profile to your security policies
- For denied-traffic logs: enable "Log at Session Start" on deny rules

**On the VM:**
```bash
# Install rsyslog receiver
sudo cp config-examples/49-palo.conf /etc/rsyslog.d/49-palo.conf
sudo touch /var/log/palo-alto.log
sudo systemctl restart rsyslog

# Install logrotate
sudo cp config-examples/palo-alto.logrotate /etc/logrotate.d/palo-alto

# Install the syslog ingester service
# Edit config-examples/palo_ingest.service: replace YOUR_USER
sudo cp config-examples/palo_ingest.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now palo_ingest.service
```

Verify syslog is arriving:
```bash
tail /var/log/palo-alto.log
# Should show lines like:
# Jul 5 07:54:21 PA-440 1,2026/07/05 07:54:19,...,TRAFFIC,...
```

Seed mock data (optional, for testing without a live NGFW):
```bash
python3 palo_ingest.py --db ~/palo.duckdb --mock --hours 24 --reset
```

### 5. Set up SNMP polling (System Performance widget)

**On the NGFW:**
- Device → Setup → Management → SNMP
- Enable SNMPv2c, set a community string, add your VM's IP to allowed clients

**On the VM:**
```bash
# Test connectivity
python3 palo_snmp_poll.py --host YOUR_NGFW_IP --community YOUR_COMMUNITY --test

# Install the poller service
# Edit config-examples/palo_snmp_poll.service: replace YOUR_USER, YOUR_NGFW_IP, YOUR_COMMUNITY
sudo cp config-examples/palo_snmp_poll.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now palo_snmp_poll.service
```

### 6. Set up the dashboard

```bash
# Install the streamlit service
# Edit config-examples/streamlit.service: replace YOUR_USER
sudo cp config-examples/streamlit.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now streamlit.service

# Verify
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8765/
```

### 7. (Optional) Set up Cloudflare Tunnel for public access

See `cloudflare_tunnel_setup.md` for step-by-step instructions. The short version:

```bash
# Install cloudflared
# Login, create tunnel, route DNS
cloudflared tunnel login
cloudflared tunnel create my-dashboard
cloudflared tunnel route dns my-dashboard dashboard.example.com

# Copy config (edit config-examples/cloudflared-config.yml first)
cp config-examples/cloudflared-config.yml ~/.cloudflared/config.yml

# Install as a service
sudo cloudflared service install
```

Set up Cloudflare Access (Zero Trust dashboard) to gate who can reach the dashboard.

---

## File inventory

### Application code

| File | Purpose |
| --- | --- |
| `app.py` | Streamlit entry point — multipage nav (Local Network + Firewall) |
| `suri_dashboard.py` | Local Network page (Suricata eve dashboard) |
| `pages/local_network.py` | Nav page wrapper for `suri_dashboard.py` |
| `pages/firewall.py` | Firewall page (Palo Alto NGFW dashboard) |
| `eve_tail2duckdb.py` | Suricata eve.json → DuckDB ingester |
| `palo_ingest.py` | PAN-OS syslog → DuckDB ingester (with `--mock` and `--tail` modes) |
| `palo_snmp_poll.py` | PAN-OS SNMP poller → metrics DuckDB |

### Config examples

| File | Purpose |
| --- | --- |
| `config-examples/cloudflared-config.yml` | Cloudflare tunnel config template |
| `config-examples/49-palo.conf` | rsyslog PAN-OS receiver (UDP 5140) |
| `config-examples/palo-alto.logrotate` | Log rotation for palo-alto.log |
| `config-examples/eve_tail2duckdb.service` | systemd unit for Suricata ingester |
| `config-examples/palo_ingest.service` | systemd unit for NGFW syslog ingester |
| `config-examples/palo_snmp_poll.service` | systemd unit for SNMP poller |
| `config-examples/streamlit.service` | systemd unit for the dashboard |

### Documentation

| File | Purpose |
| --- | --- |
| `NGFW_SETUP.md` | Detailed NGFW syslog + SNMP setup guide |
| `dashboard_operations_guide.md` | Operations & reference guide |
| `cloudflare_tunnel_setup.md` | Cloudflare tunnel step-by-step setup |

---

## DuckDB schemas

### eve.duckdb (Suricata)

```
events:      event_hash (PK), timestamp, flow_id, in_iface, event_type, vlan,
             src_ip, src_port, dest_ip, dest_port, ip_v, proto, app_proto,
             pkt_src, alert_signature, alert_severity, ingested_at
dns_events:  event_hash (PK), timestamp, flow_id, src_ip, dest_ip, dns_type,
             tx_id, id, flags, rcode, opcode, rrname, rrtype, queries
flow_events: event_hash (PK), timestamp, flow_id, src_ip, dest_ip,
             pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient,
             start, "end", age, state, reason, alerted, tx_cnt, app_proto
```

### palo.duckdb (NGFW syslog)

```
traffic: event_id (PK), timestamp, serial, src_ip, src_zone, src_port,
         dest_ip, dest_zone, dest_port, app, action, bytes_sent, bytes_recv,
         packets, session_id, proto, rule, "user",
         app_category, app_subcategory, app_technology, app_risk
threat:  event_id (PK), timestamp, serial, src_ip, dest_ip, app,
         threat_name, threat_type, severity, action, category, subcategory,
         session_id
system:  event_id (PK), timestamp, serial, severity, event_name, module,
         description
```

Note: PAN-OS logs URL-filtering hits as THREAT entries with subtype `url`.
The dashboard's URL filtering widget reads `threat WHERE threat_type='url'`.

### palo_metrics.duckdb (SNMP)

```
metrics: ts, cpu_pct, mem_pct, dp_cpu_pct, active_sessions, session_util_pct,
         sess_tcp, sess_udp, sess_icmp, sess_ssl_proxy, ssl_proxy_util, cps,
         pkt_desc_pct, hw_buf_pct, sw_buf_pct,
         throughput_in, throughput_out, ha_state
```

---

## Key design decisions

- **Three separate DuckDB files** — DuckDB allows only one read-write connection per file. The syslog ingester and SNMP poller each get their own DB file to avoid lock contention. The dashboard opens all three read-only.
- **Bulk COPY ingest** — Both ingesters use `INSERT ... SELECT FROM read_json_auto()` via temp JSONL files, ~100x faster than row-by-row inserts.
- **Idempotent re-ingest** — All tables use SHA1-based primary keys with `INSERT OR IGNORE`, so re-reading lines after a crash or log rotation is safe.
- **Log rotation handling** — The PAN-OS ingester detects file truncation (offset > file size) and resets to 0 automatically.
- **No live polling** — The dashboard renders on page load; use the ↻ Refresh button or the auto-refresh toggle. No `@st.fragment(run_every=...)` unless the user opts in.
- **qmark `?` placeholders** — All DuckDB queries use positional `?` params, not `%(name)s` or `:name`.
- **Auth via Cloudflare Access** — The dashboard has no own login gate. Access is enforced at the Cloudflare edge.

---

## SNMP OIDs

The poller uses these OIDs (verified on PAN-OS 11.x, PA-440):

| Metric | OID | Source |
| --- | --- | --- |
| Session utilization | `25461.2.1.2.3.1.0` | PAN-COMMON-MIB `panSessionUtilization` |
| Session max | `25461.2.1.2.3.2.0` | PAN-COMMON-MIB `panSessionMax` |
| Active sessions | `25461.2.1.2.3.3.0` | PAN-COMMON-MIB `panSessionActive` |
| TCP sessions | `25461.2.1.2.3.4.0` | PAN-COMMON-MIB `panSessionActiveTcp` |
| UDP sessions | `25461.2.1.2.3.5.0` | PAN-COMMON-MIB `panSessionActiveUdp` |
| ICMP sessions | `25461.2.1.2.3.6.0` | PAN-COMMON-MIB `panSessionActiveICMP` |
| SSL proxy sessions | `25461.2.1.2.3.7.0` | PAN-COMMON-MIB `panSessionActiveSslProxy` |
| SSL proxy util | `25461.2.1.2.3.8.0` | PAN-COMMON-MIB `panSessionSslProxyUtilization` |
| CPS | `25461.2.1.2.3.12.0` | PAN-COMMON-MIB `panSessionCps` |
| Management CPU | `1.3.6.1.2.1.25.3.3.1.2.1` | HOST-RESOURCES-MIB `hrProcessorLoad.1` |
| Dataplane CPU | `1.3.6.1.2.1.25.3.3.1.2.2` | HOST-RESOURCES-MIB `hrProcessorLoad.2` |
| Memory used | `1.3.6.1.2.1.25.2.3.1.6.1020` | HOST-RESOURCES-MIB `hrStorageUsed` |
| Memory size | `1.3.6.1.2.1.25.2.3.1.5.1020` | HOST-RESOURCES-MIB `hrStorageSize` |
| HA state | `25461.2.1.2.1.11.0` | PAN-COMMON-MIB `panSysHAState` (string) |
| Interface octets | `1.3.6.1.2.1.2.2.1.10/16` + ifIndex | IF-MIB `ifInOctets/ifOutOctets` |

PAN-OS SNMP MIB modules can be downloaded from Palo Alto's support site.

---

## License

This project is provided as-is for educational and operational use. No warranty expressed or implied.

---

## Credits

Built with [Streamlit](https://streamlit.io), [DuckDB](https://duckdb.org), [Plotly](https://plotly.com), [pysnmp](https://github.com/pysnmp/pysnmp), [Suricata](https://suricata.io), and [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/).
