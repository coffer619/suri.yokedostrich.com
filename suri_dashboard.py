#!/usr/bin/env python3
"""
suri_dashboard.py
-----------------
A Streamlit dashboard over the Suricata eve.json -> DuckDB index
produced by eve_tail2duckdb.py.

Features
--------
* Time-window selector: last 1m / 5m / 15m / 1h / 24h / 7d / all.
  Windows are anchored to the newest event timestamp in the DB or to
  wall-clock now. All displayed times are converted to the local system
  timezone (America/Chicago).
* Protocol filter (sidebar): searchable multiselect of app_proto values,
  with on/off selection. Counts shown alongside. Stable labels so removal
  actually works.
* Per-widget controls:
    - Top Talkers: filter by IP substring + local protocol selection.
    - Protocol Usage: choose which protocols to display.
    - Per-IP Drilldown: visual breakdown (pie + bar) instead of a table.
* Read-only connection with lock-conflict retry -> safe alongside the
  running tail ingester. No live polling; use "↻ Refresh now" to re-query.

Run:
    export PATH="$HOME/.local/bin:$PATH"
    streamlit run suri_dashboard.py -- [--db ./eve.duckdb]

NOTE: DuckDB's Python API uses qmark (`?`) param style. All queries use `?`
with a positional list. Param ordering in every query is:
[time-window params] + [proto params] + [extra params].
"""

from __future__ import annotations

import argparse
import os
import time
from datetime import timedelta

import duckdb
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Config / connection
# ---------------------------------------------------------------------------

DEFAULT_DB = os.environ.get("EVE_DUCKDB", "/home/suricata/eve.duckdb")

# Local timezone for display. The system is America/Chicago; events are
# stored as TIMESTAMPTZ and DuckDB returns them tz-aware, so we convert for
# display and use local now for the "now" anchor.
LOCAL_TZ = "America/Chicago"

# window label -> delta ; anchor is controlled separately in the sidebar.
WINDOWS = [
    ("Last 1 minute",  timedelta(minutes=1)),
    ("Last 5 minutes", timedelta(minutes=5)),
    ("Last 15 minutes", timedelta(minutes=15)),
    ("Last hour",       timedelta(hours=1)),
    ("Last 24 hours",   timedelta(hours=24)),
    ("Last 7 days",     timedelta(days=7)),
    ("All data",        None),
]


def open_db_readonly(db_path: str, retries: int = 1200, wait: float = 0.05):
    """Open a read-only DuckDB connection, retrying on lock conflicts.

    Polls every 50ms for up to ~60s so a refresh rides out even a long
    back-to-back ingester flush burst.
    """
    last = None
    for _ in range(retries):
        try:
            return duckdb.connect(db_path, read_only=True)
        except (duckdb.IOException, duckdb.ConnectionException) as exc:
            last = exc
            time.sleep(wait)
    raise last


@st.cache_resource
def get_db_path(db_path: str) -> str:
    if not os.path.exists(db_path):
        st.error(f"DuckDB file not found: {db_path}")
        st.stop()
    return db_path


def q(con, sql, params=None) -> pd.DataFrame:
    """Run a query using qmark `?` placeholders with a positional list."""
    return con.execute(sql, params or []).fetch_df()


def to_local(ts) -> str:
    """Format a tz-aware timestamp in the local timezone for display."""
    if ts is None or pd.isna(ts):
        return "(none)"
    try:
        return pd.Timestamp(ts).tz_convert(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return str(ts)


def fmt_bytes(x) -> str:
    """Human-readable byte count."""
    x = float(x or 0)
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(x) < 1024:
            return f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} EB"


# ---------------------------------------------------------------------------
# Filter computation
# ---------------------------------------------------------------------------

def build_time_clause(window_label: str, anchor_choice: str, con) -> tuple[str, list]:
    """Return (WHERE timestamp clause, params) for the chosen window."""
    delta = next(d for (lbl, d) in WINDOWS if lbl == window_label)
    if delta is None:
        return "1=1", []

    if anchor_choice == "now":
        anchor = pd.Timestamp.now(tz=LOCAL_TZ)
    else:  # "latest event"
        row = q(con, "SELECT max(timestamp) m FROM events")
        anchor = row.iloc[0]["m"]
        if pd.isna(anchor):
            return "1=1", []

    cutoff = anchor - delta
    return "timestamp >= ?", [cutoff]


def build_proto_clause(selected_protos, all_protos) -> tuple[str, list]:
    """Return (proto AND-clause, params) filtering events.app_proto.

    selected_protos is the list of protocols to INCLUDE.
    - empty selection -> AND 1=0 (matches nothing)
    - all selected    -> '' (no filter)
    - subset          -> AND COALESCE(app_proto,'(none)') IN (?,?,...)
    """
    if not selected_protos:
        return "AND 1=0", []
    if set(selected_protos) == set(all_protos):
        return "", []
    placeholders = ",".join("?" * len(selected_protos))
    return f"AND COALESCE(app_proto,'(none)') IN ({placeholders})", list(selected_protos)


def build_srcip_clause(con, ts_clause, ts_params, proto_clause, proto_params,
                       all_protos, selected_protos) -> tuple[str, list, list]:
    """Return (src_ip AND-clause, params, ip_list) restricting to source IPs
    that actually use the selected protocol(s) in the time window.

    When all protocols are selected (no filter), returns ('', [], []) so every
    widget shows all source IPs. When a subset is selected, only source IPs
    that have events with those app_protos in the window are shown anywhere —
    so an IP with no DHCP traffic disappears from all widgets when DHCP is the
    selected protocol.
    """
    if not selected_protos or set(selected_protos) == set(all_protos):
        return "", [], []
    ips = q(con, f"""
        SELECT DISTINCT src_ip FROM events
        WHERE {ts_clause} {proto_clause} AND src_ip IS NOT NULL
    """, ts_params + proto_params)["src_ip"].dropna().tolist()
    if not ips:
        # No source IP uses the selected protocol -> match nothing.
        return "AND 1=0", [], []
    placeholders = ",".join("?" * len(ips))
    return f"AND src_ip IN ({placeholders})", list(ips), list(ips)


# ---------------------------------------------------------------------------
# Chart sections
# ---------------------------------------------------------------------------

def _alert_exclusion(exclude_ethertype) -> str:
    return "AND alert_signature != 'SURICATA Ethertype unknown'" \
        if exclude_ethertype else ""


def kpi_row(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, exclude_ethertype):
    excl = _alert_exclusion(exclude_ethertype)
    noflow = "AND event_type != 'flow'"
    n_events = q(con, f"SELECT count(*) n FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} {noflow}",
                 ts_params + proto_params + srcip_params)["n"].iloc[0]
    n_dns    = q(con, f"SELECT count(*) n FROM dns_events WHERE {ts_clause} {srcip_clause}", ts_params + srcip_params)["n"].iloc[0]
    n_alerts = q(con, f"SELECT count(*) n FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} AND event_type='alert' {excl}",
                 ts_params + proto_params + srcip_params)["n"].iloc[0]

    c1, c2, c3 = st.columns(3)
    c1.metric("Events", f"{n_events:,}")
    c2.metric("DNS events", f"{n_dns:,}")
    c3.metric("Alerts", f"{n_alerts:,}")


def chart_top_talkers(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, all_protos):
    st.subheader("Top Talkers")

    with st.expander("Top Talkers filters", expanded=False):
        ip_filter = st.text_input(
            "Filter by IP (substring, e.g. 192.168 or 8.8.8)",
            value="", key="tt_ip_filter",
            help="Show only IPs containing this substring. Blank = all IPs.")
        limit = st.slider("How many IPs to chart", 5, 40, 15, key="tt_limit")

    # Uses the global sidebar protocol filter (proto_clause) + the source-IP
    # scoping (srcip_clause) from the selected protocol(s).
    ip_pat = None
    if ip_filter.strip():
        esc = ip_filter.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        ip_pat = '%' + esc + '%'

    tab_src, tab_dst = st.tabs(["By source IP (events)", "By dest IP (events)"])

    with tab_src:
        sql = f"""
            SELECT src_ip AS ip, count(*) AS events
            FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} AND src_ip IS NOT NULL
            {'AND src_ip LIKE ?' if ip_pat else ''}
            GROUP BY 1 ORDER BY events DESC LIMIT ?
        """
        params = ts_params + proto_params + srcip_params + ([ip_pat] if ip_pat else []) + [limit]
        df = q(con, sql, params)
        if df.empty:
            st.info("No data for these filters.")
        else:
            df = df.rename(columns={"ip": "src_ip"})
            fig = px.bar(df, x="events", y="src_ip", orientation="h",
                         labels={"src_ip": "Source IP", "events": "Events"},
                         color="events", color_continuous_scale="Blues")
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=450)
            st.plotly_chart(fig, use_container_width=True)

    with tab_dst:
        sql = f"""
            SELECT dest_ip AS ip, count(*) AS events
            FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} AND dest_ip IS NOT NULL
            {'AND dest_ip LIKE ?' if ip_pat else ''}
            GROUP BY 1 ORDER BY events DESC LIMIT ?
        """
        params = ts_params + proto_params + srcip_params + ([ip_pat] if ip_pat else []) + [limit]
        df = q(con, sql, params)
        if df.empty:
            st.info("No data for these filters.")
        else:
            df = df.rename(columns={"ip": "dest_ip"})
            fig = px.bar(df, x="events", y="dest_ip", orientation="h",
                         labels={"dest_ip": "Destination IP", "events": "Events"},
                         color="events", color_continuous_scale="Oranges")
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=450)
            st.plotly_chart(fig, use_container_width=True)


def chart_alert_distribution(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, exclude_ethertype):
    excl = _alert_exclusion(exclude_ethertype)
    noflow = "AND event_type != 'flow'"
    st.subheader("Alert Distribution")
    df = q(con, f"""
        SELECT event_type, count(*) AS c
        FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} {noflow}
        GROUP BY 1 ORDER BY c DESC
    """, ts_params + proto_params + srcip_params)
    n_alerts = q(con, f"""
        SELECT count(*) n FROM events
        WHERE {ts_clause} {proto_clause} {srcip_clause} AND event_type='alert' {excl}
    """, ts_params + proto_params + srcip_params)["n"].iloc[0]
    n_alerts = int(n_alerts) if not pd.isna(n_alerts) else 0
    col_a, col_b = st.columns(2)

    with col_a:
        if n_alerts == 0:
            st.caption("⚠️ No `alert` events in this window (no Suricata alerts fired, "
                       "or rules not loaded). Showing overall **event-type mix** instead.")
            if df.empty:
                st.info("No data in this window for the selected protocol(s).")
            else:
                fig = px.pie(df, names="event_type", values="c", hole=0.4,
                             labels={"c": "events"})
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        else:
            adf = q(con, f"""
                SELECT COALESCE(alert_signature, '(unknown)') AS signature,
                       count(*) AS c
                FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} AND event_type='alert' {excl}
                GROUP BY 1 ORDER BY c DESC LIMIT ?
            """, ts_params + proto_params + srcip_params + [25])
            fig = px.bar(adf, x="c", y="signature", orientation="h",
                         labels={"signature": "Alert", "c": "Count"},
                         color="c", color_continuous_scale="Reds")
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=500)
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.markdown("**Severity breakdown**")
        if n_alerts == 0:
            st.info("No alerts to break down. The pie chart on the left shows the "
                    "event-type distribution.")
        else:
            sev = q(con, f"""
                SELECT alert_severity AS severity,
                       count(*) AS c
                FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} AND event_type='alert' {excl}
                GROUP BY 1 ORDER BY severity
            """, ts_params + proto_params + srcip_params)
            if sev.empty:
                st.info("No severity data.")
            else:
                sev["severity"] = sev["severity"].map(
                    {1: "High", 2: "Medium", 3: "Low"}.get).fillna("Other")
                fig = px.pie(sev, names="severity", values="c", hole=0.4)
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)


def chart_protocol_usage(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, all_protos):
    st.subheader("Protocol Usage")
    # Uses the global sidebar protocol filter. Flow events excluded from
    # count-based charts so they don't dilute (their bytes feed throughput).
    noflow = "AND event_type != 'flow'"
    col_l3, col_app = st.columns(2)

    with col_l3:
        st.markdown("**L3/L4 protocol**")
        df = q(con, f"""
            SELECT COALESCE(proto,'(none)') AS proto, count(*) AS c
            FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} {noflow}
            GROUP BY 1 ORDER BY c DESC
        """, ts_params + proto_params + srcip_params)
        if df.empty:
            st.info("No data for the selected protocol(s).")
        else:
            fig = px.pie(df, names="proto", values="c", hole=0.4,
                         labels={"c": "events"})
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    with col_app:
        st.markdown("**Application protocol (`app_proto`)**")
        df = q(con, f"""
            SELECT COALESCE(app_proto,'(unknown)') AS app_proto, count(*) AS c
            FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} {noflow}
            GROUP BY 1 ORDER BY c DESC LIMIT ?
        """, ts_params + proto_params + srcip_params + [15])
        if df.empty:
            st.info("No data for the selected protocol(s).")
        else:
            fig = px.bar(df, x="c", y="app_proto", orientation="h",
                         labels={"app_proto": "App protocol", "c": "Events"},
                         color="c", color_continuous_scale="Tealgrn")
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=400)
            st.plotly_chart(fig, use_container_width=True)


def chart_throughput(con, ts_clause, ts_params, selected_protos, all_protos, srcip_clause, srcip_params):
    """Throughput over time: bytes TX (toserver) and RX (toclient) layered.

    Reads from flow_events, filtered by the sidebar protocol selection (via
    app_proto) and an optional source-IP substring.
    """
    st.subheader("Throughput (bytes over time)")

    with st.expander("Throughput filters", expanded=False):
        tcol1, tcol2 = st.columns(2)
        with tcol1:
            src_filter = st.text_input(
                "Filter by source IP (substring, e.g. 192.168)",
                value="", key="thr_src_filter",
                help="Restrict to flows whose src_ip contains this substring. "
                     "Blank = all source IPs.")
        with tcol2:
            bucket = st.selectbox(
                "Bucket size", ["minute", "5 minutes", "hour"], index=0,
                key="thr_bucket")

    fproto_clause, fproto_params = build_proto_clause(selected_protos, all_protos)
    src_pat = None
    if src_filter.strip():
        esc = src_filter.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        src_pat = '%' + esc + '%'

    expr = {"minute": "date_trunc('minute', timestamp)",
            "5 minutes": "timestamp - INTERVAL '5 minutes' * (EXTRACT(minute FROM timestamp)::INT // 5)",
            "hour": "date_trunc('hour', timestamp)"}[bucket]

    sql = f"""
        SELECT {expr} AS bucket,
               sum(COALESCE(bytes_toserver,0))  AS tx_bytes,
               sum(COALESCE(bytes_toclient,0)) AS rx_bytes
        FROM flow_events
        WHERE {ts_clause} {fproto_clause} {srcip_clause}
        {'AND src_ip LIKE ?' if src_pat else ''}
        GROUP BY 1 ORDER BY bucket
    """
    params = ts_params + fproto_params + srcip_params + ([src_pat] if src_pat else [])
    df = q(con, sql, params)
    if df.empty:
        st.info("No flow/byte data for these filters.")
        return
    df["bucket"] = pd.to_datetime(df["bucket"]).dt.tz_convert(LOCAL_TZ)
    df["TX (MB)"] = df["tx_bytes"].astype(float) / (1024**2)
    df["RX (MB)"] = df["rx_bytes"].astype(float) / (1024**2)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df["bucket"], y=df["TX (MB)"], mode="lines",
                             name="TX (toserver)", stackgroup="bytes",
                             line=dict(color="#1f77b4")))
    fig.add_trace(go.Scatter(x=df["bucket"], y=df["RX (MB)"], mode="lines",
                             name="RX (toclient)", stackgroup="bytes",
                             line=dict(color="#ff7f0e")))
    total_tx = df["tx_bytes"].sum()
    total_rx = df["rx_bytes"].sum()
    fig.update_layout(
        xaxis_title="Time (local)", yaxis_title="Bytes (MB)",
        hovermode="x unified", height=400,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption(f"Totals in window — TX: **{fmt_bytes(total_tx)}**  ·  RX: **{fmt_bytes(total_rx)}**")


def chart_dns(con, ts_clause, ts_params, srcip_clause, srcip_params):
    st.subheader("DNS Details")
    df = q(con, f"""
        SELECT rrname, count(*) AS c
        FROM dns_events WHERE {ts_clause} {srcip_clause} AND rrname IS NOT NULL
        GROUP BY 1 ORDER BY c DESC LIMIT ?
    """, ts_params + srcip_params + [20])
    if df.empty:
        st.info("No DNS data in this window.")
    else:
        fig = px.bar(df, x="c", y="rrname", orientation="h",
                     labels={"rrname": "Query name", "c": "Count"},
                     color="c", color_continuous_scale="Sunset")
        fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=500)
        st.plotly_chart(fig, use_container_width=True)


def ip_drilldown(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, srcip_list,
                 all_protos, db_path, window_label, anchor_choice, selected_protos):
    st.subheader("Per-IP Drilldown")
    noflow = "AND event_type != 'flow'"

    # The candidate IP list is expensive and would re-run on every keystroke.
    # Cache it briefly so typing/clicking is instant and lock-free.
    # When a protocol subset is selected (srcip_list non-empty), candidates are
    # ONLY the source IPs that use that protocol. Otherwise (all protocols)
    # candidates are all src+dest IPs in the window.
    @st.cache_data(ttl=30, show_spinner=False)
    def _candidate_ips(_db_path, _window, _anchor, _protos, _ts_clause, _ts_params,
                       _proto_clause, _proto_params, _srcip_clause, _srcip_params):
        _noflow = "AND event_type != 'flow'"
        c = open_db_readonly(_db_path)
        try:
            if _srcip_clause:
                # Protocol-filtered: only source IPs that use the protocol.
                df = q(c, f"""
                    SELECT src_ip AS ip, count(*) AS total
                    FROM events WHERE {_ts_clause} {_proto_clause} {_srcip_clause} {_noflow}
                      AND src_ip IS NOT NULL
                    GROUP BY 1 ORDER BY total DESC LIMIT 1000
                """, _ts_params + _proto_params + _srcip_params)
            else:
                # No protocol filter: all src + dest IPs.
                df = q(c, f"""
                    SELECT ip, sum(c) AS total FROM (
                        SELECT src_ip AS ip, count(*) AS c
                        FROM events WHERE {_ts_clause} {_proto_clause} {_noflow} AND src_ip IS NOT NULL
                        GROUP BY 1
                        UNION ALL
                        SELECT dest_ip AS ip, count(*) AS c
                        FROM events WHERE {_ts_clause} {_proto_clause} {_noflow} AND dest_ip IS NOT NULL
                        GROUP BY 1
                    ) GROUP BY 1 ORDER BY total DESC LIMIT 1000
                """, _ts_params + _proto_params + _ts_params + _proto_params)
        finally:
            c.close()
        return df

    ips = _candidate_ips(db_path, window_label, anchor_choice, tuple(selected_protos),
                         ts_clause, tuple(ts_params), proto_clause, tuple(proto_params),
                         srcip_clause, tuple(srcip_params))
    if ips.empty:
        st.info("No data in this window for the selected protocol(s).")
        return

    # Sort IPs in a way that is totally ordered across IPv4/IPv6/non-IP
    # strings (ipaddress refuses to compare v4 vs v6, so we use a numeric
    # key: (version, packed-int-or-zero) so v4 sorts before v6).
    import ipaddress
    def ip_key(v):
        try:
            a = ipaddress.ip_address(v)
            return (a.version, int(a))
        except Exception:
            return (0, -1)
    ips_sorted = ips.sort_values("ip", key=lambda s: s.map(ip_key), kind="stable")

    # Phase 3 item 3.6: wrap the search + dropdown + breakdown in an
    # @st.fragment so typing in the search box only re-runs THIS fragment,
    # not the whole dashboard. Without this, every keystroke re-runs all the
    # upstream queries (Top Talkers, alerts, protocol usage, throughput, DNS)
    # making the search feel laggy.
    @st.fragment
    def _drill_search_and_breakdown():
        st.caption("Type to search the IP list; the dropdown filters live.")
        search = st.text_input("Search IP", value="", key="drill_search",
                               placeholder="e.g. 192.168.1 or 10.0.0")
        term = search.strip()
        if term:
            filtered = ips_sorted[ips_sorted["ip"].str.contains(term, na=False)]
        else:
            filtered = ips_sorted
        if filtered.empty:
            st.info(f"No IPs matching '{term}'.")
            return

        ip_options = [f"{r['ip']}  ({int(r['total']):,} events)" for _, r in filtered.iterrows()]
        ip_map = {ip_options[i]: filtered.iloc[i]["ip"] for i in range(len(ip_options))}
        chosen = st.selectbox("Select an IP address", ip_options, key="drill_ip")
        if not chosen:
            return
        ip = ip_map[chosen]

        # Open a FRESH read-only connection inside the fragment — the parent
        # `con` may be closed by the time the fragment reruns on keystroke.
        frag_con = open_db_readonly(db_path)
        try:
            # Per-IP breakdown. UNION ALL of two index-backed scans.
            rows = q(frag_con, f"""
                SELECT event_type, COALESCE(proto,'(none)') AS proto,
                       COALESCE(app_proto,'(none)') AS app_proto,
                       dest_ip, dest_port, sum(c) AS c FROM (
                    SELECT event_type, proto, app_proto, dest_ip, dest_port, count(*) AS c
                    FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} {noflow} AND src_ip = ?
                    GROUP BY 1,2,3,4,5
                    UNION ALL
                    SELECT event_type, proto, app_proto, dest_ip, dest_port, count(*) AS c
                    FROM events WHERE {ts_clause} {proto_clause} {srcip_clause} {noflow} AND dest_ip = ?
                    GROUP BY 1,2,3,4,5
                ) GROUP BY 1,2,3,4,5 ORDER BY c DESC LIMIT 200
            """, ts_params + proto_params + srcip_params + [ip] + ts_params + proto_params + srcip_params + [ip])
        finally:
            frag_con.close()
        if rows.empty:
            st.info(f"No breakdown data for {ip} in this window.")
            return

        total_events = int(rows["c"].sum())
        st.caption(f"**{ip}** — {total_events:,} events in this window")

        col_p, col_b = st.columns(2)

        with col_p:
            # Pie: traffic by application protocol.
            by_app = rows.groupby("app_proto", as_index=False)["c"].sum().sort_values("c", ascending=False)
            fig = px.pie(by_app, names="app_proto", values="c", hole=0.4,
                         title="Traffic by application protocol",
                         labels={"c": "events"})
            fig.update_layout(height=380)
            st.plotly_chart(fig, use_container_width=True)

        with col_b:
            # Bar: top destination IP:port pairs.
            rows["dest"] = rows["dest_ip"].fillna("?") + ":" + rows["dest_port"].astype(str)
            by_dest = rows.groupby("dest", as_index=False)["c"].sum().sort_values("c", ascending=False).head(15)
            fig = px.bar(by_dest, x="c", y="dest", orientation="h",
                         title="Top destinations (IP:port)",
                         labels={"dest": "Destination", "c": "Events"},
                         color="c", color_continuous_scale="Blugrn")
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=380)
            st.plotly_chart(fig, use_container_width=True)

        # Second row: event_type + proto breakdown as a small stacked bar.
        by_et = rows.groupby(["event_type", "proto"], as_index=False)["c"].sum()
        fig = px.bar(by_et, x="event_type", y="c", color="proto",
                     title="Event types by L3 protocol",
                     labels={"c": "Events", "event_type": "Event type"})
        fig.update_layout(height=350, barmode="stack")
        st.plotly_chart(fig, use_container_width=True)

    _drill_search_and_breakdown()


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def render_dashboard(con, window_label, anchor_choice, selected_protos, all_protos,
                     exclude_ethertype, db_path):
    ts_clause, ts_params = build_time_clause(window_label, anchor_choice, con)
    proto_clause, proto_params = build_proto_clause(selected_protos, all_protos)
    # Source-IP scoping: when a protocol subset is selected, only source IPs
    # that use that protocol appear in ANY widget.
    srcip_clause, srcip_params, srcip_list = build_srcip_clause(
        con, ts_clause, ts_params, proto_clause, proto_params,
        all_protos, selected_protos)

    span = q(con, "SELECT min(timestamp) lo, max(timestamp) hi FROM events")
    lo, hi = span.iloc[0]["lo"], span.iloc[0]["hi"]
    if pd.isna(lo) or pd.isna(hi):
        st.warning("No events in the database yet. Run the tail ingester first.")
        return

    proto_note = (f"Protocols: {', '.join(selected_protos)}"
                  if len(selected_protos) != len(all_protos) else "All protocols")
    now_local = pd.Timestamp.now(tz=LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    st.caption(f"Data span: **{to_local(lo)}** → **{to_local(hi)}**  ·  "
               f"Window: **{window_label}** (anchor: {anchor_choice})  ·  {proto_note}  ·  "
               f"Local now: {now_local}")

    kpi_row(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, exclude_ethertype)
    st.divider()
    chart_top_talkers(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, all_protos)
    chart_alert_distribution(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, exclude_ethertype)
    chart_protocol_usage(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, all_protos)
    chart_throughput(con, ts_clause, ts_params, selected_protos, all_protos, srcip_clause, srcip_params)
    chart_dns(con, ts_clause, ts_params, srcip_clause, srcip_params)
    ip_drilldown(con, ts_clause, ts_params, proto_clause, proto_params, srcip_clause, srcip_params, srcip_list,
                 all_protos, db_path, window_label, anchor_choice, selected_protos)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def render_local_network_page(db_path: str | None = None) -> None:
    """Render the Suricata eve dashboard: sidebar controls + all widgets.

    Used both from main() (standalone `streamlit run suri_dashboard.py`) and
    as a st.navigation page from app.py (the new left-side menu entrypoint).
    Does NOT call st.set_page_config — the entry point owns that, so a single
    page-config call happens per app run (Streamlit requires this).
    """
    if db_path is None:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--db", default=DEFAULT_DB)
        args, _ = parser.parse_known_args()
        db_path = get_db_path(args.db)

    st.title("🛡️ Suricata eve → DuckDB Dashboard")

    try:
        con = open_db_readonly(db_path)
    except (duckdb.IOException, duckdb.ConnectionException) as exc:
        st.error(f"Could not open eve.duckdb read-only: {exc}. "
                 f"Is the ingester holding the lock? Try again in a moment.")
        return

    try:
        # ---- Sidebar controls ----
        st.sidebar.markdown("### Time window")
        # Phase 3 item 3.3: shared time window across both pages. If the
        # Firewall page set st.session_state["global_window"], honor it here.
        # Use the union of options so a value set on the Firewall page (which
        # has '6 hours') is valid here too.
        ln_windows = [w[0] for w in WINDOWS]
        cur_global = st.session_state.get("global_window")
        default_idx = 2  # Last 15 minutes
        if cur_global in ln_windows:
            default_idx = ln_windows.index(cur_global)
        window_label = st.sidebar.selectbox(
            "Window", ln_windows, index=default_idx, key="ln_window",
            help="Windows are anchored to the newest event in the DB by default. "
                 "Switch the anchor to 'now' for true wall-clock windows. "
                 "This is shared with the Firewall page.")
        st.session_state["global_window"] = window_label
        anchor_choice = st.sidebar.radio(
            "Anchor", ["latest event", "now"],
            help="'latest event' = relative to newest ingested event (robust against "
                 "clock skew / stale captures). 'now' = relative to wall clock.")

        st.sidebar.markdown("### Protocol filter")
        st.sidebar.caption("Select which application protocols to **include**. "
                           "Type to search. Remove an item with its ✕ button.")
        # Distinct app_proto across the whole DB, most common first. IMPORTANT:
        # use STABLE labels (protocol name only, no volatile counts) so
        # Streamlit can track selection state across reruns. The count table
        # below IS window-scoped so its numbers match the charts.
        all_protos = q(con, """
            SELECT COALESCE(app_proto,'(none)') AS p, count(*) AS c
            FROM events GROUP BY 1 ORDER BY c DESC
        """)["p"].tolist()

        # ---- Phase 3 item 3.5: protocol-filter presets ----
        # Quick-select presets so the user doesn't have to scroll a long
        # multiselect to remove DNS or focus on web traffic. Selecting a
        # preset sets the multiselect accordingly; "Custom" leaves it alone.
        proto_set = set(all_protos)
        PRESETS = {
            "All protocols": list(all_protos),
            "No DNS": [p for p in all_protos if p != "dns"],
            "Alerts only": [p for p in all_protos if p == "alert"] or list(all_protos),
            "Web (http, tls, quic)": [p for p in all_protos if p in ("http", "tls", "quic")],
            "Custom": None,  # leave the multiselect as-is
        }
        # The preset radio default depends on whether the current selection
        # matches a preset; otherwise default to "Custom".
        cur_sel = st.session_state.get("global_protos", list(all_protos))
        cur_set = set(cur_sel)
        default_preset = "Custom"
        for name, members in PRESETS.items():
            if members is not None and set(members) == cur_set:
                default_preset = name
                break
        preset = st.sidebar.radio(
            "Preset", list(PRESETS.keys()),
            index=list(PRESETS.keys()).index(default_preset),
            horizontal=True, key="proto_preset",
            help="Quick-select common protocol scopes. Pick 'Custom' to use "
                 "the multiselect below verbatim.")
        if PRESETS[preset] is not None and set(PRESETS[preset]) != cur_set:
            st.session_state["global_protos"] = PRESETS[preset]

        selected_protos = st.sidebar.multiselect(
            "Protocols to include", all_protos,
            default=list(all_protos), key="global_protos",
            help="Filters all event-based charts. DNS usually dominates; remove it "
                 "to focus on tls/http/quic/alerts/etc. '(none)' = events with no "
                 "scored app protocol (decoder/stats noise).")
        # Count table scoped to the selected time window + excluding flow, so
        # its numbers agree with the Protocol Usage chart below.
        anchor_val = "now" if anchor_choice == "now" else "latest"
        ts_clause, ts_params = build_time_clause(window_label, anchor_val, con)
        proto_df = q(con, f"""
            SELECT COALESCE(app_proto,'(none)') AS p, count(*) AS c
            FROM events WHERE {ts_clause} AND event_type != 'flow'
            GROUP BY 1 ORDER BY c DESC
        """, ts_params)
        st.sidebar.caption("Event counts in the current time window:")
        st.sidebar.dataframe(
            proto_df.rename(columns={"p": "Protocol", "c": "Events"}),
            use_container_width=True, hide_index=True, height=180)

        st.sidebar.markdown("### Alert filter")
        exclude_ethertype = st.sidebar.checkbox(
            "Exclude 'SURICATA Ethertype unknown' alerts", value=True,
            help="These decoder noise alerts usually dominate the count and add "
                 "little signal. On by default.")

        st.sidebar.markdown("---")
        if st.sidebar.button("↻ Refresh now"):
            st.rerun()
        st.sidebar.caption(f"DB: `{os.path.abspath(db_path)}` (read-only)  ·  "
                           f"TZ: {LOCAL_TZ}")

        render_dashboard(con, window_label,
                         "now" if anchor_choice == "now" else "latest",
                         selected_protos, all_protos, exclude_ethertype, db_path)
    finally:
        con.close()


def main():
    st.set_page_config(page_title="Suricata eve DuckDB Dashboard",
                       page_icon="🛡️", layout="wide")

    # NOTE: Authentication is handled by Cloudflare Access in front of the
    # Cloudflare Tunnel (per-email allow-list / SSO). The dashboard itself
    # runs without its own login gate so that Access is the single source of
    # truth for who can reach it. Do NOT re-add a password gate here unless
    # Access is removed — double-prompting would be redundant.
    render_local_network_page()


if __name__ == "__main__":
    main()
