"""
pages/firewall_v2.py — Palo Alto NGFW dashboard page (PHASE 3 MOCKUP).

Non-production mockup implementing Phase 3 UX improvements from
ux_review/UX_PLAN_COMBINED.md. Runs on port 8766 via app_mockup.py so
production (port 8765, pages/firewall.py) is untouched until approved.

Phase 3 keeps the Phase 2 enhancements (KPI deltas, security badges, traffic
trends, volume bars) and adds interaction + navigation improvements:
  3.1  Clickable IP drill-down: the Top sources table is selectable; picking
       a row shows a focus panel with that IP's sessions/threats/URL hits/apps.
  3.2  Unified time/refresh toolbar at the top of the page (time window +
       auto-refresh toggle + last-updated + ↻ Refresh). Auto-refresh uses
       @st.fragment(run_every=...) gated on the toggle — user-controlled,
       not forced.
  3.3  Shared time window across both pages via st.session_state["global_window"].
       Setting it on either page carries to the other so IDS + NGFW correlate.
  3.4  Tab content indicators: "Top sources (15)", "Action mix: allow 99% / deny 1%".

Reads palo.duckdb read-only using the same conventions as the eve dashboard.
"""

from __future__ import annotations

import os
import time
from datetime import timedelta

import duckdb
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from palo_ingest import open_db as open_palo_db  # reuse the same open helper

LOCAL_TZ = "America/Chicago"
DEFAULT_PALO_DB = os.environ.get("PALO_DUCKDB", "/home/suricata/palo.duckdb")
# Metrics live in a SEPARATE DB to avoid lock contention with the syslog
# ingester (which holds the write lock on palo.duckdb). The SNMP poller writes
# here; the dashboard reads read-only.
# MOCKUP: hardcoded to the mock DB so it always reads the new-schema data
# regardless of env vars.
DEFAULT_METRICS_DB = os.environ.get("PALO_METRICS_DUCKDB", "/home/suricata/palo_metrics.duckdb")

WINDOWS = [
    ("Last 15 minutes", timedelta(minutes=15)),
    ("Last 1 hour",     timedelta(hours=1)),
    ("Last 6 hours",    timedelta(hours=6)),
    ("Last 24 hours",   timedelta(hours=24)),
    ("Last 7 days",     timedelta(days=7)),
    ("All data",        None),
]


# ---------------------------------------------------------------------------
# helpers (mirror suri_dashboard conventions)
# ---------------------------------------------------------------------------

def open_ro(db_path: str, retries: int = 600, wait: float = 0.05):
    last = None
    for _ in range(retries):
        try:
            return duckdb.connect(db_path, read_only=True)
        except (duckdb.IOException, duckdb.ConnectionException) as e:
            last = e
            time.sleep(wait)
    raise last


def q(con, sql, params=None) -> pd.DataFrame:
    return con.execute(sql, params or []).fetch_df()


def to_local(ts) -> str:
    if ts is None or pd.isna(ts):
        return "(none)"
    try:
        return pd.Timestamp(ts).tz_convert(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return str(ts)


def fmt_bytes(x) -> str:
    x = float(x or 0)
    for u in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(x) < 1024:
            return f"{x:.1f} {u}"
        x /= 1024
    return f"{x:.1f} EB"


def build_time_clause(window_label: str) -> tuple[str, list]:
    """Time clause for `timestamp` columns. Anchor = wall-clock now."""
    delta = next(d for (lbl, d) in WINDOWS if lbl == window_label)
    if delta is None:
        return "1=1", []
    cutoff = pd.Timestamp.now(tz=LOCAL_TZ) - delta
    return "timestamp >= ?", [cutoff]


def window_delta(window_label: str):
    """Return the timedelta for a window label, or None for 'All data'."""
    return next(d for (lbl, d) in WINDOWS if lbl == window_label)


def build_prev_time_clause(window_label: str) -> tuple[str, list]:
    """Time clause for the PREVIOUS equal-length window (for KPI deltas)."""
    delta = window_delta(window_label)
    if delta is None:
        return "1=1", []
    now = pd.Timestamp.now(tz=LOCAL_TZ)
    prev_end = now - delta
    prev_start = now - (delta * 2)
    return "timestamp >= ? AND timestamp < ?", [prev_start, prev_end]




# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------

def kpi_row(con, tclause, tparams, window_label):
    """Top KPI cards: active sessions, threats blocked, URL blocks, throughput.

    Phase 2 enhancements (on top of original layout):
      * `delta` vs the previous equal-length window (st.metric delta arrow).
      * `help=` tooltips on each KPI.
      * Security KPIs (Threats blocked, URL-filter blocks) get a colored
        status badge immediately under the metric so security events draw
        the eye when present.
    """
    prev_clause, prev_params = build_prev_time_clause(window_label)
    has_prev = bool(prev_params)  # False for 'All data'

    def _prev_int(sql, params):
        if not has_prev:
            return None
        v = q(con, sql, params)["n"].iloc[0] if " n " in sql else q(con, sql, params)["s"].iloc[0]
        return int(v) if not pd.isna(v) else 0

    # Active sessions = distinct session_id in the window's traffic logs.
    n_sess = q(con, f"""
        SELECT count(DISTINCT session_id) n FROM traffic WHERE {tclause}
    """, tparams)["n"].iloc[0]
    n_sess = int(n_sess) if not pd.isna(n_sess) else 0
    prev_sess = _prev_int(f"""
        SELECT count(DISTINCT session_id) n FROM traffic WHERE {prev_clause}
    """, prev_params) if has_prev else None

    n_threats = q(con, f"""
        SELECT count(*) n FROM threat
        WHERE {tclause} AND action NOT IN ('alert','allow')
    """, tparams)["n"].iloc[0]
    n_threats = int(n_threats) if not pd.isna(n_threats) else 0
    prev_threats = _prev_int(f"""
        SELECT count(*) n FROM threat
        WHERE {prev_clause} AND action NOT IN ('alert','allow')
    """, prev_params) if has_prev else None

    n_url_block = q(con, f"""
        SELECT count(*) n FROM url
        WHERE {tclause} AND action NOT IN ('allow','alert')
    """, tparams)["n"].iloc[0]
    n_url_block = int(n_url_block) if not pd.isna(n_url_block) else 0
    prev_url_block = _prev_int(f"""
        SELECT count(*) n FROM url
        WHERE {prev_clause} AND action NOT IN ('allow','alert')
    """, prev_params) if has_prev else None

    # Throughput = sum of bytes_sent+bytes_recv in window.
    tp = q(con, f"""
        SELECT sum(COALESCE(bytes_sent,0)+COALESCE(bytes_recv,0)) s FROM traffic
        WHERE {tclause}
    """, tparams)["s"].iloc[0]
    tp = int(tp) if not pd.isna(tp) else 0
    prev_tp = _prev_int(f"""
        SELECT sum(COALESCE(bytes_sent,0)+COALESCE(bytes_recv,0)) s FROM traffic
        WHERE {prev_clause}
    """, prev_params) if has_prev else None

    def _delta(cur, prev):
        """st.metric delta. None when no previous window; int delta otherwise."""
        if prev is None or not has_prev:
            return None
        return int(cur) - int(prev)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Active sessions", f"{n_sess:,}", delta=_delta(n_sess, prev_sess),
              help="Distinct session IDs in the traffic log for this window. "
                   "Delta is vs the previous equal-length window.")
    c2.metric("Threats blocked", f"{n_threats:,}", delta=_delta(n_threats, prev_threats),
              help="Threats (spyware/virus/vulnerability/...) blocked or dropped "
                   "in this window.")
    # Security badge under the Threats KPI — draws the eye when > 0.
    if n_threats > 0:
        c2.caption("🔴 threats detected")
    else:
        c2.caption("🟢 no threats")

    c3.metric("URL-filter blocks", f"{n_url_block:,}", delta=_delta(n_url_block, prev_url_block),
              help="URL-filtering blocks (block/continue/override) in this window.")
    if n_url_block > 0:
        c3.caption("🔴 blocks")
    else:
        c3.caption("🟢 no blocks")

    c4.metric("Traffic in window", fmt_bytes(tp), delta=_delta(tp, prev_tp),
              help="Total bytes (sent + received) across all sessions in the window.")

    # "Compared to what?" — make the delta context explicit (Phase 2 item 2.1).
    # For 'All data' there's no previous window, so no deltas and no caption.
    if has_prev:
        delta_w = window_delta(window_label)
        prev_end = pd.Timestamp.now(tz=LOCAL_TZ) - delta_w
        prev_start = prev_end - delta_w
        st.caption(
            f"_Deltas compare to the previous equal window: "
            f"{prev_start.strftime('%b %-d %-I:%M %p')} → "
            f"{prev_end.strftime('%b %-d %-I:%M %p %Z')}._"
        )


def traffic_trends(con, tclause, tparams, window_label):
    """Throughput over time (tweak #3: match the eve dashboard's chart).

    Replaced the earlier bar chart with a stacked-area line chart identical
    in spirit to suri_dashboard.chart_throughput: go.Scatter(mode="lines",
    stackgroup="bytes") for TX (bytes_sent) and RX (bytes_recv), with a
    bucket-size selector and optional source-IP filter. The Palo Alto traffic
    logs have per-row bytes_sent/bytes_recv with dense per-minute coverage,
    so this renders the same smooth area chart as the eve flow_events widget.
    """
    st.subheader("Throughput (bytes over time)")

    with st.expander("Throughput filters", expanded=False):
        tcol1, tcol2 = st.columns(2)
        with tcol1:
            src_filter = st.text_input(
                "Filter by source IP (substring, e.g. 192.168)",
                value="", key="palo_thr_src_filter",
                help="Restrict to traffic whose src_ip contains this substring. "
                     "Blank = all source IPs.")
        with tcol2:
            bucket = st.selectbox(
                "Bucket size", ["minute", "5 minutes", "hour"], index=0,
                key="palo_thr_bucket")

    src_pat = None
    if src_filter.strip():
        esc = (src_filter.strip().replace('\\', '\\\\')
               .replace('%', '\%').replace('_', '\_'))
        src_pat = '%' + esc + '%'

    bucket_expr = {
        "minute": "date_trunc('minute', timestamp)",
        "5 minutes": "timestamp - INTERVAL '5 minutes' * (EXTRACT(minute FROM timestamp)::INT // 5)",
        "hour": "date_trunc('hour', timestamp)",
    }[bucket]

    sql = f"""
        SELECT {bucket_expr} AS bucket,
               sum(COALESCE(bytes_sent,0))  AS tx_bytes,
               sum(COALESCE(bytes_recv,0)) AS rx_bytes
        FROM traffic
        WHERE {tclause}
        {'AND src_ip LIKE ?' if src_pat else ''}
        GROUP BY 1 ORDER BY bucket
    """
    df = q(con, sql, tparams + ([src_pat] if src_pat else []))
    if df.empty:
        st.info("No traffic/byte data for these filters.")
        return
    df["bucket"] = pd.to_datetime(df["bucket"]).dt.tz_convert(LOCAL_TZ)
    df["TX (MB)"] = df["tx_bytes"].astype(float) / (1024**2)
    df["RX (MB)"] = df["rx_bytes"].astype(float) / (1024**2)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df["bucket"], y=df["TX (MB)"], mode="lines",
                             name="TX (sent)", stackgroup="bytes",
                             line=dict(color="#1f77b4")))
    fig.add_trace(go.Scatter(x=df["bucket"], y=df["RX (MB)"], mode="lines",
                             name="RX (received)", stackgroup="bytes",
                             line=dict(color="#ff7f0e")))
    total_tx = int(df["tx_bytes"].sum())
    total_rx = int(df["rx_bytes"].sum())
    fig.update_layout(
        xaxis_title="Time (local)", yaxis_title="Bytes (MB)",
        hovermode="x unified", height=400,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption(f"Totals in window — TX: **{fmt_bytes(total_tx)}**  ·  RX: **{fmt_bytes(total_rx)}**")


def _action_mix_label(con, tclause, tparams) -> str:
    """Short 'allow 99% / deny 1%' label for the Action mix tab."""
    df = q(con, f"""
        SELECT action, count(*) sessions
        FROM traffic WHERE {tclause}
        GROUP BY 1 ORDER BY sessions DESC
    """, tparams)
    if df.empty:
        return "Action mix"
    total = int(df["sessions"].sum())
    parts = []
    for _, r in df.iterrows():
        pct = 100 * int(r["sessions"]) / total if total else 0
        parts.append(f"{r['action']} {pct:.0f}%" if total else str(r['action']))
    return "Action mix: " + " / ".join(parts)


def ip_focus(con, tclause, tparams, ip):
    """Focus panel for a selected IP (Phase 3 item 3.1).

    Shown when a row is selected in the Top sources table. Renders that IP's:
      * traffic breakdown (sessions, bytes, top apps, top dests, action mix)
      * threat hits (if any) including URL-filtering alerts
    Reads both the traffic and threat tables for the selected IP in the window.
    """
    st.markdown(f"#### Focus: `{ip}`")

    # --- Traffic side ---
    tdf = q(con, f"""
        SELECT count(*) sessions,
               sum(COALESCE(bytes_sent,0)+COALESCE(bytes_recv,0)) bytes,
               count(DISTINCT session_id) distinct_sessions
        FROM traffic WHERE {tclause} AND (src_ip = ? OR dest_ip = ?)
    """, tparams + [ip, ip])
    if tdf.empty or int(tdf.iloc[0]["sessions"]) == 0:
        st.info(f"No traffic for {ip} in this window.")
    else:
        r = tdf.iloc[0]
        total_bytes = int(r["bytes"])
        st.caption(f"{int(r['sessions']):,} traffic rows · "
                   f"{int(r['distinct_sessions']):,} distinct sessions · "
                   f"{fmt_bytes(total_bytes)} bytes")

        col_a, col_d, col_act = st.columns(3)
        with col_a:
            st.markdown("**Top apps**")
            adf = q(con, f"""
                SELECT app, count(*) c, sum(bytes_sent+bytes_recv) bytes
                FROM traffic WHERE {tclause} AND (src_ip = ? OR dest_ip = ?)
                  AND app IS NOT NULL
                GROUP BY 1 ORDER BY bytes DESC LIMIT 10
            """, tparams + [ip, ip])
            if adf.empty:
                st.caption("(none)")
            else:
                adf["bytes_mb"] = adf["bytes"].astype(float) / (1024**2)
                st.dataframe(adf.rename(columns={"app": "App", "c": "Sessions"})[["App", "Sessions", "bytes_mb"]],
                             use_container_width=True, hide_index=True, height=200,
                             column_config={"bytes_mb": st.column_config.NumberColumn("Bytes (MB)", format="%.2f")})
        with col_d:
            st.markdown("**Top destinations**")
            ddf = q(con, f"""
                SELECT dest_ip, dest_port, count(*) c
                FROM traffic WHERE {tclause} AND (src_ip = ? OR dest_ip = ?)
                  AND dest_ip IS NOT NULL
                GROUP BY 1,2 ORDER BY c DESC LIMIT 10
            """, tparams + [ip, ip])
            if ddf.empty:
                st.caption("(none)")
            else:
                ddf["dest"] = ddf["dest_ip"] + ":" + ddf["dest_port"].astype(str)
                st.dataframe(ddf.rename(columns={"dest": "Destination", "c": "Sessions"})[["Destination", "Sessions"]],
                             use_container_width=True, hide_index=True, height=200)
        with col_act:
            st.markdown("**Action mix**")
            actdf = q(con, f"""
                SELECT action, count(*) c
                FROM traffic WHERE {tclause} AND (src_ip = ? OR dest_ip = ?)
                GROUP BY 1 ORDER BY c DESC
            """, tparams + [ip, ip])
            if actdf.empty:
                st.caption("(none)")
            else:
                fig = px.pie(actdf, names="action", values="c", hole=0.4,
                             color="action",
                             color_discrete_map={
                                 "allow": "#2ca02c", "deny": "#d62728",
                                 "drop": "#7f7f7f", "drop-packet": "#17becf",
                                 "reset-both": "#9467bd", "reset-client": "#bcbd22",
                                 "reset-server": "#e377c2",
                             })
                fig.update_layout(height=220, showlegend=True,
                                  legend=dict(orientation="h", y=-0.2, font=dict(size=9)))
                st.plotly_chart(fig, use_container_width=True)

    # --- Threat side ---
    thdf = q(con, f"""
        SELECT threat_type, count(*) c,
               sum(CASE WHEN action NOT IN ('alert','allow') THEN 1 ELSE 0 END) blocked
        FROM threat WHERE {tclause} AND (src_ip = ? OR dest_ip = ?)
        GROUP BY 1 ORDER BY c DESC
    """, tparams + [ip, ip])
    if not thdf.empty and int(thdf["c"].sum()) > 0:
        st.markdown("**Threat hits**")
        st.dataframe(thdf.rename(columns={"threat_type": "Threat type",
                                          "c": "Hits", "blocked": "Blocked"}),
                     use_container_width=True, hide_index=True, height=150)


def traffic_summary(con, tclause, tparams):
    """Traffic summary — top 25 per tab, with selectable rows.

    * Top 25 sources / destinations / apps (no pagination — fixed limit).
    * Bytes as numeric MB so column sorting works correctly.
    * The Sources table is selectable: picking a row opens the IP focus panel
      and filters Threat/URL/Application widgets to that IP.
    """
    st.subheader("Traffic summary")
    LIMIT = 25

    tab_src, tab_dst, tab_app, tab_act = st.tabs(
        ["Top sources", "Top destinations", "Top apps", "Action mix"])

    with tab_src:
        df = q(con, f"""
            SELECT src_ip, count(*) sessions, sum(bytes_sent+bytes_recv) bytes
            FROM traffic WHERE {tclause} AND src_ip IS NOT NULL
            GROUP BY 1 ORDER BY bytes DESC LIMIT ?
        """, tparams + [LIMIT])
        if df.empty:
            st.info("No traffic data.")
            st.session_state.pop("focus_ip", None)
        else:
            df["bytes_mb"] = df["bytes"].astype(float) / (1024**2)
            disp = df.rename(columns={"src_ip": "Source IP", "sessions": "Sessions"})
            disp = disp[["Source IP", "Sessions", "bytes_mb"]]
            st.caption("Select a row to drill into that source IP.")
            event = st.dataframe(
                disp, use_container_width=True, hide_index=True,
                on_select="rerun", key="top_sources_select",
                column_config={
                    "bytes_mb": st.column_config.NumberColumn(
                        "Bytes (MB)", format="%.2f",
                        help="Total bytes (sent + received). Sorts numerically."),
                })

            sel_rows = (event.selection.rows if hasattr(event, "selection")
                        else st.session_state.get("top_sources_select", {}).get("rows", []))
            if sel_rows:
                chosen_idx = sel_rows[0]
                if 0 <= chosen_idx < len(df):
                    chosen_ip = df.iloc[chosen_idx]["src_ip"]
                    st.session_state["focus_ip"] = chosen_ip
                    st.divider()
                    ip_focus(con, tclause, tparams, chosen_ip)
            else:
                st.session_state.pop("focus_ip", None)

    with tab_dst:
        df = q(con, f"""
            SELECT dest_ip, dest_port, count(*) sessions,
                   sum(bytes_sent+bytes_recv) bytes
            FROM traffic WHERE {tclause} AND dest_ip IS NOT NULL
            GROUP BY 1,2 ORDER BY bytes DESC LIMIT ?
        """, tparams + [LIMIT])
        if df.empty:
            st.info("No traffic data.")
        else:
            df["dest"] = df["dest_ip"] + ":" + df["dest_port"].astype(str)
            df["bytes_mb"] = df["bytes"].astype(float) / (1024**2)
            disp = df[["dest", "sessions", "bytes_mb"]].rename(
                columns={"dest": "Destination", "sessions": "Sessions"})
            st.dataframe(disp, use_container_width=True, hide_index=True,
                column_config={
                    "bytes_mb": st.column_config.NumberColumn(
                        "Bytes (MB)", format="%.2f",
                        help="Total bytes (sent + received). Sorts numerically."),
                })

    with tab_app:
        df = q(con, f"""
            SELECT app, count(*) sessions, sum(bytes_sent+bytes_recv) bytes
            FROM traffic WHERE {tclause} AND app IS NOT NULL
            GROUP BY 1 ORDER BY bytes DESC LIMIT ?
        """, tparams + [LIMIT])
        if df.empty:
            st.info("No app data.")
        else:
            df["bytes_mb"] = df["bytes"].astype(float) / (1024**2)
            disp = df.rename(columns={"app": "Application", "sessions": "Sessions"})
            disp = disp[["Application", "Sessions", "bytes_mb"]]
            st.dataframe(disp, use_container_width=True, hide_index=True,
                column_config={
                    "bytes_mb": st.column_config.NumberColumn(
                        "Bytes (MB)", format="%.2f",
                        help="Total bytes (sent + received). Sorts numerically."),
                })

    with tab_act:
        df = q(con, f"""
            SELECT action, count(*) sessions
            FROM traffic WHERE {tclause}
            GROUP BY 1 ORDER BY sessions DESC
        """, tparams)
        if df.empty:
            st.info("No traffic data.")
        else:
            fig = px.pie(df, names="action", values="sessions", hole=0.4,
                         labels={"sessions": "Sessions"})
            fig.update_layout(height=380)
            st.plotly_chart(fig, use_container_width=True)


def application_usage(con, tclause, tparams):
    """Application usage + overall risk score (tweak #4).

    Displays each application's category / subcategory / technology / risk
    (captured from the PAN-OS TRAFFIC log's app-metadata fields) alongside
    traffic volume, and computes an overall risk score weighted by traffic:
        score = sum(app_risk * bytes) / sum(bytes)   (1-5 scale)
    so an app carrying lots of traffic with a high risk rating dominates the
    score. Honors the focus IP if one is set.
    """
    st.subheader("Application usage")
    focus_ip = st.session_state.get("focus_ip")
    focus_clause = ""
    focus_params: list = []
    if focus_ip:
        focus_clause = " AND (src_ip = ? OR dest_ip = ?)"
        focus_params = [focus_ip, focus_ip]
        st.caption(f"🔎 Filtered to apps used by **{focus_ip}**.")

    # Gracefully handle the case where the app-metadata columns don't exist
    # yet (pre-reingest) so the page doesn't crash.
    try:
        df = q(con, f"""
            SELECT app, app_category, app_subcategory, app_technology, app_risk,
                   count(*) sessions,
                   sum(COALESCE(bytes_sent,0)+COALESCE(bytes_recv,0)) bytes
            FROM traffic WHERE {tclause}{focus_clause}
              AND app IS NOT NULL AND app_category IS NOT NULL AND app_category <> ''
            GROUP BY 1,2,3,4,5 ORDER BY bytes DESC LIMIT 25
        """, tparams + focus_params)
    except Exception:
        st.info("App-metadata columns not populated yet. Run "
                "`bash /home/suricata/setup/reingest_traffic.sh` to add "
                "app_category/app_subcategory/app_technology/app_risk and "
                "re-ingest.")
        return

    if df.empty:
        st.info("No application metadata in this window.")
        return

    # Overall weighted risk score: sum(risk * bytes) / sum(bytes), 1-5 scale.
    total_bytes = int(df["bytes"].sum())
    if total_bytes > 0:
        weighted = float((df["app_risk"] * df["bytes"]).sum()) / total_bytes
    else:
        weighted = 0.0
    # Color the score: 1-2 green, 2-3.5 yellow, >3.5 red.
    if weighted <= 2:
        badge, label = "🟢", "low"
    elif weighted <= 3.5:
        badge, label = "🟡", "moderate"
    else:
        badge, label = "🔴", "elevated"

    c_score, c_top, c_bytes = st.columns([2, 2, 2])
    c_score.metric("Overall risk score", f"{weighted:.2f} / 5",
                   help="Traffic-weighted average of app risk ratings: "
                        "sum(app_risk × bytes) / sum(bytes). Higher = riskier "
                        "traffic mix.")
    c_score.caption(f"{badge} {label}")
    c_top.metric("Top app by volume", df.iloc[0]["app"])
    c_bytes.metric("Total app traffic", fmt_bytes(total_bytes))

    # (The per-category bar chart was removed per user request — the same
    # information is in the detailed table below, where it's easier to read.)

    # Detailed table. Bytes as numeric MB so sorting works correctly
    # (a human-readable string like '1.2 MB' sorts alphabetically, not by
    # actual magnitude — '1.2 MB' would sort before '500 KB').
    df["bytes_mb"] = df["bytes"].astype(float) / (1024**2)
    disp = df.rename(columns={
        "app": "Application", "app_category": "Category",
        "app_subcategory": "Subcategory", "app_technology": "Technology",
        "app_risk": "Risk", "sessions": "Sessions",
    })
    disp = disp[["Application", "Category", "Subcategory", "Technology",
                 "Risk", "Sessions", "bytes_mb"]]
    st.dataframe(disp, use_container_width=True, hide_index=True,
        column_config={
            "bytes_mb": st.column_config.NumberColumn(
                "Bytes (MB)", format="%.2f",
                help="Total bytes (sent + received). Sorts numerically."),
        })


def threat_prevention(con, tclause, tparams):
    """Threat prevention overview (spyware / virus / vulnerability / ...).

    Excludes the ``url`` subtype because PAN-OS logs URL-filtering hits as
    THREAT/url rows — those are shown in the dedicated URL filtering widget,
    not here, so real malware/exploit threats aren't drowned out.

    Tweak #1: when a focus IP is set (via the Top sources selection), this
    widget filters to threats involving that IP (src_ip or dest_ip).
    """
    st.subheader("Threat prevention")
    # Exclude url-subtype rows (they're URL-filtering alerts, shown elsewhere).
    threat_where = f"{tclause} AND threat_type != 'url'"
    focus_ip = st.session_state.get("focus_ip")
    focus_params: list = []
    if focus_ip:
        threat_where += " AND (src_ip = ? OR dest_ip = ?)"
        focus_params = [focus_ip, focus_ip]
        st.caption(f"🔎 Filtered to threats involving **{focus_ip}** "
                   f"(selected in Top sources). "
                   f"[Clear the selection there to unfilter.]")

    col_t, col_o = st.columns(2)

    with col_t:
        st.markdown("**Threats by type**")
        df = q(con, f"""
            SELECT threat_type, count(*) c
            FROM threat WHERE {threat_where}
            GROUP BY 1 ORDER BY c DESC
        """, tparams + focus_params)
        if df.empty:
            st.info("No threat data. (URL-filtering hits are shown in the "
                    "URL filtering section below.)")
        else:
            fig = px.pie(df, names="threat_type", values="c", hole=0.4,
                         labels={"c": "hits"})
            fig.update_layout(height=380)
            st.plotly_chart(fig, use_container_width=True)

    with col_o:
        st.markdown("**Threats over time (by type)**")
        df = q(con, f"""
            SELECT date_trunc('hour', timestamp) AS bucket, threat_type, count(*) c
            FROM threat WHERE {threat_where}
            GROUP BY 1,2 ORDER BY bucket
        """, tparams + focus_params)
        if df.empty:
            st.info("No threat data.")
        else:
            df["bucket"] = pd.to_datetime(df["bucket"]).dt.tz_convert(LOCAL_TZ)
            fig = px.bar(df, x="bucket", y="c", color="threat_type",
                         labels={"c": "Hits", "bucket": "Time (local)"},
                         barmode="stack")
            fig.update_layout(height=380, legend=dict(orientation="h", y=1.05))
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("**Top threat signatures**")
    df = q(con, f"""
        SELECT threat_name, threat_type, severity, count(*) c,
               sum(CASE WHEN action NOT IN ('alert','allow') THEN 1 ELSE 0 END) blocked
        FROM threat WHERE {threat_where}
        GROUP BY 1,2,3 ORDER BY c DESC LIMIT 15
    """, tparams + focus_params)
    if df.empty:
        st.info("No threat data.")
    else:
        max_hits = int(df["c"].max()) if not df.empty else 1
        df["hits_bar"] = df["c"].astype(float) / max(max_hits, 1)
        disp = df.rename(columns={
            "threat_name": "Signature", "threat_type": "Type",
            "severity": "Severity", "c": "Hits", "blocked": "Blocked"})
        disp = disp[["Signature", "Type", "Severity", "Hits", "Blocked", "hits_bar"]]
        st.dataframe(disp, use_container_width=True, hide_index=True,
            column_config={
                "hits_bar": st.column_config.ProgressColumn(
                    "Volume", min_value=0, max_value=1.0, format="",
                    help="Relative hits (bar = hits vs the top signature). "
                         "Table sorted by hits."),
            })


def url_filtering(con, tclause, tparams):
    """URL filtering overview.

    IMPORTANT: PAN-OS logs URL-filtering hits as **THREAT** log entries with
    subtype ``url`` — there is no separate ``URL`` log type in this PAN-OS
    config. So this widget reads from the ``threat`` table where
    ``threat_type='url'`` rather than from a ``url`` table. Field mapping for
    the url subtype: ``threat_name`` is the URL, ``category`` is the URL
    category, ``severity`` is the severity, ``action`` is the URL-filtering
    action.

    PAN-OS URL filtering actions:
      allow    — permitted, not logged by the URL profile itself
      alert    — permitted AND logged (the "alert" profile action = allow+log)
      block    — blocked (user sees a block page / reset)
      continue — block page shown with a click-through option
      override — admin override of a block

    Most profiles run "alert" on the bulk of categories so the traffic is
    allowed but logged. This widget shows ALL url-subtype threat rows (not
    just hard blocks) and breaks everything out by action so the
    allow/alert/block mix is visible per category and per URL.
    """
    st.subheader("URL filtering")

    # URL-filtering rows live in the threat table with threat_type='url'.
    # Build a combined WHERE clause + params for every query below.
    url_where = f"{tclause} AND threat_type='url'"
    # tclause already contributes tparams; the 'url' literal is inlined.

    # Tweak #1: when a focus IP is set (via the Top sources selection),
    # filter to URL-filtering hits involving that IP. The focus params are
    # appended to tparams for every query below.
    focus_ip = st.session_state.get("focus_ip")
    focus_params: list = []
    if focus_ip:
        url_where += " AND (src_ip = ? OR dest_ip = ?)"
        focus_params = [focus_ip, focus_ip]
        st.caption(f"🔎 Filtered to URL-filtering hits involving **{focus_ip}** "
                   f"(selected in Top sources). "
                   f"[Clear the selection there to unfilter.]")
    # Every query in this widget uses url_params = tparams + focus_params,
    # in that order (time-window params first, then the focus-IP params).
    url_params = tparams + focus_params

    # ---- KPI strip: total / allow / alert / block ----
    totals = q(con, f"""
        SELECT
          count(*) AS total,
          sum(CASE WHEN action='allow'    THEN 1 ELSE 0 END) AS allow,
          sum(CASE WHEN action='alert'    THEN 1 ELSE 0 END) AS alert,
          sum(CASE WHEN action NOT IN ('allow','alert') THEN 1 ELSE 0 END) AS blocked
        FROM threat WHERE {url_where}
    """, url_params)
    if not totals.empty:
        r = totals.iloc[0].fillna(0)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("URL events", f"{int(r['total']):,}")
        m2.metric("Allowed", f"{int(r['allow']):,}")
        m3.metric("Alerted (logged)", f"{int(r['alert']):,}")
        m4.metric("Blocked", f"{int(r['blocked']):,}")

    with st.expander("URL filtering filters", expanded=False):
        url_limit = st.slider("How many categories / URLs to chart", 5, 40, 15,
                              key="url_limit")
        url_search = st.text_input("Filter URL by substring", value="",
                                   key="url_search",
                                   placeholder="e.g. google or .com")

    url_pat = None
    if url_search.strip():
        esc = (url_search.strip().replace('\\', '\\\\')
               .replace('%', '\%').replace('_', '\_'))
        url_pat = '%' + esc + '%'

    tab_cat, tab_url, tab_act = st.tabs(["Top categories", "Top URLs", "Actions"])

    # ---- Top categories: a single table (category + subcategory + per-action
    # counts + total). No bar chart per user request — the table carries the
    # breakdown, including the URL subcategory (risk-level / sub-class).
    with tab_cat:
        df = q(con, f"""
            SELECT category, subcategory, action, count(*) c
            FROM threat WHERE {url_where}
              AND category IS NOT NULL AND category <> ''
            GROUP BY 1,2,3 ORDER BY c DESC
        """, url_params)
        if df.empty:
            st.info("No URL data in this window.")
        else:
            # Pivot per (category, subcategory) row with action columns.
            pivot = (df.pivot_table(index=["category", "subcategory"],
                                    columns="action", values="c",
                                    aggfunc="sum", fill_value=0)
                       .reset_index())
            pivot["total"] = (pivot.drop(columns=["category", "subcategory"])
                                  .sum(axis=1))
            pivot = pivot.sort_values("total", ascending=False).head(url_limit * 2)

            # Ensure all action columns exist for a stable display.
            for col in ("allow", "alert", "block", "continue", "override"):
                if col not in pivot.columns:
                    pivot[col] = 0
            disp = pivot[["category", "subcategory", "total",
                          "allow", "alert", "block", "continue", "override"]]
            disp = disp.rename(columns={
                "category": "Category", "subcategory": "Subcategory",
                "total": "Total",
            })
            st.dataframe(disp, use_container_width=True, hide_index=True)

    # ---- Top URLs (all actions) ----
    # For the url subtype, threat_name holds the URL.
    with tab_url:
        df = q(con, f"""
            SELECT threat_name AS url, category, subcategory, action, severity,
                   count(*) c
            FROM threat WHERE {url_where}
              {'AND threat_name LIKE ?' if url_pat else ''}
            GROUP BY 1,2,3,4,5 ORDER BY c DESC LIMIT ?
        """, url_params + ([url_pat] if url_pat else []) + [url_limit * 2])
        if df.empty:
            st.info("No URL data in this window.")
        else:
            st.dataframe(df.rename(columns={
                "url": "URL", "category": "Category",
                "subcategory": "Subcategory", "action": "Action",
                "severity": "Severity", "c": "Count"}),
                use_container_width=True, hide_index=True)

    # ---- Actions section: overall distribution + blocked-only categories ----
    with tab_act:
        col_pie, col_blk = st.columns(2)
        with col_pie:
            st.markdown("**Action distribution (all URL events)**")
            df = q(con, f"""
                SELECT action, count(*) c FROM threat WHERE {url_where}
                GROUP BY 1 ORDER BY c DESC
            """, url_params)
            if df.empty:
                st.info("No URL data.")
            else:
                fig = px.pie(df, names="action", values="c", hole=0.4,
                             labels={"c": "URL events"},
                             color="action",
                             color_discrete_map={
                                 "allow": "#2ca02c", "alert": "#ff7f0e",
                                 "block": "#d62728", "continue": "#9467bd",
                                 "override": "#8c564b",
                             })
                fig.update_layout(height=380)
                st.plotly_chart(fig, use_container_width=True)
        with col_blk:
            st.markdown("**Blocked categories** (block / continue / override)")
            df = q(con, f"""
                SELECT category, count(*) c
                FROM threat WHERE {url_where}
                  AND action NOT IN ('allow','alert')
                GROUP BY 1 ORDER BY c DESC LIMIT ?
            """, url_params + [url_limit])
            if df.empty:
                st.info("No blocked URL data in this window."
                        " (If your profile is mostly 'alert', blocks only show"
                        " for categories set to 'block'.)")
            else:
                fig = px.bar(df, x="c", y="category", orientation="h",
                             color="c", color_continuous_scale="Reds",
                             labels={"category": "Category", "c": "Blocks"})
                fig.update_layout(yaxis={"categoryorder": "total ascending"},
                                  height=380)
                st.plotly_chart(fig, use_container_width=True)


def performance_gauges(con, window_label):
    """SNMP-style system health: CPU/mem/sessions/HA from the metrics table.

    Reads from a SEPARATE metrics DB (palo_metrics.duckdb) to avoid lock
    contention with the syslog ingester. The `con` param (palo.duckdb) is not
    used for metrics queries — we open a second read-only connection.
    """
    st.subheader("System performance (SNMP)")
    # Open the metrics DB read-only (separate file from palo.duckdb).
    metrics_db = DEFAULT_METRICS_DB
    if not os.path.exists(metrics_db):
        st.info("No metrics DB yet. Start the SNMP poller "
                "(`palo_snmp_poll.service`) to begin collecting NGFW health "
                "metrics.")
        return
    try:
        mcon = open_ro(metrics_db)
    except (duckdb.IOException, duckdb.ConnectionException) as exc:
        st.error(f"Could not open {metrics_db} read-only: {exc}")
        return

    try:
        latest = q(mcon, "SELECT * FROM metrics ORDER BY ts DESC LIMIT 1")
        if latest.empty:
            st.info("No metrics data yet. The SNMP poller is running but hasn't "
                    "written any rows. Wait for the first poll interval.")
            return

        r = latest.iloc[0]
        ha = r.get("ha_state", "?")
        ha_color = "🟢" if str(ha).lower() == "active" else "🟡"

        # ---- Row 1: CPU / Mem / DP CPU / Sessions / HA ----
        g1, g2, g3, g4, g5 = st.columns(5)
        g1.metric("CPU (mgmt)", f"{r['cpu_pct']:.1f}%")
        g2.metric("Memory", f"{r['mem_pct']:.1f}%")
        g3.metric("Dataplane CPU", f"{r['dp_cpu_pct']:.1f}%")
        g4.metric("Active sessions", f"{int(r['active_sessions']):,}")
        g5.metric("HA state", f"{ha_color} {ha}")

        # ---- Row 2: Session protocol breakdown (TCP/UDP/ICMP/SSL proxy) ----
        st.markdown("**Session breakdown**")
        s1, s2, s3, s4, s5, s6 = st.columns(6)
        s1.metric("TCP", f"{int(r.get('sess_tcp') or 0):,}")
        s2.metric("UDP", f"{int(r.get('sess_udp') or 0):,}")
        s3.metric("ICMP", f"{int(r.get('sess_icmp') or 0):,}")
        s4.metric("SSL proxy", f"{int(r.get('sess_ssl_proxy') or 0):,}")
        s5.metric("CPS", f"{int(r.get('cps') or 0):,}",
                 help="Connections per second — the session setup rate.")
        # Session utilization progress bar.
        util = float(r.get("session_util_pct", 0) or 0)
        s6.metric("Session util", f"{util:.1f}%")
        st.progress(min(util / 100.0, 1.0))

        # ---- Row 3: SSL proxy utilization (conditional) ----
        ssl_util = float(r.get("ssl_proxy_util", 0) or 0)
        if int(r.get("sess_ssl_proxy") or 0) > 0:
            st.markdown("**SSL proxy**")
            st.caption(f"SSL proxy utilization: **{ssl_util:.1f}%** "
                       f"({int(r.get('sess_ssl_proxy') or 0):,} active sessions)")
            st.progress(min(ssl_util / 100.0, 1.0))

        # History charts for the chosen window.
        delta = next(d for (lbl, d) in WINDOWS if lbl == window_label)
        if delta is None:
            hist = q(mcon, "SELECT * FROM metrics ORDER BY ts")
        else:
            cutoff = pd.Timestamp.now(tz=LOCAL_TZ) - delta
            hist = q(mcon, "SELECT * FROM metrics WHERE ts >= ? ORDER BY ts", [cutoff])

        # History chart: Sessions + CPS over time only.
        if not hist.empty:
            hist["ts"] = pd.to_datetime(hist["ts"]).dt.tz_convert(LOCAL_TZ)
            fig = go.Figure()
            if "sess_tcp" in hist.columns:
                fig.add_trace(go.Scatter(x=hist["ts"], y=hist["sess_tcp"],
                                         name="TCP sessions", line=dict(color="#1f77b4")))
            if "sess_udp" in hist.columns:
                fig.add_trace(go.Scatter(x=hist["ts"], y=hist["sess_udp"],
                                         name="UDP sessions", line=dict(color="#ff7f0e")))
            if "sess_ssl_proxy" in hist.columns:
                fig.add_trace(go.Scatter(x=hist["ts"], y=hist["sess_ssl_proxy"],
                                         name="SSL proxy", line=dict(color="#9467bd")))
            if "cps" in hist.columns:
                fig.add_trace(go.Scatter(x=hist["ts"], y=hist["cps"],
                                         name="CPS", line=dict(color="#2ca02c")))
            fig.update_layout(xaxis_title="Time (local)", yaxis_title="Count",
                              height=380, legend=dict(orientation="h", y=1.05),
                              title="Sessions + CPS over time")
            st.plotly_chart(fig, use_container_width=True)
    finally:
        mcon.close()


def system_events(con, tclause, tparams):
    st.subheader("System events")
    df = q(con, f"""
        SELECT timestamp, severity, event_name, module, description
        FROM system WHERE {tclause}
        ORDER BY timestamp DESC LIMIT 50
    """, tparams)
    if df.empty:
        st.info("No system events.")
        return
    df["timestamp"] = df["timestamp"].apply(to_local)
    st.dataframe(df.rename(columns={
        "timestamp": "Time", "severity": "Severity", "event_name": "Event",
        "module": "Module", "description": "Description"}),
        use_container_width=True, hide_index=True, height=320)


# ---------------------------------------------------------------------------
# render entry
# ---------------------------------------------------------------------------

def _toolbar(window_label, db_path):
    """Unified time/refresh toolbar (Phase 3 item 3.2).

    Groups time-window selection, auto-refresh toggle, last-updated stamp,
    and ↻ Refresh into one top-of-page toolbar instead of scattering them
    across the sidebar. Auto-refresh uses @st.fragment(run_every=...) gated
    on the toggle — user-controlled, not forced.

    Returns the chosen window_label (also mirrored into session_state as
    "global_window" per Phase 3 item 3.3 so the Local Network page can share).
    """
    tc1, tc2, tc3, tc4 = st.columns([2, 1, 2, 1])
    with tc1:
        opts = [w[0] for w in WINDOWS]
        # Phase 3 item 3.3: shared time window across both pages.
        cur = st.session_state.get("global_window", window_label)
        idx = opts.index(cur) if cur in opts else 3
        window_label = st.selectbox("Time window", opts, index=idx,
                                    key="fw_window", label_visibility="collapsed")
        st.session_state["global_window"] = window_label
    with tc2:
        auto = st.toggle("Auto-refresh", value=False, key="fw_auto",
                         help="When on, refresh this page every 15 seconds.")
    with tc3:
        last_upd = pd.Timestamp.now(tz=LOCAL_TZ).strftime("%-I:%M:%S %p %Z")
        st.caption(f"Updated {last_upd}")
    with tc4:
        if st.button("↻ Refresh", key="fw_refresh_btn", use_container_width=True):
            st.rerun()

    # Auto-refresh fragment: a no-op fragment that reruns every 15s when the
    # toggle is on. When off, it does nothing (run_every only fires when the
    # fragment is rendered AND the toggle is on — we gate by only emitting it
    # conditionally). Streamlit requires the decorator to be statically
    # applied, so we always define it but only call it when auto is on.
    @st.fragment(run_every=timedelta(seconds=15))
    def _auto_refresh():
        st.rerun()

    if auto:
        _auto_refresh()

    return window_label


def render():
    st.title("🔥 Palo Alto NGFW Dashboard")

    db_path = DEFAULT_PALO_DB
    if not os.path.exists(db_path):
        st.warning(
            f"`{db_path}` not found yet. The Firewall page reads from a "
            f"DuckDB file populated by `palo_ingest.py`.\n\n"
            f"**To preview the mockup**, seed synthetic data:\n\n"
            f"```\npython3 /home/suricata/palo_ingest.py --db {db_path} --mock --hours 24\n```\n\n"
            f"**To wire real data**, point the NGFW syslog at this VM "
            f"(see `NGFW_SETUP.md`) and start `palo_ingest.service`.")
        return

    try:
        con = open_ro(db_path)
    except (duckdb.IOException, duckdb.ConnectionException) as exc:
        st.error(f"Could not open {db_path} read-only: {exc}")
        return

    try:
        # ---- Phase 3 item 3.2: unified time/refresh toolbar at the top ----
        # The sidebar still keeps the DB caption + a redundant refresh for
        # muscle-memory, but the primary controls are now in the toolbar.
        window_label = _toolbar(st.session_state.get("global_window",
                                                      "Last 24 hours"),
                                db_path)

        st.sidebar.markdown("### Firewall")
        st.sidebar.caption(f"DB: `{db_path}` (read-only) · TZ: {LOCAL_TZ}")
        if st.sidebar.button("↻ Refresh now"):
            st.rerun()

        tclause, tparams = build_time_clause(window_label)

        # Data span banner.
        span = q(con, "SELECT min(timestamp) lo, max(timestamp) hi FROM traffic")
        lo, hi = span.iloc[0]["lo"], span.iloc[0]["hi"]
        if pd.isna(lo) or pd.isna(hi):
            st.info("The `traffic` table is empty. Run "
                    "`palo_ingest.py --mock` or wait for syslog to arrive.")
            return
        st.caption(f"Data span: **{to_local(lo)}** → **{to_local(hi)}** · "
                   f"Window: **{window_label}**")

        kpi_row(con, tclause, tparams, window_label)
        st.divider()
        traffic_trends(con, tclause, tparams, window_label)
        traffic_summary(con, tclause, tparams)
        application_usage(con, tclause, tparams)
        url_filtering(con, tclause, tparams)
        threat_prevention(con, tclause, tparams)
        performance_gauges(con, window_label)
        system_events(con, tclause, tparams)
    finally:
        con.close()
