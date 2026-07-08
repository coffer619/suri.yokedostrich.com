#!/usr/bin/env python3
"""
app.py — Streamlit entry point with a left-side navigation menu.

Two pages:
  * Local Network  → the existing Suricata eve dashboard (suri_dashboard.py)
  * Firewall       → the Palo Alto NGFW dashboard (pages/firewall.py)

The existing dashboard's behavior is preserved byte-for-byte: the Local
Network page calls suri_dashboard.render_local_network_page(), which is the
same body the old main() ran. Running `streamlit run suri_dashboard.py`
directly still works as a standalone fallback (it has its own main()).

Run:
    streamlit run app.py --server.address 127.0.0.1 --server.port 8765 \
        --server.headless true
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Make the project root importable so `pages/` can import suri_dashboard and
# palo_ingest when loaded as st.Page callables.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pages import local_network, firewall  # noqa: E402


def main():
    st.set_page_config(
        page_title="Network & Security Dashboard",
        page_icon="🛡️", layout="wide")

    pg = st.navigation([
        st.Page(local_network.render, url_path="local-network",
                title="Local Network", icon="📡", default=True),
        st.Page(firewall.render, url_path="firewall",
                title="Firewall", icon="🔥"),
    ])
    pg.run()


if __name__ == "__main__":
    main()
