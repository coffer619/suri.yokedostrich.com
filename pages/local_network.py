"""
pages/local_network.py — "Local Network" nav page.

Thin wrapper around suri_dashboard.render_local_network_page() so the
existing Suricata eve dashboard renders unchanged under the new left-side
menu. All sidebar controls, widgets, filters and behavior are identical to
running `streamlit run suri_dashboard.py` directly.
"""

from __future__ import annotations

import streamlit as st

# suri_dashboard.py lives one directory above the pages/ package.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from suri_dashboard import render_local_network_page  # noqa: E402


def render():
    render_local_network_page()
