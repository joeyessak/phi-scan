"""`phi-scan dashboard` command — real-time scan statistics."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import typer
from rich.live import Live

from phi_scan.audit import get_last_scan, query_recent_scans
from phi_scan.constants import DEFAULT_DATABASE_PATH, EXIT_CODE_CLEAN
from phi_scan.output import build_dashboard_layout

_DASHBOARD_REFRESH_SECONDS: float = 2.0
_DASHBOARD_REFRESH_RATE: float = 4.0
_DASHBOARD_HISTORY_COUNT: int = 10
_DASHBOARD_LOOKBACK_DAYS: int = 30
_DASHBOARD_FINDINGS_JSON_KEY: str = "findings_json"
_DASHBOARD_CATEGORY_KEY: str = "hipaa_category"
_DASHBOARD_UNKNOWN_CATEGORY: str = "unknown"
_DASHBOARD_EMPTY_FINDINGS_JSON: str = "[]"


def _aggregate_category_totals(recent_scans: list[dict[str, Any]]) -> dict[str, int]:
    """Sum HIPAA category occurrences across all recent scan findings_json blobs.

    PHI safety guarantee: findings_json blobs written by audit.py contain only
    value_hash (SHA-256), file_path_hash (SHA-256), hipaa_category, severity,
    confidence, and line_number. Raw PHI values and code_context are explicitly
    excluded at the write path (see audit.py::_serialize_finding_for_storage).
    """
    totals: dict[str, int] = {}
    for row in recent_scans:
        category_finding_records = json.loads(
            row.get(_DASHBOARD_FINDINGS_JSON_KEY, _DASHBOARD_EMPTY_FINDINGS_JSON)
        )
        for finding_record in category_finding_records:
            category = finding_record.get(_DASHBOARD_CATEGORY_KEY, _DASHBOARD_UNKNOWN_CATEGORY)
            totals[category] = totals.get(category, 0) + 1
    return totals


def display_dashboard() -> None:
    """Rich Live real-time scan dashboard.

    Ctrl+C (KeyboardInterrupt) is the expected and only exit mechanism for this
    command. The signal is caught here as an intentional boundary — not a domain
    error — solely to stop the Rich Live display cleanly before process exit.
    """
    database_path = Path(DEFAULT_DATABASE_PATH)
    try:
        with Live(refresh_per_second=_DASHBOARD_REFRESH_RATE, screen=True) as live:
            while True:
                recent_scans = query_recent_scans(database_path, _DASHBOARD_LOOKBACK_DAYS)
                last_scan = get_last_scan(database_path)
                category_totals = _aggregate_category_totals(recent_scans)
                layout = build_dashboard_layout(
                    recent_scans[:_DASHBOARD_HISTORY_COUNT],
                    category_totals,
                    last_scan,
                )
                live.update(layout)
                time.sleep(_DASHBOARD_REFRESH_SECONDS)
    except KeyboardInterrupt:
        raise typer.Exit(code=EXIT_CODE_CLEAN)
