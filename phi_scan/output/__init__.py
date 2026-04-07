# ruff: noqa: F401
"""Output formatters (table, json, csv, sarif, junit, codequality, gitlab-sast) and Rich UI.

This package was previously a single output.py module. All public symbols are
re-exported here for backwards compatibility so existing ``from phi_scan.output
import X`` imports continue to work unchanged. Private symbols are accessible
directly from their submodule (e.g. ``from phi_scan.output.console import _X``).
"""

from __future__ import annotations

from phi_scan.output.console import (
    create_scan_progress,
    display_banner,
    display_baseline_diff,
    display_baseline_drift_warning,
    display_baseline_scan_notice,
    display_baseline_summary,
    display_category_breakdown,
    display_clean_result,
    display_clean_summary_panel,
    display_code_context_panel,
    display_exit_code_message,
    display_file_tree,
    display_file_type_summary,
    display_findings_table,
    display_phase_audit,
    display_phase_collecting,
    display_phase_report,
    display_phase_scanning,
    display_phase_separator,
    display_risk_level_badge,
    display_scan_header,
    display_severity_inline,
    display_status_spinner,
    display_summary_panel,
    display_violation_alert,
    display_violation_summary_panel,
    format_table,
    get_console,
)
from phi_scan.output.dashboard import build_dashboard_layout
from phi_scan.output.serializers import (
    format_codequality,
    format_csv,
    format_gitlab_sast,
    format_json,
    format_junit,
    format_sarif,
)
from phi_scan.output.watch import (
    WATCH_RESULT_CLEAN_TEXT,
    WATCH_RESULT_VIOLATION_FORMAT,
    WatchEvent,
    build_watch_layout,
)

__all__ = [
    "build_dashboard_layout",
    "build_watch_layout",
    "create_scan_progress",
    "display_banner",
    "display_baseline_diff",
    "display_baseline_drift_warning",
    "display_baseline_scan_notice",
    "display_baseline_summary",
    "display_category_breakdown",
    "display_clean_result",
    "display_clean_summary_panel",
    "display_code_context_panel",
    "display_exit_code_message",
    "display_file_tree",
    "display_file_type_summary",
    "display_findings_table",
    "display_phase_audit",
    "display_phase_collecting",
    "display_phase_report",
    "display_phase_scanning",
    "display_phase_separator",
    "display_risk_level_badge",
    "display_scan_header",
    "display_severity_inline",
    "display_status_spinner",
    "display_summary_panel",
    "display_violation_alert",
    "display_violation_summary_panel",
    "format_codequality",
    "format_csv",
    "format_gitlab_sast",
    "format_json",
    "format_junit",
    "format_sarif",
    "format_table",
    "get_console",
    "WATCH_RESULT_CLEAN_TEXT",
    "WATCH_RESULT_VIOLATION_FORMAT",
    "WatchEvent",
]
