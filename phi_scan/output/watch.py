"""Watch mode layout builders and WatchEvent data model."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich import box as rich_box
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Style constants (local to this module — no shared import needed)
# ---------------------------------------------------------------------------

_STYLE_BOLD_CYAN: str = "bold cyan"
_STYLE_DIM: str = "dim"
_STYLE_BOLD_GREEN: str = "bold green"
_STYLE_BOLD_RED: str = "bold red"

# ---------------------------------------------------------------------------
# Unicode support detection (minimal copy — same logic as console.py)
# ---------------------------------------------------------------------------

_UNICODE_ENCODING_PREFIX: str = "UTF"
_UNICODE_ICON_CLEAN: str = "✅"
_ASCII_ICON_CLEAN: str = "[OK]"
_UNICODE_ICON_VIOLATION: str = "⚠"
_ASCII_ICON_VIOLATION: str = "[!]"


def _is_unicode_terminal() -> bool:
    encoding: str = getattr(sys.stdout, "encoding", None) or ""
    return encoding.upper().startswith(_UNICODE_ENCODING_PREFIX)


_WATCH_UNICODE_SUPPORTED: bool = _is_unicode_terminal()
_WATCH_ICON_CLEAN: str = _UNICODE_ICON_CLEAN if _WATCH_UNICODE_SUPPORTED else _ASCII_ICON_CLEAN
_WATCH_ICON_VIOLATION: str = (
    _UNICODE_ICON_VIOLATION if _WATCH_UNICODE_SUPPORTED else _ASCII_ICON_VIOLATION
)

# ---------------------------------------------------------------------------
# Watch mode display constants
# ---------------------------------------------------------------------------

_WATCH_HEADER_PANEL_TITLE: str = "PhiScan — Watch Mode"
_WATCH_HEADER_FORMAT: str = "Watching: {path}  —  Press [bold]Ctrl+C[/bold] to stop"
# Shown in the panel subtitle so it appears inside the Rich alternate-screen buffer,
# not on stdout before Live() takes over (which would immediately scroll out of view).
_WATCH_PHASE_ONE_NOTE: str = (
    "Detection engine not loaded — run `phi-scan setup` to enable full scanning."
)
_WATCH_HEADER_HEIGHT: int = 4
_WATCH_HEADER_SECTION: str = "watch_header"
_WATCH_BODY_SECTION: str = "watch_body"
_WATCH_LOG_PANEL_TITLE: str = "Recent Events"
_WATCH_NO_EVENTS_TEXT: str = "Waiting for file changes…"
_WATCH_COL_TIME: str = "Time"
_WATCH_COL_FILE: str = "Changed File"
_WATCH_COL_RESULT: str = "Result"
# Timestamp format applied in _build_watch_event_table — kept here so the
# display concern (how to render a datetime) stays in the same module that renders it.
_WATCH_TIMESTAMP_FORMAT: str = "%H:%M:%S"
# Style strings derived from WatchEvent.is_clean in _build_watch_event_table.
# Kept here (display layer) so WatchEvent only carries the typed is_clean bool.
_WATCH_RESULT_CLEAN_STYLE: str = _STYLE_BOLD_GREEN
_WATCH_RESULT_VIOLATION_STYLE: str = _STYLE_BOLD_RED
# Result text constants are public (no underscore) because cli.py imports them to
# build _WatchScanOutcome. Keeping them here rather than in constants.py preserves
# the display-layer boundary — they format terminal strings, not domain values.
WATCH_RESULT_CLEAN_TEXT: str = f"{_WATCH_ICON_CLEAN} Clean"
WATCH_RESULT_VIOLATION_FORMAT: str = f"{_WATCH_ICON_VIOLATION}  {{count}} findings detected"
# Rich inline markup template: "[{style}]text[/{style}]". Extracted so the
# literal tag syntax does not appear as a magic string in rendering logic.
_RICH_STYLED_TEXT_FORMAT: str = "[{style}]{text}[/{style}]"
# Filler for the two unused columns in the empty-state placeholder row.
_WATCH_EMPTY_CELL: str = ""


@dataclass(frozen=True)
class WatchEvent:
    """A single watch-mode event record rendered in the rolling event table.

    Created by cli.py when watchdog fires and scan_file completes; consumed
    by watch.py to render the rolling log table. Frozen to prevent mutation
    across the shared deque boundary between the watchdog thread and main thread.
    event_time is stored as datetime so formatting stays in watch.py and events
    remain sortable/comparable without reparsing a formatted string.
    """

    event_time: datetime
    file_path: str
    result_text: str
    # Typed boolean rather than a raw Rich style string — keeps the data model free of
    # display concerns. The rendering layer (_build_watch_event_table) derives the style.
    is_clean: bool


def _build_watch_header_panel(watch_path: Path) -> Panel:
    """Build the persistent header panel shown at the top of the watch display.

    Args:
        watch_path: The directory currently being watched.

    Returns:
        Rich Panel with the watching path and Ctrl+C instruction.
    """
    watch_header_text = _WATCH_HEADER_FORMAT.format(path=str(watch_path))
    return Panel(
        watch_header_text,
        title=_WATCH_HEADER_PANEL_TITLE,
        subtitle=_WATCH_PHASE_ONE_NOTE,
        style=_STYLE_BOLD_CYAN,
    )


def _build_watch_event_table(events: Sequence[WatchEvent]) -> Table:
    """Build the rolling event log table from recent watch events.

    Args:
        events: Sequence of WatchEvent records (most recent last).

    Returns:
        Rich Table with time, changed file, and mini scan result columns.
    """
    table = Table(
        title=_WATCH_LOG_PANEL_TITLE,
        box=rich_box.SIMPLE,
        show_header=True,
        expand=True,
    )
    table.add_column(_WATCH_COL_TIME, style=_STYLE_DIM, no_wrap=True)
    table.add_column(_WATCH_COL_FILE)
    table.add_column(_WATCH_COL_RESULT, no_wrap=True)
    if not events:
        table.add_row(_WATCH_NO_EVENTS_TEXT, _WATCH_EMPTY_CELL, _WATCH_EMPTY_CELL)
        return table
    for event in events:
        result_cell_style = (
            _WATCH_RESULT_CLEAN_STYLE if event.is_clean else _WATCH_RESULT_VIOLATION_STYLE
        )
        result_markup = _RICH_STYLED_TEXT_FORMAT.format(
            style=result_cell_style, text=event.result_text
        )
        table.add_row(
            event.event_time.strftime(_WATCH_TIMESTAMP_FORMAT),
            event.file_path,
            result_markup,
        )
    return table


def build_watch_layout(watch_path: Path, events: Sequence[WatchEvent]) -> Layout:
    """Build the Rich Layout for the watch mode live display.

    Args:
        watch_path: The directory currently being watched.
        events: Recent watch events for the rolling event log.

    Returns:
        Layout with a persistent header panel and rolling event table.
    """
    layout = Layout()
    layout.split_column(
        Layout(name=_WATCH_HEADER_SECTION, size=_WATCH_HEADER_HEIGHT),
        Layout(name=_WATCH_BODY_SECTION),
    )
    layout[_WATCH_HEADER_SECTION].update(_build_watch_header_panel(watch_path))
    layout[_WATCH_BODY_SECTION].update(_build_watch_event_table(events))
    return layout
