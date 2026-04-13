"""Leaf helpers and dataclasses shared across CLI command modules.

Extracted from ``phi_scan/cli/__init__.py`` as the first slice of the CLI
monolith decomposition. Contains only leaf helpers with no Typer command
registrations — every symbol here is re-exported from ``phi_scan.cli`` for
test-import compatibility.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import pathspec
import typer
from rich.progress import Progress, TaskID

from phi_scan import __version__
from phi_scan.constants import (
    DEFAULT_IGNORE_FILENAME,
    EXIT_CODE_ERROR,
    PathspecMatchStyle,
)
from phi_scan.diff import get_changed_files_from_diff
from phi_scan.logging_config import replace_logger_handlers
from phi_scan.models import ScanConfig
from phi_scan.scanner import (
    MAX_WORKER_COUNT,
    MIN_WORKER_COUNT,
    collect_scan_targets,
    is_path_excluded,
    load_ignore_patterns,
)

# ---------------------------------------------------------------------------
# Version flag
# ---------------------------------------------------------------------------

_VERSION_OUTPUT_FORMAT: str = "phi-scan {version}"
_VERSION_FLAG_HELP: str = "Show version and exit."

# ---------------------------------------------------------------------------
# Progress bar display
# ---------------------------------------------------------------------------

# Maximum characters of a file path shown in the progress bar description column.
# Longer paths are truncated with a leading ellipsis so the bar layout stays stable.
_PROGRESS_FILENAME_MAX_CHARS: int = 38
_PROGRESS_FILENAME_ELLIPSIS: str = "…"
# Label shown in the progress bar description column when parallel scanning is active.
_PARALLEL_SCAN_PROGRESS_LABEL: str = f"scanning{_PROGRESS_FILENAME_ELLIPSIS}"

# ---------------------------------------------------------------------------
# Worker count validation
# ---------------------------------------------------------------------------

_DEFAULT_WORKER_COUNT: int = MIN_WORKER_COUNT
_WORKERS_BELOW_MINIMUM_ERROR: str = f"--workers must be at least {MIN_WORKER_COUNT}"
_WORKERS_ABOVE_MAXIMUM_ERROR: str = f"--workers must not exceed {MAX_WORKER_COUNT}"

# ---------------------------------------------------------------------------
# Hook path guards
# ---------------------------------------------------------------------------

# CWD-relative by design: hook commands are always run from the repo root.
_GIT_DIR_PATH: Path = Path(".git")
_GIT_DIR_NOT_FOUND_MESSAGE: str = "Not a git repository — .git directory not found."
_HOOK_SYMLINKED_COMPONENT_ERROR: str = (
    "Hook path component {component!r} is a symlink — refusing to write."
)

# ---------------------------------------------------------------------------
# Log level configuration
# ---------------------------------------------------------------------------

_LOG_LEVEL_DEBUG: str = "debug"
_LOG_LEVEL_INFO: str = "info"
_LOG_LEVEL_WARNING: str = "warning"
_LOG_LEVEL_ERROR: str = "error"

_LOG_LEVEL_MAP: dict[str, int] = {
    _LOG_LEVEL_DEBUG: logging.DEBUG,
    _LOG_LEVEL_INFO: logging.INFO,
    _LOG_LEVEL_WARNING: logging.WARNING,
    _LOG_LEVEL_ERROR: logging.ERROR,
}

# ---------------------------------------------------------------------------
# Scan-option dataclasses
# ---------------------------------------------------------------------------


@dataclass
class _ScanTargetOptions:
    """Options that control which files are selected for scanning.

    Groups four related inputs so _resolve_scan_targets stays within the
    three-argument limit required by CLAUDE.md.
    """

    scan_root: Path
    diff_ref: str | None
    single_file: Path | None
    config: ScanConfig


@dataclass(frozen=True)
class _ScanPhaseOptions:
    """Execution-phase flags controlling phase headers and data selection."""

    is_verbose: bool = False
    should_use_baseline: bool = False


@dataclass(frozen=True)
class _ScanExecutionOptions:
    """Execution parameters threaded from the scan command into the scan loop."""

    worker_count: int = _DEFAULT_WORKER_COUNT
    should_show_progress: bool = False


@dataclass(frozen=True)
class _ProgressScanContext:
    """Arguments for _run_scan_with_progress and its sequential/parallel sub-helpers."""

    scan_targets: tuple[Path, ...]
    config: ScanConfig
    worker_count: int
    progress: Progress
    task_id: TaskID


# ---------------------------------------------------------------------------
# Leaf helpers
# ---------------------------------------------------------------------------


def _configure_logging(log_level: str, log_file: Path | None, is_quiet: bool) -> None:
    """Apply logging configuration from CLI flags."""
    level = _LOG_LEVEL_MAP.get(log_level.lower(), logging.WARNING)
    replace_logger_handlers(console_level=level, log_file_path=log_file, is_quiet=is_quiet)


def _load_combined_ignore_patterns(scan_config: ScanConfig) -> list[str]:
    """Return .phi-scanignore patterns merged with any config-level exclude_paths."""
    ignore_patterns = load_ignore_patterns(Path(DEFAULT_IGNORE_FILENAME))
    if scan_config.exclude_paths:
        ignore_patterns.extend(scan_config.exclude_paths)
    return ignore_patterns


def _normalize_diff_path(diff_file: Path, scan_root: Path) -> Path:
    """Return diff_file as a path relative to scan_root for exclusion matching."""
    if diff_file.is_relative_to(scan_root):
        return diff_file.relative_to(scan_root)
    return diff_file


def _resolve_scan_targets(options: _ScanTargetOptions) -> list[Path]:
    """Return the list of files to scan based on the mode flags in options.

    Priority order: --file > --diff > directory traversal.
    """
    if options.single_file is not None:
        return [options.single_file]
    ignore_patterns = _load_combined_ignore_patterns(options.config)
    if options.diff_ref is not None:
        exclusion_spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, ignore_patterns)
        scan_root = options.scan_root.resolve()
        return [
            diff_file
            for diff_file in get_changed_files_from_diff(options.diff_ref)
            if not is_path_excluded(_normalize_diff_path(diff_file, scan_root), exclusion_spec)
        ]
    return collect_scan_targets(options.scan_root, ignore_patterns, options.config)


def _truncate_filename_for_progress(file_path: Path) -> str:
    """Return the file path as a string, truncated to fit the progress bar column."""
    path_string = file_path.as_posix()
    if len(path_string) <= _PROGRESS_FILENAME_MAX_CHARS:
        return path_string
    return _PROGRESS_FILENAME_ELLIPSIS + path_string[-_PROGRESS_FILENAME_MAX_CHARS:]


def _validate_worker_count(worker_count: int) -> None:
    """Raise typer.BadParameter if worker_count is outside the permitted range."""
    if worker_count < MIN_WORKER_COUNT:
        raise typer.BadParameter(_WORKERS_BELOW_MINIMUM_ERROR)
    if worker_count > MAX_WORKER_COUNT:
        raise typer.BadParameter(_WORKERS_ABOVE_MAXIMUM_ERROR)


def _reject_hook_path_with_symlinked_component(hook_path: Path) -> None:
    """Reject if any existing ancestor directory of hook_path is itself a symlink."""
    for ancestor in reversed(list(hook_path.parents)):
        if ancestor.is_symlink():
            typer.echo(
                _HOOK_SYMLINKED_COMPONENT_ERROR.format(component=str(ancestor)),
                err=True,
            )
            raise typer.Exit(code=EXIT_CODE_ERROR)


def _reject_missing_git_directory() -> None:
    """Reject if the .git directory is absent in the current working directory."""
    if not _GIT_DIR_PATH.is_dir():
        typer.echo(_GIT_DIR_NOT_FOUND_MESSAGE, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)


def _echo_version(is_version_requested: bool) -> None:
    """Print the installed phi-scan version and exit."""
    if is_version_requested:
        typer.echo(_VERSION_OUTPUT_FORMAT.format(version=__version__))
        raise typer.Exit()
