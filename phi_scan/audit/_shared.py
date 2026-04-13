"""Leaf helpers shared by the audit package — DB connection, git identity, timestamps.

Contains no crypto or hash-chain logic. Everything here is safe to import
from any audit submodule with no circular-dependency risk.
"""

from __future__ import annotations

import datetime
import errno
import hashlib
import logging
import os
import sqlite3
import subprocess
from pathlib import Path

from phi_scan.exceptions import AuditLogError
from phi_scan.logging_config import get_logger

_logger: logging.Logger = get_logger("audit")

# ---------------------------------------------------------------------------
# Log and error message templates (leaf-level)
# ---------------------------------------------------------------------------

_SYMLINK_DATABASE_PATH_ERROR: str = (
    "Audit database path {path!r} is a symlink — symlinks are prohibited "
    "to prevent log-redirection attacks"
)
_SCHEMA_VERSION_MISSING_ERROR: str = "schema_meta table exists but the schema_version key is absent"
_DATABASE_ERROR: str = "Audit database operation failed: {detail}"

# ---------------------------------------------------------------------------
# Implementation constants
# ---------------------------------------------------------------------------

_SCAN_EVENTS_TABLE: str = "scan_events"
_SCHEMA_META_TABLE: str = "schema_meta"
_SCHEMA_VERSION_KEY: str = "schema_version"
_CREATED_AT_KEY: str = "created_at"
_UNKNOWN_REPOSITORY: str = "unknown"
_UNKNOWN_BRANCH: str = "unknown"
_BOOLEAN_TRUE: int = 1
_BOOLEAN_FALSE: int = 0
_EVENT_TYPE_SCAN: str = "scan"
_NOTIFICATIONS_EMPTY_JSON: str = "[]"
# O_NOFOLLOW is POSIX-only (Linux/macOS). On Windows it does not exist;
# _reject_symlink_database_path falls back to Path.is_symlink() there.
_O_NOFOLLOW: int | None = getattr(os, "O_NOFOLLOW", None)
_PRAGMA_WAL_MODE: str = "PRAGMA journal_mode=WAL"
_LAST_SCAN_LIMIT: int = 1
_GIT_SUBPROCESS_TIMEOUT_SECONDS: int = 5
_GIT_BRANCH_ARGS: tuple[str, ...] = ("git", "branch", "--show-current")
_GIT_TOPLEVEL_ARGS: tuple[str, ...] = ("git", "rev-parse", "--show-toplevel")
# git log pretty-format specifiers used for committer identity.
# %cn = committer name (the person who applied the commit, not the author)
# %ce = committer email
# These are hashed before storage — raw values are never persisted.
_GIT_FORMAT_COMMITTER_NAME: str = "--format=%cn"
_GIT_FORMAT_COMMITTER_EMAIL: str = "--format=%ce"
_GIT_COMMITTER_NAME_ARGS: tuple[str, ...] = ("git", "log", "-1", _GIT_FORMAT_COMMITTER_NAME)
_GIT_COMMITTER_EMAIL_ARGS: tuple[str, ...] = ("git", "log", "-1", _GIT_FORMAT_COMMITTER_EMAIL)

# CI/CD environment variable names for PR number and pipeline detection.
_ENV_PR_NUMBER_GITHUB: str = "GITHUB_PR_NUMBER"
_ENV_PR_NUMBER_GITLAB: str = "CI_MERGE_REQUEST_IID"
_ENV_PR_NUMBER_BITBUCKET: str = "BITBUCKET_PR_ID"
_ENV_PIPELINE_GITHUB: str = "GITHUB_ACTIONS"
_ENV_PIPELINE_GITLAB: str = "GITLAB_CI"
_ENV_PIPELINE_JENKINS: str = "JENKINS_URL"
_ENV_PIPELINE_CIRCLECI: str = "CIRCLECI"
_ENV_PIPELINE_BITBUCKET: str = "BITBUCKET_PIPELINE_UUID"
_PIPELINE_GITHUB_NAME: str = "github-actions"
_PIPELINE_GITLAB_NAME: str = "gitlab-ci"
_PIPELINE_JENKINS_NAME: str = "jenkins"
_PIPELINE_CIRCLECI_NAME: str = "circleci"
_PIPELINE_BITBUCKET_NAME: str = "bitbucket-pipelines"
_PIPELINE_LOCAL: str = "local"


def _get_current_timestamp() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.datetime.now(datetime.UTC).isoformat()


def _reject_symlink_database_path(database_path: Path) -> None:
    """Raise AuditLogError if database_path is a symbolic link.

    Symlinks are rejected to prevent log-redirection attacks: an attacker
    who can create a symlink at the expected database path could redirect
    all audit writes to an arbitrary file (e.g. /dev/null or a file they
    control), silently discarding the audit trail or poisoning a different
    file. Rejecting symlinks forces the path to resolve to a real file.
    """
    if _O_NOFOLLOW is not None:
        # POSIX: O_NOFOLLOW atomically rejects symlinks in a single syscall.
        try:
            fd = os.open(str(database_path), os.O_RDONLY | _O_NOFOLLOW)
            os.close(fd)
        except OSError as os_error:
            if os_error.errno == errno.ELOOP:
                raise AuditLogError(
                    _SYMLINK_DATABASE_PATH_ERROR.format(path=database_path)
                ) from os_error
            if os_error.errno != errno.ENOENT:
                # Unexpected OS error (e.g. EACCES, EPERM) — surface as AuditLogError.
                raise AuditLogError(_DATABASE_ERROR.format(detail=os_error)) from os_error
            # ENOENT is intentionally ignored — new databases created by sqlite3.connect.
    else:
        # Windows fallback: O_NOFOLLOW unavailable; is_symlink() has a small TOCTOU
        # window but is the best available check on this platform.
        if database_path.is_symlink():
            raise AuditLogError(_SYMLINK_DATABASE_PATH_ERROR.format(path=database_path))


def _ensure_database_parent_exists(database_path: Path) -> None:
    """Create the parent directory of database_path if it does not exist."""
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as io_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=io_error)) from io_error


def _open_database(database_path: Path) -> sqlite3.Connection:
    """Open and configure a SQLite connection to the audit database.

    Symlink detection uses O_NOFOLLOW (see _reject_symlink_database_path),
    which closes the TOCTOU race that existed between is_symlink() and
    sqlite3.connect() in earlier versions.
    """
    _reject_symlink_database_path(database_path)
    _ensure_database_parent_exists(database_path)
    try:
        connection = sqlite3.connect(str(database_path))
    except sqlite3.Error as db_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    try:
        connection.row_factory = sqlite3.Row
        connection.execute(_PRAGMA_WAL_MODE)
    except sqlite3.Error as config_error:
        connection.close()
        raise AuditLogError(_DATABASE_ERROR.format(detail=config_error)) from config_error
    return connection


def _get_current_branch() -> str:
    """Return the current git branch name, or 'unknown' if unavailable."""
    try:
        completed_process = subprocess.run(
            _GIT_BRANCH_ARGS,
            capture_output=True,
            text=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if completed_process.returncode == 0:
            branch = completed_process.stdout.strip()
            return branch if branch else _UNKNOWN_BRANCH
    except (OSError, subprocess.TimeoutExpired) as git_error:
        _logger.warning("Could not determine git branch: %s", type(git_error).__name__)
    return _UNKNOWN_BRANCH


def _get_current_repository_path() -> str:
    """Return the git repository root path, or the current directory if unavailable."""
    try:
        completed_process = subprocess.run(
            _GIT_TOPLEVEL_ARGS,
            capture_output=True,
            text=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if completed_process.returncode == 0:
            return completed_process.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as git_error:
        _logger.warning("Could not determine git repository path: %s", type(git_error).__name__)
    return str(Path.cwd())


def _fetch_git_command_stdout(args: tuple[str, ...]) -> str:
    """Run a git log format command and return its stdout, or empty string on failure."""
    try:
        completed_process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if completed_process.returncode == 0:
            return completed_process.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as git_error:
        _logger.warning("Could not run git format command: %s", type(git_error).__name__)
    return ""


def _hash_git_committer_field(args: tuple[str, ...]) -> str:
    """Return SHA-256 hash of a git log committer field, or empty string if unavailable."""
    field_value = _fetch_git_command_stdout(args)
    return hashlib.sha256(field_value.encode()).hexdigest() if field_value else ""


def _detect_pr_number() -> str:
    """Return the PR/MR number from CI environment variables, or empty string."""
    for env_var in (
        _ENV_PR_NUMBER_GITHUB,
        _ENV_PR_NUMBER_GITLAB,
        _ENV_PR_NUMBER_BITBUCKET,
    ):
        pr_number_string = os.environ.get(env_var, "")
        if pr_number_string:
            return pr_number_string
    return ""


def _detect_pipeline() -> str:
    """Return the CI/CD pipeline name from environment variables, or 'local'."""
    if os.environ.get(_ENV_PIPELINE_GITHUB):
        return _PIPELINE_GITHUB_NAME
    if os.environ.get(_ENV_PIPELINE_GITLAB):
        return _PIPELINE_GITLAB_NAME
    if os.environ.get(_ENV_PIPELINE_JENKINS):
        return _PIPELINE_JENKINS_NAME
    if os.environ.get(_ENV_PIPELINE_CIRCLECI):
        return _PIPELINE_CIRCLECI_NAME
    if os.environ.get(_ENV_PIPELINE_BITBUCKET):
        return _PIPELINE_BITBUCKET_NAME
    return _PIPELINE_LOCAL


# _collect_repository_identity and _collect_committer_identity live in
# phi_scan.audit.__init__ so that tests which patch
# phi_scan.audit._get_current_repository_path (and friends) see the patched
# bindings when identity is collected. Keeping the aggregator functions at
# the package surface preserves monkey-patch compatibility.
