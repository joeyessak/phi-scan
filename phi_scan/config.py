"""YAML configuration loading and validation for PhiScan (.phi-scanner.yml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from phi_scan.constants import (
    AUDIT_RETENTION_DAYS,
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_CONFIG_FILENAME,
    MAX_FILE_SIZE_MB,
    OutputFormat,
    SeverityLevel,
)
from phi_scan.exceptions import ConfigurationError
from phi_scan.models import ScanConfig

__all__ = ["create_default_config", "load_config"]

# ---------------------------------------------------------------------------
# YAML structure keys — no string literals in logic
# ---------------------------------------------------------------------------

_YAML_SECTION_SCAN: str = "scan"
_YAML_SECTION_OUTPUT: str = "output"
_YAML_SECTION_AUDIT: str = "audit"
_YAML_KEY_VERSION: str = "version"
_YAML_KEY_CONFIDENCE_THRESHOLD: str = "confidence_threshold"
_YAML_KEY_SEVERITY_THRESHOLD: str = "severity_threshold"
_YAML_KEY_MAX_FILE_SIZE_MB: str = "max_file_size_mb"
_YAML_KEY_FOLLOW_SYMLINKS: str = "follow_symlinks"
_YAML_KEY_INCLUDE_EXTENSIONS: str = "include_extensions"
_YAML_KEY_EXCLUDE_PATHS: str = "exclude_paths"
_YAML_KEY_OUTPUT_FORMAT: str = "format"
_YAML_KEY_DATABASE_PATH: str = "database_path"

# ---------------------------------------------------------------------------
# Config defaults and constraints
# ---------------------------------------------------------------------------

_SUPPORTED_CONFIG_VERSION: int = 1
_CONFIG_FILE_ENCODING: str = "utf-8"
_DEFAULT_DATABASE_PATH: str = "~/.phi-scanner/audit.db"

# ---------------------------------------------------------------------------
# Error message templates
# ---------------------------------------------------------------------------

_CONFIG_READ_ERROR: str = "Cannot read config file {path!r}: {error}"
_CONFIG_PARSE_ERROR: str = "Failed to parse config file {path!r}: {error}"
_CONFIG_WRITE_ERROR: str = "Cannot write config file {path!r}: {error}"
_UNSUPPORTED_VERSION_ERROR: str = "Unsupported config version {version!r} — expected {expected}"
_FOLLOW_SYMLINKS_ERROR: str = (
    "follow_symlinks must be false — symlink traversal is a security violation "
    "that can cause infinite loops in CI/CD environments"
)
_INVALID_OUTPUT_FORMAT_ERROR: str = "output.format {value!r} is not valid. Accepted values: {valid}"
_INVALID_SEVERITY_ERROR: str = (
    "scan.severity_threshold {value!r} is not valid. Accepted values: {valid}"
)
_INVALID_DATABASE_PATH_ERROR: str = "audit.database_path must be a string, got {value!r}"

# ---------------------------------------------------------------------------
# Default config template — written by create_default_config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_CONTENT: str = """\
# PhiScan configuration — {filename}
# Run `phi-scan explain config` for full documentation.

version: 1

scan:
  # Minimum confidence score to report a finding (0.0–1.0).
  confidence_threshold: {confidence_threshold}

  # Minimum severity: low, medium, or high.
  severity_threshold: low

  # Skip files larger than this limit (megabytes).
  max_file_size_mb: {max_file_size_mb}

  # SECURITY: must remain false. Setting true raises ConfigurationError.
  follow_symlinks: false

  # Allowlist of extensions to scan. null = scan all non-binary text files.
  include_extensions: null

  # Gitignore-style exclusion patterns evaluated at every directory depth.
  exclude_paths:
    - .git/
    - .venv/
    - node_modules/
    - dist/
    - build/
    - "*.egg-info/"
    - __pycache__/
    - .mypy_cache/
    - .ruff_cache/
    - .pytest_cache/
    - htmlcov/
    - "*.pyc"

output:
  # table, json, sarif, csv, pdf, html, junit, codequality, gitlab-sast
  format: table
  quiet: false

audit:
  # ~ is expanded via Path.expanduser() at runtime, not by the YAML parser.
  database_path: "{default_db}"

  # HIPAA 45 CFR §164.530(j): minimum 6-year retention = {retention_days} days.
  retention_days: {retention_days}

ai:
  # Disabled by default — all scanning is local. See CLAUDE.md before enabling.
  enable_claude_review: false
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> ScanConfig:
    """Load and validate a .phi-scanner.yml configuration file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        A ScanConfig populated from the file, with defaults for omitted fields.

    Raises:
        ConfigurationError: If the file cannot be read, cannot be parsed as
            YAML, contains an unsupported version, or any field value is invalid.
    """
    raw_config = _read_config_file(config_path)
    _reject_unsupported_version(raw_config)
    scan_section: dict[str, Any] = raw_config.get(_YAML_SECTION_SCAN, {})
    output_section: dict[str, Any] = raw_config.get(_YAML_SECTION_OUTPUT, {})
    audit_section: dict[str, Any] = raw_config.get(_YAML_SECTION_AUDIT, {})
    _reject_follow_symlinks_enabled(scan_section)
    _parse_output_format(output_section)
    _expand_database_path(audit_section)
    return _build_scan_config(scan_section)


def create_default_config(output_path: Path) -> None:
    """Write a default .phi-scanner.yml configuration file to output_path.

    Args:
        output_path: Destination path for the generated config file.

    Raises:
        ConfigurationError: If the file cannot be written.
    """
    content = _DEFAULT_CONFIG_CONTENT.format(
        filename=DEFAULT_CONFIG_FILENAME,
        confidence_threshold=DEFAULT_CONFIDENCE_THRESHOLD,
        max_file_size_mb=MAX_FILE_SIZE_MB,
        default_db=_DEFAULT_DATABASE_PATH,
        retention_days=AUDIT_RETENTION_DAYS,
    )
    try:
        output_path.write_text(content, encoding=_CONFIG_FILE_ENCODING)
    except OSError as error:
        raise ConfigurationError(
            _CONFIG_WRITE_ERROR.format(path=output_path, error=error)
        ) from error


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _read_config_file(config_path: Path) -> dict[str, Any]:  # noqa: ANN401
    """Read and parse a YAML config file into a raw dict.

    Args:
        config_path: Path to the YAML file.

    Returns:
        The top-level parsed mapping.

    Raises:
        ConfigurationError: If the file cannot be read or is not valid YAML.
    """
    try:
        content = config_path.read_text(encoding=_CONFIG_FILE_ENCODING)
    except OSError as error:
        raise ConfigurationError(
            _CONFIG_READ_ERROR.format(path=config_path, error=error)
        ) from error
    try:
        raw = yaml.safe_load(content)
    except yaml.YAMLError as error:
        raise ConfigurationError(
            _CONFIG_PARSE_ERROR.format(path=config_path, error=error)
        ) from error
    if not isinstance(raw, dict):
        raise ConfigurationError(
            _CONFIG_PARSE_ERROR.format(path=config_path, error="top-level value is not a mapping")
        )
    return raw


def _reject_unsupported_version(raw_config: dict[str, Any]) -> None:
    """Raise ConfigurationError if the config version is not supported.

    Args:
        raw_config: The top-level parsed config dict.

    Raises:
        ConfigurationError: If version is missing or not the supported value.
    """
    version = raw_config.get(_YAML_KEY_VERSION)
    if version != _SUPPORTED_CONFIG_VERSION:
        raise ConfigurationError(
            _UNSUPPORTED_VERSION_ERROR.format(version=version, expected=_SUPPORTED_CONFIG_VERSION)
        )


def _reject_follow_symlinks_enabled(scan_section: dict[str, Any]) -> None:
    """Raise ConfigurationError if follow_symlinks is set to true.

    Args:
        scan_section: The scan: section of the parsed config.

    Raises:
        ConfigurationError: If follow_symlinks is True.
    """
    if scan_section.get(_YAML_KEY_FOLLOW_SYMLINKS) is True:
        raise ConfigurationError(_FOLLOW_SYMLINKS_ERROR)


def _parse_output_format(output_section: dict[str, Any]) -> OutputFormat:
    """Parse and validate the output format, defaulting to TABLE.

    Maps "gitlab-sast" to OutputFormat.GITLAB_SAST via value-based enum
    lookup — never via string transformation such as replace() or upper().

    Args:
        output_section: The output: section of the parsed config.

    Returns:
        The resolved OutputFormat member.

    Raises:
        ConfigurationError: If the format string is not a valid OutputFormat value.
    """
    format_value = output_section.get(_YAML_KEY_OUTPUT_FORMAT, OutputFormat.TABLE.value)
    try:
        return OutputFormat(format_value)
    except ValueError as error:
        valid = ", ".join(member.value for member in OutputFormat)
        raise ConfigurationError(
            _INVALID_OUTPUT_FORMAT_ERROR.format(value=format_value, valid=valid)
        ) from error


def _expand_database_path(audit_section: dict[str, Any]) -> Path:
    """Return the audit database path with ~ expanded via Path.expanduser().

    Args:
        audit_section: The audit: section of the parsed config.

    Returns:
        The fully expanded Path to the audit database.

    Raises:
        ConfigurationError: If database_path is present but not a string.
    """
    raw_path = audit_section.get(_YAML_KEY_DATABASE_PATH, _DEFAULT_DATABASE_PATH)
    if not isinstance(raw_path, str):
        raise ConfigurationError(_INVALID_DATABASE_PATH_ERROR.format(value=raw_path))
    return Path(raw_path).expanduser()


def _build_scan_config(scan_section: dict[str, Any]) -> ScanConfig:
    """Build a ScanConfig from the scan: section of a parsed config.

    Args:
        scan_section: The scan: section dict. Missing keys fall back to
            ScanConfig defaults.

    Returns:
        A validated ScanConfig instance.

    Raises:
        ConfigurationError: If any field value is invalid.
    """
    severity_value = scan_section.get(_YAML_KEY_SEVERITY_THRESHOLD, SeverityLevel.LOW.value)
    try:
        severity = SeverityLevel(severity_value)
    except ValueError as error:
        valid = ", ".join(member.value for member in SeverityLevel)
        raise ConfigurationError(
            _INVALID_SEVERITY_ERROR.format(value=severity_value, valid=valid)
        ) from error
    return ScanConfig(
        confidence_threshold=float(
            scan_section.get(_YAML_KEY_CONFIDENCE_THRESHOLD, DEFAULT_CONFIDENCE_THRESHOLD)
        ),
        severity_threshold=severity,
        max_file_size_mb=int(scan_section.get(_YAML_KEY_MAX_FILE_SIZE_MB, MAX_FILE_SIZE_MB)),
        should_follow_symlinks=False,
        include_extensions=scan_section.get(_YAML_KEY_INCLUDE_EXTENSIONS),
        exclude_paths=list(scan_section.get(_YAML_KEY_EXCLUDE_PATHS, [])),
    )
