"""Tests for phi_scan.constants — named constants, enums, and derived values."""

import pytest

from phi_scan.constants import (
    AUDIT_RETENTION_DAYS,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_SIZE_MB,
    OutputFormat,
)

# Derived from the same arithmetic as the constant: 4 standard years × 365 + 2 leap years × 366.
# This makes the HIPAA 6-year minimum verifiable without importing private helpers.
_EXPECTED_HIPAA_RETENTION_DAYS: int = (4 * 365) + (2 * 366)


def test_max_file_size_bytes_equals_mb_times_bytes_per_megabyte() -> None:
    assert MAX_FILE_SIZE_BYTES == MAX_FILE_SIZE_MB * 1024 * 1024


def test_audit_retention_days_equals_hipaa_six_year_minimum() -> None:
    assert AUDIT_RETENTION_DAYS == _EXPECTED_HIPAA_RETENTION_DAYS


def test_output_format_raises_value_error_for_unknown_value() -> None:
    # _missing_ returns None for unknown values; Python's enum machinery
    # then raises ValueError — callers should catch ValueError, not check None.
    with pytest.raises(ValueError):
        OutputFormat("unknown-format")


def test_output_format_missing_matches_gitlab_sast_by_value() -> None:
    assert OutputFormat("gitlab-sast") is OutputFormat.GITLAB_SAST


def test_output_format_missing_is_case_insensitive() -> None:
    assert OutputFormat("TABLE") is OutputFormat.TABLE
