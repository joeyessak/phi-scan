"""Auto-fix synthetic data replacement engine (Phase 2F).

Replaces detected PHI values with deterministic synthetic data.  The same
PHI value always produces the same synthetic replacement within a scan run,
ensuring referential integrity (e.g. "John Smith" on line 10 and line 50
both become the same synthetic name).

Suppressed lines (``# phi-scan:ignore``) are never modified.

Supported output modes:
    DRY_RUN  — print unified diff to stdout; do not write files
    APPLY    — overwrite files in place after user confirms
    PATCH    — write a ``.patch`` file suitable for ``git apply``
"""

from __future__ import annotations

import difflib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from phi_scan.constants import (
    DEFAULT_TEXT_ENCODING,
    FICTIONAL_PHONE_EXCHANGE,
    FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX,
    FICTIONAL_PHONE_SUBSCRIBER_MAX,
    FICTIONAL_PHONE_SUBSCRIBER_MIN,
    PhiCategory,
)
from phi_scan.exceptions import FileReadError, MissingOptionalDependencyError
from phi_scan.hashing import compute_value_hash
from phi_scan.regex_detector import PhiPattern, get_phi_pattern_registry
from phi_scan.suppression import load_suppressions

__all__ = [
    "FixMode",
    "FixReplacement",
    "FixResult",
    "apply_approved_replacements",
    "collect_file_replacements",
    "fix_file",
    "generate_synthetic_value",
]

# Faker is an optional dependency; the fix engine raises MissingOptionalDependencyError
# at call time when it is not installed rather than failing at import time.
_FAKER_AVAILABLE: bool
try:
    from faker import Faker as _FakerClass

    _FAKER_AVAILABLE = True
except ImportError:
    _FakerClass = None  # type: ignore[assignment,misc]
    _FAKER_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# --- Deterministic seeding ---
# First 8 hex characters of the SHA-256 digest are used as the 32-bit seed.
# Using only 8 chars keeps the seed space tractable while still making
# identical PHI values deterministically produce identical replacements.
_SEED_HEX_CHARS: int = 8
_SEED_HEX_BASE: int = 16

# --- Synthetic SSN (000-00-XXXX — SSA reserved "all-zero area" range) ---
_SSN_SYNTHETIC_AREA: str = "000"
_SSN_SYNTHETIC_GROUP: str = "00"
_SSN_SERIAL_MAX: int = 9999
_SSN_SERIAL_DISPLAY_WIDTH: int = 4
_SSN_SEPARATOR: str = "-"

# --- Synthetic MRN ---
_MRN_PREFIX: str = "MRN-"
_MRN_MAX_VALUE: int = 999999
_MRN_DISPLAY_WIDTH: int = 6

# --- Synthetic Email (RFC 2606 example.com — never reaches a real inbox) ---
_EMAIL_USER_PREFIX: str = "user"
_EMAIL_SAFE_DOMAIN: str = "example.com"
_EMAIL_AT_SEPARATOR: str = "@"
_EMAIL_USER_MAX: int = 99999

# --- Synthetic IP (RFC 5737 TEST-NET-1 range — 192.0.2.0/24) ---
_IP_RFC5737_TEST_NET_1_PREFIX: str = "192.0.2."
_IP_LAST_OCTET_MIN: int = 1
_IP_LAST_OCTET_MAX: int = 254  # 255 is reserved for subnet broadcast

# --- Synthetic URL (RFC 2606 example.com — never routes to a real resource) ---
_URL_SAFE_BASE: str = "https://example.com/resource/"
_URL_PATH_ID_MAX: int = 99999

# --- Synthetic numeric identifiers ---
_ACCOUNT_PREFIX: str = "ACCT-"
_PLAN_PREFIX: str = "PLAN-"
_DEVICE_PREFIX: str = "DEV-"
_CERT_PREFIX: str = "CERT-"
_UNIQUE_ID_PREFIX: str = "ID-"
_NUMERIC_ID_MAX: int = 999999
_NUMERIC_ID_DISPLAY_WIDTH: int = 6

# --- Synthetic VIN placeholder (ISO 3779 check-digit computation is non-trivial;
#     a static placeholder clearly communicates removal without pretending to be valid) ---
_VIN_SYNTHETIC: str = "00000000000000000"

# --- Synthetic photo placeholder (cannot generate a real image) ---
_PHOTO_SYNTHETIC: str = "[PHOTO_REMOVED]"

# --- Synthetic date range (1950–2000 produces plausible but clearly fictional dates) ---
_DATE_YEAR_MIN: int = 1950
_DATE_YEAR_MAX: int = 2000
_DATE_MONTH_MIN: int = 1
_DATE_MONTH_MAX: int = 12
_DATE_DAY_MIN: int = 1
# Use 28 as the safe upper bound — all calendar months have at least 28 days,
# so randint(1, 28) never produces an invalid date regardless of month.
_DATE_DAY_SAFE_MAX: int = 28

# --- Unified diff ---
_DIFF_CONTEXT_LINES: int = 3
_DIFF_FROM_PREFIX: str = "a/"
_DIFF_TO_PREFIX: str = "b/"

# --- Patch file ---
_PATCH_SUFFIX: str = ".patch"

# --- Line number base (1-indexed, matching ScanFinding.line_number) ---
_LINE_NUMBER_START: int = 1

# --- Suppression map sentinels ---
# These mirror the private constants in suppression.py, which are not exported.
# Duplicated here rather than importing to avoid coupling to private identifiers.
_SUPPRESS_ALL_SENTINEL: str = "*"
_FILE_SUPPRESS_SENTINEL_LINE: int = -1

# --- Error and hint messages ---
_FAKER_INSTALL_HINT: str = (
    "faker is required for `phi-scan fix`. "
    "Install it with: pip install phi-scan[dev]  or  pip install faker"
)
_EMPTY_UNIFIED_DIFF: str = ""


# ---------------------------------------------------------------------------
# Public enums and dataclasses
# ---------------------------------------------------------------------------


class FixMode(StrEnum):
    """Output mode for the auto-fix engine.

    DRY_RUN produces a unified diff without modifying any files.
    APPLY overwrites the target file in place.
    PATCH writes a ``.patch`` file that can be reviewed and applied with
    ``git apply``.
    """

    DRY_RUN = "dry-run"
    APPLY = "apply"
    PATCH = "patch"


@dataclass(frozen=True)
class FixReplacement:
    """A single PHI replacement in a source file.

    Captures both the original matched text and the synthetic replacement
    so callers can display diffs and obtain informed consent before applying.

    Args:
        line_number: 1-indexed line number of the match.
        start_column: 0-indexed start position of the match within the line.
        end_column: 0-indexed exclusive end position of the match.
        original_text: Raw matched PHI value (used only during replacement;
            never written to audit logs or persistent storage).
        synthetic_text: Deterministic synthetic replacement value.
        hipaa_category: PHI category that triggered the replacement.
    """

    line_number: int
    start_column: int
    end_column: int
    original_text: str
    synthetic_text: str
    hipaa_category: PhiCategory


@dataclass(frozen=True)
class FixResult:
    """The outcome of a fix operation on a single file.

    Args:
        file_path: The file that was processed.
        replacements_applied: All replacements that were (or would be) applied,
            in the order they were collected.
        unified_diff: Unified diff string showing the changes.  Empty string
            when no replacements were found.
        patch_path: Path to the written ``.patch`` file, or None when the
            mode is not PATCH or the diff was empty.
    """

    file_path: Path
    replacements_applied: tuple[FixReplacement, ...]
    unified_diff: str
    patch_path: Path | None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collect_file_replacements(file_path: Path) -> list[FixReplacement]:
    """Scan file_path and return all PHI replacements without modifying the file.

    Suppressed lines are excluded.  The replacements are ordered by line number
    then by start column; callers that apply them must do so right-to-left within
    each line to preserve column offsets.

    Args:
        file_path: Path to the source file to scan.

    Returns:
        List of FixReplacement objects ready for display or application.

    Raises:
        MissingOptionalDependencyError: If faker is not installed.
        FileReadError: If the file cannot be read or decoded.
    """
    _reject_faker_unavailable()
    _file_content, file_lines = _read_file_content(file_path)
    suppression_map = load_suppressions(file_lines)
    return _collect_file_replacements(file_lines, suppression_map)


def fix_file(
    file_path: Path,
    mode: FixMode,
    patch_dir: Path | None = None,
) -> FixResult:
    """Scan file_path, generate synthetic replacements, and act on them.

    Args:
        file_path: Path to the source file to fix.
        mode: FixMode.DRY_RUN to preview, APPLY to overwrite, PATCH to write
            a ``.patch`` file.
        patch_dir: Directory where the ``.patch`` file is written.  Defaults
            to the parent directory of file_path when mode is PATCH.

    Returns:
        FixResult with replacements and unified diff.

    Raises:
        MissingOptionalDependencyError: If faker is not installed.
        FileReadError: If the file cannot be read or decoded.
    """
    _reject_faker_unavailable()
    file_content, file_lines = _read_file_content(file_path)
    suppression_map = load_suppressions(file_lines)
    replacements = _collect_file_replacements(file_lines, suppression_map)
    new_lines = _apply_replacements_to_lines(file_lines, replacements)
    unified_diff = _generate_unified_diff(file_path, file_lines, new_lines)
    patch_path: Path | None = None
    if mode == FixMode.APPLY and replacements:
        file_path.write_text(_EMPTY_UNIFIED_DIFF.join(new_lines), encoding=DEFAULT_TEXT_ENCODING)
    elif mode == FixMode.PATCH and unified_diff:
        resolved_patch_dir = patch_dir if patch_dir is not None else file_path.parent
        patch_path = _write_patch_file(unified_diff, file_path, resolved_patch_dir)
    return FixResult(
        file_path=file_path,
        replacements_applied=tuple(replacements),
        unified_diff=unified_diff,
        patch_path=patch_path,
    )


def apply_approved_replacements(file_path: Path, replacements: list[FixReplacement]) -> FixResult:
    """Apply a caller-approved subset of replacements and overwrite file_path in place.

    Intended for interactive mode: the caller presents replacements to the user,
    collects approval (y/n/a/s), then passes only the approved items here.

    Args:
        file_path: Path to the source file to modify.
        replacements: Approved replacements to apply.  May be a subset of the
            list returned by collect_file_replacements.

    Returns:
        FixResult with unified diff reflecting the applied changes.

    Raises:
        FileReadError: If the file cannot be read or decoded.
    """
    _file_content, file_lines = _read_file_content(file_path)
    new_lines = _apply_replacements_to_lines(file_lines, replacements)
    unified_diff = _generate_unified_diff(file_path, file_lines, new_lines)
    if replacements:
        file_path.write_text(_EMPTY_UNIFIED_DIFF.join(new_lines), encoding=DEFAULT_TEXT_ENCODING)
    return FixResult(
        file_path=file_path,
        replacements_applied=tuple(replacements),
        unified_diff=unified_diff,
        patch_path=None,
    )


def generate_synthetic_value(hipaa_category: PhiCategory, value_hash: str) -> str:
    """Return a deterministic synthetic replacement for a PHI value.

    The same (hipaa_category, value_hash) pair always returns the same
    synthetic string, ensuring referential integrity across a file.

    Args:
        hipaa_category: The HIPAA category that governs what kind of synthetic
            value is appropriate.
        value_hash: SHA-256 hex digest of the original PHI value.  The first
            eight hex characters seed the Faker instance.

    Returns:
        A synthetic string that is safe to commit (no real PHI).

    Raises:
        MissingOptionalDependencyError: If faker is not installed.
    """
    _reject_faker_unavailable()
    fake = _build_seeded_faker(value_hash)
    generator = _SYNTHETIC_GENERATORS.get(hipaa_category)
    if generator is not None:
        return generator(fake)
    return _generate_synthetic_unique_id(fake)


# ---------------------------------------------------------------------------
# Private helpers — file I/O
# ---------------------------------------------------------------------------


def _reject_faker_unavailable() -> None:
    if not _FAKER_AVAILABLE:
        raise MissingOptionalDependencyError(_FAKER_INSTALL_HINT)


def _read_file_content(file_path: Path) -> tuple[str, list[str]]:
    """Return (full_text, lines_with_endings) for file_path.

    Args:
        file_path: Path to read.

    Returns:
        Tuple of the full text content and its lines (with line endings preserved
        by splitlines(keepends=True) so round-trip join reconstructs the original).

    Raises:
        FileReadError: If the file cannot be opened or decoded.
    """
    try:
        full_text = file_path.read_text(encoding=DEFAULT_TEXT_ENCODING)
    except OSError as os_error:
        raise FileReadError(f"Could not read {file_path}: {os_error}") from os_error
    except UnicodeDecodeError as decode_error:
        raise FileReadError(
            f"Could not decode {file_path} as {DEFAULT_TEXT_ENCODING}: {decode_error}"
        ) from decode_error
    return full_text, full_text.splitlines(keepends=True)


def _write_patch_file(unified_diff: str, file_path: Path, patch_dir: Path) -> Path:
    """Write unified_diff to a ``.patch`` file in patch_dir and return its path.

    Args:
        unified_diff: Content of the unified diff.
        file_path: Source file whose name seeds the patch filename.
        patch_dir: Directory to write the patch into.

    Returns:
        Path to the written ``.patch`` file.
    """
    patch_filename = file_path.name + _PATCH_SUFFIX
    patch_path = patch_dir / patch_filename
    patch_path.write_text(unified_diff, encoding=DEFAULT_TEXT_ENCODING)
    return patch_path


# ---------------------------------------------------------------------------
# Private helpers — replacement collection
# ---------------------------------------------------------------------------


def _collect_file_replacements(
    file_lines: list[str],
    suppression_map: dict[int, set[str]],
) -> list[FixReplacement]:
    """Collect all PHI replacements across all lines and all patterns.

    Args:
        file_lines: Lines of the source file (with endings).
        suppression_map: Suppression directives parsed from the file.

    Returns:
        Deduplicated list of FixReplacement objects ordered by line and column.
    """
    registry = get_phi_pattern_registry()
    raw_replacements: list[FixReplacement] = []
    for phi_pattern in registry:
        for line_index, line_text in enumerate(file_lines):
            line_number = line_index + _LINE_NUMBER_START
            if _is_line_suppressed(line_number, phi_pattern.entity_type, suppression_map):
                continue
            raw_replacements.extend(
                _collect_pattern_line_matches(phi_pattern, line_text, line_number)
            )
    return _deduplicate_replacements(raw_replacements)


def _collect_pattern_line_matches(
    phi_pattern: PhiPattern,
    line_text: str,
    line_number: int,
) -> list[FixReplacement]:
    """Return replacements for all matches of phi_pattern on line_text.

    Each match that passes the optional validator is converted to a
    FixReplacement with a deterministically seeded synthetic value.

    Args:
        phi_pattern: The pattern to apply.
        line_text: The raw source line (with trailing newline).
        line_number: 1-indexed line number (stored in the replacement).

    Returns:
        List of FixReplacement objects for each valid match on this line.
    """
    line_matches: list[FixReplacement] = []
    for match in phi_pattern.compiled_pattern.finditer(line_text):
        if phi_pattern.validator is not None and not phi_pattern.validator(match.group()):
            continue
        value_hash = compute_value_hash(match.group())
        synthetic = generate_synthetic_value(phi_pattern.phi_category, value_hash)
        line_matches.append(
            FixReplacement(
                line_number=line_number,
                start_column=match.start(),
                end_column=match.end(),
                original_text=match.group(),
                synthetic_text=synthetic,
                hipaa_category=phi_pattern.phi_category,
            )
        )
    return line_matches


def _is_line_suppressed(
    line_number: int,
    entity_type: str,
    suppression_map: dict[int, set[str]],
) -> bool:
    """Return True if this line / entity type is covered by a suppression directive.

    Mirrors the logic in suppression.is_finding_suppressed without requiring a
    full ScanFinding object.

    Args:
        line_number: 1-indexed line number.
        entity_type: Pattern entity type string (e.g. "us_ssn").
        suppression_map: Map produced by load_suppressions.

    Returns:
        True if the line (or the whole file) is suppressed for this entity type.
    """
    if _FILE_SUPPRESS_SENTINEL_LINE in suppression_map:
        return True
    line_suppressions = suppression_map.get(line_number)
    if line_suppressions is None:
        return False
    return _SUPPRESS_ALL_SENTINEL in line_suppressions or entity_type.upper() in line_suppressions


def _deduplicate_replacements(replacements: list[FixReplacement]) -> list[FixReplacement]:
    """Remove duplicate replacements that cover the same span.

    Multiple patterns can match the same text at the same position (e.g. an
    SSN regex and a generic number pattern).  Keep the first occurrence, which
    comes from the highest-priority pattern (registry order).

    Args:
        replacements: All raw replacements, possibly with span overlaps.

    Returns:
        List with at most one replacement per (line_number, start_column, end_column).
    """
    seen_spans: set[tuple[int, int, int]] = set()
    unique_replacements: list[FixReplacement] = []
    for replacement in replacements:
        span_key = (replacement.line_number, replacement.start_column, replacement.end_column)
        if span_key not in seen_spans:
            seen_spans.add(span_key)
            unique_replacements.append(replacement)
    return unique_replacements


# ---------------------------------------------------------------------------
# Private helpers — replacement application
# ---------------------------------------------------------------------------


def _apply_replacements_to_lines(
    original_lines: list[str],
    replacements: list[FixReplacement],
) -> list[str]:
    """Apply replacements to original_lines and return the modified line list.

    Args:
        original_lines: Source lines with line endings.
        replacements: Replacements to apply (may span multiple lines).

    Returns:
        New list of lines with all replacements applied.
    """
    line_groups: dict[int, list[FixReplacement]] = {}
    for replacement in replacements:
        line_groups.setdefault(replacement.line_number, []).append(replacement)
    new_lines = list(original_lines)
    for line_number, line_replacements in line_groups.items():
        line_index = line_number - _LINE_NUMBER_START
        new_lines[line_index] = _apply_line_replacements(
            original_lines[line_index], line_replacements
        )
    return new_lines


def _apply_line_replacements(
    line_text: str,
    line_replacements: list[FixReplacement],
) -> str:
    """Apply replacements to a single line, right-to-left to preserve column offsets.

    Applying right-to-left means earlier replacements do not shift the column
    positions of later ones, so all start_column / end_column values remain valid
    throughout the substitution loop.

    Args:
        line_text: The original source line.
        line_replacements: All replacements on this line (any order).

    Returns:
        Line text with all replacements applied.
    """
    sorted_replacements = sorted(line_replacements, key=lambda r: r.start_column, reverse=True)
    result = line_text
    for replacement in sorted_replacements:
        result = (
            result[: replacement.start_column]
            + replacement.synthetic_text
            + result[replacement.end_column :]
        )
    return result


def _generate_unified_diff(
    file_path: Path,
    original_lines: list[str],
    new_lines: list[str],
) -> str:
    """Produce a unified diff string between original_lines and new_lines.

    Args:
        file_path: Path used as the diff header (a/... and b/... prefixes).
        original_lines: Source lines before replacement.
        new_lines: Source lines after replacement.

    Returns:
        Unified diff string, or an empty string when there are no differences.
    """
    from_label = _DIFF_FROM_PREFIX + str(file_path)
    to_label = _DIFF_TO_PREFIX + str(file_path)
    diff_lines = difflib.unified_diff(
        original_lines,
        new_lines,
        fromfile=from_label,
        tofile=to_label,
        n=_DIFF_CONTEXT_LINES,
    )
    return _EMPTY_UNIFIED_DIFF.join(diff_lines)


# ---------------------------------------------------------------------------
# Private helpers — synthetic value generation
# ---------------------------------------------------------------------------


def _build_seeded_faker(value_hash: str) -> Any:
    """Construct a Faker instance seeded deterministically from value_hash.

    Args:
        value_hash: SHA-256 hex digest.  The first _SEED_HEX_CHARS characters
            are parsed as a base-16 integer to seed the instance.

    Returns:
        A seeded Faker instance.
    """
    seed = int(value_hash[:_SEED_HEX_CHARS], _SEED_HEX_BASE)
    fake = _FakerClass()
    fake.seed_instance(seed)
    return fake


def _generate_synthetic_name(fake: Any) -> str:
    return str(fake.name())


def _generate_synthetic_address(fake: Any) -> str:
    # Faker addresses include embedded newlines; replace with comma-space for
    # inline use in source code strings.
    return str(fake.address()).replace("\n", ", ")


def _generate_synthetic_date(fake: Any) -> str:
    import datetime

    synthetic_date = datetime.date(
        fake.random_int(_DATE_YEAR_MIN, _DATE_YEAR_MAX),
        fake.random_int(_DATE_MONTH_MIN, _DATE_MONTH_MAX),
        fake.random_int(_DATE_DAY_MIN, _DATE_DAY_SAFE_MAX),
    )
    return synthetic_date.isoformat()


def _generate_synthetic_phone(fake: Any) -> str:
    subscriber = fake.random_int(FICTIONAL_PHONE_SUBSCRIBER_MIN, FICTIONAL_PHONE_SUBSCRIBER_MAX)
    padded_subscriber = FICTIONAL_PHONE_SUBSCRIBER_DISPLAY_PREFIX + str(subscriber)
    return f"({FICTIONAL_PHONE_EXCHANGE}) {padded_subscriber}"


def _generate_synthetic_email(fake: Any) -> str:
    user_number = fake.random_int(1, _EMAIL_USER_MAX)
    return _EMAIL_USER_PREFIX + str(user_number) + _EMAIL_AT_SEPARATOR + _EMAIL_SAFE_DOMAIN


def _generate_synthetic_ssn(fake: Any) -> str:
    serial = fake.random_int(0, _SSN_SERIAL_MAX)
    padded_serial = str(serial).zfill(_SSN_SERIAL_DISPLAY_WIDTH)
    return (
        _SSN_SYNTHETIC_AREA + _SSN_SEPARATOR + _SSN_SYNTHETIC_GROUP + _SSN_SEPARATOR + padded_serial
    )


def _generate_synthetic_mrn(fake: Any) -> str:
    mrn_number = fake.random_int(1, _MRN_MAX_VALUE)
    return _MRN_PREFIX + str(mrn_number).zfill(_MRN_DISPLAY_WIDTH)


def _generate_synthetic_health_plan(fake: Any) -> str:
    plan_number = fake.random_int(1, _NUMERIC_ID_MAX)
    return _PLAN_PREFIX + str(plan_number).zfill(_NUMERIC_ID_DISPLAY_WIDTH)


def _generate_synthetic_account(fake: Any) -> str:
    account_number = fake.random_int(1, _NUMERIC_ID_MAX)
    return _ACCOUNT_PREFIX + str(account_number).zfill(_NUMERIC_ID_DISPLAY_WIDTH)


def _generate_synthetic_certificate(fake: Any) -> str:
    cert_number = fake.random_int(1, _NUMERIC_ID_MAX)
    return _CERT_PREFIX + str(cert_number).zfill(_NUMERIC_ID_DISPLAY_WIDTH)


def _generate_synthetic_vehicle(_fake: Any) -> str:
    # A valid VIN requires check-digit computation (ISO 3779).  A static
    # placeholder is unambiguous and avoids producing an accidentally valid VIN.
    return _VIN_SYNTHETIC


def _generate_synthetic_device(fake: Any) -> str:
    device_number = fake.random_int(1, _NUMERIC_ID_MAX)
    return _DEVICE_PREFIX + str(device_number).zfill(_NUMERIC_ID_DISPLAY_WIDTH)


def _generate_synthetic_url(fake: Any) -> str:
    path_id = fake.random_int(1, _URL_PATH_ID_MAX)
    return _URL_SAFE_BASE + str(path_id)


def _generate_synthetic_ip(fake: Any) -> str:
    last_octet = fake.random_int(_IP_LAST_OCTET_MIN, _IP_LAST_OCTET_MAX)
    return _IP_RFC5737_TEST_NET_1_PREFIX + str(last_octet)


def _generate_synthetic_photo(_fake: Any) -> str:
    # Images cannot be synthesised inline; placeholder communicates removal.
    return _PHOTO_SYNTHETIC


def _generate_synthetic_unique_id(fake: Any) -> str:
    unique_number = fake.random_int(1, _NUMERIC_ID_MAX)
    return _UNIQUE_ID_PREFIX + str(unique_number).zfill(_NUMERIC_ID_DISPLAY_WIDTH)


# ---------------------------------------------------------------------------
# Synthetic generator dispatch table
# ---------------------------------------------------------------------------

# Maps each PhiCategory to a generator function.  Categories that share the
# same synthetic format (e.g. FAX and PHONE) share the same function reference.
# Categories not present here fall back to _generate_synthetic_unique_id.
_SYNTHETIC_GENERATORS: dict[PhiCategory, Callable[[Any], str]] = {
    PhiCategory.NAME: _generate_synthetic_name,
    PhiCategory.GEOGRAPHIC: _generate_synthetic_address,
    PhiCategory.DATE: _generate_synthetic_date,
    PhiCategory.PHONE: _generate_synthetic_phone,
    PhiCategory.FAX: _generate_synthetic_phone,
    PhiCategory.EMAIL: _generate_synthetic_email,
    PhiCategory.SSN: _generate_synthetic_ssn,
    PhiCategory.MRN: _generate_synthetic_mrn,
    PhiCategory.HEALTH_PLAN: _generate_synthetic_health_plan,
    PhiCategory.ACCOUNT: _generate_synthetic_account,
    PhiCategory.CERTIFICATE: _generate_synthetic_certificate,
    PhiCategory.VEHICLE: _generate_synthetic_vehicle,
    PhiCategory.DEVICE: _generate_synthetic_device,
    PhiCategory.URL: _generate_synthetic_url,
    PhiCategory.IP: _generate_synthetic_ip,
    PhiCategory.BIOMETRIC: _generate_synthetic_unique_id,
    PhiCategory.PHOTO: _generate_synthetic_photo,
    PhiCategory.UNIQUE_ID: _generate_synthetic_unique_id,
    PhiCategory.SUBSTANCE_USE_DISORDER: _generate_synthetic_unique_id,
    PhiCategory.QUASI_IDENTIFIER_COMBINATION: _generate_synthetic_unique_id,
}
