"""Dataclasses representing scan findings, results, and configuration for PhiScan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from phi_scan.constants import (
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    DEFAULT_CONFIDENCE_THRESHOLD,
    MAX_FILE_SIZE_MB,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import ConfigurationError

__all__ = [
    "ScanConfig",
    "ScanFinding",
    "ScanResult",
]


@dataclass(frozen=True)
class ScanFinding:
    """A single PHI/PII finding detected in a source file.

    Frozen to prevent accidental mutation after detection — findings are
    immutable records of what was observed at scan time.

    Args:
        file_path: Path to the file containing the finding.
        line_number: Line number (1-indexed) where the finding appears.
        entity_type: Pattern name that matched (e.g. "us_ssn", "email_address").
        hipaa_category: HIPAA Safe Harbor category of the detected identifier.
        confidence: Detection confidence score in the range [0.0, 1.0].
        detection_layer: Layer that produced the finding.
        value_hash: SHA-256 hex digest of the raw detected value — never the raw value itself.
        severity: Severity level derived from the confidence score.
        code_context: Surrounding source lines shown in reports for human review.
        remediation_hint: Actionable guidance for removing or replacing this PHI.
    """

    file_path: Path
    line_number: int
    entity_type: str
    hipaa_category: PhiCategory
    confidence: float
    detection_layer: DetectionLayer
    value_hash: str
    severity: SeverityLevel
    code_context: str
    remediation_hint: str

    def __post_init__(self) -> None:
        if not CONFIDENCE_SCORE_MINIMUM <= self.confidence <= CONFIDENCE_SCORE_MAXIMUM:
            raise ValueError(
                f"confidence {self.confidence!r} is outside the valid range "
                f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
            )


@dataclass
class ScanResult:
    """The aggregated outcome of a completed scan operation.

    Args:
        findings: All findings produced by the scan, ordered by file path then line number.
        files_scanned: Total number of files examined.
        files_with_findings: Number of files that contained at least one finding.
        scan_duration: Wall-clock time in seconds the scan took to complete.
        is_clean: True when the scan produced zero findings at or above the threshold.
        risk_level: Overall risk classification for the scanned codebase.
        severity_counts: Number of findings per severity level.
        category_counts: Number of findings per HIPAA PHI category.
    """

    findings: list[ScanFinding]
    files_scanned: int
    files_with_findings: int
    scan_duration: float
    is_clean: bool
    risk_level: RiskLevel
    severity_counts: dict[SeverityLevel, int]
    category_counts: dict[PhiCategory, int]


@dataclass
class ScanConfig:
    """Configuration that controls the behaviour of a scan operation.

    All fields have safe defaults so callers can construct a minimal config
    and override only the settings relevant to their context.

    Args:
        exclude_paths: Glob patterns for paths to skip, evaluated at every directory depth.
        severity_threshold: Minimum severity level to include in the report.
        confidence_threshold: Minimum confidence score [0.0, 1.0] for a finding to be reported.
        should_follow_symlinks: Must remain False — symlink traversal is prohibited.
            config.py raises ConfigurationError if this is set to True.
        max_file_size_mb: Files larger than this value in megabytes are skipped.
        include_extensions: If set, only files with a suffix in this list are scanned.
            None (default) scans all non-binary text files regardless of extension.
    """

    exclude_paths: list[str] = field(default_factory=list)
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    should_follow_symlinks: bool = False
    max_file_size_mb: int = MAX_FILE_SIZE_MB
    include_extensions: list[str] | None = None

    def __post_init__(self) -> None:
        if not CONFIDENCE_SCORE_MINIMUM <= self.confidence_threshold <= CONFIDENCE_SCORE_MAXIMUM:
            raise ConfigurationError(
                f"confidence_threshold {self.confidence_threshold!r} is outside the valid range "
                f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
            )
