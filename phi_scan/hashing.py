"""Shared PHI detection utilities: value hashing, severity scoring, and finding construction.

All three functions are used by every detection layer (regex, NLP, FHIR, HL7) to
build ``ScanFinding`` objects. Centralising them here ensures the HIPAA-critical
hash function has a single implementation, severity bands stay consistent across
all layers, and the structured-finding construction pattern (hash + severity +
remediation lookup) cannot diverge between FHIR and HL7.

This module is an intentional exception to the "no premature abstraction"
rule — the identical functions existed verbatim in four detection modules
(regex_detector, nlp_detector, fhir_recognizer, hl7_scanner) before being
extracted here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    HIPAA_REMEDIATION_GUIDANCE,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding

__all__ = ["build_structured_finding", "compute_value_hash", "severity_from_confidence"]


def compute_value_hash(text: str) -> str:
    """Return the SHA-256 hex digest of text.

    Raw PHI values are never stored — only their hashes (HIPAA audit
    requirement). The hash is computed over the UTF-8 encoding of the text.

    Args:
        text: The raw matched PHI value.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def reject_out_of_range_confidence(confidence: float) -> None:
    """Raise ValueError when confidence is outside the valid [0.0, 1.0] range.

    Args:
        confidence: The confidence score to validate.

    Raises:
        ValueError: If confidence is not in [CONFIDENCE_SCORE_MINIMUM, CONFIDENCE_SCORE_MAXIMUM].
    """
    if confidence < CONFIDENCE_SCORE_MINIMUM or confidence > CONFIDENCE_SCORE_MAXIMUM:
        raise ValueError(
            f"confidence {confidence!r} is outside the valid range "
            f"[{CONFIDENCE_SCORE_MINIMUM}, {CONFIDENCE_SCORE_MAXIMUM}]"
        )


def severity_from_confidence(confidence: float) -> SeverityLevel:
    """Derive SeverityLevel from a confidence score.

    Args:
        confidence: Score in [CONFIDENCE_SCORE_MINIMUM, CONFIDENCE_SCORE_MAXIMUM].

    Returns:
        SeverityLevel for the given confidence band.

    Raises:
        ValueError: If confidence is outside [0.0, 1.0].
    """
    reject_out_of_range_confidence(confidence)
    if confidence >= CONFIDENCE_HIGH_FLOOR:
        return SeverityLevel.HIGH
    if confidence >= CONFIDENCE_MEDIUM_FLOOR:
        return SeverityLevel.MEDIUM
    if confidence >= CONFIDENCE_LOW_FLOOR:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def build_structured_finding(
    file_path: Path,
    line_number: int,
    entity_type: str,
    hipaa_category: PhiCategory,
    confidence: float,
    detection_layer: DetectionLayer,
    raw_value: str,
    code_context: str,
) -> ScanFinding:
    """Construct a ScanFinding for structured detectors (FHIR, HL7).

    Centralises the hash + severity + remediation-hint derivation that both
    FHIR and HL7 layers perform identically. Callers supply only the
    layer-specific inputs; this function ensures the HIPAA-critical operations
    cannot diverge between layers.

    Args:
        file_path: Source path recorded in the finding for reporting.
        line_number: 1-based line number of the match.
        entity_type: Human-readable entity label (e.g. field name or category value).
        hipaa_category: HIPAA category for this finding.
        confidence: Base confidence score for this detection layer.
        detection_layer: Which structured layer produced the finding.
        raw_value: The raw matched PHI value — hashed immediately, never stored.
        code_context: Pre-redacted source context string (must contain [REDACTED]).

    Returns:
        Immutable ScanFinding with value_hash, severity, and remediation_hint
        derived from the inputs.
    """
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=hipaa_category,
        confidence=confidence,
        detection_layer=detection_layer,
        value_hash=compute_value_hash(raw_value),
        severity=severity_from_confidence(confidence),
        code_context=code_context,
        remediation_hint=HIPAA_REMEDIATION_GUIDANCE.get(hipaa_category, ""),
    )
