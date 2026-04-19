"""Aggregation logic: group findings by line, deduplicate remediations, rank actions."""

from __future__ import annotations

from pathlib import Path

from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
    SEVERITY_RANK,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding
from phi_scan.report.v2.models import FileAggregate, LineAggregate, RemediationAction

_TOP_ACTIONS_COUNT: int = 5
_HOTSPOT_CATEGORY_THRESHOLD: int = 2
_QUASI_COMBO_THRESHOLD: int = 5
_HINT_TRUNCATION_LENGTH: int = 60
_COLLAPSED_INFILL: str = " … "

_ACTION_TITLE_MAP: dict[PhiCategory, str] = {
    PhiCategory.SSN: "Remove Social Security Numbers",
    PhiCategory.NAME: "Remove or fake patient names",
    PhiCategory.DATE: "Replace full dates with year only",
    PhiCategory.PHONE: "Replace phone numbers with synthetic values",
    PhiCategory.FAX: "Replace fax numbers with synthetic values",
    PhiCategory.EMAIL: "Fake email addresses",
    PhiCategory.MRN: "Replace Medical Record Numbers",
    PhiCategory.HEALTH_PLAN: "Synthesize health-plan numbers",
    PhiCategory.ACCOUNT: "Replace account numbers with synthetic values",
    PhiCategory.CERTIFICATE: "Replace certificate/license numbers",
    PhiCategory.GEOGRAPHIC: "Truncate geographic data to state or 3-digit ZIP",
    PhiCategory.IP: "Scrub IPv4 addresses from logs",
    PhiCategory.URL: "Review URLs with patient-identifying paths",
    PhiCategory.VEHICLE: "Replace vehicle identifiers",
    PhiCategory.DEVICE: "Replace device identifiers",
    PhiCategory.BIOMETRIC: "Remove biometric identifiers",
    PhiCategory.PHOTO: "Remove full-face photographs",
    PhiCategory.UNIQUE_ID: "Replace unique identifying numbers",
    PhiCategory.SUBSTANCE_USE_DISORDER: "Remove Substance Use Disorder records",
    PhiCategory.QUASI_IDENTIFIER_COMBINATION: "Break up quasi-identifier combinations",
}


def _highest_severity(findings: tuple[ScanFinding, ...] | list[ScanFinding]) -> SeverityLevel:
    """Return the highest severity level from a collection of findings."""
    best = SeverityLevel.INFO
    best_rank = SEVERITY_RANK[best]
    for finding in findings:
        rank = SEVERITY_RANK[finding.severity]
        if rank > best_rank:
            best = finding.severity
            best_rank = rank
    return best


def _build_category_counts(findings: tuple[ScanFinding, ...]) -> dict[str, int]:
    """Count occurrences of each entity_type on a line."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.entity_type] = counts.get(finding.entity_type, 0) + 1
    return counts


def _combine_remediation_hints(findings: tuple[ScanFinding, ...]) -> str:
    """Join unique remediation hints with semicolons."""
    seen: list[str] = []
    for finding in findings:
        if finding.remediation_hint and finding.remediation_hint not in seen:
            seen.append(finding.remediation_hint)
    return "; ".join(seen)


def _split_context(context: str) -> tuple[str, str] | None:
    """Split a code_context into (prefix, suffix) around the [REDACTED] marker."""
    marker = CODE_CONTEXT_REDACTED_VALUE
    marker_position = context.find(marker)
    if marker_position == -1:
        return None
    prefix = context[:marker_position]
    suffix = context[marker_position + len(marker) :]
    return (prefix, suffix)


def _build_merged_display_context(findings: tuple[ScanFinding, ...]) -> str:
    """Build a preview that redacts every finding's span on the line.

    Each ``code_context`` is the source line with one match span replaced by
    [REDACTED]; its prefix and suffix therefore contain raw source text,
    including any OTHER findings' raw values. Using a single finding's
    context would leak those other spans.

    To stay invariant-safe without re-reading disk, we pick the finding with
    the shortest prefix (earliest span) — its prefix contains no other
    finding's span — and the finding with the shortest suffix (latest
    span) — same property for the suffix — and join them around a
    collapsed ``[REDACTED] … [REDACTED]`` middle. We lose in-between
    context, but never leak raw PHI.
    """
    first_context = findings[0].code_context
    if len(findings) == 1:
        return first_context

    split_parts: list[tuple[str, str]] = []
    for finding in findings:
        parts = _split_context(finding.code_context)
        if parts is None:
            return first_context
        split_parts.append(parts)

    earliest_prefix = min(split_parts, key=lambda pair: len(pair[0]))[0]
    latest_suffix = min(split_parts, key=lambda pair: len(pair[1]))[1]

    distinct_spans = {(prefix, suffix) for prefix, suffix in split_parts}
    if len(distinct_spans) == 1:
        return first_context

    marker = CODE_CONTEXT_REDACTED_VALUE
    return f"{earliest_prefix}{marker}{_COLLAPSED_INFILL}{marker}{latest_suffix}"


def group_by_line(findings: tuple[ScanFinding, ...]) -> list[LineAggregate]:
    """Group findings by (file_path, line_number) into LineAgggregates."""
    buckets: dict[tuple[Path, int], list[ScanFinding]] = {}
    for finding in findings:
        key = (finding.file_path, finding.line_number)
        if key not in buckets:
            buckets[key] = []
        buckets[key].append(finding)

    aggregates: list[LineAggregate] = []
    for (file_path, line_number), line_findings in buckets.items():
        frozen_findings = tuple(line_findings)
        aggregates.append(
            LineAggregate(
                file_path=file_path,
                line_number=line_number,
                findings=frozen_findings,
                highest_severity=_highest_severity(line_findings),
                category_counts=_build_category_counts(frozen_findings),
                display_context=_build_merged_display_context(frozen_findings),
                combined_fix=_combine_remediation_hints(frozen_findings),
            )
        )
    return aggregates


def group_by_file(line_aggregates: list[LineAggregate]) -> list[FileAggregate]:
    """Group line aggregates by file, sorting lines within each file."""
    file_buckets: dict[Path, list[LineAggregate]] = {}
    for line_agg in line_aggregates:
        if line_agg.file_path not in file_buckets:
            file_buckets[line_agg.file_path] = []
        file_buckets[line_agg.file_path].append(line_agg)

    file_aggregates: list[FileAggregate] = []
    for file_path, lines in sorted(file_buckets.items()):
        sorted_lines = sorted(
            lines,
            key=lambda la: (-la.severity_rank, -la.finding_count, la.line_number),
        )
        file_findings = [f for la in sorted_lines for f in la.findings]
        file_aggregates.append(
            FileAggregate(
                file_path=file_path,
                line_aggregates=tuple(sorted_lines),
                total_finding_count=sum(la.finding_count for la in sorted_lines),
                highest_severity=_highest_severity(file_findings),
            )
        )
    return file_aggregates


def dedupe_remediations(findings: tuple[ScanFinding, ...]) -> list[RemediationAction]:
    """Group findings by HIPAA category into deduplicated RemediationActions.

    Keying by hipaa_category (rather than the raw hint string) collapses
    per-invocation variations — e.g., QUASI_IDENTIFIER_COMBINATION emits a
    differently worded hint for each combination it sees, but the action
    ("Break up the combination") is the same and belongs on one card.
    """
    buckets: dict[PhiCategory, list[ScanFinding]] = {}
    for finding in findings:
        if not finding.remediation_hint:
            continue
        category = finding.hipaa_category
        if category not in buckets:
            buckets[category] = []
        buckets[category].append(finding)

    actions: list[RemediationAction] = []
    for category, grouped_findings in buckets.items():
        highest_sev = _highest_severity(grouped_findings)
        mean_confidence = sum(f.confidence for f in grouped_findings) / len(grouped_findings)
        affected: list[tuple[Path, int]] = []
        seen_lines: set[tuple[Path, int]] = set()
        for finding in grouped_findings:
            key = (finding.file_path, finding.line_number)
            if key not in seen_lines:
                seen_lines.add(key)
                affected.append(key)
        affected.sort(key=lambda pair: (pair[0], pair[1]))
        representative_hint = max((f.remediation_hint for f in grouped_findings), key=len)
        title = _ACTION_TITLE_MAP.get(category, representative_hint[:_HINT_TRUNCATION_LENGTH])

        actions.append(
            RemediationAction(
                remediation_hint=representative_hint,
                title=title,
                hipaa_category=category,
                finding_count=len(grouped_findings),
                highest_severity=highest_sev,
                mean_confidence=mean_confidence,
                affected_lines=tuple(affected),
                severity_weight_score=SEVERITY_RANK[highest_sev] * len(grouped_findings),
            )
        )

    actions.sort(key=lambda a: (-a.severity_rank, -a.finding_count))
    return actions


def rank_top_actions(
    actions: list[RemediationAction],
) -> list[RemediationAction]:
    """Return the top N actions ranked by severity_weight_score descending."""
    ranked = sorted(actions, key=lambda a: (-a.severity_weight_score, -a.severity_rank))
    return ranked[:_TOP_ACTIONS_COUNT]


def compute_hotspot_count(line_aggregates: list[LineAggregate]) -> int:
    """Count lines with 2 or more distinct PHI categories."""
    return sum(
        1 for la in line_aggregates if len(la.category_counts) >= _HOTSPOT_CATEGORY_THRESHOLD
    )


def compute_category_severity_distribution(
    findings: tuple[ScanFinding, ...],
) -> dict[str, dict[SeverityLevel, int]]:
    """Build per-category severity distribution for the category breakdown bars."""
    distribution: dict[str, dict[SeverityLevel, int]] = {}
    for finding in findings:
        category_name = finding.hipaa_category.value
        if category_name not in distribution:
            distribution[category_name] = {}
        sev_counts = distribution[category_name]
        sev_counts[finding.severity] = sev_counts.get(finding.severity, 0) + 1
    return distribution


def build_line_title(line_aggregate: LineAggregate) -> str:
    """Build a human-readable title for a line aggregate."""
    categories = list(line_aggregate.category_counts.keys())

    if len(categories) >= _QUASI_COMBO_THRESHOLD:
        return f"Quasi-identifier cluster  ({len(categories)} categories co-located)"

    has_date = any("DATE" in c for c in categories)
    has_zip = any("ZIP" in c or "GEOGRAPHIC" in c for c in categories)
    has_age = any("AGE" in c for c in categories)
    has_ssn = any("SSN" in c for c in categories)

    if has_date and has_zip and has_age:
        return "DOB + ZIP + age-over-90  (Sweeney re-id risk)"
    if has_date and has_zip:
        return "DOB + ZIP  (quasi-identifier risk)"
    if has_ssn:
        return "Social Security Number"

    readable_names: list[str] = []
    for category in categories:
        name = category.lower().replace("_", " ")
        readable_names.append(name)

    combined = " + ".join(readable_names[:3])
    if len(readable_names) > 3:
        combined += f" +{len(readable_names) - 3} more"
    return combined.title()
