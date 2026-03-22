"""Named constants, enums, and remediation guidance for PhiScan."""

from enum import StrEnum

# ---------------------------------------------------------------------------
# File names
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_FILENAME = ".phi-scanner.yml"
DEFAULT_IGNORE_FILENAME = ".phi-scanignore"

# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------

# TODO(2E.9): When archive inspection ships, remove .jar and .war from
# KNOWN_BINARY_EXTENSIONS so those files are passed to the archive inspector
# instead of being skipped as opaque binary. See PLAN.md Phase 2E.9.
KNOWN_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".gif",
        ".ico",
        ".wasm",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".zip",
        ".tar",
        ".gz",
        ".jar",
        ".war",
        ".pyc",
        ".pyo",
        ".o",
        ".a",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".wav",
        ".ttf",
        ".woff",
        ".woff2",
        ".eot",
    }
)

# Number of bytes read from a file to detect binary content via null bytes.
BINARY_CHECK_BYTE_COUNT = 8192

# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

# Default minimum confidence for a finding to be reported.
DEFAULT_CONFIDENCE_THRESHOLD = 0.6

# Confidence floor that separates HIGH severity from MEDIUM.
CONFIDENCE_HIGH_FLOOR = 0.90

# Confidence floor that separates MEDIUM severity from LOW.
CONFIDENCE_MEDIUM_FLOOR = 0.70

# Confidence floor that separates LOW severity from INFO.
# Findings below this value are logged as INFO and not flagged by default.
CONFIDENCE_LOW_FLOOR = 0.40

# ---------------------------------------------------------------------------
# Confidence ranges by detection layer (informational — used in docs/logging)
# ---------------------------------------------------------------------------

# Layer 1 — Regex: structured patterns are unambiguous.
CONFIDENCE_REGEX_MIN = 0.85
CONFIDENCE_REGEX_MAX = 1.0

# Layer 2 — NLP/NER: context-dependent, model uncertainty applies.
CONFIDENCE_NLP_MIN = 0.50
CONFIDENCE_NLP_MAX = 0.90

# Layer 3 — FHIR: schema-based structural match.
CONFIDENCE_FHIR_MIN = 0.80
CONFIDENCE_FHIR_MAX = 0.95

# Layer 4 — AI: adjusts existing scores as a second-opinion refinement.
CONFIDENCE_AI_ADJUSTMENT_MAX = 0.15

# ---------------------------------------------------------------------------
# File size limit
# ---------------------------------------------------------------------------

MAX_FILE_SIZE_MB = 10

# ---------------------------------------------------------------------------
# HIPAA audit retention
# ---------------------------------------------------------------------------

# HIPAA §164.530(j) requires audit log retention for a minimum of 6 years.
# 4×365 + 2×366 = 2192 days — the mathematical maximum for a 6-year span.
# Must match the audit_retention_days default in .phi-scanner.yml.
AUDIT_RETENTION_DAYS = 2192

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_CODE_CLEAN = 0
EXIT_CODE_VIOLATION = 1

# ---------------------------------------------------------------------------
# Database schema versions
# ---------------------------------------------------------------------------

# Increment when the audit SQLite schema changes; triggers migration logic.
SCHEMA_VERSION = 1

# Increment when the scan-cache SQLite schema changes; triggers migration logic.
CACHE_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OutputFormat(StrEnum):
    """Supported --output format values for the scan command."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"
    CSV = "csv"
    PDF = "pdf"
    HTML = "html"
    JUNIT = "junit"
    CODEQUALITY = "codequality"
    GITLAB_SAST = "gitlab-sast"


class SeverityLevel(StrEnum):
    """Severity level assigned to a ScanFinding based on confidence score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskLevel(StrEnum):
    """Overall risk level for a completed ScanResult."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    CLEAN = "clean"


# ---------------------------------------------------------------------------
# HIPAA remediation guidance
# ---------------------------------------------------------------------------

HIPAA_REMEDIATION_GUIDANCE: dict[str, str] = {
    "NAME": (
        "Remove or replace the patient name with a synthetic placeholder. "
        "Use faker-generated names in test fixtures. Never commit real patient names."
    ),
    "GEOGRAPHIC": (
        "Replace geographic data smaller than state level with a placeholder. "
        "State abbreviations are generally safe; zip codes and street addresses are not."
    ),
    "DATE": (
        "Replace dates more specific than year with a synthetic date. "
        "Year-only values are acceptable under the Safe Harbor method."
    ),
    "PHONE": (
        "Replace phone numbers with a synthetic value such as (555) 000-0001. "
        "All area codes in the 555 range are reserved and safe for testing."
    ),
    "FAX": (
        "Replace fax numbers with a synthetic value. "
        "Treat fax numbers with the same care as phone numbers."
    ),
    "EMAIL": (
        "Replace email addresses with a synthetic address such as patient@example.com. "
        "The example.com domain is reserved and will never reach a real recipient."
    ),
    "SSN": (
        "Remove Social Security Numbers immediately. Use the format 000-00-0000 "
        "or a faker-generated SSN for test data. Never commit real SSNs."
    ),
    "MRN": (
        "Replace Medical Record Numbers with a synthetic identifier. "
        "Use a prefix such as TEST- to make synthetic MRNs self-evident."
    ),
    "HEALTH_PLAN": (
        "Replace health plan beneficiary numbers with synthetic values. "
        "These identifiers link directly to insurance records and must be protected."
    ),
    "ACCOUNT": (
        "Replace account numbers with synthetic values. "
        "Use a test-prefix convention so synthetic accounts are identifiable."
    ),
    "CERTIFICATE": (
        "Replace certificate and license numbers with synthetic values. "
        "These identifiers can be used to impersonate licensed practitioners."
    ),
    "VEHICLE": (
        "Replace vehicle identifiers and serial numbers with synthetic values. "
        "VINs are linkable to registered owners via public databases."
    ),
    "DEVICE": (
        "Replace device identifiers and serial numbers with synthetic values. "
        "Device IDs can be linked back to individual patients via medical records."
    ),
    "URL": (
        "Review URLs containing path segments that encode patient identifiers. "
        "Replace patient-specific URL components with synthetic values."
    ),
    "IP": (
        "Replace IP addresses that could identify individual patients with "
        "documentation-range addresses such as 192.0.2.x (RFC 5737 TEST-NET-1)."
    ),
    "BIOMETRIC": (
        "Remove biometric identifiers entirely. These cannot be changed if exposed "
        "and represent a permanent privacy risk."
    ),
    "PHOTO": (
        "Remove full-face photographs and comparable images. "
        "Do not commit patient photos to version control under any circumstances."
    ),
    "UNIQUE_ID": (
        "Replace unique identifying numbers with synthetic values. "
        "Any number that uniquely identifies a person is a HIPAA identifier."
    ),
}
