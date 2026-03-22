"""Tests for phi_scan.exceptions — custom exception hierarchy."""

from phi_scan.exceptions import (
    AuditLogError,
    ConfigurationError,
    PhiScanError,
    SchemaMigrationError,
    TraversalError,
)

_MISSING_PATH: str = "/tmp/missing"
_AUDIT_DB_PATH: str = "/var/phi-scanner/audit.db"


def test_phi_scan_error_is_exception_subclass() -> None:
    assert issubclass(PhiScanError, Exception)


def test_configuration_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(ConfigurationError, PhiScanError)


def test_traversal_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(TraversalError, PhiScanError)


def test_audit_log_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(AuditLogError, PhiScanError)


def test_schema_migration_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(SchemaMigrationError, PhiScanError)


def test_phi_scan_error_preserves_message() -> None:
    error_message = "something went wrong"

    raised_error = PhiScanError(error_message)

    assert str(raised_error) == error_message


def test_configuration_error_preserves_message() -> None:
    error_message = "invalid value 'foo' for key 'output_format': expected one of table, json"

    raised_error = ConfigurationError(error_message)

    assert str(raised_error) == error_message


def test_traversal_error_preserves_message() -> None:
    error_message = f"path '{_MISSING_PATH}' does not exist or is not readable"

    raised_error = TraversalError(error_message)

    assert str(raised_error) == error_message


def test_audit_log_error_preserves_message() -> None:
    error_message = f"cannot write to audit log at '{_AUDIT_DB_PATH}': permission denied"

    raised_error = AuditLogError(error_message)

    assert str(raised_error) == error_message


def test_schema_migration_error_preserves_message() -> None:
    error_message = "cannot migrate schema from version 1 to version 3: version 2 migration missing"

    raised_error = SchemaMigrationError(error_message)

    assert str(raised_error) == error_message


def test_phi_scan_error_is_catchable_as_exception() -> None:
    error_message = "base catch test"

    try:
        raise PhiScanError(error_message)
    except Exception as caught_error:
        assert str(caught_error) == error_message


def test_configuration_error_is_catchable_as_phi_scan_error() -> None:
    raised_error = ConfigurationError("test")

    try:
        raise raised_error
    except PhiScanError as caught_error:
        assert isinstance(caught_error, ConfigurationError)


def test_traversal_error_is_catchable_as_phi_scan_error() -> None:
    raised_error = TraversalError("test")

    try:
        raise raised_error
    except PhiScanError as caught_error:
        assert isinstance(caught_error, TraversalError)


def test_audit_log_error_is_catchable_as_phi_scan_error() -> None:
    raised_error = AuditLogError("test")

    try:
        raise raised_error
    except PhiScanError as caught_error:
        assert isinstance(caught_error, AuditLogError)


def test_schema_migration_error_is_catchable_as_phi_scan_error() -> None:
    raised_error = SchemaMigrationError("test")

    try:
        raise raised_error
    except PhiScanError as caught_error:
        assert isinstance(caught_error, SchemaMigrationError)
