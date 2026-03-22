"""Tests for phi_scan.exceptions — custom exception hierarchy."""

from phi_scan.exceptions import (
    AuditLogError,
    ConfigurationError,
    PhiScanError,
    SchemaMigrationError,
    TraversalError,
)


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
    error_message = "path '/tmp/missing' does not exist or is not readable"

    raised_error = TraversalError(error_message)

    assert str(raised_error) == error_message


def test_audit_log_error_preserves_message() -> None:
    error_message = "cannot write to audit log at '/var/phi-scanner/audit.db': permission denied"

    raised_error = AuditLogError(error_message)

    assert str(raised_error) == error_message


def test_schema_migration_error_preserves_message() -> None:
    error_message = "cannot migrate schema from version 1 to version 3: version 2 migration missing"

    raised_error = SchemaMigrationError(error_message)

    assert str(raised_error) == error_message


def test_phi_scan_error_is_catchable_as_exception() -> None:
    with_message = "base catch test"

    try:
        raise PhiScanError(with_message)
    except Exception as caught_error:
        assert str(caught_error) == with_message


def test_subclass_errors_are_catchable_as_phi_scan_error() -> None:
    # All subclasses must be catchable at the PhiScanError level so callers
    # can handle any domain error with a single except clause.
    subclasses = [ConfigurationError, TraversalError, AuditLogError, SchemaMigrationError]

    for subclass in subclasses:
        try:
            raise subclass("test")
        except PhiScanError:
            pass
        else:
            raise AssertionError(f"{subclass.__name__} was not caught as PhiScanError")
