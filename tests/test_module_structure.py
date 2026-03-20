"""Tests verifying all phi_scan module files are importable."""

import importlib

import phi_scan

PHASE_ONE_MODULES = [
    "phi_scan.constants",
    "phi_scan.exceptions",
    "phi_scan.models",
    "phi_scan.logging_config",
    "phi_scan.config",
    "phi_scan.scanner",
    "phi_scan.diff",
    "phi_scan.output",
    "phi_scan.audit",
    "phi_scan.cli",
]

FUTURE_PHASE_MODULES = [
    "phi_scan.suppression",
    "phi_scan.cache",
    "phi_scan.help_text",
    "phi_scan.fhir_recognizer",
    "phi_scan.fixer",
    "phi_scan.baseline",
    "phi_scan.notifier",
    "phi_scan.compliance",
    "phi_scan.report",
    "phi_scan.plugin_api",
]


def test_all_phase_one_modules_are_importable() -> None:
    """Every Phase 1 module must import without error."""
    for module_name in PHASE_ONE_MODULES:
        module = importlib.import_module(module_name)
        assert module is not None, f"{module_name} failed to import"


def test_all_future_phase_modules_are_importable() -> None:
    """Every future-phase stub module must import without error."""
    for module_name in FUTURE_PHASE_MODULES:
        module = importlib.import_module(module_name)
        assert module is not None, f"{module_name} failed to import"


def test_cli_app_is_typer_instance() -> None:
    """The CLI entry point must be a Typer app instance."""
    import typer

    from phi_scan.cli import app

    assert isinstance(app, typer.Typer)


def test_package_version_matches_pyproject() -> None:
    """Package version must stay consistent with pyproject.toml."""
    assert phi_scan.__version__ == "0.1.0"


def test_package_app_name_is_defined() -> None:
    """Package app name must be the CLI command name."""
    assert phi_scan.__app_name__ == "phi-scan"
