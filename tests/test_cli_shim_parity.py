"""Parity tests for top-level ``phi_scan.cli_*`` compatibility shims.

These shims preserve the historical import paths that predate the
``phi_scan.cli`` package. Each shim is a star-import re-export of its
canonical counterpart under ``phi_scan.cli.<name>``. This matrix pins
that contract in one place so per-file drift cannot accumulate.

Shim removal target: **v2.0** (see ``CHANGELOG.md`` and
``docs/lts-eol-policy.md``).
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

_SHIM_TO_CANONICAL: dict[str, str] = {
    "phi_scan.cli_baseline": "phi_scan.cli.baseline",
    "phi_scan.cli_config": "phi_scan.cli.config",
    "phi_scan.cli_explain": "phi_scan.cli.explain",
    "phi_scan.cli_plugins": "phi_scan.cli.plugins",
    "phi_scan.cli_report": "phi_scan.cli.report",
    "phi_scan.cli_scan_config": "phi_scan.cli.scan_config",
    "phi_scan.cli_watch": "phi_scan.cli.watch",
}

_SHIM_DOCSTRING_MARKER: str = "Compatibility shim"
_MINIMUM_EXPORTED_NAMES: int = 1


@pytest.fixture(
    params=list(_SHIM_TO_CANONICAL.items()),
    ids=list(_SHIM_TO_CANONICAL),
)
def load_shim_and_canonical_modules(
    request: pytest.FixtureRequest,
) -> tuple[ModuleType, ModuleType]:
    shim_path, canonical_path = request.param
    return importlib.import_module(shim_path), importlib.import_module(canonical_path)


def test_shim_module_loads_without_error(
    load_shim_and_canonical_modules: tuple[ModuleType, ModuleType],
) -> None:
    shim, _canonical = load_shim_and_canonical_modules
    assert shim is not None


def test_shim_exports_non_empty_public_names(
    load_shim_and_canonical_modules: tuple[ModuleType, ModuleType],
) -> None:
    shim, _canonical = load_shim_and_canonical_modules
    assert hasattr(shim, "__all__")
    assert len(shim.__all__) >= _MINIMUM_EXPORTED_NAMES


def test_shim_docstring_marks_compatibility(
    load_shim_and_canonical_modules: tuple[ModuleType, ModuleType],
) -> None:
    shim, _canonical = load_shim_and_canonical_modules
    assert shim.__doc__ is not None
    assert _SHIM_DOCSTRING_MARKER in shim.__doc__


def test_shim_resolves_names_identical_to_canonical(
    load_shim_and_canonical_modules: tuple[ModuleType, ModuleType],
) -> None:
    shim, canonical = load_shim_and_canonical_modules
    for exported_name in shim.__all__:
        assert hasattr(canonical, exported_name), (
            f"canonical module missing attribute {exported_name!r}"
        )
        assert getattr(shim, exported_name) is getattr(canonical, exported_name), (
            f"{exported_name!r} on shim is not the same object as on canonical module"
        )
