"""Shared pytest fixtures for PhiScan test suite."""

from pathlib import Path

import pytest


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal temporary project directory for scan tests."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    sample_file = source_dir / "example.py"
    sample_file.write_text('greeting = "hello world"\n')
    return tmp_path
