"""Git pre-commit hook and first-run setup commands."""

from __future__ import annotations

from pathlib import Path

import typer

from phi_scan.cli._shared import (
    _reject_hook_path_with_symlinked_component,
    _reject_missing_git_directory,
)
from phi_scan.constants import DEFAULT_TEXT_ENCODING

_PRE_COMMIT_HOOK_PATH: str = ".git/hooks/pre-commit"
_HOOK_INSTALLED_MESSAGE: str = "Pre-commit hook installed: {path}"
_HOOK_ALREADY_EXISTS_MESSAGE: str = (
    "Pre-commit hook already exists at {path} — not overwriting. "
    "Remove it manually or run `phi-scan uninstall-hook` first."
)
_HOOK_REMOVED_MESSAGE: str = "Pre-commit hook removed: {path}"
_HOOK_NOT_FOUND_MESSAGE: str = "No phi-scan hook found at {path}."
_HOOK_NOT_OURS_MESSAGE: str = "Hook at {path} was not installed by phi-scan — not removing."
_HOOK_IS_SYMLINK_MESSAGE: str = "Hook at {path} is a symlink — not reading or removing."
# Marker written into every hook we install; used to identify our hooks on uninstall.
_HOOK_MARKER: str = "phi-scan scan"
_HOOK_FILE_PERMISSIONS: int = 0o755
_HOOK_SCRIPT_CONTENT: str = (
    "#!/bin/sh\n"
    "# phi-scan pre-commit hook — installed by phi-scan install-hook\n"
    "phi-scan scan --diff HEAD --quiet\n"
    "if [ $? -ne 0 ]; then\n"
    "  echo 'phi-scan: PHI/PII detected — commit blocked'\n"
    "  exit 1\n"
    "fi\n"
)

_INIT_STUB_MESSAGE: str = (
    "phi-scan init: full guided setup wizard is coming in Phase 3. "
    "Run `phi-scan config init` to generate a config file now."
)
_SETUP_STUB_MESSAGE: str = (
    "phi-scan setup downloads spaCy NLP models. "
    "Run `pip install phi-scan[nlp]` first, then re-run (available from Phase 2)."
)


def install_hook() -> None:
    """Install phi-scan as a git pre-commit hook."""
    hook_path = Path(_PRE_COMMIT_HOOK_PATH)
    _reject_missing_git_directory()
    if hook_path.exists() or hook_path.is_symlink():
        typer.echo(_HOOK_ALREADY_EXISTS_MESSAGE.format(path=hook_path))
        return
    _reject_hook_path_with_symlinked_component(hook_path)
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_HOOK_SCRIPT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    hook_path.chmod(_HOOK_FILE_PERMISSIONS)
    typer.echo(_HOOK_INSTALLED_MESSAGE.format(path=hook_path))


def uninstall_hook() -> None:
    """Remove the phi-scan git pre-commit hook."""
    hook_path = Path(_PRE_COMMIT_HOOK_PATH)
    _reject_missing_git_directory()
    if not hook_path.exists():
        typer.echo(_HOOK_NOT_FOUND_MESSAGE.format(path=hook_path))
        return
    if hook_path.is_symlink():
        typer.echo(_HOOK_IS_SYMLINK_MESSAGE.format(path=hook_path))
        return
    hook_content = hook_path.read_text(encoding=DEFAULT_TEXT_ENCODING)
    if _HOOK_MARKER not in hook_content:
        typer.echo(_HOOK_NOT_OURS_MESSAGE.format(path=hook_path))
        return
    hook_path.unlink()
    typer.echo(_HOOK_REMOVED_MESSAGE.format(path=hook_path))


def initialize_project() -> None:
    """Guided first-run wizard: config, ignore file, hook, model download."""
    typer.echo(_INIT_STUB_MESSAGE)


def download_models() -> None:
    """Download spaCy NLP models and verify optional dependencies."""
    typer.echo(_SETUP_STUB_MESSAGE)
