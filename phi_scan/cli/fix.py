"""`phi-scan fix` command — PHI replacement with synthetic data."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from phi_scan.constants import EXIT_CODE_ERROR
from phi_scan.exceptions import MissingOptionalDependencyError
from phi_scan.fixer import (
    FixMode,
    FixReplacement,
    FixResult,
    apply_approved_replacements,
    collect_file_replacements,
    fix_file,
)
from phi_scan.output import get_console

_FIX_PATH_HELP: str = "File or directory to fix. Scans recursively when a directory is given."
_FIX_DRY_RUN_HELP: str = "Preview replacements as a unified diff without modifying files."
_FIX_APPLY_HELP: str = "Apply replacements in place after confirmation."
_FIX_PATCH_HELP: str = "Write a .patch file for each modified file instead of editing in place."
_FIX_INTERACTIVE_HELP: str = "Prompt for each replacement: Replace? [y/n/a(ll)/s(kip file)]"
_FIX_NO_MODE_ERROR: str = "Specify exactly one mode: --dry-run, --apply, --patch, or --interactive."
_FIX_MULTI_MODE_ERROR: str = (
    "Only one of --dry-run, --apply, --patch, or --interactive may be given at a time."
)
_FIX_NO_FINDINGS_MESSAGE: str = "No PHI found in {path} — nothing to fix."
_FIX_PATCH_WRITTEN_MESSAGE: str = "Patch written: {path}"
_FIX_APPLIED_MESSAGE: str = "Applied {count} replacement(s) to {path}."
_FIX_SKIPPED_DRY_RUN_MESSAGE: str = "(dry-run) {count} replacement(s) found in {path}."
_FIX_INTERACTIVE_PROMPT: str = "[{index}/{total}] {path}:{line} — {category} — Replace? [y/n/a/s]: "
_FIX_INTERACTIVE_APPLY_ALL: str = "a"
_FIX_INTERACTIVE_SKIP_FILE: str = "s"
_FIX_INTERACTIVE_YES: str = "y"
_FIX_INTERACTIVE_NO: str = "n"
_FIX_FAKER_MISSING_MESSAGE: str = (
    "faker is required for `phi-scan fix`. Install it with: pip install phi-scan[dev]"
)
_FIX_RGLOB_PATTERN: str = "*"
_FIX_ENUMERATE_START: int = 1


def _collect_target_files(path: Path) -> list[Path]:
    """Return scannable files under path (recursive) or [path] when path is a file."""
    if path.is_file() and not path.is_symlink():
        return [path]
    return [
        candidate
        for candidate in path.rglob(_FIX_RGLOB_PATTERN)
        if candidate.is_file() and not candidate.is_symlink()
    ]


def _print_fix_result(fix_result: FixResult, mode: FixMode) -> None:
    """Print a human-readable summary of a fix operation for one file."""
    console = get_console()
    file_path = fix_result.file_path
    count = len(fix_result.replacements_applied)
    if count == 0:
        console.print(_FIX_NO_FINDINGS_MESSAGE.format(path=file_path))
        return
    if mode == FixMode.DRY_RUN:
        console.print(fix_result.unified_diff)
        console.print(_FIX_SKIPPED_DRY_RUN_MESSAGE.format(count=count, path=file_path))
    elif mode == FixMode.APPLY:
        console.print(_FIX_APPLIED_MESSAGE.format(count=count, path=file_path))
    elif mode == FixMode.PATCH and fix_result.patch_path is not None:
        console.print(_FIX_PATCH_WRITTEN_MESSAGE.format(path=fix_result.patch_path))


def _run_interactive_fix(file_path: Path) -> None:
    """Prompt the user for each replacement in file_path and apply approved ones."""
    console = get_console()
    try:
        replacements = collect_file_replacements(file_path)
    except MissingOptionalDependencyError:
        typer.echo(_FIX_FAKER_MISSING_MESSAGE, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from None
    if not replacements:
        console.print(_FIX_NO_FINDINGS_MESSAGE.format(path=file_path))
        return
    approved: list[FixReplacement] = []
    total = len(replacements)
    for index, replacement in enumerate(replacements, start=_FIX_ENUMERATE_START):
        prompt = _FIX_INTERACTIVE_PROMPT.format(
            index=index,
            total=total,
            path=file_path,
            line=replacement.line_number,
            category=replacement.hipaa_category,
        )
        raw_answer = typer.prompt(prompt, default=_FIX_INTERACTIVE_NO).strip().lower()
        if raw_answer == _FIX_INTERACTIVE_APPLY_ALL:
            approved.extend(replacements[index - _FIX_ENUMERATE_START :])
            break
        if raw_answer == _FIX_INTERACTIVE_SKIP_FILE:
            return
        if raw_answer == _FIX_INTERACTIVE_YES:
            approved.append(replacement)
    if approved:
        fix_result = apply_approved_replacements(file_path, approved)
        console.print(
            _FIX_APPLIED_MESSAGE.format(count=len(fix_result.replacements_applied), path=file_path)
        )


def fix_command(
    path: Annotated[Path, typer.Argument(help=_FIX_PATH_HELP)] = Path("."),
    dry_run: Annotated[bool, typer.Option("--dry-run", help=_FIX_DRY_RUN_HELP)] = False,
    apply: Annotated[bool, typer.Option("--apply", help=_FIX_APPLY_HELP)] = False,
    patch: Annotated[bool, typer.Option("--patch", help=_FIX_PATCH_HELP)] = False,
    interactive: Annotated[bool, typer.Option("--interactive", help=_FIX_INTERACTIVE_HELP)] = False,
) -> None:
    """Replace detected PHI with synthetic data (dry-run, apply, patch, or interactive)."""
    selected_modes = [dry_run, apply, patch, interactive]
    mode_count = sum(selected_modes)
    if mode_count == 0:
        typer.echo(_FIX_NO_MODE_ERROR, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    if mode_count > 1:
        typer.echo(_FIX_MULTI_MODE_ERROR, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    target_files = _collect_target_files(path)
    if interactive:
        for target_file in target_files:
            _run_interactive_fix(target_file)
        return
    if dry_run:
        fix_mode = FixMode.DRY_RUN
    elif apply:
        fix_mode = FixMode.APPLY
    else:
        fix_mode = FixMode.PATCH
    for target_file in target_files:
        try:
            fix_result = fix_file(target_file, fix_mode)
        except MissingOptionalDependencyError:
            typer.echo(_FIX_FAKER_MISSING_MESSAGE, err=True)
            raise typer.Exit(code=EXIT_CODE_ERROR) from None
        _print_fix_result(fix_result, fix_mode)
