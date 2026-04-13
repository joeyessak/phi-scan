# `phi_scan/cli/__init__.py` — next-slice split plan

**Status:** PARTIALLY COMPLETED — 2026-04-12.
**Current module size:** ~826 lines (down from 1492 at the start of the
pass).

## Completed slices

- `_shared.py` — leaf helpers, option dataclasses, log-level map,
  progress-bar config, worker-count validation, hook path guards, version
  flag. (commit 103b159)
- `fix.py` — fix command, three helpers, and fix-specific constants.
  (commit 743a466)
- `hooks.py` — install-hook, uninstall-hook, init, setup commands and
  their hook-script / stub-message constants. (commit b80a0a6)
- `history.py` — history and report commands, scan-event display
  helpers, audit-event / audit-chain / history constants. (commit
  d94751c)
- `dashboard.py` — dashboard command, `_aggregate_category_totals`
  helper, eight `_DASHBOARD_*` constants. (commit 42060a1)

## Remaining slice

- `scan.py` — scan and watch commands, scan-progress helpers
  (sequential/parallel dispatch), audit persistence (`_write_audit_record`,
  `_persist_audit_record`, `_display_audit_phase_header`), notification
  dispatch (`_dispatch_notifications`), framework flag resolution
  (`_resolve_framework_flag`), phase preparation (`_prepare_scan_phase`),
  CI integration dispatch (`_run_ci_integration`, `_call_ci_integration`),
  and all scan-related constants.

Cleanup items to fold into the scan slice:

- Rename `_prepare_scan_phase` to a clear verb-noun pair
  (e.g. `_collect_scan_targets_for_phase`) — "phase" alone is vague.
- Move the orphaned `_SPINNER_NOTIFY_MESSAGE` and
  `_SPINNER_CONFIG_LOAD_MESSAGE` constants out of `__init__.py`; they are
  scan-command concerns.

The scan slice is the largest (~500 lines) and the most coupled — it
touches notification, audit, CI-integration, and rich/verbose UX surfaces
simultaneously. Extraction was deferred this pass to keep the
multi-slice PR bounded; it can be done mechanically in a dedicated
follow-up.

## Original plan (preserved for the remaining slice)

**Module size at start of pass:** 1492 lines.

The pristine-closure pass absorbed the seven satellite `cli_*.py` modules
into `phi_scan/cli/` and preserved import compatibility via top-level
shims. The large legacy body of `cli.py` now lives in `cli/__init__.py`
and is the next decomposition slice.

## Recommended split

```
phi_scan/cli/
    __init__.py          # thin dispatcher: construct app, register
                         # sub-apps, expose `app` for the pyproject entry
                         # point (pyproject.toml: phi-scan = "phi_scan.cli:app")
    _shared.py           # _ScanTargetOptions, _ScanPhaseOptions,
                         # _ScanExecutionOptions, _ProgressScanContext,
                         # _configure_logging, _load_combined_ignore_patterns,
                         # _resolve_scan_targets, _normalize_diff_path,
                         # _truncate_filename_for_progress,
                         # _validate_worker_count, _echo_version,
                         # _reject_hook_path_with_symlinked_component,
                         # _reject_missing_git_directory
    scan.py              # _run_sequential_scan_with_progress,
                         # _run_parallel_scan_with_progress,
                         # _run_scan_with_progress,
                         # _execute_scan_with_progress,
                         # _resolve_framework_flag, _prepare_scan_phase,
                         # _dispatch_notifications,
                         # _write_audit_record, _persist_audit_record,
                         # _display_audit_phase_header,
                         # _run_ci_integration, _call_ci_integration,
                         # @app.command("scan") → scan()
    fix.py               # _collect_target_files, _print_fix_result,
                         # _run_interactive_fix,
                         # @app.command("fix") → fix_command()
    history.py           # _parse_lookback_days, _display_scan_event_row,
                         # _display_scan_history,
                         # @app.command("history") → display_history(),
                         # @app.command("report") → display_last_scan()
    dashboard.py         # _aggregate_category_totals,
                         # @app.command("dashboard") → display_dashboard()
    hooks.py             # @app.command("install-hook") → install_hook(),
                         # @app.command("uninstall-hook") → uninstall_hook(),
                         # @app.command("init") → initialize_project(),
                         # @app.command("setup") → download_models()
```

## Extraction order (recommended)

1. `_shared.py` — leaf helpers with no Typer registrations. Zero risk.
2. `fix.py` — self-contained block already (three helpers + one command).
3. `hooks.py` — four trivial command registrations.
4. `history.py` — moderately coupled to scan-event rendering.
5. `dashboard.py` — one helper + one command.
6. `scan.py` — the largest and most coupled; do last once `_shared.py` is
   stable.

## Shim strategy

After each slice is extracted, the imported symbol must still be reachable
through `phi_scan.cli.<command_module>` **and** through the historical
`phi_scan.cli` surface (because existing tests import
`from phi_scan.cli import _normalize_diff_path`, etc.).

`phi_scan/cli/__init__.py` stays the canonical `app` object home; it
re-exports private helpers for test compatibility via explicit
`from phi_scan.cli._shared import _normalize_diff_path` + `__all__`
additions. Do not change test imports in this pass.

## Gates

- [ ] `uv run pytest tests/test_cli.py tests/test_cli_flags.py tests/test_cli_plugins.py` passes.
- [ ] `phi-scan --help` produces byte-identical output before/after.
- [ ] `pyproject.toml` entry point `phi_scan.cli:app` resolves.
- [ ] No test's golden output regresses.

## Non-goals

- Do not rename any Typer command (names are user-facing contract).
- Do not change help strings or option names.
- Do not reorganise the suppression, config, or baseline sub-apps (they
  are already their own modules).
