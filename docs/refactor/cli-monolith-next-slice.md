# `phi_scan/cli/__init__.py` — split plan

**Status:** COMPLETED — 2026-04-12.
**Final module size:** 128 lines (down from 1492 at the start of the pass).

## Completed slices

- `_shared.py` — leaf helpers, option dataclasses, log-level map,
  progress-bar config, worker-count validation, hook path guards, version
  flag.
- `fix.py` — fix command, three helpers, and fix-specific constants.
- `hooks.py` — install-hook, uninstall-hook, init, setup commands and
  their hook-script / stub-message constants.
- `history.py` — history and report commands, scan-event display
  helpers, audit-event / audit-chain / history constants.
- `dashboard.py` — dashboard command, `_aggregate_category_totals`
  helper, eight `_DASHBOARD_*` constants.
- `scan.py` — scan and watch commands, scan-progress helpers
  (sequential/parallel dispatch), audit persistence, notification
  dispatch, framework flag resolution, CI integration dispatch,
  `_collect_scan_targets_for_phase` (renamed from `_prepare_scan_phase`),
  and all scan-related constants including the previously-orphaned
  `_SPINNER_*` messages.

## Final structure

```
phi_scan/cli/
    __init__.py   # thin dispatcher: Typer app + sub-app registration +
                  # command wiring via app.command(name)(fn); re-exports
                  # private helpers for test-compat via __all__
    _shared.py    # dataclasses, leaf helpers, shared constants
    scan.py       # scan + watch commands and all scan orchestration
    fix.py        # fix command and helpers
    history.py    # history + report commands
    dashboard.py  # dashboard command
    hooks.py      # install-hook, uninstall-hook, init, setup commands
```

## Gates

- [x] `uv run ruff check .` passes.
- [x] `uv run ruff format --check .` passes.
- [x] `uv run mypy phi_scan` passes.
- [x] `uv run pytest -q --no-cov` — 1973 passed, 3 skipped.
- [x] `phi-scan --help` and `phi-scan scan --help` render the same
  command set and options as before.

## Follow-ups (not blocking)

- The `__all__` re-export of private names in `phi_scan/cli/__init__.py`
  is an intentional shim for test compatibility. A future cleanup could
  either promote the names to public or refactor tests to exercise the
  CLI through Typer's `CliRunner` rather than importing internals
  directly.
