# phi-scan:ignore-file
"""Orchestration dispatch for CI/CD PR comments and commit statuses.

Selects the platform-specific adapter via ``resolve_adapter`` and forwards
the request. Does nothing (with a debug/warning log) when required
context or support is missing.
"""

from __future__ import annotations

import logging

from phi_scan.ci import resolve_adapter
from phi_scan.ci._detect import PullRequestContext
from phi_scan.ci.comment_body import build_comment_body
from phi_scan.exceptions import CIIntegrationError
from phi_scan.models import ScanResult

__all__ = [
    "post_pr_comment",
    "post_pull_request_comment",
    "set_commit_status",
]

_LOG: logging.Logger = logging.getLogger(__name__)


def post_pr_comment(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Post a PR/MR comment with scan findings to the detected CI/CD platform.

    Selects the platform-specific adapter based on ``pr_context.platform``.
    Does nothing and logs a warning when the platform is ``UNKNOWN`` or when
    required context (PR number, token) is missing.
    """
    if not pr_context.pull_request_number:
        _LOG.debug("No PR number in context — skipping comment posting")
        return

    try:
        adapter = resolve_adapter(pr_context.platform)
    except CIIntegrationError:
        _LOG.warning(
            "PR comment posting not implemented for platform %s",
            pr_context.platform.value,
        )
        return

    comment_body = build_comment_body(scan_result)
    adapter.post_pull_request_comment(comment_body, pr_context)


post_pull_request_comment = post_pr_comment


def set_commit_status(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Set the commit status (PASS/FAIL) on the CI/CD platform.

    Selects the platform-specific adapter based on ``pr_context.platform``.
    Does nothing and logs a warning when required context (SHA, token) is missing.
    """
    if not pr_context.sha:
        _LOG.debug("No commit SHA in context — skipping status posting")
        return

    try:
        adapter = resolve_adapter(pr_context.platform)
    except CIIntegrationError:
        _LOG.warning(
            "Commit status not implemented for platform %s",
            pr_context.platform.value,
        )
        return

    if not adapter.can_post_commit_status:
        _LOG.debug(
            "Adapter %s does not support commit status — skipping",
            type(adapter).__name__,
        )
        return

    adapter.set_commit_status(scan_result, pr_context)
