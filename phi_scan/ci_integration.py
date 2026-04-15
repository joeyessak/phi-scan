# phi-scan:ignore-file
"""Backward-compatible façade for the CI/CD integration package.

All implementation lives in the ``phi_scan.ci`` package:

- Platform detection + PR context: ``phi_scan.ci._detect``
- Per-platform adapters: ``phi_scan.ci.github``, ``azure``, ``gitlab``, etc.
- Platform-specific extras: ``phi_scan.ci.sarif``,
  ``phi_scan.ci.bitbucket_insights``, ``phi_scan.ci.azure_devops``,
  ``phi_scan.ci.aws_security_hub``
- Comment-body formatting: ``phi_scan.ci.comment_body``
- Orchestration dispatch: ``phi_scan.ci.dispatch``

This module re-exports every symbol that was previously importable from
``phi_scan.ci_integration`` so external callers continue to work
unchanged.

Security audit summary
----------------------
All outbound HTTP calls go through ``phi_scan.ci._transport.execute_http_request``,
which re-raises both ``httpx.HTTPStatusError`` and ``httpx.RequestError`` as
``CIIntegrationError``. Error messages include only the status code and
reason phrase — never the response body.
"""

from __future__ import annotations

from phi_scan.ci import (  # noqa: F401 — backward-compatible re-exports
    AzureAdapter,
    BaseCIAdapter,
    BitbucketAdapter,
    CIPlatform,
    CircleCIAdapter,
    CodeBuildAdapter,
    GitHubAdapter,
    GitLabAdapter,
    JenkinsAdapter,
    PullRequestContext,
    detect_platform,
    get_pull_request_context,
    resolve_adapter,
)
from phi_scan.ci._base import SanitisedCommentBody
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
from phi_scan.ci.aws_security_hub import (
    convert_findings_to_asff as convert_findings_to_asff,
)
from phi_scan.ci.aws_security_hub import (
    import_findings_to_security_hub as import_findings_to_security_hub,
)
from phi_scan.ci.azure_devops import (
    create_azure_boards_work_item as create_azure_boards_work_item,
)
from phi_scan.ci.azure_devops import set_azure_build_tag as set_azure_build_tag
from phi_scan.ci.azure_devops import set_azure_pr_status as set_azure_pr_status
from phi_scan.ci.bitbucket_insights import (
    post_bitbucket_code_insights as post_bitbucket_code_insights,
)
from phi_scan.ci.comment_body import (
    BaselineComparison as BaselineComparison,
)
from phi_scan.ci.comment_body import (
    build_comment_body as build_comment_body,
)
from phi_scan.ci.comment_body import (
    build_comment_body_with_baseline as build_comment_body_with_baseline,
)
from phi_scan.ci.dispatch import post_pr_comment as post_pr_comment
from phi_scan.ci.dispatch import post_pull_request_comment as post_pull_request_comment
from phi_scan.ci.dispatch import set_commit_status as set_commit_status
from phi_scan.ci.sarif import upload_sarif_to_github as upload_sarif_to_github
from phi_scan.exceptions import CIIntegrationError  # noqa: F401 — backward-compatible re-export

PRContext = PullRequestContext
get_pr_context = get_pull_request_context

__all__ = [
    "AzureAdapter",
    "BaseCIAdapter",
    "BaselineComparison",
    "BitbucketAdapter",
    "CIIntegrationError",
    "CIPlatform",
    "CircleCIAdapter",
    "CodeBuildAdapter",
    "GitHubAdapter",
    "GitLabAdapter",
    "HttpMethod",
    "HttpRequestConfig",
    "JenkinsAdapter",
    "OperationLabel",
    "PRContext",
    "PullRequestContext",
    "SanitisedCommentBody",
    "build_comment_body",
    "build_comment_body_with_baseline",
    "convert_findings_to_asff",
    "create_azure_boards_work_item",
    "detect_platform",
    "execute_http_request",
    "get_pr_context",
    "get_pull_request_context",
    "import_findings_to_security_hub",
    "post_bitbucket_code_insights",
    "post_pr_comment",
    "post_pull_request_comment",
    "resolve_adapter",
    "set_azure_build_tag",
    "set_azure_pr_status",
    "set_commit_status",
    "upload_sarif_to_github",
]
