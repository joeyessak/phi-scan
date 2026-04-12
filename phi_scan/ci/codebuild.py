"""AWS CodeBuild adapter.

CodeBuild is a meta-platform that delegates PR comment posting to
GitHub or Bitbucket based on the source repository URL detected from
``CODEBUILD_SOURCE_REPO_URL``.

Note: AWS Security Hub ASFF import remains in ``ci_integration.py``
for now and will be migrated in a follow-up PR.
"""

from __future__ import annotations

import logging
import os

from phi_scan.ci._base import BaseCIAdapter
from phi_scan.ci._detect import CIPlatform, PRContext
from phi_scan.ci.bitbucket import BitbucketAdapter
from phi_scan.ci.github import GitHubAdapter
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_MIN_URL_PARTS_FOR_REPO_EXTRACTION: int = 2


class CodeBuildAdapter(BaseCIAdapter):
    """AWS CodeBuild adapter that delegates to GitHub or Bitbucket."""

    @property
    def supports_security_hub(self) -> bool:
        return True

    def post_pr_comment(self, comment_body: str, pr_context: PRContext) -> None:
        repo_url = os.environ.get("CODEBUILD_SOURCE_REPO_URL", "")
        if "github.com" in repo_url:
            github_context = _build_github_context_from_codebuild(repo_url, pr_context)
            GitHubAdapter().post_pr_comment(comment_body, github_context)
        elif "bitbucket.org" in repo_url:
            bitbucket_context = _build_bitbucket_context_from_codebuild(repo_url, pr_context)
            BitbucketAdapter().post_pr_comment(comment_body, bitbucket_context)
        else:
            _LOG.warning("CodeBuild: unrecognised source repo URL — skipping PR comment")

    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        _LOG.debug("CodeBuild: commit status handled via underlying VCS platform")


def _build_github_context_from_codebuild(repo_url: str, pr_context: PRContext) -> PRContext:
    parts = repo_url.rstrip("/").rstrip(".git").split("/")
    repository = (
        f"{parts[-2]}/{parts[-1]}" if len(parts) >= _MIN_URL_PARTS_FOR_REPO_EXTRACTION else None
    )
    return PRContext(
        platform=CIPlatform.GITHUB_ACTIONS,
        pr_number=pr_context.pr_number,
        repository=repository,
        sha=pr_context.sha,
        branch=pr_context.branch,
        base_branch=pr_context.base_branch,
    )


def _build_bitbucket_context_from_codebuild(repo_url: str, pr_context: PRContext) -> PRContext:
    parts = repo_url.rstrip("/").rstrip(".git").split("/")
    workspace = parts[-2] if len(parts) >= _MIN_URL_PARTS_FOR_REPO_EXTRACTION else ""
    repo_slug = parts[-1] if parts else ""
    return PRContext(
        platform=CIPlatform.BITBUCKET,
        pr_number=pr_context.pr_number,
        repository=pr_context.repository,
        sha=pr_context.sha,
        branch=pr_context.branch,
        base_branch=pr_context.base_branch,
        extras={"workspace": workspace, "repo_slug": repo_slug},
    )
