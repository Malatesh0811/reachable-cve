"""GitHub PR comment + check-run delivery.

Sticky-comment design:
  We embed a HTML-comment marker (COMMENT_MARKER) in the body. On every webhook
  call we list issue comments, find the one containing the marker, and `edit()`
  it. If none exists, we `create_issue_comment()` a new one. The marker is the
  only stable identity (GitHub does not let us set a stable comment ID), so it
  MUST stay exactly as-is — if you change it, old PRs get a second comment.
"""
from __future__ import annotations

import os
from pathlib import Path

from github import Auth, GithubIntegration


COMMENT_MARKER = "<!-- reachable-cve:bot -->"


def _client_for_installation(installation_id: int):
    app_id = os.environ["GITHUB_APP_ID"]
    key_path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "private-key.pem")
    private_key = Path(key_path).read_text()
    integ = GithubIntegration(auth=Auth.AppAuth(app_id, private_key))
    return integ.get_github_for_installation(installation_id)


def upsert_pr_comment(
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    body: str,
) -> str:
    """Create or update the bot's sticky PR comment. Returns the comment HTML URL."""
    gh = _client_for_installation(installation_id)
    repo = gh.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)
    marked = f"{COMMENT_MARKER}\n{body}"

    for c in pr.get_issue_comments():
        if c.body and COMMENT_MARKER in c.body:
            c.edit(marked)
            return c.html_url

    return pr.create_issue_comment(marked).html_url


def post_check_run(
    installation_id: int,
    repo_full_name: str,
    sha: str,
    verdict: str,
    summary: str,
) -> str | None:
    """Optionally publish a GitHub check-run that turns the PR status red/yellow/green.

    Verdict mapping:
      BLOCK -> conclusion='failure'
      WARN  -> conclusion='neutral' (still passes the required-check gate)
      PASS  -> conclusion='success'

    Requires the GitHub App to have 'Checks: write' permission.
    """
    gh = _client_for_installation(installation_id)
    repo = gh.get_repo(repo_full_name)
    conclusion = {"BLOCK": "failure", "WARN": "neutral", "PASS": "success"}.get(verdict, "neutral")
    try:
        run = repo.create_check_run(
            name="reachable-cve",
            head_sha=sha,
            status="completed",
            conclusion=conclusion,
            output={"title": f"reachable-cve: {verdict}", "summary": summary[:65000]},
        )
        return run.html_url
    except Exception:
        # Don't fail the webhook if checks: write isn't granted yet.
        return None
