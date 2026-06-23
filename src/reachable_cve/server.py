"""FastAPI webhook server for the GitHub App.

POST /webhook receives pull_request events, clones the PR head, runs `scan()`,
and upserts a PR comment with the markdown report.

Run locally:  uvicorn reachable_cve.server:app --reload
"""
from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request

from .engine import scan
from .github_bot import post_check_run, upsert_pr_comment
from .report import render_markdown


app = FastAPI(title="reachable-cve")


def _verify_signature(secret: str, body: bytes, signature: str | None):
    if not signature or not signature.startswith("sha256="):
        raise HTTPException(401, "missing signature")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "bad signature")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        _verify_signature(secret, body, x_hub_signature_256)

    if x_github_event != "pull_request":
        return {"skipped": x_github_event}

    payload = await request.json()
    if payload.get("action") not in {"opened", "synchronize", "reopened"}:
        return {"skipped": payload.get("action")}

    pr = payload["pull_request"]
    repo_full = payload["repository"]["full_name"]
    pr_number = pr["number"]
    clone_url = pr["head"]["repo"]["clone_url"]
    sha = pr["head"]["sha"]
    installation_id = payload["installation"]["id"]

    tmp = Path(tempfile.mkdtemp(prefix="rcve-"))
    try:
        subprocess.check_call(
            ["git", "clone", "--depth", "1", clone_url, str(tmp / "src")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["git", "fetch", "origin", sha], cwd=tmp / "src",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["git", "checkout", sha], cwd=tmp / "src",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        result = scan(tmp / "src")
        body_md = render_markdown(result)
        url = upsert_pr_comment(installation_id, repo_full, pr_number, body_md)
        check_url = post_check_run(
            installation_id, repo_full, sha,
            result.decision.verdict, result.decision.reason,
        )
        return {
            "ok": True,
            "comment": url,
            "check_run": check_url,
            "decision": result.decision.verdict,
            "reachable": len(result.reachable),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
