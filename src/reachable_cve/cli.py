"""Command line interface."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .engine import scan
from .logging_config import setup_logging
from .report import render_markdown, render_terminal


@click.group()
@click.option("--log-json/--log-text", default=True, help="Structured JSON logs (default) vs plain text.")
@click.option("--log-level", default="INFO", show_default=True)
def main(log_json: bool, log_level: str):
    """Reachability-aware vulnerability scanner."""
    setup_logging(level=log_level, json_output=log_json)


@main.command("scan")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["text", "markdown", "json"]), default="text")
@click.option(
    "--policy",
    type=click.Choice(["decision", "any", "reachable", "never"]),
    default="decision",
    help="Exit code policy. 'decision' uses BLOCK/WARN/PASS (0/1/2).",
)
@click.option("--block-score", type=float, default=60.0, show_default=True)
@click.option("--warn-score", type=float, default=30.0, show_default=True)
@click.option("--explain", is_flag=True, help="Print attack-path narrative for reachable findings.")
def scan_cmd(path: Path, fmt: str, policy: str, block_score: float, warn_score: float, explain: bool):
    """Scan a Python repo for reachable CVEs."""
    result = scan(path, block_score=block_score, warn_score=warn_score)

    if fmt == "text":
        click.echo(render_terminal(result, explain=explain))
    elif fmt == "markdown":
        click.echo(render_markdown(result))
    else:
        click.echo(json.dumps({
            "decision": {
                "verdict": result.decision.verdict,
                "reason": result.decision.reason,
            },
            "severity_counts": result.severity_counts,
            "findings": [
                {
                    "osv_id": f.vuln.osv_id,
                    "cve_ids": f.vuln.cve_ids,
                    "package": f.vuln.package,
                    "installed_version": f.vuln.installed_version,
                    "cvss": f.vuln.cvss,
                    "epss": f.vuln.epss,
                    "in_kev": f.vuln.in_kev,
                    "reachable": f.reach.reachable,
                    "matched_symbol": f.reach.matched_symbol,
                    "path": f.reach.path,
                    "score": f.score,
                    "severity": f.severity_label,
                    "fixed_versions": f.vuln.fixed_versions,
                    "remediation": f.vuln.remediation,
                } for f in result.findings
            ]
        }, indent=2))

    if policy == "decision":
        sys.exit(result.decision.exit_code)
    if policy == "any" and result.findings:
        sys.exit(1)
    if policy == "reachable" and result.reachable:
        sys.exit(1)


@main.command("graph")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def graph_cmd(path: Path):
    """Dump the call graph (debug)."""
    from .call_graph import build_from_repo
    cg = build_from_repo(path)
    for src, dst, data in cg.graph.edges(data=True):
        click.echo(f"{src}  ->  {dst}  ({data.get('file','')}:{data.get('line','')})")


if __name__ == "__main__":
    main()
