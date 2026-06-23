"""Render scan results: terminal table, attack-path narrative, markdown PR comment."""
from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table

from .engine import ScanResult
from .reachability import ReachabilityResult
from .scorer import Finding


VERDICT_BADGE = {
    "BLOCK": ":no_entry: **BLOCK**",
    "WARN": ":warning: **WARN**",
    "PASS": ":white_check_mark: **PASS**",
}


# ---------- Attack-path narrator ----------


def _short(name: str) -> str:
    return name.split(":", 1)[-1] if name.startswith(("ext:", "unknown:")) else name


def explain_path(r: ReachabilityResult) -> str:
    """Multi-line narrative: entrypoint → ... → SINK with file:line annotations.

    Locations come from ReachabilityResult.sink_locations which records one
    (file, line) per *edge* in the path (len = len(path) - 1).
    """
    if not r.reachable or not r.path:
        return "  (not reachable from any entrypoint)"

    lines: list[str] = [f"  {_short(r.path[0])}"]
    for i, node in enumerate(r.path[1:]):
        loc = r.sink_locations[i] if i < len(r.sink_locations) else None
        loc_str = f"  {loc[0].name}:{loc[1]}" if loc else ""
        arrow = "  -> "
        sink_marker = "  <- SINK" if i == len(r.path) - 2 else ""
        lines.append(f"{arrow}{_short(node):<35}{loc_str}{sink_marker}")
    return "\n".join(lines)


# ---------- Terminal table ----------


def _row(f: Finding) -> list[str]:
    return [
        f.vuln.osv_id,
        f.vuln.package,
        f.vuln.installed_version or "?",
        f"{f.vuln.cvss or 0:.1f}",
        f"{(f.vuln.epss or 0):.3f}",
        "yes" if f.vuln.in_kev else "no",
        "yes" if f.reach.reachable else "no",
        f"{f.score:.1f}",
        f.severity_label,
    ]


def render_terminal(result: ScanResult, explain: bool = False) -> str:
    console = Console(record=True, file=StringIO(), width=140)
    console.print(f"[bold]Decision:[/bold] {result.decision.verdict} — {result.decision.reason}")
    console.print()
    t = Table(title="reachable-cve scan", show_lines=False)
    for col in ("OSV ID", "Pkg", "Ver", "CVSS", "EPSS", "KEV", "Reach", "Score", "Severity"):
        t.add_column(col)
    for f in result.findings:
        t.add_row(*_row(f))
    console.print(t)

    if explain and result.reachable:
        console.print("\n[bold]Attack paths:[/bold]")
        for f in result.reachable:
            console.print(f"\n[cyan]{f.vuln.osv_id}[/cyan] [yellow]({f.vuln.package})[/yellow]")
            console.print(explain_path(f.reach))
    return console.export_text()


# ---------- Markdown for PR comments ----------


def _severity_summary_md(result: ScanResult) -> str:
    counts = result.severity_counts
    parts = []
    for label in ("critical", "high", "medium", "low"):
        if counts.get(label, 0):
            parts.append(f"**{counts[label]} {label}** reachable")
    if counts.get("informational", 0):
        parts.append(f"{counts['informational']} unreachable")
    return " · ".join(parts) if parts else "no findings"


def _attack_path_block_md(f: Finding) -> str:
    return "```\n" + explain_path(f.reach) + "\n```"


def render_markdown(result: ScanResult) -> str:
    out: list[str] = []
    out.append("## reachable-cve report")
    out.append("")
    out.append(f"{VERDICT_BADGE.get(result.decision.verdict, result.decision.verdict)} — {result.decision.reason}")
    out.append("")
    out.append(_severity_summary_md(result))
    out.append("")

    if result.reachable:
        out.append("### Reachable findings (act on these)")
        for f in result.reachable:
            cves = ", ".join(f.vuln.cve_ids) or f.vuln.osv_id
            out.append("")
            out.append(f"#### `{cves}` — Score **{f.score:.1f}** ({f.severity_label})")
            out.append(
                f"- Package: `{f.vuln.package}=={f.vuln.installed_version or '?'}`"
            )
            out.append(
                f"- CVSS: **{f.vuln.cvss or 0:.1f}** · EPSS: **{(f.vuln.epss or 0):.3f}** "
                f"· KEV: **{'yes' if f.vuln.in_kev else 'no'}**"
            )
            out.append(f"- Sink: `{f.reach.matched_symbol}`")
            if f.vuln.remediation:
                out.append(f"- **Remediation:** {f.vuln.remediation}")
            if f.vuln.summary:
                out.append(f"- Summary: {f.vuln.summary}")
            out.append("")
            out.append("<details><summary>Attack path</summary>")
            out.append("")
            out.append(_attack_path_block_md(f))
            out.append("")
            out.append("</details>")
        out.append("")

    if result.unreachable:
        out.append(f"<details><summary>{len(result.unreachable)} unreachable (deprioritized)</summary>")
        out.append("")
        out.append("| OSV | Package | CVSS | EPSS | KEV | Fix |")
        out.append("|---|---|---:|---:|---|---|")
        for f in result.unreachable:
            fix = f.vuln.fixed_versions[0] if f.vuln.fixed_versions else "—"
            out.append(
                f"| `{f.vuln.osv_id}` | `{f.vuln.package}=={f.vuln.installed_version or '?'}` "
                f"| {f.vuln.cvss or 0:.1f} | {(f.vuln.epss or 0):.3f} | "
                f"{'yes' if f.vuln.in_kev else 'no'} | {fix} |"
            )
        out.append("")
        out.append("</details>")
        out.append("")

    out.append("---")
    out.append(
        "_Score = 0.3·CVSS + 0.3·EPSS + 0.4·KEV, gated by static call-graph reachability. "
        "BLOCK ≥ 60 (reachable); WARN = any reachable or unreachable KEV-critical._"
    )
    return "\n".join(out)
