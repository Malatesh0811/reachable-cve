"""High-level scan orchestrator."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import logging

from .call_graph import build_from_repo
from .logging_config import log_event
from .reachability import reachable_to
from .scorer import Decision, Finding, decide, score_finding
from .vulndb import VulnRecord, collect

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    findings: list[Finding]
    repo: Path
    decision: Decision

    @property
    def reachable(self) -> list[Finding]:
        return [f for f in self.findings if f.reach.reachable]

    @property
    def unreachable(self) -> list[Finding]:
        return [f for f in self.findings if not f.reach.reachable]

    @property
    def severity_counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in self.findings:
            out[f.severity_label] = out.get(f.severity_label, 0) + 1
        return out


def scan(
    repo_root: Path,
    *,
    vulns: list[VulnRecord] | None = None,
    block_score: float = 60.0,
    warn_score: float = 30.0,
) -> ScanResult:
    """Run the full pipeline. `vulns` may be injected by tests to bypass the network."""
    cg = build_from_repo(repo_root)
    if vulns is None:
        vulns = collect(repo_root)

    findings: list[Finding] = []
    for v in vulns:
        r = reachable_to(cg, v.vulnerable_symbols, cve_ids=v.cve_ids)
        f = score_finding(v, r)
        findings.append(f)
        log_event(
            log, "finding",
            osv_id=v.osv_id, cve_ids=v.cve_ids, package=v.package,
            reachable=r.reachable, matched_symbol=r.matched_symbol,
            score=f.score, severity=f.severity_label,
            in_kev=v.in_kev, cvss=v.cvss, epss=v.epss,
            taint_reason=r.taint_reason,
        )
    findings.sort(key=lambda f: f.score, reverse=True)
    decision = decide(findings, block_score=block_score, warn_score=warn_score)
    log_event(log, "scan_done", repo=str(repo_root), decision=decision.verdict,
              n_findings=len(findings), n_reachable=sum(1 for f in findings if f.reach.reachable))
    return ScanResult(findings=findings, repo=repo_root, decision=decision)
