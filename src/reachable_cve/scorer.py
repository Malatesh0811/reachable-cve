"""Real-exploitability scorer + CI gate decision policy."""
from __future__ import annotations

from dataclasses import dataclass

from .reachability import ReachabilityResult
from .vulndb import VulnRecord

# Weights — keep KEV and reachability dominant. The CVSS term is the calibration
# anchor: a 9.8 CVSS that is BOTH reachable AND in KEV maxes the formula at
# ~98/100, which is the right ceiling for "drop everything".
W_CVSS = 0.30
W_EPSS = 0.30
W_KEV = 0.40
UNREACHABLE_PENALTY = 0.10  # final score gate when reach.reachable == False


@dataclass
class Finding:
    vuln: VulnRecord
    reach: ReachabilityResult
    score: float            # 0-100
    severity_label: str     # critical / high / medium / low / informational


def _cvss_norm(cvss: float | None) -> float:
    if cvss is None:
        return 0.0
    return max(0.0, min(cvss, 10.0)) / 10.0


def _label(score: float, reachable: bool) -> str:
    if not reachable:
        return "informational"
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_finding(v: VulnRecord, r: ReachabilityResult) -> Finding:
    raw = (
        W_CVSS * _cvss_norm(v.cvss)
        + W_EPSS * (v.epss or 0.0)
        + W_KEV * (1.0 if v.in_kev else 0.0)
    )
    if not r.reachable:
        raw *= UNREACHABLE_PENALTY
    return Finding(vuln=v, reach=r, score=round(raw * 100, 1), severity_label=_label(raw * 100, r.reachable))


# ---------- CI gate decision ----------


@dataclass
class Decision:
    verdict: str   # BLOCK | WARN | PASS
    reason: str
    exit_code: int


def decide(
    findings: list[Finding],
    block_score: float = 60.0,
    warn_score: float = 30.0,
) -> Decision:
    """Map findings to a CI verdict.

    Strict reachability: unreachable findings are informational regardless of
    KEV/CVSS. That's the whole point of the tool — alert only on what your code
    can actually call. Any other policy reintroduces the noise we set out to
    filter.

    BLOCK : at least one reachable finding with score >= block_score
    WARN  : at least one reachable finding (below the block threshold)
    PASS  : no reachable findings
    """
    reachable = [f for f in findings if f.reach.reachable]
    reachable_block = [f for f in reachable if f.score >= block_score]

    if reachable_block:
        top = max(reachable_block, key=lambda f: f.score)
        return Decision(
            "BLOCK",
            f"{len(reachable_block)} reachable finding(s) at score >= {block_score} "
            f"(top: {top.vuln.osv_id} @ {top.score})",
            exit_code=2,
        )
    if reachable:
        return Decision("WARN", f"{len(reachable)} reachable finding(s) below block threshold", exit_code=1)
    return Decision("PASS", "no reachable findings", exit_code=0)
