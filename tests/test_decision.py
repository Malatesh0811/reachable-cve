"""BLOCK / WARN / PASS policy must be deterministic and reviewable."""
from pathlib import Path

from reachable_cve.reachability import ReachabilityResult
from reachable_cve.scorer import decide, score_finding
from reachable_cve.vulndb import VulnRecord


def _v(cvss=0.0, epss=0.0, kev=False, cve="CVE-X"):
    return VulnRecord("GHSA-x", [cve], "p", "1.0", "", cvss, epss, kev, ["p.bad"])


def _reach(yes: bool):
    return ReachabilityResult(yes, "p.bad" if yes else None, ["a", "ext:p.bad"] if yes else [], [])


def test_pass_when_nothing_reachable():
    f = score_finding(_v(cvss=9.8, epss=0.5, kev=True), _reach(False))
    d = decide([f])
    assert d.verdict == "PASS"
    assert d.exit_code == 0


def test_warn_on_low_score_reachable():
    # cvss=1, epss=0, kev=false, reachable -> score ~3 (well below block, above 0)
    f = score_finding(_v(cvss=1.0), _reach(True))
    d = decide([f])
    assert d.verdict in {"WARN"}, f"got {d.verdict} score={f.score}"
    assert d.exit_code == 1


def test_block_on_high_score_reachable():
    # cvss=9.8, epss=0.9, kev=true, reachable -> ~98
    f = score_finding(_v(cvss=9.8, epss=0.9, kev=True), _reach(True))
    d = decide([f])
    assert d.verdict == "BLOCK"
    assert d.exit_code == 2


def test_block_threshold_is_tunable():
    # Pick inputs that produce a score in the [20, 60) window so the threshold
    # change is the only thing that flips the verdict.
    # Score math: 0.3 * 0.5 + 0.3 * 0.5 + 0 = 0.30 -> 30.0
    f = score_finding(_v(cvss=5.0, epss=0.5), _reach(True))
    assert f.score == 30.0, f"score sanity check failed: {f.score}"
    relaxed = decide([f], block_score=60.0)
    strict = decide([f], block_score=20.0)
    assert relaxed.verdict == "WARN"
    assert strict.verdict == "BLOCK"
