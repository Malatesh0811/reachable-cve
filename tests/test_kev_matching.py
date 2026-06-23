"""KEV membership must drive in_kev correctly, and KEV must move the score."""
import json
from pathlib import Path

from reachable_cve.reachability import ReachabilityResult
from reachable_cve.scorer import score_finding
from reachable_cve.vulndb import VulnRecord, apply_threat_intel

KEV_FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"


def _kev_set_from_fixture() -> set[str]:
    data = json.loads(KEV_FIXTURE.read_text())
    return {v["cveID"] for v in data["vulnerabilities"]}


def _mk_record(cve: str, cvss: float = 9.8) -> VulnRecord:
    return VulnRecord(
        osv_id=f"GHSA-fake-{cve}",
        cve_ids=[cve],
        package="example",
        installed_version="1.0",
        summary="",
        cvss=cvss,
        epss=0.2,
        in_kev=False,
        vulnerable_symbols=["example.bad"],
    )


def test_apply_threat_intel_flags_kev_cves():
    kev = _kev_set_from_fixture()
    in_kev_rec = _mk_record("CVE-2021-44228")     # Log4Shell — in fixture
    not_in_kev_rec = _mk_record("CVE-2000-00001")  # synthetic — not in fixture
    apply_threat_intel([in_kev_rec, not_in_kev_rec], epss_map={}, kev_set=kev)
    assert in_kev_rec.in_kev is True
    assert not_in_kev_rec.in_kev is False


def test_apply_threat_intel_pulls_max_epss_across_aliases():
    rec = VulnRecord(
        osv_id="GHSA-x", cve_ids=["CVE-A", "CVE-B"], package="p", installed_version="1.0",
        summary="", cvss=7.0, epss=None, in_kev=False, vulnerable_symbols=["p.f"],
    )
    apply_threat_intel([rec], epss_map={"CVE-A": 0.1, "CVE-B": 0.95}, kev_set=set())
    assert rec.epss == 0.95


def test_kev_adds_exactly_40_points_when_reachable():
    """Score formula: KEV weight is 0.4; reachable * 100 makes that 40 points."""
    r = ReachabilityResult(reachable=True, matched_symbol="example.bad", path=["a", "ext:example.bad"], sink_locations=[])
    base = _mk_record("CVE-X", cvss=0.0)  # zero CVSS, zero EPSS noise
    base.epss = 0.0
    base.in_kev = False
    kev = _mk_record("CVE-X", cvss=0.0)
    kev.epss = 0.0
    kev.in_kev = True

    assert round(score_finding(kev, r).score - score_finding(base, r).score, 1) == 40.0


def test_kev_dampened_by_unreachable_penalty():
    """When unreachable, the same KEV bit should contribute only 4 points (40 * 0.1)."""
    r = ReachabilityResult(reachable=False, matched_symbol=None, path=[], sink_locations=[])
    base = _mk_record("CVE-X", cvss=0.0); base.epss = 0.0; base.in_kev = False
    kev = _mk_record("CVE-X", cvss=0.0); kev.epss = 0.0; kev.in_kev = True
    delta = score_finding(kev, r).score - score_finding(base, r).score
    assert round(delta, 1) == 4.0
