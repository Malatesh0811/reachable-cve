"""Offline smoke tests — exercise parser, call graph, reachability, scorer
without hitting OSV/EPSS/KEV.
"""
from pathlib import Path

from reachable_cve.call_graph import build_from_repo
from reachable_cve.reachability import reachable_to
from reachable_cve.scorer import score_finding
from reachable_cve.vulndb import VulnRecord

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo_repo"


def test_yaml_load_is_reachable():
    cg = build_from_repo(DEMO)
    r = reachable_to(cg, ["yaml.load", "yaml.load_all"])
    assert r.reachable, "yaml.load() is called from app/config.py:main → load_config"
    assert r.matched_symbol == "yaml.load"


def test_requests_is_unreachable():
    cg = build_from_repo(DEMO)
    r = reachable_to(cg, ["requests.get", "requests.post"])
    assert not r.reachable, "requests.get is only in a never-called function"


def test_scorer_penalizes_unreachable():
    v_reach = VulnRecord("GHSA-x", ["CVE-2020-14343"], "pyyaml", "5.3.1",
                         "yaml.load deserialization", cvss=9.8, epss=0.5, in_kev=True,
                         vulnerable_symbols=["yaml.load"])
    v_unreach = VulnRecord("GHSA-y", ["CVE-2018-18074"], "requests", "2.19.0",
                           "requests redirect leak", cvss=9.8, epss=0.5, in_kev=True,
                           vulnerable_symbols=["requests.get"])
    cg = build_from_repo(DEMO)
    reach = reachable_to(cg, v_reach.vulnerable_symbols)
    unreach = reachable_to(cg, v_unreach.vulnerable_symbols)
    f_reach = score_finding(v_reach, reach)
    f_unreach = score_finding(v_unreach, unreach)
    assert f_reach.score > f_unreach.score * 5
    assert f_reach.severity_label in {"critical", "high"}
    assert f_unreach.severity_label == "informational"
