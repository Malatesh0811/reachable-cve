"""Markdown report must contain the structural pieces a PR comment needs."""
from pathlib import Path

from reachable_cve.engine import ScanResult
from reachable_cve.reachability import ReachabilityResult
from reachable_cve.report import explain_path, render_markdown
from reachable_cve.scorer import decide, score_finding
from reachable_cve.vulndb import VulnRecord


def _reach():
    return ReachabilityResult(
        reachable=True,
        matched_symbol="yaml.load",
        path=["app.config.<module>", "app.config.main", "app.config.load_config", "ext:yaml.load"],
        sink_locations=[(Path("app/config.py"), 10), (Path("app/config.py"), 6), (Path("app/config.py"), 6)],
    )


def _unreach():
    return ReachabilityResult(reachable=False, matched_symbol=None, path=[], sink_locations=[])


def _findings():
    v_reach = VulnRecord(
        "GHSA-aaaa", ["CVE-2020-14343"], "pyyaml", "5.3.1",
        "yaml.load deserialization", cvss=9.8, epss=0.9, in_kev=True,
        vulnerable_symbols=["yaml.load"], fixed_versions=["5.4"],
    )
    v_unreach = VulnRecord(
        "GHSA-bbbb", ["CVE-2023-32681"], "requests", "2.19.0",
        "proxy auth leak", cvss=6.1, epss=0.4, in_kev=False,
        vulnerable_symbols=["requests.get"], fixed_versions=["2.31.0"],
    )
    return [score_finding(v_reach, _reach()), score_finding(v_unreach, _unreach())]


def _result():
    findings = sorted(_findings(), key=lambda f: f.score, reverse=True)
    return ScanResult(findings=findings, repo=Path("."), decision=decide(findings))


def test_attack_path_explanation_includes_sink_marker():
    s = explain_path(_reach())
    assert "<- SINK" in s
    assert "yaml.load" in s
    assert "config.py" in s


def test_attack_path_for_unreachable_is_explicit():
    s = explain_path(_unreach())
    assert "not reachable" in s.lower()


def test_markdown_report_has_decision_badge():
    md = render_markdown(_result())
    # decision is BLOCK because reachable yaml.load with KEV + 9.8 CVSS scores high
    assert "BLOCK" in md
    assert "no_entry" in md  # the emoji shortcode


def test_markdown_report_has_severity_summary():
    md = render_markdown(_result())
    assert "reachable" in md
    assert "unreachable" in md


def test_markdown_report_has_remediation():
    md = render_markdown(_result())
    assert "Remediation" in md
    assert "5.4" in md  # fixed version for PyYAML in fixture


def test_markdown_report_has_attack_path_block():
    md = render_markdown(_result())
    assert "<details><summary>Attack path</summary>" in md
    assert "```" in md  # the fenced code block holding the path


def test_unreachable_block_is_collapsed_and_lists_fix():
    md = render_markdown(_result())
    assert "unreachable (deprioritized)" in md
    assert "2.31.0" in md
