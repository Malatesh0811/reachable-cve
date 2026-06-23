"""Argument-aware sink rules suppress findings when kwargs aren't present."""
from reachable_cve.taint import check


def test_no_rule_means_match():
    v = check(["CVE-9999-0000"], kwargs_present=[])
    assert v.matched is True
    assert v.reason == "no_rule"


def test_rule_with_required_kwarg_present():
    v = check(["CVE-2023-32681"], kwargs_present=["proxies", "timeout"])
    assert v.matched is True


def test_rule_with_required_kwarg_missing_suppresses():
    v = check(["CVE-2023-32681"], kwargs_present=["timeout"])
    assert v.matched is False
    assert v.reason == "required_kwargs_missing"


def test_rule_with_no_requirements_always_matches():
    # CVE-2020-14343 has no requires_kwarg_present
    v = check(["CVE-2020-14343"], kwargs_present=[])
    assert v.matched is True


import textwrap
from reachable_cve.call_graph import build_from_repo
from reachable_cve.reachability import reachable_to


REQUESTS_WITH_PROXY = textwrap.dedent("""
    import requests
    def main():
        return requests.get("http://x", proxies={"http": "http://p"})
""")

REQUESTS_NO_PROXY = textwrap.dedent("""
    import requests
    def main():
        return requests.get("http://x")
""")


def test_taint_suppresses_requests_get_without_proxies_kwarg(tmp_path):
    (tmp_path / "app.py").write_text(REQUESTS_NO_PROXY)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["requests.get"], cve_ids=["CVE-2023-32681"])
    assert not r.reachable, "should be suppressed: no proxies kwarg"
    assert r.taint_reason == "required_kwargs_missing"


def test_taint_flags_requests_get_with_proxies_kwarg(tmp_path):
    (tmp_path / "app.py").write_text(REQUESTS_WITH_PROXY)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["requests.get"], cve_ids=["CVE-2023-32681"])
    assert r.reachable, "proxies kwarg present, should flag"
