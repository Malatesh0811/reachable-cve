"""CVSS extraction must survive all four advisory shapes we see in the wild."""
import json
from pathlib import Path

from reachable_cve.vulndb import _extract_cvss

FIX = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIX / name).read_text())


def test_cvss_from_database_specific_numeric():
    # GHSA shape: authoritative numeric score on database_specific.cvss.score
    adv = _load("osv_pyyaml.json")
    assert _extract_cvss(adv) == 9.8


def test_cvss_from_database_specific_numeric_requests():
    adv = _load("osv_requests.json")
    assert _extract_cvss(adv) == 6.1


def test_cvss_computed_from_vector_when_db_specific_missing():
    # PYSEC shape: no database_specific.cvss, must compute base score from vector.
    adv = _load("osv_vector_only.json")
    score = _extract_cvss(adv)
    # AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L  -> 6.3 by CVSS 3.1 spec
    assert score is not None
    assert 6.0 <= score <= 6.5, f"expected ~6.3, got {score}"


def test_cvss_falls_back_to_severity_label():
    # Worst case: only a textual severity label exists. Map to a sensible mid-band.
    adv = _load("osv_label_only.json")
    assert _extract_cvss(adv) == 7.5  # HIGH


def test_cvss_returns_none_when_no_signal():
    assert _extract_cvss({"id": "X"}) is None
    assert _extract_cvss({"severity": []}) is None
