"""Argument-aware sink rules.

Loaded lazily from `taint_rules.yml`. The reachability matcher calls
`check(cve_ids, kwargs_at_sink)` and gets back a verdict:

  - "match"      : flag the finding as reachable
  - "no_match"   : kwarg requirements not satisfied; suppress the finding
  - "no_rule"    : no rule exists; default behavior (flag)

Only kwarg *presence* is checked today. Kwarg-value checks need dataflow.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_RULES_PATH = Path(__file__).with_name("taint_rules.yml")
_RULES_CACHE: dict | None = None


def _load() -> dict:
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    if not _RULES_PATH.exists():
        _RULES_CACHE = {}
        return _RULES_CACHE
    _RULES_CACHE = yaml.safe_load(_RULES_PATH.read_text()) or {}
    return _RULES_CACHE


@dataclass
class TaintVerdict:
    matched: bool
    reason: str


def check(cve_ids: list[str], kwargs_present: list[str]) -> TaintVerdict:
    rules = _load()
    relevant = [rules[c] for c in cve_ids if c in rules and isinstance(rules[c], dict)]
    if not relevant:
        return TaintVerdict(True, "no_rule")

    for rule in relevant:
        required = rule.get("requires_kwarg_present") or []
        if not required:
            return TaintVerdict(True, "rule_has_no_requirements")
        if all(k in kwargs_present for k in required):
            return TaintVerdict(True, f"required_kwargs_present:{required}")
    return TaintVerdict(False, "required_kwargs_missing")
