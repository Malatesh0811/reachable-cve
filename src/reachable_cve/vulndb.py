"""Vulnerability database layer.

Fetches advisories from OSV, exploit-likelihood scores from EPSS, and the CISA
KEV catalog. Produces a list of `VulnRecord` objects each tied to one or more
*vulnerable symbols* the static analyzer can look for in the call graph.

All three feeds are cached on disk (see cache.py) so a typical scan does one
warm OSV roundtrip per dependency, zero EPSS roundtrips after the first daily
scan, and zero KEV roundtrips after the first daily scan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import httpx
import yaml
from packaging.requirements import Requirement

from .cache import TTL_EPSS, TTL_KEV, TTL_OSV, cached_json
from .logging_config import log_event

OSV_API = os.getenv("OSV_API", "https://api.osv.dev/v1")
EPSS_API = os.getenv("EPSS_API", "https://api.first.org/data/v1/epss")
KEV_URL = os.getenv(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

log = logging.getLogger(__name__)


@dataclass
class VulnRecord:
    osv_id: str
    cve_ids: list[str]
    package: str
    installed_version: str
    summary: str
    cvss: float | None
    epss: float | None
    in_kev: bool
    vulnerable_symbols: list[str]
    fixed_versions: list[str] = field(default_factory=list)

    @property
    def remediation(self) -> str | None:
        if not self.fixed_versions:
            return None
        return f"upgrade {self.package} to >= {self.fixed_versions[0]}"


# ---------- Manifest parsing ----------


def parse_requirements(repo_root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    req_txt = repo_root / "requirements.txt"
    if req_txt.exists():
        for raw in req_txt.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            try:
                r = Requirement(line)
                pin = ""
                for spec in r.specifier:
                    if spec.operator == "==":
                        pin = spec.version
                out[r.name.lower()] = pin
            except Exception:
                pass

    pyproject = repo_root / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(pyproject.read_text())
        deps = data.get("project", {}).get("dependencies", []) or []
        for line in deps:
            try:
                r = Requirement(line)
                pin = ""
                for spec in r.specifier:
                    if spec.operator == "==":
                        pin = spec.version
                out.setdefault(r.name.lower(), pin)
            except Exception:
                pass
    return out


# ---------- CVSS extraction ----------

_SEVERITY_FALLBACK = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}


def _extract_cvss(adv: dict) -> float | None:
    ds = adv.get("database_specific") or {}
    cvss_obj = ds.get("cvss")
    if isinstance(cvss_obj, dict):
        score = cvss_obj.get("score")
        if isinstance(score, (int, float)) and score > 0:
            return float(score)

    sev_label = (ds.get("severity") or "").strip().upper()
    label_score = _SEVERITY_FALLBACK.get(sev_label)

    for sev in adv.get("severity", []) or []:
        score_str = (sev.get("score") or "").strip()
        if not score_str:
            continue
        try:
            if score_str.startswith("CVSS:3"):
                from cvss import CVSS3
                return float(CVSS3(score_str).base_score)
            if score_str.startswith("CVSS:2") or sev.get("type") == "CVSS_V2":
                from cvss import CVSS2
                return float(CVSS2(score_str).base_score)
            if re.match(r"^[A-Z]{1,3}:", score_str):
                from cvss import CVSS3
                return float(CVSS3("CVSS:3.1/" + score_str).base_score)
        except Exception:
            continue
    return label_score


def _fixed_versions(adv: dict) -> list[str]:
    out: list[str] = []
    for aff in adv.get("affected", []) or []:
        for r in aff.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "fixed" in ev:
                    out.append(ev["fixed"])
    return sorted(set(out))


# ---------- Threat-intel enrichment ----------


def apply_threat_intel(
    records: Iterable[VulnRecord],
    epss_map: dict[str, float],
    kev_set: set[str],
) -> None:
    for r in records:
        if not r.cve_ids:
            continue
        scores = [epss_map[c] for c in r.cve_ids if c in epss_map]
        r.epss = max(scores) if scores else r.epss
        r.in_kev = any(c in kev_set for c in r.cve_ids)


# ---------- HTTP fetchers, cached ----------


@cached_json("osv", TTL_OSV, key_from_args=lambda client, package, version: ["osv", package, version])
async def _osv_query(client: httpx.AsyncClient, package: str, version: str) -> list[dict]:
    log_event(log, "osv_query", package=package, version=version, cache="miss")
    body: dict = {"package": {"name": package, "ecosystem": "PyPI"}}
    if version:
        body["version"] = version
    r = await client.post(f"{OSV_API}/query", json=body, timeout=20)
    r.raise_for_status()
    return r.json().get("vulns", []) or []


@cached_json("epss", TTL_EPSS, key_from_args=lambda client, cves: ["epss", sorted(cves)])
async def _epss_scores(client: httpx.AsyncClient, cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    log_event(log, "epss_query", n_cves=len(cves), cache="miss")
    out: dict[str, float] = {}
    for i in range(0, len(cves), 50):
        chunk = cves[i : i + 50]
        r = await client.get(EPSS_API, params={"cve": ",".join(chunk)}, timeout=20)
        if r.status_code != 200:
            continue
        for row in r.json().get("data", []):
            try:
                out[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError):
                pass
    return out


@cached_json("kev", TTL_KEV, key_from_args=lambda client: ["kev"])
async def _kev_raw(client: httpx.AsyncClient) -> list[str]:
    fixture_path = os.environ.get("REACHABLE_CVE_KEV_FIXTURE")
    if fixture_path:
        data = json.loads(Path(fixture_path).read_text())
        return [v["cveID"] for v in data.get("vulnerabilities", [])]
    log_event(log, "kev_query", cache="miss")
    r = await client.get(KEV_URL, timeout=20)
    if r.status_code != 200:
        return []
    return [v["cveID"] for v in r.json().get("vulnerabilities", [])]


async def _kev_set(client: httpx.AsyncClient) -> set[str]:
    return set(await _kev_raw(client))


# ---------- Vulnerable-symbol mapping ----------

_BUNDLED_SYMBOL_MAP_PATH = Path(__file__).with_name("symbol_map.yml")
_SYMBOL_MAP_CACHE: dict[str, list[str]] | None = None


def _load_bundled_symbol_map() -> dict[str, list[str]]:
    global _SYMBOL_MAP_CACHE
    if _SYMBOL_MAP_CACHE is not None:
        return _SYMBOL_MAP_CACHE
    if not _BUNDLED_SYMBOL_MAP_PATH.exists():
        _SYMBOL_MAP_CACHE = {}
        return _SYMBOL_MAP_CACHE
    data = yaml.safe_load(_BUNDLED_SYMBOL_MAP_PATH.read_text()) or {}
    _SYMBOL_MAP_CACHE = {k.lower(): list(v) for k, v in (data.get("symbol_map") or {}).items()}
    return _SYMBOL_MAP_CACHE


# Back-compat: tests import SYMBOL_MAP_DEFAULT
SYMBOL_MAP_DEFAULT = _load_bundled_symbol_map()


def _load_user_symbol_map(repo_root: Path) -> dict[str, list[str]]:
    cfg = repo_root / ".reachable-cve.yml"
    if not cfg.exists():
        return {}
    try:
        data = yaml.safe_load(cfg.read_text()) or {}
        return {k.lower(): list(v) for k, v in (data.get("symbol_map") or {}).items()}
    except Exception:
        return {}


def _symbols_for(package: str, repo_root: Path) -> list[str]:
    user = _load_user_symbol_map(repo_root)
    bundled = _load_bundled_symbol_map()
    key = package.lower()
    if key in user:
        return user[key]
    if key in bundled:
        return bundled[key]
    return [package.lower()]


# ---------- Top-level orchestrator ----------


async def _collect_async(deps: dict[str, str], repo_root: Path) -> list[VulnRecord]:
    async with httpx.AsyncClient(headers={"User-Agent": "reachable-cve/0.2"}) as client:
        kev_task = asyncio.create_task(_kev_set(client))
        per_pkg = await asyncio.gather(
            *[_osv_query(client, name, version) for name, version in deps.items()],
            return_exceptions=True,
        )

        records: list[VulnRecord] = []
        all_cves: list[str] = []
        for (name, version), advs in zip(deps.items(), per_pkg):
            if isinstance(advs, Exception):
                log_event(log, "osv_error", package=name, error=str(advs))
                continue
            for adv in advs:
                cves = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
                all_cves.extend(cves)
                records.append(
                    VulnRecord(
                        osv_id=adv.get("id", ""),
                        cve_ids=cves,
                        package=name,
                        installed_version=version,
                        summary=adv.get("summary") or (adv.get("details", "") or "")[:200],
                        cvss=_extract_cvss(adv),
                        epss=None,
                        in_kev=False,
                        vulnerable_symbols=_symbols_for(name, repo_root),
                        fixed_versions=_fixed_versions(adv),
                    )
                )

        epss_map = await _epss_scores(client, sorted(set(all_cves)))
        kev = await kev_task
        apply_threat_intel(records, epss_map, kev)
        log_event(log, "collect_done", n_packages=len(deps), n_advisories=len(records))
        return records


def collect(repo_root: Path) -> list[VulnRecord]:
    deps = parse_requirements(repo_root)
    if not deps:
        return []
    return asyncio.run(_collect_async(deps, repo_root))
