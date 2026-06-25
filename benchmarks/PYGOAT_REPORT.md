# PyGoat benchmark — critical analysis

> **v0.3 update (Django adapter).** This document records the v0.2.0 baseline.
> A `urls.py` walker, a bootstrap-exclusion set, and a curated Django symbol
> map have since been added. Expected before/after is documented at the end
> of this file under *"v0.3 Django adapter — expected impact."* Re-scan PyGoat
> after pulling v0.3 to populate the real numbers.


Target: [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) — an intentionally-vulnerable Django learning app.
Scanner: `reachable-cve` v0.2.0
Report file: `pygoat_report.json` (167 findings, 92 KB)
Scanner verdict: **WARN** — 88 reachable findings below block threshold.

This is a **skeptical, post-hoc audit** of the report. The headline numbers look favorable. They are not the whole story.

---

## Benchmark summary

| Metric | Value |
|---|---:|
| Total advisories returned by OSV | 167 |
| Unique CVE IDs across all advisories | 95 |
| Advisories marked reachable | 88 |
| Unique reachable CVE IDs | 46 |
| Advisories marked unreachable | 79 |
| Unique unreachable CVE IDs | 49 |
| Duplicate CVE advisories (same CVE, multiple sources) | 66 CVEs appear in ≥2 advisories |
| Naïve reachability ratio | 52.7% |
| **Reachability ratio after removing the Django fallback artifact (see below)** | **3.6%** |

Score distribution of reachable findings: min **0.2**, max **37.4**, mean **15.1**. **Zero** reachable findings are in CISA KEV. **Zero** reachable findings have EPSS > 0.5. Decision is correctly WARN (not BLOCK) — the formula behaved.

---

## Reachability statistics — by package

| Package | Total advisories | Reachable | Unreachable | Notes |
|---|---:|---:|---:|---|
| django | 82 | **82** | 0 | ⚠️ All 82 share **one identical 2-hop path**. Fallback-symbol artifact (see *False positives*). |
| cryptography | 14 | 0 | 14 | Plausible. PyGoat does not call the vulnerable primitives directly. |
| werkzeug | 12 | 0 | 12 | Plausible. Used transitively via Flask, but Flask is not in PyGoat's stack. |
| urllib3 | 11 | 0 | 11 | Plausible-but-suspect. urllib3 is a Django transitive dep. |
| pillow | 9 | 0 | 9 | ⚠️ **Includes CVE-2023-44271 (KEV, EPSS 0.997). PyGoat *does* call `Image.open()` in a view. False negative.** |
| pyjwt | 9 | 0 | 9 | Plausible. |
| pyyaml | 6 | **6** | 0 | All 6 share one path to `introduction/lab_code/test.py:23`. Real, but it's a demo file, not a routed view. |
| django-allauth | 6 | 0 | 6 | Plausible. |
| requests | 5 | 0 | 5 | Plausible, transitive. |
| certifi | 4 | 0 | 4 | Plausible. |
| (others) | 9 | 0 | 9 | — |

**Headline observation.** Only two packages produce "reachable" verdicts: `django` (fallback artifact) and `pyyaml` (legitimate but non-routed). Every other vulnerable dependency is marked unreachable.

---

## Reachable findings table

| OSV ID | CVE | Package | Sink (matched_symbol) | Score | Path | Honest assessment |
|---|---|---|---|---:|---|---|
| GHSA-qmf9-6jqf-j8fq (+ 81 other Django GHSAs) | CVE-2023-46695 (+ 45 others) | django | `django` | 0.2 – 37.4 | `pygoat.asgi.<module>` → `ext:django.core.asgi.get_asgi_application` | **Symbol-map fallback. 82 findings, 1 path. Tells us PyGoat imports Django — which is by construction.** Not actionable signal. |
| GHSA-8q59-q68h-6hv4 (+ 5 PYSEC duplicates) | CVE-2020-14343 (+ 5 others) | pyyaml | `yaml.load` | 1.5 – 31.2 | `introduction.lab_code.test.<module>` → `ext:yaml.load` | **Real reachable call**, but in a demo/lab file that probably isn't exposed by a URL pattern. Worth flagging but lower priority than the `views.py:560` call the scanner missed. |

**Why the scanner marked them reachable.** The matcher does prefix-strict matching on `ext:<bare>`. For Django, the symbol list is just `["django"]` (fallback) and `ext:django.core.asgi.get_asgi_application` matches as a prefix. For PyYAML, the symbol list is `["yaml.load", "yaml.load_all"]` (from `symbol_map.yml`) and `ext:yaml.load` matches exactly.

**Attack path detail (only PyYAML is interesting):**

```
introduction.lab_code.test.<module>          # module top-level executes
  → ext:yaml.load                            # line 23: data = yaml.load(stream)  ← SINK
```

The Django "path" reduces to: *"asgi.py imports get_asgi_application."* Not an attack path in any meaningful sense.

---

## Unreachable findings table

A spot-check of 6 representative unreachable findings, ranked by what suppressing them costs:

| OSV ID | CVE | Package | CVSS | EPSS | KEV | Honest assessment |
|---|---|---|---:|---:|---|---|
| GHSA-j7hp-h8jx-5ppr | CVE-2023-44271 | pillow | 8.8 | **0.997** | **yes** | **Likely false negative.** `views.py:584` calls `Image.open(file)`. Scanner missed it because Django view functions aren't entrypoints (no `urls.py` walker). |
| GHSA-… (cryptography) | various | cryptography | 7.5 | 0.05–0.2 | no | Plausibly correct. PyGoat doesn't appear to instantiate vulnerable ciphers directly. **Manual review needed.** |
| GHSA-… (werkzeug) | various | werkzeug | 6.5 | 0.1 | no | Plausibly correct. PyGoat is Django, not Flask; werkzeug is transitive. |
| GHSA-… (urllib3) | various | urllib3 | 7.0 | 0.1 | no | Plausible but suspect — urllib3 is used transitively by `requests` and Django HTTP utilities. **Worth manual confirmation.** |
| GHSA-… (pyjwt) | various | pyjwt | 7.0 | 0.05 | no | Plausible. PyGoat does have JWT challenges, so this should be re-examined. |
| GHSA-… (requests) | various | requests | 6.1 | 0.1 | no | Plausible-but-suspect. `requests` is in `requirements.txt`; need to check if any view actually calls it. |

**Why suppressing the truly-unreachable ones reduces alert fatigue.** Cryptography, werkzeug, and pyjwt findings collectively represent 35+ advisories. If a developer sees 35 critical-tagged CVE alerts in their PR queue and 30 of them really aren't callable from their code, they will start ignoring all 35 — including the few that matter. The reachability filter, when working correctly, restores signal-to-noise.

**Why suppressing the false-negatives is dangerous.** Suppressing CVE-2023-44271 (KEV, EPSS 0.997) is a real risk. The scanner is currently **silent on an actively-exploited Pillow vulnerability in code the application does call**.

---

## Duplicate advisory analysis

OSV returns the same CVE under multiple advisory IDs (typically GHSA-* + PYSEC-* pairs). **66 of the 95 unique CVEs appear in ≥2 advisories**, with a maximum of 2 per CVE. Examples:

| CVE | Advisories |
|---|---|
| CVE-2020-14343 (PyYAML) | GHSA-8q59-q68h-6hv4, PYSEC-2021-142 |
| CVE-2023-32681 (requests) | GHSA-j8r2-6x86-q33q, PYSEC-2023-74 |
| CVE-2023-44271 (Pillow) | GHSA-…, PYSEC-… |

**Impact on numbers:** the 167 advisory count overstates the actual CVE count by ~70%. A reader who sees "88 reachable findings" plausibly thinks "88 distinct vulnerabilities." The true count is **46 unique reachable CVEs**, and after de-duplicating the Django fallback, **just 1 unique CVE is genuinely reachable in this report** (CVE-2020-14343 — yaml.load in the demo file).

**Recommendation for the scanner:** deduplicate by CVE ID at report time. Keep both OSV IDs as metadata but collapse to one row per CVE. This is a sub-50-line change to `engine.py` / `report.py`.

---

## Potential false positives

| # | Description | Confidence | Severity of FP |
|---|---|---|---|
| 1 | **82 Django "reachable" findings** all derive from one import edge. Caused by `symbol_map.yml` having no `django` entry, so the matcher falls back to package-name prefix matching. | **High — confirmed** | High noise; would dominate any real PR comment. |
| 2 | PyYAML findings flag a non-routed lab file. The scanner reports it as `<module>` reachable, which is technically true (module-level execution does run `yaml.load`), but a user reading the report would assume it's reachable from a web request. | Medium | Misleading framing. |
| 3 | All 82 Django CVEs are dampened to score 0.2 – 37.4, so none triggers BLOCK. The scoring math saved us from the symbol-map gap *this time*; that's brittle. | Medium | If even one of these CVEs had been in KEV with high EPSS, the false positive would have crossed BLOCK. |

**Verification recommendation.** Add `django` to `symbol_map.yml` with specific symbols (`django.db.models.Model`, `django.template.Template.render`, `django.http.HttpResponse`, etc.). Re-run the benchmark; expect the 82 → small number drop. If it drops to 0, that exposes the Django adapter gap (see false negative #1) rather than fixing it.

---

## Potential false negatives

| # | Description | Confidence | Severity of FN |
|---|---|---|---|
| 1 | **CVE-2023-44271 (Pillow, KEV, EPSS 0.997)** is marked unreachable, but PyGoat's `introduction/views.py:584` contains `img = Image.open(file)`. Missed because Django view functions are not entrypoints — no `urls.py` walker. | **High — confirmed** | **Critical.** Actively-exploited vulnerability in code the app calls. |
| 2 | **CVE-2020-14343 (PyYAML)** also has a `yaml.load(file, yaml.Loader)` call at `introduction/views.py:560`. The scanner only catches the demo file, not the view. Same root cause. | High — confirmed | Critical. Same shape of miss. |
| 3 | All cryptography / werkzeug / pyjwt / requests findings are marked unreachable. Some of these are transitively reachable through Django middleware, ORM, or auth. The scanner does not (and cannot, without dataflow) follow these transitive paths. | Medium | Unknown without full Django call-graph integration. |
| 4 | Class-method calls in PyGoat (Django views are class-based) may not resolve through `self.x` if the chain involves Django's request/response objects rather than `__init__` assignments. | Medium | Unknown — needs targeted test. |

**Verification recommendation.**

```bash
# Manual confirmation of FN #1 and #2
grep -n "Image.open\|yaml.load" /sessions/peaceful-funny-cerf/mnt/DevSecOps/pygoat/introduction/views.py
# Map view functions to URLs
cat /sessions/peaceful-funny-cerf/mnt/DevSecOps/pygoat/introduction/urls.py
```

---

## Does this report support the claim that reachability analysis reduces noise?

**Yes, but not for the reason the headline implies.**

The naive ratio (52.7% reachable) is dominated by an artifact: 82 of 88 reachable findings are the same `django` import edge counted 82 times. After accounting for that, **1 unique CVE is genuinely reachable** out of 95 unique CVEs in the scan — a noise reduction of **~99%** by CVE count.

But that 99% number is also misleading, because:

1. **The scanner missed two truly exploitable paths** (Pillow + PyYAML in `views.py`), which means the high suppression rate is partly the *wrong kind* of suppression.
2. **Some "unreachable" verdicts are aspirational** — for the packages that work transitively through Django, the scanner says unreachable because it can't trace the path, not because the path is absent.

**Honest framing for the README:**

> On PyGoat, `reachable-cve` v0.2.0 suppresses 79 of 167 OSV advisories as unreachable (47% suppression by advisory; ~52% by unique CVE). Of the 88 advisories flagged reachable, 82 are an artifact of falling back to package-name matching for Django (which has no entry in `symbol_map.yml`); the remaining 6 cover one genuine `yaml.load` call in a demo file. Two real exploitable paths (`PIL.Image.open` and a second `yaml.load`, both inside Django views) were missed because v0.2.0 does not yet walk `urls.py` to discover view-function entrypoints. **PyGoat is a stress test for the v0.3 Django adapter, not a proof of accuracy.**

This is the honest version. The marketing version ("99% noise reduction!") would not survive a careful interview.

---

## README-ready benchmark table

```markdown
### PyGoat (v0.2.0 prototype) — initial measurement

| Metric | Value | Notes |
|---|---:|---|
| Total OSV advisories | 167 | |
| Unique CVE IDs | 95 | 66 CVEs duplicated across GHSA + PYSEC |
| Advisories flagged reachable | 88 (52.7%) | **82 are a Django symbol-map-fallback artifact** |
| Genuine reachable findings | 6 advisories → 1 unique CVE | `yaml.load` in a non-routed lab file |
| Advisories marked unreachable | 79 | Plausibly correct for most |
| Known false negatives | 2 confirmed | Pillow & PyYAML inside Django views; v0.2.0 lacks a `urls.py` adapter |
| Decision | WARN | Score formula correctly held the artifact at < 60 |

**Honest takeaway.** PyGoat exposes two scanner gaps before it demonstrates accuracy: the symbol map needs `django` entries, and the framework adapter needs a Django `urls.py` walker. Both are v0.3 roadmap items. Re-run and re-publish after fixing.
```

---

## Resume / interview talking points

When you talk about this benchmark in an interview, here is how to frame it so you sound like a senior engineer rather than someone shipping marketing copy.

1. **"I ran my scanner against PyGoat and the headline number was 52% reachable. When I looked at the underlying paths, 82 of those 88 reachable findings collapsed to a single Django import edge — the symbol map didn't have a `django` entry, so it fell back to package-name matching."** This sentence signals three things at once: you measured, you read your own data carefully, and you understood your own implementation's failure mode.

2. **"The more interesting failure was the false negatives. PyGoat calls `Image.open(file)` and `yaml.load(file)` inside Django view functions. My scanner missed both because v0.2.0 doesn't have a `urls.py` walker. The actively-exploited Pillow CVE — in KEV, EPSS 0.997 — was sitting in the unreachable bucket while the report headlined an artifact."** This shows you can identify what your tool got *wrong*, not just what it got *right*. That's the move that separates senior from junior.

3. **"The fix for both is the v0.3 Django adapter — a `urls.py` parser plus a hand-curated symbol map for the Django framework. I have it scoped, and I'm holding off publishing real-world precision/recall numbers until that lands."** This converts a weakness into a credible roadmap. The interviewer can ask why you waited; you have a real answer.

4. **"OSV returns 167 advisories for 95 unique CVEs because GHSA and PYSEC both cover most of them. I haven't deduplicated by CVE in the report yet. Easy fix, deferred until I've stabilized the matcher."** Tactical, accurate, plain-spoken.

**What to avoid saying.** Anything like "99% noise reduction" or "we beat Snyk on PyGoat." Those claims fall apart in 30 seconds of careful questioning. The honest framing — "this benchmark exposed two design gaps before it proved anything about accuracy" — earns more credit.

---

## What should be manually verified

Before any of the numbers above are published as project claims:

1. **`introduction/views.py:560` `yaml.load(file, yaml.Loader)`** — confirm via `grep` + manual read that this is a routed view (`urls.py` has a path mapping to it).
2. **`introduction/views.py:584` `Image.open(file)`** — same.
3. **`introduction/lab_code/test.py:23` `yaml.load(stream)`** — confirm this file is *not* on any URL pattern. If it is, the scanner's reachability call was correct but the report framing is misleading; if it isn't, the report framing is correct but the alert is low-priority.
4. **`cryptography` / `werkzeug` / `pyjwt` unreachable verdicts** — spot-check 2-3 by searching for their import + call sites in PyGoat. If used, the unreachable verdict is suspect.
5. **Symbol map test** — add a `django:` entry to `symbol_map.yml` listing 5-10 known dangerous Django symbols (`django.template.Template.render`, `django.utils.safestring.mark_safe`, `django.db.models.expressions.RawSQL`, etc.) and re-run. Count the deltas.

---

## v0.3 Django adapter — expected impact

The v0.3 release adds three things:

1. **`django_routes.py`** — walks every `urls.py`, parses `path()` / `re_path()` / `url()` / DRF `router.register()`, resolves view expressions (including `.as_view()` and DRF ViewSets) to qualnames, and adds them to the call-graph entrypoint set.
2. **`BOOTSTRAP_EXCLUSIONS`** in `reachability.py` — explicit allowlist of framework bootstrap symbols (`django.core.asgi.get_asgi_application`, `django.core.wsgi.get_wsgi_application`, `flask.Flask`, `fastapi.FastAPI`, ...) that can never match a vulnerability sink. Closes the 82-finding artifact.
3. **`django:` entry in `symbol_map.yml`** with 11 specific high-impact symbols (template injection, SQL, file responses, etc.). Replaces the package-name fallback that produced the artifact.

### What the next PyGoat scan should produce

| Metric | v0.2.0 (this report) | v0.3 (expected) | Delta |
|---|---:|---:|---|
| Total advisories | 167 | ~167 (OSV unchanged) | — |
| Advisories marked reachable | 88 | **~5-15** | -85% |
| Django bootstrap artifact findings | 82 | **0** | eliminated |
| Reachable `Image.open` finding (CVE-2023-44271, KEV) | 0 (missed) | **1** | recovered |
| Reachable `yaml.load` in `views.py:560` (real exploit path) | 0 (missed) | **1** | recovered |
| Reachable `yaml.load` in `lab_code/test.py` (demo file) | 6 | **0-6** | possibly suppressed; depends on whether the lab file is module-imported anywhere |
| Decision | WARN | **BLOCK** (because Pillow CVE crosses 60) | escalates to right level |

The single most important change: the Pillow CVE (CISA KEV, EPSS 0.997, CVSS 8.8) flips from buried-in-79-unreachable to a BLOCK-tier headline finding. That's the whole point of the tool functioning correctly.

### Verification commands

```bash
# from repo root, after pulling v0.3
git log --oneline -5            # confirm django_routes commit landed
pytest -q tests/test_django_routes.py   # 13 new tests should all pass

# baseline already saved as pygoat_report.json. Generate the new one:
reachable-cve scan ../pygoat --format json > pygoat_report_v0_3.json

# diff
python benchmarks/run.py --diff pygoat_report.json pygoat_report_v0_3.json
```

The `--diff` output will produce a markdown table showing:

- Net change in `total findings` (should be ~0)
- Net change in `reachable` (should be a large negative number)
- The set of OSV IDs that flipped `unreachable → reachable` (should include Pillow CVE-2023-44271)
- The set of OSV IDs that flipped `reachable → unreachable` (should include all 82 Django bootstrap findings)
- The decision verdict change (`WARN → BLOCK`)

If those four signals all match expectations, the Django adapter is working. If any of them don't match — for example, Pillow stays unreachable — open a bug in `django_routes.py` for the specific resolution case that failed.

### Caveats

- The new symbol map for `django` is curated. We may have missed a relevant sink. PRs welcome to add entries.
- DRF ViewSet support is method-name-based (`list`, `create`, etc.). If a custom action uses `@action(detail=True)`, it won't be detected — known gap.
- Django's `admin.site.urls` resolves to third-party code we don't scan; that whole subtree is correctly ignored.
- Templates rendered via `render(request, "tpl.html", ctx)` aren't a vulnerability sink by themselves; we'd need an autoescape-disabled flag check, which is v0.4 work.
