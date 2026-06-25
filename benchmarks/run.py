"""Benchmark runner: scans each target in labels.yml, compares findings to
ground truth, and prints precision/recall/F1.

Usage:
    python benchmarks/run.py
    python benchmarks/run.py --target pygoat   # single target
    python benchmarks/run.py --output md       # GitHub-flavored markdown table
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

# allow `python benchmarks/run.py` from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reachable_cve.engine import scan  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
LABELS = Path(__file__).with_name("labels.yml")


def _confusion(predicted: dict[str, bool], truth: dict[str, bool]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    keys = set(predicted) | set(truth)
    for k in keys:
        p = predicted.get(k)
        t = truth.get(k)
        if t is None:
            continue  # ungraded — don't count
        if p is None:
            # We didn't even surface this CVE — counts as a miss only if truth was True
            if t:
                fn += 1
            continue
        if t and p: tp += 1
        elif t and not p: fn += 1
        elif not t and p: fp += 1
        else: tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _metrics(c: dict[str, int]) -> dict[str, float]:
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


def _scan_target(name: str, spec: dict) -> dict:
    path = (REPO_ROOT / "benchmarks" / spec["path"]).resolve() if not Path(spec["path"]).is_absolute() else Path(spec["path"])
    if not path.exists():
        return {"target": name, "status": "skipped", "reason": f"path missing: {path}"}

    result = scan(path)
    predicted = {}
    for f in result.findings:
        for cve in f.vuln.cve_ids:
            predicted[cve] = f.reach.reachable

    truth_block = (spec.get("ground_truth") or {})
    truth = {cve: bool(d.get("reachable_truth", False)) for cve, d in truth_block.items()}

    conf = _confusion(predicted, truth)
    return {
        "target": name,
        "status": "ok",
        "path": str(path),
        "n_predicted": len(predicted),
        "n_labeled": len(truth),
        "decision": result.decision.verdict,
        "confusion": conf,
        "metrics": _metrics(conf),
    }


def _render_markdown(reports: list[dict]) -> str:
    out = ["# reachable-cve benchmark", ""]
    out.append("| Target | Predicted | Labeled | Precision | Recall | F1 | Decision |")
    out.append("|---|---:|---:|---:|---:|---:|---|")
    for r in reports:
        if r["status"] != "ok":
            out.append(f"| {r['target']} | — | — | — | — | — | {r.get('reason', r['status'])} |")
            continue
        m = r["metrics"]
        out.append(
            f"| {r['target']} | {r['n_predicted']} | {r['n_labeled']} | "
            f"{m['precision']} | {m['recall']} | {m['f1']} | {r['decision']} |"
        )
    return "\n".join(out)


def _scan_to_findings_dict(path: Path) -> dict[str, dict]:
    """Run a scan on a path and return {osv_id: minimal_finding_dict}."""
    result = scan(path)
    out = {}
    for f in result.findings:
        out[f.vuln.osv_id] = {
            "osv_id": f.vuln.osv_id,
            "cve_ids": f.vuln.cve_ids,
            "package": f.vuln.package,
            "reachable": f.reach.reachable,
            "matched_symbol": f.reach.matched_symbol,
            "score": f.score,
            "severity": f.severity_label,
        }
    return out


def _diff_reports(before_path: Path, after_path: Path) -> str:
    """Compare two saved JSON reports (each in the JSON output shape from scan_cmd).

    Returns a markdown report of: counts before/after, decision change, which
    findings flipped reachable, which paths flipped sink.
    """
    a = json.loads(before_path.read_text())
    b = json.loads(after_path.read_text())

    def by_id(d):
        return {f["osv_id"]: f for f in d.get("findings", [])}

    ba = by_id(a)
    bb = by_id(b)
    all_ids = set(ba) | set(bb)

    def count(d, **filters):
        items = d.get("findings", [])
        for k, v in filters.items():
            items = [f for f in items if f.get(k) == v]
        return len(items)

    lines = ["# benchmark diff", ""]
    lines.append(f"- before file: `{before_path.name}`")
    lines.append(f"- after  file: `{after_path.name}`")
    lines.append("")
    lines.append("| metric | before | after | delta |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| total findings | {len(ba)} | {len(bb)} | {len(bb)-len(ba):+d} |")
    lines.append(f"| reachable | {count(a, reachable=True)} | {count(b, reachable=True)} | {count(b, reachable=True)-count(a, reachable=True):+d} |")
    lines.append(f"| unreachable | {count(a, reachable=False)} | {count(b, reachable=False)} | {count(b, reachable=False)-count(a, reachable=False):+d} |")
    lines.append(f"| decision | {a.get('decision',{}).get('verdict','?')} | {b.get('decision',{}).get('verdict','?')} | — |")
    lines.append("")

    flipped_to_reachable = []
    flipped_to_unreachable = []
    added = []
    removed = []
    for oid in all_ids:
        fa, fb = ba.get(oid), bb.get(oid)
        if fa is None: added.append(oid); continue
        if fb is None: removed.append(oid); continue
        if not fa["reachable"] and fb["reachable"]:
            flipped_to_reachable.append((oid, fb))
        if fa["reachable"] and not fb["reachable"]:
            flipped_to_unreachable.append((oid, fa))

    def _list(rows, title):
        if not rows: return
        lines.append(f"## {title}  ({len(rows)})")
        lines.append("")
        lines.append("| OSV | package | sink | score |")
        lines.append("|---|---|---|---:|")
        for oid, f in rows[:50]:
            lines.append(f"| `{oid}` | {f.get('package','?')} | `{f.get('matched_symbol') or '—'}` | {f.get('score','?')} |")
        lines.append("")

    _list(flipped_to_reachable, "Flipped → reachable (was unreachable in baseline)")
    _list(flipped_to_unreachable, "Flipped → unreachable (was reachable in baseline)")

    if added:
        lines.append(f"## New findings ({len(added)})")
        lines.append(", ".join(f"`{o}`" for o in sorted(added)[:30]) + (" …" if len(added) > 30 else ""))
        lines.append("")
    if removed:
        lines.append(f"## Removed findings ({len(removed)})")
        lines.append(", ".join(f"`{o}`" for o in sorted(removed)[:30]) + (" …" if len(removed) > 30 else ""))
        lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", help="run a single target by name")
    ap.add_argument("--output", choices=["json", "md", "text"], default="text")
    ap.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"),
                    help="Diff two JSON report files and exit")
    args = ap.parse_args()

    if args.diff:
        print(_diff_reports(Path(args.diff[0]), Path(args.diff[1])))
        return

    spec = yaml.safe_load(LABELS.read_text())
    targets = spec.get("targets") or {}
    if args.target:
        targets = {args.target: targets[args.target]}

    reports = [_scan_target(name, t) for name, t in targets.items()]

    if args.output == "json":
        print(json.dumps(reports, indent=2, default=str))
    elif args.output == "md":
        print(_render_markdown(reports))
    else:
        for r in reports:
            if r["status"] != "ok":
                print(f"{r['target']:20} SKIP  {r.get('reason','')}")
                continue
            m = r["metrics"]
            print(f"{r['target']:20} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}  "
                  f"({r['confusion']['tp']}TP {r['confusion']['fp']}FP "
                  f"{r['confusion']['tn']}TN {r['confusion']['fn']}FN) decision={r['decision']}")


if __name__ == "__main__":
    main()
