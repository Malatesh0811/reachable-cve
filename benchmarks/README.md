# Benchmarks

Reproducible accuracy measurements for `reachable-cve`. Run them every time
you change the parser, call graph, or reachability code.

## What's here

- `labels.yml` — hand-labeled ground truth (which CVEs are *actually* reachable
  in each target repo)
- `run.py` — scans each target, compares to labels, prints precision/recall/F1

## Targets

| Target | Path | Notes |
|---|---|---|
| `demo_vulnerable` | `examples/demo_repo` (vendored) | One reachable + two unreachable CVEs |
| `clean_baseline` | `examples/demo_repo_clean` | Vulnerable deps pinned, none ever called |
| `pygoat` | `benchmarks/_external/pygoat` (clone first) | Intentionally-vulnerable Django app |

## Run

```bash
# pip install -e .[dev]   (once)

# Local-only targets (demo_vulnerable + clean_baseline)
python benchmarks/run.py

# Add PyGoat
git clone https://github.com/adeyosemanputra/pygoat benchmarks/_external/pygoat
python benchmarks/run.py

# GitHub-flavored markdown table for the README
python benchmarks/run.py --output md > benchmarks/RESULTS.md
```

Expected console output (demo + clean baselines only):

```
demo_vulnerable      P=1.000 R=1.000 F1=1.000  (1TP 0FP 2TN 0FN) decision=BLOCK
clean_baseline       P=0.000 R=0.000 F1=0.000  (0TP 0FP 0TN 0FN) decision=PASS
```

## How to add a target

1. Place / clone the repo under `benchmarks/_external/<name>` (gitignored).
2. Run a scan: `reachable-cve scan benchmarks/_external/<name> --format json > /tmp/raw.json`
3. Read each finding and decide if it's *really* reachable. Add to `labels.yml`:
   ```yaml
   <name>:
     path: ./_external/<name>
     ground_truth:
       CVE-XXXX-YYYY: { reachable_truth: true, rationale: "called from views.py:42" }
   ```
4. Re-run `python benchmarks/run.py` and confirm precision/recall match expectations.

## How precision/recall are computed

- **TP**: we flagged it as reachable AND truth says reachable.
- **FP**: we flagged it as reachable BUT truth says unreachable.
- **FN**: we said unreachable BUT truth says reachable.
- **TN**: we said unreachable AND truth agrees.

Findings that aren't in the labels file are ignored (ungraded — don't penalize).
