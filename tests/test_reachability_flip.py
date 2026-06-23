"""Regression test: swapping yaml.load -> yaml.safe_load flips reachability."""
import textwrap
from pathlib import Path

from reachable_cve.call_graph import build_from_repo
from reachable_cve.reachability import reachable_to


VULNERABLE = textwrap.dedent("""
    import yaml

    def load_config(path):
        with open(path) as f:
            return yaml.load(f)

    def main():
        return load_config("config.yml")
""")

SAFE = textwrap.dedent("""
    import yaml

    def load_config(path):
        with open(path) as f:
            return yaml.safe_load(f)

    def main():
        return load_config("config.yml")
""")


def _write_repo(root: Path, body: str):
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "config.py").write_text(body)


def test_yaml_load_is_reachable(tmp_path):
    _write_repo(tmp_path, VULNERABLE)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load", "yaml.load_all"])
    assert r.reachable
    assert r.matched_symbol == "yaml.load"
    assert r.path[-1] == "ext:yaml.load"
    # path includes the intermediate function we called through
    assert any("load_config" in n for n in r.path)


def test_path_reconstruction_yields_file_lines(tmp_path):
    _write_repo(tmp_path, VULNERABLE)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable
    # at least one edge should have (file, line) — the actual yaml.load call site
    assert r.sink_locations, "expected sink_locations to be populated"
    last_file, last_line = r.sink_locations[-1]
    assert last_file.name == "config.py"
    assert isinstance(last_line, int) and last_line > 0


def test_swap_to_safe_load_makes_it_unreachable(tmp_path):
    _write_repo(tmp_path, SAFE)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load", "yaml.load_all"])
    # yaml.safe_load is NOT in the vulnerable symbol list and the strict
    # prefix matcher (yaml.load + "." or exact) must NOT match "yaml.safe_load".
    assert not r.reachable, f"safe_load should not match yaml.load; got path={r.path}"


def test_safe_load_still_appears_in_callgraph(tmp_path):
    """Negative-control sanity check: the parser still saw the call, just not as a sink."""
    _write_repo(tmp_path, SAFE)
    cg = build_from_repo(tmp_path)
    nodes = set(cg.graph.nodes)
    assert "ext:yaml.safe_load" in nodes, "tree-sitter must have produced the safe_load edge"
