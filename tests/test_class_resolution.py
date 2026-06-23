"""Class-aware resolution: self.x = yaml.load; self.x(data) -> yaml.load reachable."""
import textwrap

from reachable_cve.call_graph import build_from_repo
from reachable_cve.reachability import reachable_to


CLASS_VULN = textwrap.dedent("""
    import yaml

    class Loader:
        def __init__(self):
            self._load = yaml.load
        def run(self, data):
            return self._load(data)

    def main():
        return Loader().run("data")
""")

CLASS_SAFE = textwrap.dedent("""
    import yaml

    class Loader:
        def __init__(self):
            self._load = yaml.safe_load
        def run(self, data):
            return self._load(data)

    def main():
        return Loader().run("data")
""")


def _write(root, body):
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "loader.py").write_text(body)


def test_self_dot_alias_to_yaml_load_is_reachable(tmp_path):
    _write(tmp_path, CLASS_VULN)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable, f"path={r.path}"
    assert r.matched_symbol == "yaml.load"


def test_self_dot_alias_to_safe_load_is_unreachable(tmp_path):
    _write(tmp_path, CLASS_SAFE)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert not r.reachable
