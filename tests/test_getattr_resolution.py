"""getattr(mod, 'name') with a string literal must produce a real sink edge."""
import textwrap

from reachable_cve.call_graph import build_from_repo
from reachable_cve.reachability import reachable_to


GETATTR_VULN = textwrap.dedent('''
    import yaml

    load_fn = getattr(yaml, "load")

    def main(data):
        return load_fn(data)
''')

GETATTR_SAFE = textwrap.dedent('''
    import yaml

    load_fn = getattr(yaml, "safe_load")

    def main(data):
        return load_fn(data)
''')


def _write(root, body):
    (root / "app").mkdir(parents=True, exist_ok=True)
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "dyn.py").write_text(body)


def test_getattr_constant_string_resolves_to_sink(tmp_path):
    _write(tmp_path, GETATTR_VULN)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable, f"path={r.path}"


def test_getattr_with_safe_name_does_not_match_load(tmp_path):
    _write(tmp_path, GETATTR_SAFE)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert not r.reachable
