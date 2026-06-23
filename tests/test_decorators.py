"""Decorated functions parse correctly and decorators are recorded."""
import textwrap

from reachable_cve.call_graph import build_from_repo
from reachable_cve.parser import parse_repo


WRAPPED = textwrap.dedent("""
    import functools
    import yaml

    def cached(fn):
        @functools.wraps(fn)
        def inner(*a, **kw):
            return fn(*a, **kw)
        return inner

    @cached
    def loader(data):
        return yaml.load(data)

    def main():
        return loader("x")
""")


def test_decorator_names_are_recorded(tmp_path):
    (tmp_path / "app.py").write_text(WRAPPED)
    mods = parse_repo(tmp_path)
    fn_decos = {f.name: f.decorators for m in mods for f in m.functions}
    # `inner` is decorated with @functools.wraps(fn) — args stripped, name kept
    assert fn_decos["inner"] == ["functools.wraps"]
    # `loader` is decorated with @cached
    assert fn_decos["loader"] == ["cached"]
    # `cached` and `main` are undecorated
    assert fn_decos["cached"] == []
    assert fn_decos["main"] == []


def test_decorated_function_body_still_reaches_sink(tmp_path):
    (tmp_path / "app.py").write_text(WRAPPED)
    from reachable_cve.reachability import reachable_to
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable, "loader's body calls yaml.load; reachability should find it"
