"""Framework-decorated handlers become entrypoints."""
import textwrap

from reachable_cve.call_graph import build_from_repo
from reachable_cve.frameworks import is_entrypoint_decorator
from reachable_cve.reachability import reachable_to


def test_decorator_suffix_match():
    assert is_entrypoint_decorator("app.route")
    assert is_entrypoint_decorator("router.get")
    assert is_entrypoint_decorator("blueprint.route")
    assert is_entrypoint_decorator("api.app.post")  # FastAPI APIRouter rename
    assert not is_entrypoint_decorator("requests.get")  # too generic
    assert not is_entrypoint_decorator("my_custom_decorator")


FASTAPI_APP = textwrap.dedent("""
    import yaml
    from fastapi import APIRouter
    router = APIRouter()

    def _load(s):
        return yaml.load(s)

    @router.post("/upload")
    def upload(data: str):
        return _load(data)
""")


def test_fastapi_route_makes_handler_an_entrypoint(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "api.py").write_text(FASTAPI_APP)
    cg = build_from_repo(tmp_path)
    # upload is decorated with @router.post → should be in entrypoints
    assert any(ep.endswith(".upload") for ep in cg.entrypoints), \
        f"entries: {sorted(cg.entrypoints)}"
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable, f"path={r.path}"


FLASK_APP = textwrap.dedent("""
    import yaml
    from flask import Flask
    app = Flask(__name__)

    @app.route("/load")
    def load(data):
        return yaml.load(data)
""")


def test_flask_route_makes_handler_an_entrypoint(tmp_path):
    (tmp_path / "app.py").write_text(FLASK_APP)
    cg = build_from_repo(tmp_path)
    assert any(ep.endswith(".load") for ep in cg.entrypoints)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable
