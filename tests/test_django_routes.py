"""Django URL adapter: parse urls.py, treat routed views as entrypoints."""
import textwrap
from pathlib import Path

from reachable_cve.call_graph import build_from_repo
from reachable_cve.django_routes import (
    discover_entrypoints,
    find_urls_files,
    parse_urls_file,
)
from reachable_cve.reachability import BOOTSTRAP_EXCLUSIONS, reachable_to


# ---------- helpers ----------


def _mk_django_app(root: Path, urls_body: str, views_body: str, app: str = "app"):
    (root / app).mkdir(parents=True, exist_ok=True)
    (root / app / "__init__.py").write_text("")
    (root / app / "urls.py").write_text(urls_body)
    (root / app / "views.py").write_text(views_body)


# ---------- 1. direct path() routes ----------


PATH_ROUTES_URLS = textwrap.dedent("""
    from django.urls import path
    from . import views

    urlpatterns = [
        path("upload/", views.upload),
        path("show/<int:pk>/", views.show),
    ]
""")

PATH_ROUTES_VIEWS = textwrap.dedent("""
    import yaml

    def upload(request):
        return yaml.load(request.FILES["f"])     # SINK: reachable

    def show(request, pk):
        return None
""")


def test_path_route_promotes_view_to_entrypoint(tmp_path):
    _mk_django_app(tmp_path, PATH_ROUTES_URLS, PATH_ROUTES_VIEWS)
    cg = build_from_repo(tmp_path)
    assert "app.views.upload" in cg.entrypoints
    assert "app.views.show" in cg.entrypoints


def test_yaml_load_inside_routed_view_is_reachable(tmp_path):
    _mk_django_app(tmp_path, PATH_ROUTES_URLS, PATH_ROUTES_VIEWS)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable, f"path={r.path}"
    assert r.path[0].startswith("app.views.upload"), f"unexpected entry: {r.path}"
    assert r.path[-1] == "ext:yaml.load"


# ---------- 2. re_path() ----------


RE_PATH_URLS = textwrap.dedent(r"""
    from django.urls import re_path
    from . import views

    urlpatterns = [
        re_path(r"^api/upload$", views.upload),
    ]
""")


def test_re_path_route_promotes_view(tmp_path):
    _mk_django_app(tmp_path, RE_PATH_URLS, PATH_ROUTES_VIEWS)
    cg = build_from_repo(tmp_path)
    assert "app.views.upload" in cg.entrypoints


# ---------- 3. nested include() ----------


ROOT_URLS = textwrap.dedent("""
    from django.urls import path, include

    urlpatterns = [
        path("api/", include("api.urls")),
    ]
""")

API_URLS = textwrap.dedent("""
    from django.urls import path
    from . import views

    urlpatterns = [
        path("data/", views.fetch),
    ]
""")

API_VIEWS = textwrap.dedent("""
    import yaml
    def fetch(request):
        return yaml.load(request.body)            # SINK in an included urls.py
""")


def test_included_urls_views_become_entrypoints(tmp_path):
    # Root project at tmp_path/myproj, included app at tmp_path/api
    (tmp_path / "myproj").mkdir()
    (tmp_path / "myproj" / "__init__.py").write_text("")
    (tmp_path / "myproj" / "urls.py").write_text(ROOT_URLS)
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "__init__.py").write_text("")
    (tmp_path / "api" / "urls.py").write_text(API_URLS)
    (tmp_path / "api" / "views.py").write_text(API_VIEWS)

    cg = build_from_repo(tmp_path)
    assert "api.views.fetch" in cg.entrypoints, sorted(cg.entrypoints)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable


# ---------- 4. class-based views via .as_view() ----------


CBV_URLS = textwrap.dedent("""
    from django.urls import path
    from . import views

    urlpatterns = [
        path("upload/", views.UploadView.as_view()),
    ]
""")

CBV_VIEWS = textwrap.dedent("""
    import yaml
    from django.views import View

    class UploadView(View):
        def post(self, request):
            return yaml.load(request.body)        # SINK: reachable via .as_view()
        def get(self, request):
            return None
""")


def test_class_based_view_methods_become_entrypoints(tmp_path):
    _mk_django_app(tmp_path, CBV_URLS, CBV_VIEWS)
    cg = build_from_repo(tmp_path)
    # The adapter adds <Class>.<http-method> for each canonical method.
    assert "app.views.UploadView.post" in cg.entrypoints
    assert "app.views.UploadView.get" in cg.entrypoints


def test_cbv_post_method_reaches_yaml_load(tmp_path):
    _mk_django_app(tmp_path, CBV_URLS, CBV_VIEWS)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable, f"path={r.path}"
    assert "post" in r.path[0], f"expected post() in entry: {r.path[0]}"


# ---------- 5. DRF ViewSets ----------


DRF_URLS = textwrap.dedent("""
    from django.urls import path, include
    from rest_framework.routers import DefaultRouter
    from . import views

    router = DefaultRouter()
    router.register(r"users", views.UserViewSet)

    urlpatterns = [path("", include(router.urls))]
""")

DRF_VIEWS = textwrap.dedent("""
    import yaml
    from rest_framework import viewsets

    class UserViewSet(viewsets.ModelViewSet):
        def create(self, request):
            return yaml.load(request.body)        # SINK: reachable via DRF router
""")


def test_drf_viewset_methods_become_entrypoints(tmp_path):
    _mk_django_app(tmp_path, DRF_URLS, DRF_VIEWS)
    cg = build_from_repo(tmp_path)
    assert "app.views.UserViewSet.create" in cg.entrypoints
    assert "app.views.UserViewSet.list" in cg.entrypoints


def test_drf_viewset_create_reaches_yaml_load(tmp_path):
    _mk_django_app(tmp_path, DRF_URLS, DRF_VIEWS)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["yaml.load"])
    assert r.reachable


# ---------- 6. bootstrap exclusion: ASGI import doesn't count as Django sink ----------


ASGI_ONLY = textwrap.dedent("""
    import os
    from django.core.asgi import get_asgi_application
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "x.settings")
    application = get_asgi_application()
""")


def test_asgi_bootstrap_is_excluded_from_matches(tmp_path):
    """Headline PyGoat FP: 82 findings from one asgi.py import. Must not match."""
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "__init__.py").write_text("")
    (tmp_path / "proj" / "asgi.py").write_text(ASGI_ONLY)
    cg = build_from_repo(tmp_path)
    # Even with the dumbest possible symbol list, the bootstrap should not match
    for sym_list in (["django"], ["django.core"], ["django.core.asgi"]):
        r = reachable_to(cg, sym_list)
        assert not r.reachable, (
            f"asgi bootstrap matched for symbols={sym_list}; path={r.path}"
        )


def test_bootstrap_exclusion_set_contains_get_asgi_application():
    assert "django.core.asgi.get_asgi_application" in BOOTSTRAP_EXCLUSIONS
    assert "django.core.wsgi.get_wsgi_application" in BOOTSTRAP_EXCLUSIONS


# ---------- 7. specific Django sinks still match ----------


TEMPLATE_VIEW = textwrap.dedent("""
    from django.urls import path
    from . import views
    urlpatterns = [path("show/", views.unsafe_render)]
""")

TEMPLATE_VIEW_CODE = textwrap.dedent("""
    from django.template import Template, Context
    def unsafe_render(request):
        t = Template(request.GET["src"])
        return t.render(Context({}))              # SINK: SSTI via attacker-controlled template
""")


def test_django_template_render_is_a_real_sink(tmp_path):
    _mk_django_app(tmp_path, TEMPLATE_VIEW, TEMPLATE_VIEW_CODE)
    cg = build_from_repo(tmp_path)
    r = reachable_to(cg, ["django.template.Template.render"])
    assert r.reachable, f"path={r.path}"


# ---------- 8. utilities: urls.py discovery and parser ----------


def test_find_urls_files_skips_venv(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "urls.py").write_text("urlpatterns = []")
    (tmp_path / ".venv" / "lib" / "site-packages").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "site-packages" / "urls.py").write_text("urlpatterns = []")
    found = find_urls_files(tmp_path)
    assert any("app" in str(p) for p in found)
    assert not any(".venv" in str(p) for p in found)


def test_parse_urls_file_returns_routes_and_drf(tmp_path):
    (tmp_path / "u.py").write_text(DRF_URLS)
    routes, drfs = parse_urls_file(tmp_path / "u.py")
    assert any(d.viewset_expr.endswith("UserViewSet") for d in drfs), drfs
    assert len(routes) >= 1  # the include() row counts as a route call too
