"""Django URL pattern resolver.

Walks every `urls.py` in the repo, extracts route declarations
(`path()`, `re_path()`, the legacy `url()`, and DRF `router.register()`),
and resolves the view expression to one or more qualnames that the call-graph
builder should treat as entrypoints.

What we resolve today:
  - `path("foo/", views.my_view)`          -> ["<pkg>.views.my_view"]
  - `path("foo/", MyView.as_view())`        -> ["<pkg>.MyView.<http-method>" for method in {get,post,...}]
  - `path("foo/", views.MyView.as_view())`  -> ["<pkg>.views.MyView.<http-method>" ...]
  - `re_path(r"^foo$", views.fn)`           -> same as path()
  - `path("api/", include("api.urls"))`     -> handled implicitly: every urls.py is processed,
                                               so views in api/urls.py get their own entries
  - `router.register("users", UserViewSet)` -> ["<pkg>.UserViewSet.<drf-method>" ...]

What we DON'T resolve:
  - Cross-package include() that points at an installed third-party app
  - Dynamic URLConf assembly (e.g. patterns built in a loop)
  - View expressions that aren't a Name or AttributeAccess
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tree_sitter_languages import get_parser


_parser = get_parser("python")


HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")
DRF_VIEWSET_METHODS = ("list", "create", "retrieve", "update", "partial_update", "destroy")


@dataclass
class Route:
    pattern: str
    view_expr: str       # textual view expression
    urls_file: Path


@dataclass
class DRFRegistration:
    prefix: str
    viewset_expr: str
    urls_file: Path


# ---------- helpers ----------


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _is_route_call(name: str) -> bool:
    """`path`, `re_path`, `url`, or any attribute access ending in those."""
    if name in {"path", "re_path", "url"}:
        return True
    return name.endswith(".path") or name.endswith(".re_path") or name.endswith(".url")


def _is_register_call(name: str) -> bool:
    """`router.register` / `*.register` from DRF DefaultRouter / SimpleRouter."""
    return name == "register" or name.endswith(".register")


def _positional_args(call_node, src: bytes) -> list[str]:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    out = []
    for child in args.children:
        if child.type in ("(", ")", ","):
            continue
        if child.type == "keyword_argument":
            continue
        out.append(_text(child, src))
    return out


# ---------- urls.py discovery ----------


def find_urls_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("urls.py"):
        sp = str(p)
        if any(seg in sp for seg in
               ("/.venv/", "/venv/", "/site-packages/", "/.git/", "/build/", "/dist/", "\\.venv\\", "\\venv\\")):
            continue
        out.append(p)
    return out


# ---------- single-file parser ----------


def _walk_for_routes(node, src: bytes, urls_file: Path,
                     routes: list[Route], drfs: list[DRFRegistration]) -> None:
    if node.type == "call":
        func = node.child_by_field_name("function")
        if func is not None:
            fname = _text(func, src)
            args = _positional_args(node, src)
            if _is_route_call(fname) and len(args) >= 2:
                routes.append(Route(
                    pattern=args[0].strip("'\"r"),
                    view_expr=args[1].strip(),
                    urls_file=urls_file,
                ))
            elif _is_register_call(fname) and len(args) >= 2:
                drfs.append(DRFRegistration(
                    prefix=args[0].strip("'\"r"),
                    viewset_expr=args[1].strip(),
                    urls_file=urls_file,
                ))
    for c in node.children:
        _walk_for_routes(c, src, urls_file, routes, drfs)


def parse_urls_file(urls_file: Path) -> tuple[list[Route], list[DRFRegistration]]:
    src = urls_file.read_bytes()
    tree = _parser.parse(src)
    routes: list[Route] = []
    drfs: list[DRFRegistration] = []
    _walk_for_routes(tree.root_node, src, urls_file, routes, drfs)
    return routes, drfs


# ---------- view expression -> qualname ----------


def _app_prefix_for(urls_file: Path, repo_root: Path) -> str:
    """The dotted module path of the directory containing urls.py.

    /repo/myapp/urls.py            -> "myapp"
    /repo/pygoat/intro/urls.py     -> "pygoat.intro"
    /repo/urls.py                  -> ""
    """
    try:
        rel = urls_file.parent.relative_to(repo_root)
    except ValueError:
        return ""
    parts = [p for p in rel.parts if p not in (".", "")]
    return ".".join(parts)


def _strip_as_view(expr: str) -> tuple[str, bool]:
    """Strip a trailing `.as_view(...)` or `.as_view`. Returns (base, was_class_based).

    Uses substring search rather than parens-stripping, because a destructive
    `rstrip(")")` would chew through the parens we are trying to find.
    """
    e = expr.strip()
    idx = e.find(".as_view(")
    if idx >= 0:
        return e[:idx], True
    if e.endswith(".as_view"):
        return e[: -len(".as_view")], True
    return e, False


def _normalize_view_qualname(view_expr: str, urls_file: Path, repo_root: Path) -> list[str]:
    """Resolve a view expression to one or more entrypoint qualnames.

    Returns [] if the expression is `include(...)` or otherwise unresolvable.
    """
    expr = view_expr.strip()
    if expr.startswith("include("):
        return []
    if not expr:
        return []

    base, is_cbv = _strip_as_view(expr)
    base = base.strip()
    if not base:
        return []

    prefix = _app_prefix_for(urls_file, repo_root)

    # If the user wrote a dotted form starting with "views" or just a bare class/func,
    # qualify it with the prefix. If it's already absolutely qualified, leave it alone.
    parts = base.split(".")
    if parts[0] in {"views", "viewsets", "api"} or len(parts) == 1:
        qual = f"{prefix}.{base}" if prefix else base
    else:
        qual = base

    if is_cbv:
        return [f"{qual}.{m}" for m in HTTP_METHODS]
    return [qual]


def _viewset_methods_qualname(viewset_expr: str, urls_file: Path, repo_root: Path) -> list[str]:
    """DRF ViewSet — return the six standard methods qualified."""
    base = viewset_expr.strip().lstrip("(").rstrip(")")
    if not base:
        return []
    prefix = _app_prefix_for(urls_file, repo_root)
    parts = base.split(".")
    if parts[0] in {"views", "viewsets", "api"} or len(parts) == 1:
        qual = f"{prefix}.{base}" if prefix else base
    else:
        qual = base
    return [f"{qual}.{m}" for m in DRF_VIEWSET_METHODS]


# ---------- top-level: discover all view entrypoints ----------


def discover_entrypoints(repo_root: Path) -> set[str]:
    """Walk every urls.py and return the qualnames every routed view should be marked as."""
    entries: set[str] = set()
    for urls_file in find_urls_files(repo_root):
        routes, drfs = parse_urls_file(urls_file)
        for r in routes:
            for q in _normalize_view_qualname(r.view_expr, urls_file, repo_root):
                entries.add(q)
        for d in drfs:
            for q in _viewset_methods_qualname(d.viewset_expr, urls_file, repo_root):
                entries.add(q)
    return entries
