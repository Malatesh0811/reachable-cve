"""Interprocedural call-graph construction with Tier 2 resolution.

Tier 2 wins over Tier 1:
  - `self.attr` is resolved using __init__ assignments (class-aware).
  - `getattr(mod, "fn")(x)` produces a real edge to ext:mod.fn.
  - Framework decorators (Flask/FastAPI/Celery/...) seed extra entrypoints.
  - Re-exports of local symbols resolve to local qualnames, not ext:.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from .frameworks import is_entrypoint_decorator
from .parser import (
    ClassAttrAssign,
    GetattrAlias,
    ImportRecord,
    ParsedModule,
    parse_repo,
)


@dataclass
class CallGraph:
    graph: nx.DiGraph
    entrypoints: set[str]
    source_locations: dict[str, tuple[Path, int]]
    # qualname -> list of kwarg names recorded at the (last) call site reaching it
    sink_call_kwargs: dict[str, list[list[str]]] = field(default_factory=dict)


def _alias_table(imports: list[ImportRecord]) -> dict[str, str]:
    table: dict[str, str] = {}
    for imp in imports:
        if imp.names:
            for orig, alias in imp.names:
                table[alias] = f"{imp.module}.{orig}" if imp.module else orig
        else:
            table[imp.alias or imp.module] = imp.module
    return table


def _resolve_callee(
    expr: str,
    aliases: dict[str, str],
    local_funcs: set[str],
    module: str,
    class_attr_table: dict[tuple[str, str], str] | None = None,
    enclosing: str | None = None,
    getattr_table: dict[tuple[str, str], str] | None = None,
    local_var_table: dict[tuple[str, str], str] | None = None,
) -> list[str]:
    """Resolve a textual callee expression to one or more qualnames."""
    expr = expr.strip()
    if not expr or expr.startswith("("):
        return [f"unknown:{expr}"]

    parts = expr.split(".")
    head = parts[0]
    tail = parts[1:]

    # Local-var class binding: t = Template(...); t.render(...) -> Template.render(...)
    # We rewrite the expression to start with the bound class name, then recurse.
    # Falls back silently if the variable isn't tracked.
    if tail and local_var_table and enclosing:
        bound = local_var_table.get((enclosing, head))
        if bound is not None:
            return _resolve_callee(
                bound + "." + ".".join(tail),
                aliases, local_funcs, module,
                class_attr_table=class_attr_table, enclosing=enclosing,
                getattr_table=getattr_table, local_var_table=local_var_table,
            )

    # Class instantiation chain: "<LocalClass>().method[...]" -> "<module>.<LocalClass>.method[...]"
    # tree-sitter emits the literal text of the function expression, so a call
    # like Loader().run("x") arrives here with head="Loader()" and tail=["run"].
    if head.endswith("()") and tail:
        cls = head[:-2]
        candidate = f"{module}.{cls}." + ".".join(tail)
        if candidate in local_funcs:
            return [candidate]

    # Class-aware: self.X / self.X.Y...
    if head == "self" and tail:
        attr = tail[0]
        rest = tail[1:]
        # Find the class we're inside by walking the enclosing qualname up.
        # enclosing looks like "module.Class.method" — class is the parent of method.
        if enclosing and class_attr_table:
            enc_parts = enclosing.split(".")
            for cut in range(len(enc_parts) - 1, 0, -1):
                class_qual = ".".join(enc_parts[:cut])
                rhs = class_attr_table.get((class_qual, attr))
                if rhs is not None:
                    # Re-resolve the RHS expression as a callee, then optionally
                    # append any further attribute access.
                    resolved = _resolve_callee(
                        rhs, aliases, local_funcs, module,
                        class_attr_table=class_attr_table, enclosing=enclosing,
                        getattr_table=getattr_table,
                    )
                    if rest:
                        return [r + "." + ".".join(rest) if not r.startswith(("ext:", "unknown:")) else r + "." + ".".join(rest) for r in resolved]
                    return resolved
        return []  # punt on unresolved self.x

    # getattr alias: local = getattr(yaml, "load") -> calling `local(...)` hits yaml.load.
    # Table is keyed by module (not enclosing scope) so a module-level alias is
    # visible to every function defined in the same module.
    if getattr_table and not tail:
        ga = getattr_table.get((module, head))
        if ga is not None:
            return [f"ext:{ga}"]

    if not tail:
        local = f"{module}.{head}"
        if local in local_funcs:
            return [local]
        if head in aliases:
            # Re-export check: an aliased import that points at a known local function
            # should resolve to the local function, not ext:.
            base = aliases[head]
            if base in local_funcs:
                return [base]
            return [f"ext:{base}"]
        return [f"unknown:{head}"]

    if head in aliases:
        base = aliases[head]
        full = base + "." + ".".join(tail)
        if full in local_funcs:
            return [full]
        return [f"ext:{full}"]

    local = f"{module}.{head}." + ".".join(tail)
    if local in local_funcs:
        return [local]
    return [f"unknown:{expr}"]


def _build_class_attr_table(modules: list[ParsedModule]) -> dict[tuple[str, str], str]:
    table: dict[tuple[str, str], str] = {}
    for m in modules:
        for ca in m.class_attr_assigns:
            table[(ca.class_qualname, ca.attr)] = ca.rhs_expr
    return table


def _build_local_var_table(modules: list[ParsedModule]) -> dict[tuple[str, str], str]:
    """(scope_qualname, local_name) -> class_name from `name = Class(...)` assignments."""
    table: dict[tuple[str, str], str] = {}
    for m in modules:
        for lv in m.local_var_assigns:
            table[(lv.scope_qualname, lv.local_name)] = lv.callee_name
    return table


def _build_getattr_table(modules: list[ParsedModule]) -> dict[tuple[str, str], str]:
    """(module_name, local_name) -> 'base.attr'

    Keyed by module so a module-level `load_fn = getattr(yaml, "load")` is
    visible from every function in that module. Function-local getattr aliases
    are tracked at module scope too — fine for Tier 2, since variable shadowing
    by the same name is rare in practice.
    """
    table: dict[tuple[str, str], str] = {}
    for m in modules:
        aliases = _alias_table(m.imports)
        for ga in m.getattr_aliases:
            base = aliases.get(ga.base, ga.base)
            table[(m.module, ga.local_name)] = f"{base}.{ga.attr}"
    return table


def build(modules: list[ParsedModule]) -> CallGraph:
    g = nx.DiGraph()
    source_locations: dict[str, tuple[Path, int]] = {}
    entrypoints: set[str] = set()
    local_funcs: set[str] = set()
    sink_call_kwargs: dict[str, list[list[str]]] = {}

    for m in modules:
        for fn in m.functions:
            local_funcs.add(fn.qualname)
            source_locations[fn.qualname] = (m.path, fn.start)

    class_attr_table = _build_class_attr_table(modules)
    getattr_table = _build_getattr_table(modules)
    local_var_table = _build_local_var_table(modules)

    for m in modules:
        aliases = _alias_table(m.imports)
        module_entry = f"{m.module}.<module>"
        g.add_node(module_entry)
        entrypoints.add(module_entry)

        for fn in m.functions:
            g.add_node(fn.qualname)
            if fn.name in {"main", "handler", "lambda_handler", "app"}:
                entrypoints.add(fn.qualname)
            if any(is_entrypoint_decorator(d) for d in fn.decorators):
                entrypoints.add(fn.qualname)
            if fn.name.startswith("test_"):
                entrypoints.add(fn.qualname)

        for call in m.calls:
            targets = _resolve_callee(
                call.callee_expr, aliases, local_funcs, m.module,
                class_attr_table=class_attr_table, enclosing=call.caller_qualname,
                getattr_table=getattr_table, local_var_table=local_var_table,
            )
            for t in targets:
                g.add_edge(call.caller_qualname, t, line=call.line, file=str(m.path),
                           kwargs=list(call.kwargs_present))
                if t.startswith("ext:"):
                    sink_call_kwargs.setdefault(t, []).append(list(call.kwargs_present))

    return CallGraph(
        graph=g,
        entrypoints=entrypoints,
        source_locations=source_locations,
        sink_call_kwargs=sink_call_kwargs,
    )


def build_from_repo(root: Path) -> CallGraph:
    cg = build(parse_repo(root))
    # Django adapter: every routed view becomes an additional entrypoint.
    # We add the qualnames regardless of whether the function actually exists in
    # the graph — BFS just won't traverse from a missing node. This means a
    # urls.py that points at a third-party view (e.g. `admin.site.urls`) doesn't
    # blow up; it just contributes no edges.
    try:
        from .django_routes import discover_entrypoints as _discover_django
        cg.entrypoints.update(_discover_django(root))
    except Exception:
        # Tree-sitter parse failures inside urls.py shouldn't crash the whole scan
        pass
    return cg
