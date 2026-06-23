"""Tree-sitter Python parser.

Tier 2 additions:
  - FunctionDef.decorators        : list of decorator expression strings
  - CallSite.kwargs_present       : list of kwarg names at the call site
  - ParsedModule.class_attr_assigns: self.X = <expr> from __init__ bodies
  - ParsedModule.getattr_aliases  : local_name = getattr(<module>, "<const>")

These richer fields drive class-aware resolution, dynamic-dispatch handling,
and argument-aware sink matching downstream.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from tree_sitter_languages import get_parser


@dataclass
class ImportRecord:
    module: str
    alias: str | None
    names: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class FunctionDef:
    qualname: str
    name: str
    start: int
    end: int
    decorators: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    caller_qualname: str
    callee_expr: str
    line: int
    kwargs_present: list[str] = field(default_factory=list)


@dataclass
class ClassAttrAssign:
    """A `self.X = <expr>` statement inside a class's __init__.

    `class_qualname` is the dotted class path (module.ClassName).
    `rhs_expr` is the textual right-hand-side, resolved later by call_graph.
    """
    class_qualname: str
    attr: str
    rhs_expr: str


@dataclass
class GetattrAlias:
    """A `local = getattr(<module_or_name>, "<const>")` assignment.

    Tier 2 only handles string-literal attribute names.
    """
    scope_qualname: str
    local_name: str
    base: str
    attr: str


@dataclass
class ParsedModule:
    path: Path
    module: str
    imports: list[ImportRecord] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    class_attr_assigns: list[ClassAttrAssign] = field(default_factory=list)
    getattr_aliases: list[GetattrAlias] = field(default_factory=list)


_parser = get_parser("python")


def _text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _module_name_for(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else path.stem


def parse_file(path: Path, root: Path) -> ParsedModule:
    src = path.read_bytes()
    tree = _parser.parse(src)
    module = _module_name_for(path, root)
    pm = ParsedModule(path=path, module=module)
    _walk(tree.root_node, src, pm, enclosing=f"{module}.<module>", class_stack=[])
    return pm


def _decorators_of(node, src: bytes) -> list[str]:
    out: list[str] = []
    parent = node.parent
    if parent is None or parent.type != "decorated_definition":
        return out
    for child in parent.children:
        if child.type == "decorator":
            expr_node = None
            for c in child.children:
                if c.type not in ("@",):
                    expr_node = c
            if expr_node is not None:
                # Strip a trailing call: `@app.route("/x")` -> `app.route`
                txt = _text(expr_node, src)
                if "(" in txt:
                    txt = txt.split("(", 1)[0]
                out.append(txt.strip())
    return out


def _kwargs_of_call(call_node, src: bytes) -> list[str]:
    out: list[str] = []
    arg_node = call_node.child_by_field_name("arguments")
    if arg_node is None:
        return out
    for arg in arg_node.children:
        if arg.type == "keyword_argument":
            name_node = arg.child_by_field_name("name")
            if name_node is not None:
                out.append(_text(name_node, src))
    return out


def _maybe_record_self_assign(node, src: bytes, pm: ParsedModule, enclosing: str, class_stack: list[str]):
    """If `node` is `self.X = <expr>` inside __init__ of a class, record it."""
    if not class_stack:
        return
    # We are inside a function. `enclosing` is module.Class[...].fn — match the fn name.
    if not enclosing.endswith(".__init__"):
        return
    if node.type != "assignment":
        return
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    if left.type != "attribute":
        return
    obj = left.child_by_field_name("object")
    attr = left.child_by_field_name("attribute")
    if obj is None or attr is None or _text(obj, src) != "self":
        return
    class_qual = ".".join([pm.module] + class_stack)
    pm.class_attr_assigns.append(
        ClassAttrAssign(class_qualname=class_qual, attr=_text(attr, src), rhs_expr=_text(right, src))
    )


def _maybe_record_getattr_alias(node, src: bytes, pm: ParsedModule, enclosing: str):
    """If `node` is `local = getattr(<X>, "<const>")`, record the alias."""
    if node.type != "assignment":
        return
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None or left.type != "identifier" or right.type != "call":
        return
    func = right.child_by_field_name("function")
    if func is None or _text(func, src) != "getattr":
        return
    args = right.child_by_field_name("arguments")
    if args is None:
        return
    positional = [c for c in args.children if c.type not in ("(", ")", ",")]
    if len(positional) < 2:
        return
    base_txt = _text(positional[0], src)
    attr_node = positional[1]
    if attr_node.type != "string":
        return
    attr_txt = _text(attr_node, src).strip("'\"")
    pm.getattr_aliases.append(
        GetattrAlias(
            scope_qualname=enclosing,
            local_name=_text(left, src),
            base=base_txt,
            attr=attr_txt,
        )
    )


def _walk(node, src: bytes, pm: ParsedModule, enclosing: str, class_stack: list[str]):
    t = node.type
    if t == "import_statement":
        for child in node.children:
            if child.type == "dotted_name":
                pm.imports.append(ImportRecord(module=_text(child, src), alias=_text(child, src)))
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                pm.imports.append(ImportRecord(module=_text(name_node, src), alias=_text(alias_node, src)))
        return

    if t == "import_from_statement":
        module_node = node.child_by_field_name("module_name")
        module = _text(module_node, src) if module_node else ""
        names: list[tuple[str, str]] = []
        for child in node.children:
            if child.type == "dotted_name" and child is not module_node:
                n = _text(child, src)
                names.append((n, n))
            elif child.type == "aliased_import":
                orig = _text(child.child_by_field_name("name"), src)
                alias = _text(child.child_by_field_name("alias"), src)
                names.append((orig, alias))
        pm.imports.append(ImportRecord(module=module, alias=None, names=names))
        return

    if t == "class_definition":
        name = _text(node.child_by_field_name("name"), src)
        class_stack = class_stack + [name]
        body = node.child_by_field_name("body")
        if body:
            for c in body.children:
                _walk(c, src, pm, enclosing, class_stack)
        return

    if t in ("function_definition", "async_function_definition"):
        name = _text(node.child_by_field_name("name"), src)
        qual_parts = [pm.module] + class_stack + [name]
        qualname = ".".join(qual_parts)
        pm.functions.append(
            FunctionDef(
                qualname=qualname,
                name=name,
                start=node.start_point[0] + 1,
                end=node.end_point[0] + 1,
                decorators=_decorators_of(node, src),
            )
        )
        body = node.child_by_field_name("body")
        if body:
            for c in body.children:
                _walk(c, src, pm, enclosing=qualname, class_stack=class_stack)
        return

    if t == "assignment":
        _maybe_record_self_assign(node, src, pm, enclosing, class_stack)
        _maybe_record_getattr_alias(node, src, pm, enclosing)
        # fall through to allow recursion into the RHS

    if t == "call":
        func_node = node.child_by_field_name("function")
        if func_node is not None:
            pm.calls.append(
                CallSite(
                    caller_qualname=enclosing,
                    callee_expr=_text(func_node, src),
                    line=node.start_point[0] + 1,
                    kwargs_present=_kwargs_of_call(node, src),
                )
            )

    for c in node.children:
        _walk(c, src, pm, enclosing, class_stack)


def discover_python_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.py"):
        sp = str(p)
        if any(seg in sp for seg in ("/.venv/", "/venv/", "/site-packages/", "/.git/", "/build/", "/dist/")):
            continue
        yield p


def parse_repo(root: Path) -> list[ParsedModule]:
    return [parse_file(p, root) for p in discover_python_files(root)]
