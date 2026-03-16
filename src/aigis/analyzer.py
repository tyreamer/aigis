"""Python AST analyzer — builds an ExecutionGraph from source files."""

from __future__ import annotations

import ast
from pathlib import Path

from .frameworks import (
    APPROVAL_COMPILE_KWARGS,
    APPROVAL_DECORATOR_PATTERNS,
    BUDGET_KWARGS,
    COMPILE_FALSE_POSITIVES,
    CONSENT_DECORATOR_PATTERNS,
    ENTRY_POINT_METHODS,
    ENTRY_POINT_NAMES,
    GRAPH_CONSTRUCTORS,
    TOOL_DECORATORS,
    TOOL_REGISTRATION_METHODS,
    TOOL_REGISTRATION_NAME_PATTERNS,
)
from .graph import ExecutionGraph
from .models import Edge, EdgeKind, Location, Node, NodeKind

# ---------------------------------------------------------------------------
# Sink catalogs  (Python ecosystem, not framework-specific)
# ---------------------------------------------------------------------------

MUTATING_SINKS: dict[tuple[str, str], str] = {
    # Filesystem
    ("os", "remove"): "file deletion",
    ("os", "unlink"): "file deletion",
    ("os", "rmdir"): "directory deletion",
    ("os", "rename"): "file rename",
    ("shutil", "rmtree"): "recursive deletion",
    ("shutil", "move"): "file move",
    ("shutil", "copy"): "file copy",
    ("shutil", "copy2"): "file copy",
    # Subprocess / OS commands
    ("subprocess", "run"): "subprocess execution",
    ("subprocess", "call"): "subprocess execution",
    ("subprocess", "check_call"): "subprocess execution",
    ("subprocess", "check_output"): "subprocess execution",
    ("subprocess", "Popen"): "subprocess execution",
    ("os", "system"): "system command",
    ("os", "popen"): "system command",
    # HTTP mutations
    ("requests", "post"): "outbound HTTP POST",
    ("requests", "put"): "outbound HTTP PUT",
    ("requests", "delete"): "outbound HTTP DELETE",
    ("requests", "patch"): "outbound HTTP PATCH",
    ("httpx", "post"): "outbound HTTP POST",
    ("httpx", "put"): "outbound HTTP PUT",
    ("httpx", "delete"): "outbound HTTP DELETE",
    ("httpx", "patch"): "outbound HTTP PATCH",
}

PRIVILEGED_SINKS: set[tuple[str, str]] = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
    ("os", "system"),
    ("os", "popen"),
}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class PythonAnalyzer:
    """Walk Python files and build an ExecutionGraph."""

    def analyze(self, path: Path) -> ExecutionGraph:
        graph = ExecutionGraph()
        target = Path(path)
        files = [target] if target.is_file() else sorted(target.rglob("*.py"))
        for f in files:
            self._analyze_file(f, graph)
        return graph

    def _analyze_file(self, path: Path, graph: ExecutionGraph):
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            return

        file_str = str(path)
        imports = _collect_imports(tree)
        func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        graph_vars: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_defs[node.name] = node

        # Collect variable names assigned from graph constructors
        # e.g.  graph = StateGraph(...)  or  g = MessageGraph(...)
        _collect_graph_vars(tree, imports, graph_vars)

        # Pass 1: @tool-decorated functions
        for func in func_defs.values():
            if _is_tool_decorated(func):
                _register_tool(func, file_str, imports, graph)

        # Pass 2: entry points, registrations, LangGraph nodes
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                _process_call(node, file_str, imports, func_defs, graph, graph_vars)


# ---------------------------------------------------------------------------
# Import collection
# ---------------------------------------------------------------------------

def _collect_graph_vars(tree: ast.AST, imports: dict[str, str], out: set[str]):
    """Find variable names assigned from known graph constructors.

    Matches patterns like:
        graph = StateGraph(...)
        g = MessageGraph(...)
        workflow = langgraph.graph.StateGraph(...)
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        ctor_name = ""
        if isinstance(call.func, ast.Name):
            ctor_name = call.func.id
        elif isinstance(call.func, ast.Attribute):
            ctor_name = call.func.attr
        if ctor_name in GRAPH_CONSTRUCTORS:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.add(target.id)


def _collect_imports(tree: ast.AST) -> dict[str, str]:
    """Map local names -> module paths."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{module}.{alias.name}"
    return imports


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def _is_tool_decorated(func: ast.FunctionDef) -> bool:
    for dec in func.decorator_list:
        name = _decorator_name(dec).lower()
        if name in TOOL_DECORATORS:
            return True
    return False


def _decorator_name(dec: ast.expr) -> str:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    if isinstance(dec, ast.Attribute):
        return dec.attr
    return ""


# ---------------------------------------------------------------------------
# Approval / consent detection
# ---------------------------------------------------------------------------

def _find_approval_decorator(func: ast.FunctionDef) -> str | None:
    """Return the raw decorator name if an approval pattern is found, else None."""
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if any(pat in name.lower() for pat in APPROVAL_DECORATOR_PATTERNS):
            return name
    return None


def _find_consent_decorator(func: ast.FunctionDef) -> str | None:
    """Return the raw decorator name if a consent/policy pattern is found."""
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if any(pat in name.lower() for pat in CONSENT_DECORATOR_PATTERNS):
            return name
    return None


# Patterns that count as approval when found as calls in a function body
_BODY_APPROVAL_PATTERNS = APPROVAL_DECORATOR_PATTERNS | {"input"}


def _has_approval_in_body(func: ast.FunctionDef) -> str | None:
    """Return the call name if an approval-like call is in the body, else None."""
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if any(pat in name.lower() for pat in _BODY_APPROVAL_PATTERNS):
                return name
    return None


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


# ---------------------------------------------------------------------------
# Sink detection
# ---------------------------------------------------------------------------

def _find_sinks(
    func: ast.FunctionDef, imports: dict[str, str]
) -> list[tuple[str, str, int]]:
    """Return (module, method, line) for each sink in the function body."""
    sinks: list[tuple[str, str, int]] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        result = _classify_sink(node, imports)
        if result:
            sinks.append((*result, node.lineno))
    return sinks


def _classify_sink(call: ast.Call, imports: dict[str, str]) -> tuple[str, str] | None:
    # module.method(...)
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if isinstance(call.func.value, ast.Name):
            obj = call.func.value.id
            resolved = imports.get(obj, obj)
            if (obj, attr) in MUTATING_SINKS:
                return (obj, attr)
            if (resolved, attr) in MUTATING_SINKS:
                return (resolved, attr)
            for mod, meth in MUTATING_SINKS:
                if attr == meth and (obj == mod or resolved == mod or resolved.endswith(f".{mod}")):
                    return (mod, meth)

    # Direct call: func(...)
    if isinstance(call.func, ast.Name):
        func_name = call.func.id
        resolved = imports.get(func_name, "")
        for mod, meth in MUTATING_SINKS:
            if func_name == meth and (resolved.endswith(f".{meth}") or resolved == f"{mod}.{meth}"):
                return (mod, meth)
        # Special case: open() with write mode
        if func_name == "open" and _open_is_write(call):
            return ("builtins", "open")

    return None


def _open_is_write(call: ast.Call) -> bool:
    if len(call.args) >= 2:
        mode_arg = call.args[1]
        if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
            if any(m in mode_arg.value for m in ("w", "a", "x")):
                return True
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            if any(m in str(kw.value.value) for m in ("w", "a", "x")):
                return True
    return False


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def _register_tool(
    func: ast.FunctionDef,
    file_str: str,
    imports: dict[str, str],
    graph: ExecutionGraph,
    extra_metadata: dict | None = None,
) -> str:
    tool_id = f"tool:{file_str}:{func.name}:{func.lineno}"
    if tool_id in graph.nodes:
        return tool_id

    loc = Location(file=file_str, line=func.lineno, col=func.col_offset)
    graph.add_node(
        Node(
            id=tool_id,
            kind=NodeKind.TOOL_DEF,
            name=func.name,
            location=loc,
            metadata=extra_metadata or {},
        )
    )

    # Approval gate?
    approval_dec = _find_approval_decorator(func)
    consent_dec = _find_consent_decorator(func)
    body_approval = _has_approval_in_body(func)

    has_approval = approval_dec or consent_dec or body_approval
    is_consent = consent_dec is not None

    if has_approval:
        if consent_dec:
            signal_source = f"decorator:{consent_dec}"
        elif approval_dec:
            signal_source = f"decorator:{approval_dec}"
        else:
            signal_source = f"body_call:{body_approval}"

        gate_id = f"gate:{file_str}:{func.name}:{func.lineno}"
        graph.add_node(
            Node(
                id=gate_id,
                kind=NodeKind.APPROVAL_GATE,
                name=f"approval:{func.name}",
                location=loc,
                metadata={"is_consent": is_consent, "source": signal_source},
            )
        )
        graph.add_edge(Edge(source=gate_id, target=tool_id, kind=EdgeKind.WRAPS))

    # Sinks
    for mod, meth, line in _find_sinks(func, imports):
        sink_id = f"sink:{file_str}:{mod}.{meth}:{line}"
        desc = MUTATING_SINKS.get((mod, meth), "side effect")
        graph.add_node(
            Node(
                id=sink_id,
                kind=NodeKind.SINK,
                name=f"{mod}.{meth}",
                location=Location(file=file_str, line=line),
                metadata={"description": desc, "privileged": (mod, meth) in PRIVILEGED_SINKS},
            )
        )
        graph.add_edge(Edge(source=tool_id, target=sink_id, kind=EdgeKind.CALLS))

    return tool_id


def _is_graph_compile(call: ast.Call, imports: dict[str, str], graph_vars: set[str]) -> bool:
    """Determine if a .compile() call is on a graph object (not re.compile, etc.).

    Heuristics (in order):
    1. If receiver is a known graph variable name -> yes
    2. If receiver is a known false positive (re, pattern, ...) -> no
    3. If call has graph-specific kwargs (interrupt_before, recursion_limit, checkpointer) -> yes
    4. If receiver is a chained call like StateGraph(...).compile() -> yes
    5. Otherwise -> no  (prefer false negatives over false positives)
    """
    if not isinstance(call.func, ast.Attribute):
        return False

    receiver = call.func.value

    # 1. Known graph variable
    if isinstance(receiver, ast.Name) and receiver.id in graph_vars:
        return True

    # 2. Known false positive
    if isinstance(receiver, ast.Name):
        name_lower = receiver.id.lower()
        resolved = imports.get(receiver.id, "").lower()
        if name_lower in COMPILE_FALSE_POSITIVES or resolved in COMPILE_FALSE_POSITIVES:
            return False
        # Also reject if the resolved import is clearly not a graph
        for fp in COMPILE_FALSE_POSITIVES:
            if fp in resolved:
                return False

    # 3. Graph-specific kwargs present
    graph_kwargs = APPROVAL_COMPILE_KWARGS | BUDGET_KWARGS | {"checkpointer"}
    for kw in call.keywords:
        if kw.arg in graph_kwargs:
            return True

    # 4. Chained: StateGraph(...).compile()
    if isinstance(receiver, ast.Call):
        chained_name = _call_name(receiver)
        if chained_name in GRAPH_CONSTRUCTORS:
            return True

    # 5. Default: reject to avoid false positives
    return False


def _process_call(
    call: ast.Call,
    file_str: str,
    imports: dict[str, str],
    func_defs: dict[str, ast.FunctionDef],
    graph: ExecutionGraph,
    graph_vars: set[str] | None = None,
):
    call_nm = _call_name(call)

    # --- Entry points: AgentExecutor(...), graph.compile(...) ---------------
    is_entry = call_nm in ENTRY_POINT_NAMES
    if not is_entry and isinstance(call.func, ast.Attribute) and call.func.attr in ENTRY_POINT_METHODS:
        is_entry = _is_graph_compile(call, imports, graph_vars or set())
    if is_entry:
        loc = Location(file=file_str, line=call.lineno, col=call.col_offset)
        ep_id = f"entry:{file_str}:{call_nm}:{call.lineno}"
        graph.add_node(Node(id=ep_id, kind=NodeKind.ENTRY_POINT, name=call_nm, location=loc))

        # Budget kwargs
        for kw in call.keywords:
            if kw.arg in BUDGET_KWARGS:
                budget_id = f"budget:{file_str}:{kw.arg}:{call.lineno}"
                graph.add_node(
                    Node(id=budget_id, kind=NodeKind.BUDGET_CONTROL, name=kw.arg,
                         location=loc, metadata={"type": kw.arg})
                )
                graph.add_edge(Edge(source=budget_id, target=ep_id, kind=EdgeKind.WRAPS))
                break

        # tools=[...] kwarg
        for kw in call.keywords:
            if kw.arg == "tools" and isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    tool_name = elt.id if isinstance(elt, ast.Name) else None
                    if tool_name:
                        if tool_name in func_defs:
                            tid = _register_tool(
                                func_defs[tool_name], file_str, imports, graph,
                                extra_metadata={"registration": "tools_list"},
                            )
                            graph.add_edge(Edge(source=ep_id, target=tid, kind=EdgeKind.REGISTERS))
                        else:
                            for node in graph.nodes_by_kind(NodeKind.TOOL_DEF):
                                if node.name == tool_name:
                                    graph.add_edge(Edge(source=ep_id, target=node.id, kind=EdgeKind.REGISTERS))

        # LangGraph interrupt_before -> approval gate on entry point
        for kw in call.keywords:
            if kw.arg in APPROVAL_COMPILE_KWARGS:
                gate_id = f"gate:{file_str}:{kw.arg}:{call.lineno}"
                graph.add_node(
                    Node(
                        id=gate_id, kind=NodeKind.APPROVAL_GATE, name=kw.arg,
                        location=loc, metadata={"type": "langgraph_interrupt", "source": f"compile_kwarg:{kw.arg}"},
                    )
                )
                graph.add_edge(Edge(source=gate_id, target=ep_id, kind=EdgeKind.WRAPS))

    # --- LangGraph: graph.add_node("name", func) ---------------------------
    if isinstance(call.func, ast.Attribute) and call.func.attr in TOOL_REGISTRATION_METHODS:
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Name):
            func_name = call.args[1].id
            if func_name in func_defs:
                _register_tool(
                    func_defs[func_name], file_str, imports, graph,
                    extra_metadata={"registration": "langgraph_add_node"},
                )

    # --- Custom: register_tool(func) patterns -------------------------------
    if isinstance(call.func, ast.Name):
        name_lower = call.func.id.lower()
        if all(pat in name_lower for pat in TOOL_REGISTRATION_NAME_PATTERNS):
            for arg in call.args:
                if isinstance(arg, ast.Name) and arg.id in func_defs:
                    _register_tool(
                        func_defs[arg.id], file_str, imports, graph,
                        extra_metadata={"registration": "register_tool_call"},
                    )
