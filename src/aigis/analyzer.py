"""Python AST analyzer — builds an ExecutionGraph from source files."""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path

from .frameworks import (
    APPROVAL_COMPILE_KWARGS,
    APPROVAL_DECORATOR_PATTERNS,
    BUDGET_KWARGS,
    COMPILE_FALSE_POSITIVES,
    CONSENT_DECORATOR_PATTERNS,
    ENTRY_POINT_METHODS,
    ENTRY_POINT_NAMES,
    ENTRY_POINT_QUALIFIED,
    EXECUTION_BUDGET_PATTERNS,
    FILE_LEVEL_BUDGET_FUNCTIONS,
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

    def analyze(
        self, path: Path, exclude_patterns: list[str] | None = None
    ) -> ExecutionGraph:
        graph = ExecutionGraph()
        target = Path(path)
        if target.is_file():
            files = [target]
        else:
            files = sorted(target.rglob("*.py"))
            if exclude_patterns:
                files = [
                    f for f in files
                    if not _is_excluded(f, target, exclude_patterns)
                ]
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
        entry_var_map: dict[str, str] = {}  # variable name -> entry point node ID
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                _process_call(node, file_str, imports, func_defs, graph, graph_vars)

        # Pass 3: LangGraph interrupt() as file-level approval signal
        _detect_interrupt_calls(tree, file_str, imports, graph)

        # Pass 4: execution-time budget detection
        # First, collect variable names assigned from entry point constructors
        _collect_entry_vars(tree, file_str, imports, graph, entry_var_map, graph_vars)
        # Then, scan for execution calls that carry budget kwargs
        _detect_execution_budgets(tree, file_str, imports, graph, entry_var_map)

        # Pass 5: propagate budgets through known wrapper patterns
        # e.g. GroupChat(max_round=N) → GroupChatManager(groupchat=chat_var)
        _propagate_wrapper_budgets(tree, file_str, graph, entry_var_map)

        # Pass 6: file-level budget from standalone orchestration functions
        # e.g. initiate_group_chat(pattern=p, max_rounds=5)
        _detect_file_level_budgets(tree, file_str, imports, graph)


# ---------------------------------------------------------------------------
# Import collection
# ---------------------------------------------------------------------------

def _is_excluded(
    file_path: Path, base: Path, patterns: list[str]
) -> bool:
    """Check if a file matches any exclusion pattern."""
    try:
        rel = file_path.relative_to(base)
    except ValueError:
        rel = file_path
    rel_posix = rel.as_posix()
    name = file_path.name

    for pattern in patterns:
        # Directory pattern (ends with /)
        if pattern.endswith("/"):
            dir_name = pattern.rstrip("/")
            if any(part == dir_name for part in rel.parts[:-1]):
                return True
            # Also match if the relative path starts with the dir
            if rel_posix.startswith(dir_name + "/"):
                return True
        else:
            # File name glob pattern
            if fnmatch.fnmatch(name, pattern):
                return True
            if fnmatch.fnmatch(rel_posix, pattern):
                return True
    return False


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
    # Disambiguate names that exist in multiple frameworks (e.g. "Agent")
    if is_entry and call_nm in ENTRY_POINT_QUALIFIED:
        qualified_modules = ENTRY_POINT_QUALIFIED[call_nm]
        resolved = imports.get(call_nm, "")
        if resolved:
            is_entry = any(resolved.startswith(mod) for mod in qualified_modules)
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


# ---------------------------------------------------------------------------
# LangGraph interrupt() detection
# ---------------------------------------------------------------------------

# Modules whose `interrupt` import counts as a LangGraph HITL signal
_INTERRUPT_MODULES = {"langgraph.types", "langgraph"}


def _detect_interrupt_calls(
    tree: ast.AST,
    file_str: str,
    imports: dict[str, str],
    graph: ExecutionGraph,
):
    """Detect interrupt() calls from langgraph.types as file-level approval.

    If `interrupt` is imported from a LangGraph module and called anywhere
    in the file, attach an APPROVAL_GATE to every ENTRY_POINT in this file.
    """
    # Check if interrupt is imported from a LangGraph module
    interrupt_name = None
    for local_name, resolved in imports.items():
        if resolved in {f"{mod}.interrupt" for mod in _INTERRUPT_MODULES}:
            interrupt_name = local_name
            break

    if interrupt_name is None:
        return

    # Check if interrupt() is actually called anywhere in the file
    has_interrupt_call = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == interrupt_name:
                has_interrupt_call = True
                break

    if not has_interrupt_call:
        return

    # Attach approval gate to all entry points in this file
    for ep in graph.nodes_by_kind(NodeKind.ENTRY_POINT):
        if ep.location.file != file_str:
            continue
        gate_id = f"gate:{file_str}:interrupt:{ep.location.line}"
        if gate_id in graph.nodes:
            continue
        graph.add_node(
            Node(
                id=gate_id,
                kind=NodeKind.APPROVAL_GATE,
                name="interrupt",
                location=ep.location,
                metadata={"type": "langgraph_interrupt", "source": "interrupt_call"},
            )
        )
        graph.add_edge(Edge(source=gate_id, target=ep.id, kind=EdgeKind.WRAPS))


# ---------------------------------------------------------------------------
# Execution-time budget detection (Pass 4)
# ---------------------------------------------------------------------------

def _collect_entry_vars(
    tree: ast.AST,
    file_str: str,
    imports: dict[str, str],
    graph: ExecutionGraph,
    entry_var_map: dict[str, str],
    graph_vars: set[str],
):
    """Map variable names to entry point node IDs.

    Matches patterns like:
        agent = Agent(...)
        crew = Crew(...)
        app = graph.compile(...)
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        call_nm = _call_name(call)

        # Check if this call created an entry point we already registered
        # Build the expected entry point ID
        ep_id = f"entry:{file_str}:{call_nm}:{call.lineno}"

        # For compile() calls, the call_name is "compile" from the attribute
        if isinstance(call.func, ast.Attribute):
            ep_id_method = f"entry:{file_str}:{call.func.attr}:{call.lineno}"
            if ep_id_method in graph.nodes:
                ep_id = ep_id_method

        if ep_id in graph.nodes:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    entry_var_map[target.id] = ep_id

    # One-hop aliasing: b = a where a is already an entry var
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if isinstance(node.value, ast.Name) and node.value.id in entry_var_map:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in entry_var_map:
                    entry_var_map[target.id] = entry_var_map[node.value.id]


def _detect_execution_budgets(
    tree: ast.AST,
    file_str: str,
    imports: dict[str, str],
    graph: ExecutionGraph,
    entry_var_map: dict[str, str],
):
    """Detect execution-time budget controls on entry point variables.

    Scans for calls like:
        Runner.run(agent, max_turns=5)       — budget via positional arg link
        agent.invoke(input, config={...})    — budget via receiver variable
        manager.initiate_chat(..., max_turns=N) — budget via receiver variable
    Also resolves simple config variable references:
        cfg = {"recursion_limit": 25}
        app.invoke(input, config=cfg)
    """
    if not EXECUTION_BUDGET_PATTERNS:
        return

    # Collect simple dict variable assignments for config resolution
    dict_vars = _collect_dict_vars(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for pattern in EXECUTION_BUDGET_PATTERNS:
            ep_id = _match_execution_pattern(node, pattern, entry_var_map, imports)
            if ep_id is None:
                continue

            # Found a matching execution call with budget — create the budget node
            budget_kwarg = _find_budget_kwarg_in_call(node, pattern, dict_vars)
            if budget_kwarg:
                budget_id = f"budget:{file_str}:exec:{budget_kwarg}:{node.lineno}"
                if budget_id not in graph.nodes:
                    loc = Location(file=file_str, line=node.lineno, col=node.col_offset)
                    graph.add_node(
                        Node(
                            id=budget_id,
                            kind=NodeKind.BUDGET_CONTROL,
                            name=budget_kwarg,
                            location=loc,
                            metadata={"type": budget_kwarg, "source": "execution_call"},
                        )
                    )
                    graph.add_edge(Edge(source=budget_id, target=ep_id, kind=EdgeKind.WRAPS))


def _match_execution_pattern(
    call: ast.Call,
    pattern: dict,
    entry_var_map: dict[str, str],
    imports: dict[str, str],
) -> str | None:
    """Check if a call matches an execution budget pattern and return the entry point ID.

    Returns the matched entry point node ID, or None if no match.
    """
    methods = pattern.get("methods", set())

    # All patterns require attribute-style calls: something.method(...)
    if not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr not in methods:
        return None

    # Pattern type 1: Class.method(entry_var, ..., budget_kwarg=N)
    # e.g. Runner.run(agent, max_turns=5)
    if "callers" in pattern:
        callers = pattern["callers"]
        if isinstance(call.func.value, ast.Name):
            if call.func.value.id not in callers:
                resolved = imports.get(call.func.value.id, "")
                if not any(c in resolved for c in callers):
                    return None
        else:
            return None

        arg_idx = pattern.get("entry_arg_index", 0)
        if len(call.args) <= arg_idx:
            return None
        arg = call.args[arg_idx]
        if isinstance(arg, ast.Name) and arg.id in entry_var_map:
            return entry_var_map[arg.id]
        return None

    # Pattern type 2: entry_var.method(..., budget_kwarg=N)
    # e.g. app.invoke(input, config={"recursion_limit": 25})
    if pattern.get("receiver_is_entry"):
        if isinstance(call.func.value, ast.Name):
            var_name = call.func.value.id
            if var_name in entry_var_map:
                return entry_var_map[var_name]
        return None

    # Pattern type 3: any_receiver.method(entry_var, ..., budget_kwarg=N)
    # e.g. proxy.initiate_chat(assistant, max_turns=5)
    # The receiver can be anything, but the positional arg must be an entry var.
    if pattern.get("any_receiver"):
        arg_idx = pattern.get("entry_arg_index", 0)
        if len(call.args) <= arg_idx:
            return None
        arg = call.args[arg_idx]
        if isinstance(arg, ast.Name) and arg.id in entry_var_map:
            return entry_var_map[arg.id]
        return None

    return None


def _find_budget_kwarg_in_call(
    call: ast.Call,
    pattern: dict,
    dict_vars: dict[str, set[str]] | None = None,
) -> str | None:
    """Find a budget kwarg in a call, checking direct kwargs, config dicts,
    and config variable references."""
    # Check direct kwargs
    budget_kwargs = pattern.get("budget_kwargs", set())
    for kw in call.keywords:
        if kw.arg in budget_kwargs:
            return kw.arg

    # Check config dict: config={"recursion_limit": 25}
    config_keys = pattern.get("budget_in_config", set())
    if config_keys:
        for kw in call.keywords:
            if kw.arg == "config":
                # Literal dict: config={"recursion_limit": 25}
                if isinstance(kw.value, ast.Dict):
                    for key in kw.value.keys:
                        if isinstance(key, ast.Constant) and key.value in config_keys:
                            return key.value
                # Variable reference: config=cfg (resolve via dict_vars)
                if (
                    dict_vars
                    and isinstance(kw.value, ast.Name)
                    and kw.value.id in dict_vars
                ):
                    for key in config_keys:
                        if key in dict_vars[kw.value.id]:
                            return key

    return None


def _collect_dict_vars(tree: ast.AST) -> dict[str, set[str]]:
    """Collect variable names assigned to dict literals, recording their keys.

    Matches: cfg = {"recursion_limit": 25, "other": "value"}
    Returns: {"cfg": {"recursion_limit", "other"}}
    """
    result: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        keys: set[str] = set()
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
        if keys:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = keys
    return result


# ---------------------------------------------------------------------------
# Budget propagation through wrapper patterns (Pass 5)
# ---------------------------------------------------------------------------

# Maps wrapper entry point name -> kwarg that references the inner entry point variable
_BUDGET_PROPAGATION = {
    "GroupChatManager": "groupchat",
}


def _propagate_wrapper_budgets(
    tree: ast.AST,
    file_str: str,
    graph: ExecutionGraph,
    entry_var_map: dict[str, str],
):
    """Propagate budget controls from inner entry points to their wrappers.

    Handles patterns like:
        chat = GroupChat(agents=[...], max_round=10)
        manager = GroupChatManager(groupchat=chat)

    If 'chat' has a BUDGET_CONTROL, copy it to 'manager'.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        call_nm = _call_name(call)

        if call_nm not in _BUDGET_PROPAGATION:
            continue

        inner_kwarg = _BUDGET_PROPAGATION[call_nm]

        # Find the wrapper's entry point ID
        wrapper_ep_id = f"entry:{file_str}:{call_nm}:{call.lineno}"
        if wrapper_ep_id not in graph.nodes:
            continue

        # Find the inner entry point variable from kwargs
        inner_var = None
        for kw in call.keywords:
            if kw.arg == inner_kwarg and isinstance(kw.value, ast.Name):
                inner_var = kw.value.id
                break

        if inner_var is None or inner_var not in entry_var_map:
            continue

        inner_ep_id = entry_var_map[inner_var]

        # Check if the inner entry point has budget controls
        inner_budgets = [
            e for e in graph.edges_to(inner_ep_id, EdgeKind.WRAPS)
            if graph.nodes[e.source].kind == NodeKind.BUDGET_CONTROL
        ]

        # Propagate each budget control to the wrapper
        for edge in inner_budgets:
            budget_node = graph.nodes[edge.source]
            prop_id = f"budget:{file_str}:prop:{budget_node.name}:{call.lineno}"
            if prop_id not in graph.nodes:
                graph.add_node(
                    Node(
                        id=prop_id,
                        kind=NodeKind.BUDGET_CONTROL,
                        name=budget_node.name,
                        location=budget_node.location,
                        metadata={
                            "type": budget_node.name,
                            "source": f"propagated_from:{inner_var}",
                        },
                    )
                )
                graph.add_edge(Edge(source=prop_id, target=wrapper_ep_id, kind=EdgeKind.WRAPS))


# ---------------------------------------------------------------------------
# File-level budget from standalone orchestration functions (Pass 6)
# ---------------------------------------------------------------------------

def _detect_file_level_budgets(
    tree: ast.AST,
    file_str: str,
    imports: dict[str, str],
    graph: ExecutionGraph,
):
    """Detect standalone function calls that apply a budget to all entry points.

    Handles patterns like:
        from autogen.agentchat import initiate_group_chat
        result = initiate_group_chat(pattern=p, max_rounds=5)

    When a recognized orchestration function is called with a budget kwarg,
    attach a BUDGET_CONTROL to every entry point in the same file.
    """
    if not FILE_LEVEL_BUDGET_FUNCTIONS:
        return

    # Find which local names map to known orchestration functions
    known_locals: dict[str, set[str]] = {}  # local_name -> budget_kwargs
    for local_name, resolved in imports.items():
        # resolved is like "autogen.agentchat.initiate_group_chat"
        for func_name, budget_kwargs in FILE_LEVEL_BUDGET_FUNCTIONS.items():
            if resolved.endswith(f".{func_name}") or local_name == func_name:
                known_locals[local_name] = budget_kwargs

    if not known_locals:
        return

    # Scan for calls to these functions with budget kwargs
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in known_locals:
            continue

        budget_kwargs = known_locals[node.func.id]
        found_kwarg = None
        for kw in node.keywords:
            if kw.arg in budget_kwargs:
                found_kwarg = kw.arg
                break

        if found_kwarg is None:
            continue

        # Apply budget to all entry points in this file
        for ep in graph.nodes_by_kind(NodeKind.ENTRY_POINT):
            if ep.location.file != file_str:
                continue
            budget_id = f"budget:{file_str}:filelevel:{found_kwarg}:{node.lineno}:{ep.location.line}"
            if budget_id not in graph.nodes:
                loc = Location(file=file_str, line=node.lineno, col=node.col_offset)
                graph.add_node(
                    Node(
                        id=budget_id,
                        kind=NodeKind.BUDGET_CONTROL,
                        name=found_kwarg,
                        location=loc,
                        metadata={
                            "type": found_kwarg,
                            "source": f"file_level_function:{node.func.id}",
                        },
                    )
                )
                graph.add_edge(Edge(source=budget_id, target=ep.id, kind=EdgeKind.WRAPS))
