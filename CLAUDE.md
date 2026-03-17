# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Aigis** is an AI Execution Governance Linter — a Python CLI that statically detects unsafe autonomy in AI agent applications before runtime. It verifies that AI agents cannot take high-impact actions without explicit approval, least privilege, and hard bounds.

The broader vision (see `northStar.txt`) is Rekall — a Git-like governance infrastructure for agentic execution. Aigis is the first implementation: a deterministic static analysis tool.

## Rekall Workflow

Rekall tracks session context, failed attempts, and decisions across conversations. **Follow this protocol every session:**

1. **Start of session**: Run `rekall brief` to get current focus, blockers, failed attempts, and next actions
2. **Log failed attempts**: `rekall attempts add <id> --title "..." --evidence "..."`
3. **Log decisions**: `rekall decisions propose`
4. **Checkpoint completed work**: `rekall checkpoint --commit auto`
5. **End of session**: `rekall session end --summary '...'`

## Build & Run

```bash
pip install -e .          # install in dev mode
aeg scan <path>           # scan a file or directory
aeg scan . -f json        # JSON output
aeg scan . -f sarif       # SARIF output
aeg scan . -o report.json -f json   # write to file
aeg scan . --config .aigis.yaml     # use config for suppressions
aeg scan . --baseline bl.json       # fail only on new findings
aeg scan . -s warning               # exit 1 on warnings too (default: error only)
aeg baseline . -o bl.json           # create baseline from current findings
```

## Testing

```bash
python -m pytest tests/ -v              # all tests (80 tests)
python -m pytest tests/test_rules.py    # just rule tests
python -m pytest tests/ -k "aeg001"     # single rule by keyword
python -m pytest tests/test_suppression.py  # suppression tests
python -m pytest tests/test_baseline.py     # baseline tests
```

Test fixtures live in `tests/fixtures/` — each file is a self-contained Python module representing a safe or unsafe AI agent pattern.

## Architecture

```
src/aigis/
  models.py        # Core data: Node, Edge, Finding, Evidence, RuleResult, TriState, enums
  graph.py         # ExecutionGraph IR — nodes + edges with query methods
  analyzer.py      # Python AST walker -> builds ExecutionGraph from source files
  frameworks/      # Framework-specific detection patterns (add new frameworks here)
    __init__.py    #   Merges all framework patterns for analyzer consumption
    langchain.py   #   LangChain: @tool, AgentExecutor, max_iterations
    langgraph.py   #   LangGraph: add_node, compile, interrupt_before, recursion_limit
    openai_agents.py # OpenAI Agents SDK: @function_tool, Agent, max_turns
    crewai.py      #   CrewAI: Crew, max_iter, max_rpm
    autogen.py     #   AutoGen/AG2: AssistantAgent, GroupChat, max_turns, max_round
    custom.py      #   Generic approval/consent/tool-registration patterns
  rules/           # One file per rule, each exports check(graph) -> RuleResult
    aeg001_unguarded_mutating.py
    aeg002_privileged_no_consent.py
    aeg003_missing_budget.py
  config.py        # YAML config loader (.aigis.yaml)
  suppression.py   # Inline comment + config-based suppression filtering
  baseline.py      # Baseline create/load/filter (fingerprint-based)
  output.py        # Formatters: console, JSON, SARIF
  cli.py           # Typer CLI entry point (aeg command)
```

**Data flow:** `Python files -> analyzer (AST) -> ExecutionGraph -> rules (check) -> [Finding] -> suppressions -> baseline -> output`

### Key Concepts

- **ExecutionGraph**: IR with typed nodes (TOOL_DEF, ENTRY_POINT, APPROVAL_GATE, SINK, BUDGET_CONTROL) and edges (CALLS, REGISTERS, WRAPS)
- **Evidence**: Structured explanation on each Finding (subject_name, sink_type, approval_signal_found/kind, budget_signal_found, confidence, rationale, remediation)
- **Sink catalog**: `MUTATING_SINKS` dict in `analyzer.py` maps `(module, method)` pairs to descriptions. `PRIVILEGED_SINKS` is the subset requiring consent/policy wrappers.
- **Approval vs Consent**: AEG001 accepts any approval pattern (decorators/calls with "approve", "confirm", etc.). AEG002 requires stricter consent/policy patterns ("policy", "consent"). A generic `@requires_approval` satisfies AEG001 but not AEG002.
- **Execution-time budgets**: AEG003 checks both constructor kwargs (e.g. `Agent(max_turns=N)`) and execution-time calls (e.g. `Runner.run(agent, max_turns=N)`, `app.invoke(input, config={"recursion_limit": N})`). Framework modules declare `EXECUTION_BUDGET_PATTERNS` for this.
- **TriState**: `YES/NO/UNKNOWN` — unknown does not fail by default.
- **Suppression**: Inline comments (`# aigis: disable=AEG001` or `# noqa: AEG001`) and YAML config (by rule, path glob, symbol name).
- **Baseline**: Fingerprint = sha256(rule_id + relative_path + subject_name). Survives line-number shifts.

### Adding a New Framework

1. Create `src/aigis/frameworks/myframework.py` with pattern constants
2. Import and merge in `src/aigis/frameworks/__init__.py`
3. No changes to analyzer.py or rules needed if patterns fit existing categories

### Adding a New Rule

1. Create `src/aigis/rules/aeg00N_name.py` with `RULE_ID` and `def check(graph) -> RuleResult`
2. Populate `Evidence` on each finding
3. Register in `src/aigis/rules/__init__.py`
4. Add SARIF metadata in `output.py` `RULE_METADATA`
5. Add fixture files in `tests/fixtures/` and tests in `tests/test_rules.py`

## Design Constraints

- All detection is deterministic — no LLM-based judgment
- "Missing guard" is a first-class concept, not an afterthought
- Tri-state reasoning: yes / no / unknown; unknown does not fail by default
- Rules return findings, not fixes — the linter reports, humans decide
- Each rule is a pure function: `check(ExecutionGraph) -> RuleResult`
- Prefer low noise over broad coverage (false negatives > false positives)
- Exit code 1 when findings at/above severity threshold, 0 on clean, 2 on bad input

## Known Limitations

- No cross-file call graph resolution (sinks must be in the same function body as the tool)
- No data-flow analysis (can't track tainted inputs through variables)
- SQL mutation detection not yet implemented (cursor.execute patterns are ambiguous)
- `open()` detection only catches literal mode strings, not variable modes
- Custom tool registration only matches function names containing "register" + "tool"
- Dynamic/metaprogramming-based tool registration not detected
