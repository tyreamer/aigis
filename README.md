# aigis

**AI Execution Governance Linter** — static analysis CLI that detects unsafe autonomy in AI agent applications before runtime.

aigis statically verifies that AI agents cannot take high-impact actions without explicit approval, least privilege, and hard bounds — before they ever run.

## Install

```bash
pip install -e .
```

## Quick Start

```bash
# Scan a file or directory
aeg scan .

# JSON output for CI
aeg scan . -f json

# SARIF for GitHub Code Scanning
aeg scan . -f sarif -o results.sarif

# Create a baseline (accept current findings, fail only on new ones)
aeg baseline . -o aigis-baseline.json
aeg scan . --baseline aigis-baseline.json

# Only fail on errors (ignore warnings)
aeg scan . --severity-threshold error

# Use a config file for suppressions
aeg scan . --config .aigis.yaml
```

## What It Detects

aigis implements three rules that check for missing governance controls in AI agent code:

### AEG001 — Mutating Tool Without Approval Gate

Fires when a tool registered with an AI agent framework performs side-effecting operations without any approval mechanism.

**Detected side effects:** file writes/deletes (`os.remove`, `shutil.rmtree`), subprocess execution (`subprocess.run`, `os.system`), outbound HTTP mutations (`requests.post`, `httpx.put`), file creation via `open()` with write mode.

**Example (flagged):**
```python
@tool
def delete_user(user_id: str):
    os.remove(f"/data/{user_id}.json")  # AEG001: no approval gate
```

**Example (clean):**
```python
@tool
@requires_approval
def delete_user(user_id: str):
    os.remove(f"/data/{user_id}.json")  # Approval decorator detected
```

### AEG002 — Privileged Operation Without Consent/Policy Wrapper

Fires when a tool performs privileged operations (subprocess, system commands) without an explicit consent or policy wrapper. A generic `@requires_approval` is **not sufficient** — this rule requires patterns like `@requires_consent`, `@policy_check`, or similar.

**Example (flagged despite having generic approval):**
```python
@tool
@requires_approval  # Generic approval — not consent-level
def run_command(cmd: str):
    subprocess.run(cmd, shell=True)  # AEG002: needs @requires_consent or @policy_check
```

**Example (clean):**
```python
@tool
@requires_consent
def run_command(cmd: str):
    subprocess.run(cmd, shell=True)  # Consent-level wrapper detected
```

### AEG003 — Missing Execution Budget

Fires when an agent entry point (`AgentExecutor`, `graph.compile()`) has no iteration or budget limit.

**Example (flagged):**
```python
agent = AgentExecutor(agent=llm, tools=[my_tool])  # AEG003: no max_iterations
```

**Example (clean):**
```python
agent = AgentExecutor(agent=llm, tools=[my_tool], max_iterations=10)
```

## Suppression

### Inline Comments

Suppress specific findings with comments on the function definition line:

```python
@tool  # aigis: disable=AEG001 -- reviewed and accepted risk
def my_tool():
    os.remove(path)

@tool  # noqa: AEG001
def another_tool():
    shutil.rmtree(path)
```

### YAML Config

Create `.aigis.yaml`:

```yaml
suppressions:
  - rule: AEG001
    path: "tests/**"
    reason: "Test fixtures are not production code"

  - rule: AEG002
    symbol: run_shell_command
    reason: "Has runtime approval via CLI prompt"

  - rule: AEG003
    reason: "Budget enforcement handled externally"
```

## Baseline Support

Create a baseline to accept current findings and only fail on new ones:

```bash
# Snapshot current state
aeg baseline . -o aigis-baseline.json

# CI: fail only on new findings
aeg scan . --baseline aigis-baseline.json
```

Baseline fingerprints use rule ID + file path + tool name (not line numbers), so they survive minor code edits.

## Supported Frameworks

| Framework | Tool Detection | Entry Points | Approval Patterns | Budget Controls |
|-----------|---------------|-------------|-------------------|-----------------|
| **LangChain** | `@tool` decorator | `AgentExecutor(...)` | Approval/consent decorators | `max_iterations`, `timeout` |
| **LangGraph** | `graph.add_node(name, func)` | `graph.compile(...)` | `interrupt_before=[...]` | `recursion_limit` |
| **Custom** | `register_tool(func)` patterns | — | Decorator/body call matching | — |

## Output Formats

- **Console** — human-readable with evidence, remediation, and per-rule summary
- **JSON** — structured findings with full evidence objects
- **SARIF v2.1.0** — for GitHub Code Scanning, VS Code SARIF Viewer, etc.

## What It Does NOT Detect

- **Cross-file call graphs** — sinks must be in the same function body as the tool definition. Indirect calls through helper functions are not traced.
- **Data-flow analysis** — cannot track tainted inputs through variable assignments.
- **Runtime behavior** — all analysis is static and deterministic. Runtime-only approval patterns (e.g., middleware, external policy engines) are not detected.
- **SQL mutations** — `cursor.execute()` patterns are too ambiguous without query string analysis.
- **Dynamic tool registration** — tools registered via runtime reflection or metaprogramming are not detected.
- **Non-Python code** — only Python source files are analyzed.
- **LLM-based judgment** — detection is purely pattern-based. Semantic understanding of what a tool "does" is not attempted.

## Design Principles

- **Deterministic** — all detection comes from code patterns, never LLM judgment
- **Tri-state reasoning** — yes / no / unknown; unknown does not fail by default
- **Low noise over broad coverage** — prefer false negatives to false positives
- **Missing guard is first-class** — the absence of a control is the finding, not a heuristic guess
- **Evidence-first** — every finding includes structured evidence explaining what was found, what was missing, and how to fix it
