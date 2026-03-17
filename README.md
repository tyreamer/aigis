# aigis

**Static analysis for AI agent safety.** Catches tools that can delete, execute, or exfiltrate without approval — before your agent ever runs.

> *Your agent has `subprocess.run(cmd, shell=True)` exposed as a tool with no approval gate. aigis finds that.*

## Status: Public Alpha

aigis is in early public alpha (v0.2.0). The core rules are stable and validated against real-world repos, but the API surface, output format, and framework coverage may change. Feedback and issues welcome.

## Why This Matters

AI agents call tools. Tools delete files, run shell commands, send HTTP requests. If there is no approval gate, no consent wrapper, and no iteration limit — the agent can do whatever it wants, for as long as it wants.

aigis catches these governance gaps before they reach production.

## The Finding That Explains the Category

```python
@tool
def run_cmd(cmd: str, timeout: int = 30) -> str:
    """Execute a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
```

```
AIGIS001  ERROR  run_cmd — subprocess execution without approval gate
AIGIS002  ERROR  run_cmd — privileged operation without consent wrapper
```

An AI agent tool that runs arbitrary shell commands with `shell=True`. No human approval. No consent policy. Both rules fire.

## Install

```bash
pip install -e .
```

## Quick Start

```bash
aigis scan .                                   # scan current directory
aigis scan examples/unsafe_tool.py             # scan a single file
aigis scan . -f json                           # JSON output for CI
aigis scan . -f html -o report.html            # visual HTML report
aigis scan . -f sarif -o results.sarif         # SARIF for GitHub Code Scanning
aigis baseline . -o .aigis-baseline.json       # create a baseline
aigis scan . --baseline .aigis-baseline.json   # fail only on new findings
```

## Rules

### AIGIS001 — Mutating Tool Without Approval Gate

Fires when a tool performs side effects (file I/O, subprocess, HTTP mutations) with no approval mechanism.

```python
# Flagged:
@tool
def delete_user(user_id: str):
    os.remove(f"/data/{user_id}.json")

# Clean:
@tool
@requires_approval
def delete_user(user_id: str):
    os.remove(f"/data/{user_id}.json")
```

### AIGIS002 — Privileged Operation Without Consent Wrapper

Fires when a tool calls subprocess/system commands without an explicit consent or policy wrapper. Generic `@requires_approval` is not sufficient — requires `@requires_consent`, `@policy_check`, or similar.

```python
# Flagged (generic approval is not consent-level):
@tool
@requires_approval
def run_command(cmd: str):
    subprocess.run(cmd, shell=True)

# Clean:
@tool
@requires_consent
def run_command(cmd: str):
    subprocess.run(cmd, shell=True)
```

### AIGIS003 — Missing Execution Budget

Fires when an agent entry point has no iteration or budget limit — neither on the constructor nor on any execution call in the same file.

```python
# Flagged:
agent = Agent(name="x", tools=[my_tool])
Runner.run(agent, input="go")               # no max_turns anywhere

# Clean (constructor budget):
agent = AgentExecutor(agent=llm, tools=[t], max_iterations=10)

# Clean (execution-time budget):
agent = Agent(name="x", tools=[my_tool])
Runner.run(agent, input="go", max_turns=10)
```

## Supported Frameworks

| Framework | Tool Detection | Entry Points | Budget Controls |
|-----------|---------------|-------------|-----------------|
| **LangChain** | `@tool` | `AgentExecutor` | `max_iterations`, `timeout` |
| **LangGraph** | `add_node` | `compile()` | `recursion_limit` |
| **OpenAI Agents** | `@function_tool` | `Agent()` | `max_turns` (constructor or `Runner.run`) |
| **CrewAI** | `@tool` | `Crew()` | `max_iter`, `max_rpm` |
| **AutoGen / AG2** | `register_for_llm` | `AssistantAgent`, `GroupChat` | `max_turns`, `max_round` |

## Suppression

### Inline

```python
@tool  # aigis: disable=AIGIS001 -- reviewed and accepted risk
def my_tool():
    os.remove(path)
```

### Config File

Create `.aigis.yaml` in your project root:

```yaml
suppressions:
  - rule: AIGIS001
    path: "scripts/**"
    reason: "Internal tooling with runtime approval"

  - rule: AIGIS003
    symbol: my_agent
    reason: "Budget enforced by external orchestrator"
```

## Baseline

Accept current findings, fail only on new ones:

```bash
aigis baseline . -o .aigis-baseline.json
aigis scan . --baseline .aigis-baseline.json
```

Fingerprints use rule ID + file path + tool name (not line numbers), so they survive code edits.

## Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **Console** | Local development | `aigis scan .` |
| **JSON** | CI pipelines, scripting | `aigis scan . -f json` |
| **SARIF** | GitHub Code Scanning | `aigis scan . -f sarif -o results.sarif` |
| **HTML** | Reports, reviews, demos | `aigis scan . -f html -o report.html` |

## What It Does NOT Detect

- **Cross-file call graphs** — sinks must be in the same function body as the tool
- **Data-flow analysis** — cannot track tainted inputs through variables
- **Runtime behavior** — all analysis is static and deterministic
- **SQL mutations** — `cursor.execute()` is too ambiguous without query analysis
- **Dynamic tool registration** — runtime reflection / metaprogramming
- **Non-Python code** — Python source files only
- **LLM-based judgment** — purely pattern-based, no semantic understanding

## Design Principles

- **Deterministic** — code patterns only, never LLM judgment
- **Tri-state** — yes / no / unknown; unknown does not fail
- **Low noise** — false negatives over false positives
- **Missing guard is first-class** — the absence of a control is the finding
- **Evidence-first** — every finding explains what, why, and how to fix
