# aigis

**Governance linting for AI agents.** Verify that your agents can't delete, execute, or exfiltrate without approval — before they ever run.

Aigis statically analyzes Python AI agent code and reports missing governance controls: approval gates on dangerous tools, consent wrappers on privileged operations, and execution budgets on agent loops. It works across LangChain, LangGraph, OpenAI Agents SDK, CrewAI, and AutoGen — with zero runtime dependencies.

> **Public Alpha (v0.2.0)** — core rules are stable and validated against real-world repos. API surface and framework coverage may evolve. [Feedback welcome.](https://github.com/tyreamer/aigis/issues)

---

## Why This Exists

AI agents call tools. Tools can delete files, run shell commands, and send HTTP requests. Most agent frameworks make it easy to expose these capabilities — and easy to forget the controls.

Traditional SAST finds software vulnerabilities (SQL injection, XSS). Runtime AI safety tools catch bad behavior after deployment. Neither answers the question that matters before you ship:

**Can this agent take high-impact actions without human approval, and can it run forever?**

Aigis answers that question at build time, from code alone, with no LLM required.

## What One Scan Gives You

```bash
$ aigis scan examples/unsafe_tool.py
```
```
aigis v0.2.0 - AI Execution Governance Linter
Scanning: examples/unsafe_tool.py

  AIGIS001  ERROR  examples/unsafe_tool.py:13:0
    Tool 'run_cmd' reaches side-effecting sink(s) [subprocess.run] without an approval gate
    Evidence: sink=subprocess execution | approval=no | confidence=high
    Fix: Add an approval decorator or wrap side-effecting calls with a confirmation check.

  AIGIS002  ERROR  examples/unsafe_tool.py:13:0
    Tool 'run_cmd' performs privileged operation(s) [subprocess.run] without a consent/policy wrapper
    Evidence: sink=subprocess execution | approval=no | confidence=high
    Fix: Add a consent/policy decorator (e.g. @requires_consent, @policy_check).

Found 2 finding(s) (2 error, 0 warning)
```

From one scan, you get:
- Every tool that can mutate, execute, or send data — and whether it has an approval gate
- Every privileged operation (subprocess, system commands) — and whether it has a consent wrapper
- Every agent entry point — and whether it has an iteration/budget limit
- Structured evidence explaining *what* was found, *why* it matters, and *how* to fix it
- Output in console, JSON, SARIF, or a visual HTML report

## The Code That Defines the Category

```python
@tool
def run_cmd(cmd: str, timeout: int = 30) -> str:
    """Execute a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
```

An AI agent tool that runs arbitrary shell commands with `shell=True` and agent-controlled input. No human approval. No consent policy. No iteration limit on the agent calling it.

Aigis fires both **AIGIS001** (no approval gate) and **AIGIS002** (no consent wrapper). This pattern was found in a real course repo with hundreds of forks.

## Who This Is For

- **AI platform teams** building tool-using agents for production
- **AppSec engineers** adding agent code to their security review process
- **Architecture leads** establishing governance standards for agentic systems
- **Platform engineering** teams shipping LangGraph/CrewAI/OpenAI Agents infrastructure

Aigis is built for teams where agents interact with real systems — not toy chatbots.

## Install

```bash
pip install git+https://github.com/tyreamer/aigis.git
```

Or clone and install locally:

```bash
git clone https://github.com/tyreamer/aigis.git
cd aigis
pip install -e .
```

## 5-Minute Quick Start

```bash
# Scan your agent code
aigis scan /path/to/your/project

# Scan the included examples
aigis scan examples/unsafe_tool.py       # fires AIGIS001 + AIGIS002
aigis scan examples/unbounded_agent.py   # fires AIGIS001 + AIGIS003
aigis scan examples/safe_agent.py        # clean — no findings

# Generate a visual HTML report
aigis scan /path/to/your/project -f html -o report.html

# CI-ready outputs
aigis scan . -f json                     # structured JSON
aigis scan . -f sarif -o results.sarif   # GitHub Code Scanning

# Baseline workflow: accept current findings, fail only on new ones
aigis baseline . -o .aigis-baseline.json
aigis scan . --baseline .aigis-baseline.json
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

**Detected sinks:** `os.remove`, `shutil.rmtree`, `subprocess.run`, `os.system`, `requests.post`, `httpx.put`, `open()` with write mode, and more.

### AIGIS002 — Privileged Operation Without Consent Wrapper

Fires when a tool calls subprocess or system commands without an explicit consent or policy wrapper. Generic `@requires_approval` is not sufficient — requires `@requires_consent`, `@policy_check`, or similar.

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

Aigis checks budget controls at both construction time and execution time, including `Runner.run(max_turns=N)`, `app.invoke(config={"recursion_limit": N})`, `initiate_group_chat(max_rounds=N)`, and config variable resolution.

### AIGIS004 — Unbounded Retry / Loop

Fires when a tool contains a retry decorator without max attempts, or a `while True` loop without a break condition.

```python
# Flagged:
@tool
@retry                              # no stop=, no max_retries=
def fetch_data(url: str) -> str:
    return requests.post(url).text

# Clean:
@tool
@retry(stop=stop_after_attempt(3))
def fetch_data(url: str) -> str:
    return requests.post(url).text
```

### AIGIS005 — User-Controlled Budget Without Cap

Fires when an execution budget parameter (`max_turns`, `recursion_limit`, etc.) receives its value from a variable rather than a constant, with no visible server-side cap.

```python
# Flagged:
def run_agent(user_max_turns: int):
    Runner.run(agent, input="go", max_turns=user_max_turns)  # no cap

# Clean:
def run_agent(user_max_turns: int):
    Runner.run(agent, input="go", max_turns=min(user_max_turns, 50))
```

### AIGIS006 — Raw Chat History as Retrieval Query

Fires when a raw chat history variable (`messages`, `chat_history`, `conversation`) is passed directly to a retrieval function without a query rewriting step.

```python
# Flagged:
results = store.similarity_search(chat_history)  # raw transcript as query

# Clean:
query = condense_question(chat_history)
results = store.similarity_search(query)
```

## Supported Frameworks

| Framework | Tool Detection | Entry Points | Budget Controls |
|-----------|---------------|-------------|-----------------|
| **LangChain** | `@tool` | `AgentExecutor` | `max_iterations`, `timeout` |
| **LangGraph** | `add_node` | `compile()` | `recursion_limit` |
| **OpenAI Agents** | `@function_tool` | `Agent()` | `max_turns` (constructor or `Runner.run`) |
| **CrewAI** | `@tool` | `Crew()` | `max_iter`, `max_rpm` |
| **AutoGen / AG2** | `register_for_llm` | `AssistantAgent`, `GroupChat` | `max_turns`, `max_round` |

## Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **Console** | Local development | `aigis scan .` |
| **JSON** | CI pipelines, scripting | `aigis scan . -f json` |
| **SARIF** | GitHub Code Scanning | `aigis scan . -f sarif -o results.sarif` |
| **HTML** | Reports, reviews, demos | `aigis scan . -f html -o report.html` |

The HTML report is a self-contained dark-mode file with filters, expandable evidence cards, remediation guidance, and framework-specific context. No backend required — open it in any browser.

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

### Baseline

Accept current findings, fail only on new ones:

```bash
aigis baseline . -o .aigis-baseline.json
aigis scan . --baseline .aigis-baseline.json
```

Fingerprints use rule ID + file path + tool name (not line numbers), so they survive code edits.

## How Aigis Is Different

| | Traditional SAST | Runtime AI Safety | **Aigis** |
|---|---|---|---|
| **When** | Build time | Runtime | **Build time** |
| **What** | Software vulns (SQLi, XSS) | Model behavior, guardrails | **Agent governance controls** |
| **Checks for** | Code flaws | Harmful outputs | **Missing approval, consent, bounds** |
| **Requires runtime** | No | Yes | **No** |
| **AI/LLM needed** | No | Often | **No** |

Aigis is not a prompt scanner, a model guardrail, or a vulnerability finder. It checks whether the structural controls that should exist in agent code — approval gates, consent wrappers, execution budgets — are actually present.

## What It Does NOT Detect

- **Cross-file call graphs** — sinks must be in the same function body as the tool
- **Data-flow analysis** — cannot track tainted inputs through variables
- **Runtime behavior** — all analysis is static and deterministic
- **SQL mutations** — `cursor.execute()` is too ambiguous without query analysis
- **Dynamic tool registration** — runtime reflection / metaprogramming
- **Non-Python code** — Python only
- **LLM-based judgment** — purely pattern-based, no semantic understanding

## Roadmap

**What works well today:**
- Tool detection and sink analysis across 6 frameworks
- Approval/consent/budget governance checks
- Constructor-time and execution-time budget detection
- Suppression, baselines, and 4 output formats

**What's next:**
- Cross-file call graph support
- Data-flow tracking for indirect sinks
- Posture summary (aggregate governance metrics per scan)
- PyPI package publishing (`pip install aigis`)
- Published GitHub Action
- Additional framework depth (LlamaIndex, Google ADK)

**Explicitly out of scope for now:**
- TypeScript/JavaScript support
- Runtime monitoring
- LLM-based detection
- Cloud dashboard or hosted service

## Design Principles

- **Deterministic** — code patterns only, never LLM judgment
- **Tri-state** — yes / no / unknown; unknown does not fail
- **Low noise** — false negatives over false positives
- **Missing guard is first-class** — the absence of a control is the finding
- **Evidence-first** — every finding explains what, why, and how to fix

## Feedback

Aigis is in public alpha. If you're building tool-using agents and want governance visibility before production, we want to hear from you.

- [Open an issue](https://github.com/tyreamer/aigis/issues) with findings, false positives, or framework gaps
- [Start a discussion](https://github.com/tyreamer/aigis/discussions) about your governance workflow

We're especially interested in feedback from teams shipping agents with file access, network access, or subprocess execution.
