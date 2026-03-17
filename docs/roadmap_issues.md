# Roadmap Issues

Create these as GitHub Issues. Copy-paste the title and body.

---

## GitHub Repo Settings

**Description:** Static analysis CLI that catches unsafe AI agent autonomy before runtime. Detects missing approval gates, consent wrappers, and execution budgets across LangChain, LangGraph, OpenAI Agents, CrewAI, and AutoGen.

**Topics:** `ai-agents`, `static-analysis`, `security`, `governance`, `linter`, `langchain`, `langgraph`, `openai`, `crewai`, `autogen`, `python`

---

## Issue 1: Cross-file call graph resolution

**Title:** Support cross-file call graph resolution for sinks and budgets

**Labels:** `enhancement`, `scope:analysis`

**Body:**
Currently aigis only analyzes within a single file. This means:
- If a tool delegates to a helper in another file that calls `subprocess.run`, the sink is not detected
- If `Agent()` is defined in one file and `Runner.run(agent, max_turns=10)` is in another, the budget is not linked

This is the most-requested enhancement for reducing false negatives on well-structured codebases.

**Complexity:** High — requires multi-file import resolution and variable tracking.

---

## Issue 2: Data-flow / taint analysis for indirect sinks

**Title:** Detect sinks through one-hop helper function calls

**Labels:** `enhancement`, `scope:analysis`

**Body:**
If a `@tool` function calls a helper that internally calls `subprocess.run`, aigis doesn't see the sink:

```python
@tool
def deploy(env):
    return run_deploy_script(env)  # aigis can't see subprocess.run inside run_deploy_script
```

Supporting one-hop intra-file function call resolution would catch this common pattern.

---

## Issue 3: TypeScript / JavaScript support

**Title:** Add TypeScript/JavaScript agent framework support

**Labels:** `enhancement`, `scope:language`

**Body:**
Vercel AI SDK, LangChain.js, and other JS/TS agent frameworks are widely used. Adding TypeScript support would expand aigis coverage significantly.

Requires a separate AST parser (e.g. tree-sitter for TS) and framework pattern modules for JS/TS agent libraries.

---

## Issue 4: PyPI package publishing

**Title:** Publish aigis to PyPI

**Labels:** `enhancement`, `scope:packaging`

**Body:**
Currently aigis is installed via `pip install git+...` or `pip install -e .`. Publishing to PyPI would make installation simpler:

```bash
pip install aigis
```

Needs: PyPI account, build pipeline, version automation.

---

## Issue 5: SQL mutation detection

**Title:** Detect SQL mutation patterns (INSERT/UPDATE/DELETE) in cursor.execute

**Labels:** `enhancement`, `scope:rules`

**Body:**
`cursor.execute("DELETE FROM users WHERE ...")` is a mutating operation that should be flagged by AEG001, but `cursor.execute` is too ambiguous without analyzing the SQL string (it could be a SELECT).

Options:
- Flag all `cursor.execute` with a lower confidence
- Parse literal SQL strings for mutation keywords
- Add as a separate rule (AEG004?)

---

## Issue 6: LlamaIndex framework validation

**Title:** Validate and expand LlamaIndex framework support

**Labels:** `enhancement`, `scope:frameworks`

**Body:**
LlamaIndex patterns exist in the codebase but have not been validated against real-world LlamaIndex repos. Specifically:
- `AgentRunner` as entry point
- `FunctionCallingAgentWorker.from_tools()` patterns
- `FunctionTool.from_defaults()` tool factory
- `QueryEngineTool.from_defaults()` RAG tool patterns

Needs: find 3-5 real LlamaIndex agent repos, scan them, verify detection quality.

---

## Issue 7: Published GitHub Action

**Title:** Create a published GitHub Action for aigis

**Labels:** `enhancement`, `scope:packaging`

**Body:**
Currently we provide an example workflow file. A published GitHub Action (`uses: tyreamer/aigis-action@v1`) would make CI integration one-liner:

```yaml
- uses: tyreamer/aigis-action@v1
  with:
    path: src/
    format: sarif
```

---

## Issue 8: VS Code extension

**Title:** VS Code extension for inline aigis findings

**Labels:** `enhancement`, `scope:ux`

**Body:**
Show aigis findings inline in VS Code using the SARIF Viewer or a custom extension. Findings would appear as squiggly underlines on `@tool` decorated functions.
