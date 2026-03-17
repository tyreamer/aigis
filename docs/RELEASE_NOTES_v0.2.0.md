# aigis v0.2.0 Release Notes

**AI Execution Governance Linter** — catch unsafe AI agent autonomy before runtime.

This is the first public alpha release of aigis. It statically scans Python AI agent code for missing governance controls: approval gates, consent wrappers, and execution budgets.

## What's New in v0.2.0

### 6-Framework Support

aigis now detects governance gaps across all major Python agent frameworks:

| Framework | What's Detected |
|-----------|----------------|
| **LangChain** | `@tool` sinks, `AgentExecutor` budgets |
| **LangGraph** | `compile()` budgets, `interrupt()` HITL, `add_node` tools |
| **OpenAI Agents SDK** | `@function_tool` sinks, `Agent` budgets, `Runner.run` execution-time budgets |
| **CrewAI** | `@tool` sinks, `Crew` budgets |
| **AutoGen / AG2** | `AssistantAgent`/`GroupChat` budgets, `initiate_group_chat` orchestration budgets |
| **Custom** | `register_tool()` patterns, approval/consent decorator matching |

### Execution-Time Budget Detection (AEG003)

AEG003 now checks for budget controls at both construction and execution time:

```python
# Detected as bounded (clean):
agent = Agent(name="x", tools=[t])
Runner.run(agent, input="go", max_turns=10)  # budget at execution time

# Detected as bounded (clean):
app = graph.compile()
app.invoke(input, config={"recursion_limit": 25})  # budget in config
```

Supported execution-time patterns:
- `Runner.run(agent, max_turns=N)` / `Runner.run_sync` / `Runner.run_streamed`
- `proxy.initiate_chat(agent, max_turns=N)`
- `app.invoke(input, config={"recursion_limit": N})`
- `initiate_group_chat(max_rounds=N)` (file-level)
- Config variable resolution: `cfg = {"recursion_limit": 25}; app.invoke(input, config=cfg)`
- GroupChat budget propagation to GroupChatManager
- One-hop variable aliasing

### LangGraph interrupt() as HITL Signal

`interrupt()` imported from `langgraph.types` is now recognized as a human-in-the-loop approval signal, covering modern LangGraph patterns alongside the existing `interrupt_before` kwarg detection.

### Default Test File Exclusion

Test files (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`) are excluded from scanning by default. Override with `--no-default-excludes`.

### Framework-Specific Evidence

AEG003 findings now include the framework name and targeted remediation:

```
[OpenAI Agents SDK] Entry point 'Agent' creates an agent execution loop
with no budget limit. Checked constructor kwargs and same-file execution
calls — no budget control found on either.
Fix: Add an execution budget: max_turns=N on Agent() or Runner.run(..., max_turns=N).
```

### CI Integration

Example GitHub Actions workflow included at `.github/workflows/aigis.yml` with SARIF upload to GitHub Code Scanning.

## Quality

- **AEG001/AEG002 precision: 100%** across 15 real-world repos
- **AEG003 precision: ~85-90%** after execution-time budget detection
- **113 tests**, all passing
- **Zero false positives** on AEG001/AEG002

## Install

```bash
pip install git+https://github.com/tyreamer/aigis.git
aeg scan .
```

## Known Limitations

See [release_readiness.md](release_readiness.md) for full details. Key limitations:
- No cross-file call graph resolution
- No data-flow / taint analysis
- Python only (no TypeScript)
- No PyPI package yet
