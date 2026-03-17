# Release Readiness Assessment

## Is Aigis ready for public GitHub release?

**Yes, with caveats documented below.**

The scanner is functionally complete for its first wedge: detecting unsafe autonomy, missing approval gates, and unbounded execution in Python AI agent code. It produces structured, actionable findings with framework-specific remediation. It supports suppressions, baselines, and three output formats (console, JSON, SARIF). It works with 6 major agent frameworks.

## What is solid

- **AEG001/AEG002 precision: 100%** — zero false positives across 15 real-world repos (2,355 files)
- **AEG003 precision: ~85-90%** — after AG2 fix, remaining findings are genuinely unbounded patterns
- **6 frameworks supported**: LangChain, LangGraph, OpenAI Agents, CrewAI, AutoGen/AG2, custom patterns
- **CLI ergonomics**: clean `aeg scan/baseline` commands, `--format`, `--baseline`, `--config`
- **Output formats**: console, JSON, SARIF (GitHub Code Scanning compatible)
- **Suppression**: inline comments + YAML config
- **Baseline**: fingerprint-based, survives line-number shifts
- **Test coverage**: 113 tests, all passing
- **Examples**: 3 polished demo files + example config + GitHub Action workflow

## What is still rough

- **No PyPI package yet** — install is `pip install -e .` or `pip install git+...`
- **No logo/branding** — plain text CLI
- **Version 0.1.0** — signals early-stage appropriately
- **LlamaIndex coverage is untested** — patterns exist but no real-world validation
- **Cross-file analysis not supported** — this is a known limitation by design

## What should not be promised yet

- TypeScript support
- Dashboard or web UI
- LLM-based detection or semantic analysis
- Cross-file call graph resolution
- Data-flow or taint analysis
- SQL injection detection
- Production-grade CI integration (the GitHub Action is an example, not a published action)

## 3 Strongest Demo Moments

### 1. `run_cmd` — the category definer
```python
@tool
def run_cmd(cmd: str):
    subprocess.run(cmd, shell=True)
```
Both AEG001 and AEG002 fire. Universally understood risk: agent-controlled shell execution without approval. Discovered in a real course repo with hundreds of forks.

### 2. Unbounded agent loop
```python
agent = Agent(name="writer", tools=[write_file])
Runner.run(agent, input="Create 100 config files")  # no max_turns
```
AEG003 fires. The agent can write files indefinitely. Discovered that only 4/186 Runner.run calls in the OpenAI SDK examples use `max_turns`.

### 3. Clean scan on governed code
```python
@tool
@requires_consent
def deploy(env: str):
    subprocess.run(["deploy", "--env", env])

agent = AgentExecutor(agent=None, tools=[deploy], max_iterations=10)
```
Zero findings. Shows that Aigis doesn't cry wolf — properly governed code passes cleanly.

## 3 Biggest Known Limitations

1. **No cross-file analysis** — if the budget is set in a different file from the agent definition, Aigis can't link them. Workaround: inline suppression with a comment.

2. **No data-flow tracking** — if a tool delegates to a helper function that calls `subprocess.run`, Aigis won't see the sink. The sink must be in the tool function body.

3. **AEG003 volume on large repos** — in repos with many agent definitions (hundreds of `Agent()` calls), AEG003 can produce high volume. This is usually correct (the code genuinely lacks budgets) but can feel noisy. Workaround: baseline + suppress by path.
