# Aigis Roadmap

## What Works Well Today (v0.2.0)

- **3 governance rules** covering approval gates, consent wrappers, and execution budgets
- **6 frameworks** supported: LangChain, LangGraph, OpenAI Agents SDK, CrewAI, AutoGen/AG2, custom
- **Constructor and execution-time** budget detection with variable tracking and config resolution
- **4 output formats**: console, JSON, SARIF, HTML
- **Suppression system**: inline comments + YAML config
- **Baseline support**: fingerprint-based, survives line-number shifts
- **Default test file exclusion** with override flag
- **117 tests** passing, validated against 15 real-world repos

## What's Coming Next

| Priority | Feature | Why It Matters |
|----------|---------|---------------|
| **High** | Cross-file budget/sink linkage | Many repos define agents in one file and execute in another |
| ~~**Done**~~ | ~~PyPI package~~ | ~~`pip install aigis-lint`~~ |
| **High** | Posture summary output | Aggregate governance metrics per scan (tools found, gates present, budgets set) |
| **Medium** | One-hop data-flow for indirect sinks | Catch tools that delegate to helpers containing dangerous calls |
| **Medium** | Published GitHub Action | One-liner CI integration: `uses: tyreamer/aigis-action@v1` |
| **Medium** | LlamaIndex validation | Framework patterns exist but need real-world validation |
| **Low** | PR diff / governance delta view | Show what changed between two scans |
| **Low** | Additional framework depth | Google ADK, Dify, custom orchestrators |

## Explicitly Out of Scope (For Now)

- TypeScript / JavaScript support
- Runtime monitoring or guardrails
- LLM-based detection or semantic analysis
- Cloud dashboard or hosted service
- Enterprise SSO / team management

## Where Feedback Is Most Valuable

1. **False positives** — findings that fired incorrectly on your code
2. **Framework gaps** — agent patterns aigis doesn't recognize
3. **Missing sinks** — dangerous operations not in the sink catalog
4. **Workflow fit** — how aigis does/doesn't fit your CI/CD pipeline
5. **Output quality** — whether findings are clear enough to act on
