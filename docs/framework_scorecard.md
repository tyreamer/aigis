# Framework Adapter Scorecard

Internal quality scorecard for each framework adapter. Updated after each evaluation pass.

## Scoring Criteria

| Metric | Description |
|--------|-------------|
| **Tool discovery rate** | % of tool definitions in test repos correctly identified |
| **Approval/HITL detection rate** | % of approval/consent patterns correctly recognized |
| **Entrypoint detection rate** | % of agent entry points correctly identified |
| **Precision on real repos** | % of findings that are correct (not false positives) |
| **Human agreement rate** | % of findings humans agree with (from evaluation) |

## Current Scores

### LangChain
| Metric | Score | Notes |
|--------|-------|-------|
| Tool discovery | 100% | @tool decorator — reliable |
| Approval/HITL detection | 100% | Decorator substring matching works |
| Entrypoint detection | 100% | AgentExecutor, create_react_agent |
| Precision on real repos | 100% | 14/14 AEG001 findings correct |
| Human agreement | 100% | All findings verified in eval |

### LangGraph
| Metric | Score | Notes |
|--------|-------|-------|
| Tool discovery | 95% | add_node works; misses wrapper-function graph vars |
| Approval/HITL detection | 85% | interrupt_before works; interrupt() now supported |
| Entrypoint detection | 90% | compile() heuristic good; misses graph vars from factory functions |
| Precision on real repos | ~83% | Some test-code and subgraph noise on AEG003 |
| Human agreement | ~85% | Subgraph findings are arguable |

### MCP
| Metric | Score | Notes |
|--------|-------|-------|
| Tool discovery | 100% | @mcp.tool() via attribute matching |
| Approval/HITL detection | N/A | No MCP-specific approval patterns |
| Entrypoint detection | N/A | MCP servers are tool hosts, not agent loops |
| Precision on real repos | 100% | 9/9 findings correct |
| Human agreement | 100% | All verified |

### OpenAI Agents SDK (NEW)
| Metric | Score | Notes |
|--------|-------|-------|
| Tool discovery | TBD | @function_tool decorator added |
| Approval/HITL detection | TBD | Decorator matching via existing custom patterns |
| Entrypoint detection | TBD | Agent() as entry point added |
| Precision on real repos | TBD | Needs eval pass on openai-agents-python |
| Human agreement | TBD | Pending |

### CrewAI (NEW)
| Metric | Score | Notes |
|--------|-------|-------|
| Tool discovery | TBD | @tool (shared with LangChain) |
| Approval/HITL detection | TBD | Decorator matching via existing patterns |
| Entrypoint detection | TBD | Crew() as entry point added |
| Precision on real repos | TBD | Needs eval pass |
| Human agreement | TBD | Pending |

### AutoGen / AG2 (NEW)
| Metric | Score | Notes |
|--------|-------|-------|
| Tool discovery | TBD | register_for_llm, register_for_execution |
| Approval/HITL detection | TBD | No AutoGen-specific approval patterns yet |
| Entrypoint detection | TBD | AssistantAgent, GroupChat, GroupChatManager |
| Precision on real repos | TBD | Needs eval pass |
| Human agreement | TBD | Pending |

## Evaluation History

| Date | Repos Scanned | Total Files | Findings | FP Rate | Notes |
|------|--------------|-------------|----------|---------|-------|
| 2026-03-16 | 13 | 2,355 | 57 | 0% | Initial eval — LangGraph/LangChain/MCP only |
