# Repo Positioning Summary

## Product Thesis

Aigis is governance linting for AI agents — static analysis that verifies approval gates, consent wrappers, and execution budgets exist in agent code before runtime.

## One-Sentence Pitch

Aigis catches AI agent tools that can delete, execute, or exfiltrate without approval — before the agent ever runs.

## One-Paragraph Pitch

AI agents call tools that interact with real systems: deleting files, running shell commands, sending HTTP requests. Most agent frameworks make it easy to expose these capabilities and easy to forget the controls. Aigis statically analyzes Python agent code and reports missing governance controls — approval gates on dangerous tools, consent wrappers on privileged operations, and execution budgets on agent loops. It works across LangChain, LangGraph, OpenAI Agents SDK, CrewAI, and AutoGen, with structured evidence and actionable remediation in every finding.

## Target Audience

1. **AI platform teams** building tool-using agents for production
2. **AppSec engineers** adding agent code to security review
3. **Architecture/governance leads** setting standards for agentic systems
4. **Platform engineering** shipping agent infrastructure

## Differentiation

| | Traditional SAST | Runtime AI Safety | **Aigis** |
|---|---|---|---|
| **When** | Build time | Runtime | **Build time** |
| **What** | Software vulns | Model behavior | **Agent governance** |
| **Checks for** | Code flaws | Harmful outputs | **Missing controls** |
| **Requires runtime** | No | Yes | **No** |

Aigis is not Semgrep for prompts. It's not a guardrail. It checks whether the structural controls that should exist in agent code — approval gates, consent wrappers, execution budgets — are actually present.

## Why the Repo Now Presents More Value

**Before:** "Interesting scanner with 3 rules and some framework support."

**After:** The repo communicates:
- A clear product category (governance linting for AI agents)
- A specific wedge (missing controls, not code flaws)
- Who should care (platform teams, AppSec, governance leads)
- What you get from one scan (not just alerts — governance visibility)
- How it's different from SAST and runtime AI safety
- An honest alpha scope with clear roadmap
- A first-run path a stranger can follow in 5 minutes
