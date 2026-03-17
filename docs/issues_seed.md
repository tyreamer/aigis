# Issue Seeds

Create these as GitHub Issues to show project activity and direction.

---

### 1. Cross-file budget and sink linkage

**Title:** Support cross-file call graph resolution for sinks and budgets

**Description:** Aigis currently only links budgets and sinks within a single file. If `Agent()` is defined in `agents.py` and `Runner.run(agent, max_turns=10)` is in `main.py`, the budget is not linked.

**Why it matters:** Well-structured codebases separate agent definition from execution. This is the most common false negative pattern.

**Priority:** High

---

### 2. Publish to PyPI

**Title:** Publish aigis to PyPI for `pip install aigis`

**Description:** Currently requires `pip install git+...` or local install. PyPI publishing would make adoption frictionless.

**Priority:** High

---

### 3. Posture summary output

**Title:** Add aggregate governance posture summary to scan output

**Description:** After scanning, show a summary like: "12 tools found, 3 unguarded. 5 entry points, 2 unbounded. 4 privileged operations, 1 without consent." This turns aigis from "a list of findings" into "a governance dashboard in your terminal."

**Why it matters:** Teams want to know their overall posture, not just individual findings.

**Priority:** High

---

### 4. One-hop data-flow for indirect sinks

**Title:** Detect sinks through one-hop helper function calls

**Description:** If a `@tool` calls `deploy_service(env)` which internally calls `subprocess.run(...)`, aigis doesn't see the sink. Supporting one-hop intra-file function resolution would catch this.

**Priority:** Medium

---

### 5. Published GitHub Action

**Title:** Create a published GitHub Action for one-liner CI integration

**Description:** `uses: tyreamer/aigis-action@v1` with inputs for path, format, and baseline.

**Priority:** Medium

---

### 6. LlamaIndex real-world validation

**Title:** Validate LlamaIndex framework support against real repos

**Description:** LlamaIndex patterns exist in the codebase but haven't been validated. Need to scan 3-5 real LlamaIndex agent repos and verify detection quality.

**Priority:** Medium

---

### 7. PR governance delta view

**Title:** Show governance delta between two scans or commits

**Description:** "This PR added 2 unguarded tools and removed 1 execution budget." Would make code review governance-aware.

**Priority:** Low

---

### 8. SQL mutation detection

**Title:** Detect SQL mutation patterns in cursor.execute

**Description:** `cursor.execute("DELETE FROM users WHERE ...")` is a mutating operation. Currently not detected because `cursor.execute` is ambiguous without query analysis.

**Priority:** Low
