# Media Plan — Screenshots and Visual Assets

## Assets Needed

### 1. Terminal screenshot: flagship finding

**Command:**
```bash
aigis scan examples/unsafe_tool.py --config /dev/null
```

**Setup:**
- Terminal: dark theme (e.g. iTerm2 Snazzy, Windows Terminal One Half Dark, or VS Code terminal)
- Font: JetBrains Mono or Cascadia Code, 14-16px
- Width: ~100 columns
- Clean prompt (no path clutter)

**What to capture:** The full output showing AIGIS001 + AIGIS002 firing on `run_cmd` with evidence and fix lines.

### 2. Terminal screenshot: clean scan

**Command:**
```bash
aigis scan examples/safe_agent.py --config /dev/null
```

**What to capture:** "No findings" — shows aigis doesn't cry wolf on governed code.

### 3. HTML report screenshot

**Command:**
```bash
aigis scan examples/ -f html -o report.html --config /dev/null
```

**What to capture:** Open `report.html` in Chrome/Edge. Screenshot the hero section showing:
- Metric cards (3 errors, 1 warning)
- Rule breakdown cards
- The governance status badge

**Second screenshot:** Scroll to a finding card, expand it to show evidence grid + rationale + remediation.

### 4. Side-by-side: unsafe vs safe

Create a two-panel image showing:

**Left panel — Unsafe:**
```python
@tool
def run_cmd(cmd: str) -> str:
    result = subprocess.run(cmd, shell=True, ...)
    return result.stdout
```
With AIGIS001 + AIGIS002 firing below.

**Right panel — Safe:**
```python
@tool
@requires_consent
def run_cmd(cmd: str) -> str:
    result = subprocess.run(cmd, shell=True, ...)
    return result.stdout
```
With "No findings" below.

### 5. GitHub social preview image

- 1280x640px
- Dark background matching the report aesthetic
- Aigis logo + tagline: "Governance linting for AI agents"
- Upload via GitHub repo Settings > Social preview

## File naming

Save screenshots to `docs/media/`:
```
docs/media/terminal-finding.png
docs/media/terminal-clean.png
docs/media/html-report-hero.png
docs/media/html-report-finding.png
docs/media/safe-vs-unsafe.png
docs/media/social-preview.png
```

## Embedding in README

After screenshots are captured, add to README:

```markdown
## What One Scan Gives You

![Terminal output showing aigis findings](docs/media/terminal-finding.png)

## HTML Report

![HTML report showing governance posture](docs/media/html-report-hero.png)
```
