"""HTML output formatter — premium single-file security report."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import Finding, RuleResult, Severity


def format_html(
    results: list[RuleResult],
    target: str,
    suppressed_count: int = 0,
    baselined_count: int = 0,
) -> str:
    all_findings = _collect_findings(results)

    # Build JSON data for the template
    findings_json = json.dumps([_finding_to_dict(f, target) for f in all_findings])
    summary = {
        "version": __version__,
        "target": target,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total": len(all_findings),
        "errors": sum(1 for f in all_findings if f.severity == Severity.ERROR),
        "warnings": sum(1 for f in all_findings if f.severity == Severity.WARNING),
        "notes": sum(1 for f in all_findings if f.severity == Severity.NOTE),
        "suppressed": suppressed_count,
        "baselined": baselined_count,
        "by_rule": _count_by_rule(all_findings),
        "by_file": _count_by_file(all_findings, target),
    }
    summary_json = json.dumps(summary)

    return _TEMPLATE.replace("/*__FINDINGS_DATA__*/[]", findings_json).replace(
        "/*__SUMMARY_DATA__*/{}", summary_json
    )


def _finding_to_dict(f: Finding, target: str) -> dict:
    try:
        rel_path = str(Path(f.location.file).relative_to(Path(target).resolve()))
    except ValueError:
        rel_path = f.location.file
    rel_path = rel_path.replace("\\", "/")

    d: dict = {
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "message": f.message,
        "file": rel_path,
        "line": f.location.line,
        "col": f.location.col,
    }
    if f.evidence:
        d["evidence"] = f.evidence.to_dict()
    return d


def _count_by_rule(findings: list[Finding]) -> dict:
    counts: dict[str, dict[str, int]] = {}
    for f in findings:
        rc = counts.setdefault(f.rule_id, {"error": 0, "warning": 0, "note": 0})
        rc[f.severity.value] += 1
    return counts


def _count_by_file(findings: list[Finding], target: str) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        try:
            rel = str(Path(f.location.file).relative_to(Path(target).resolve()))
        except ValueError:
            rel = f.location.file
        rel = rel.replace("\\", "/")
        counts[rel] = counts.get(rel, 0) + 1
    return counts


def _collect_findings(results: list[RuleResult]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)
    return sorted(findings, key=lambda f: (f.location.file, f.location.line))


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aigis report</title>
<style>
/* ===== RESET & FOUNDATIONS ===== */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

@font-face {
  font-family: 'Geist';
  src: local('Geist'), local('GeistVF');
}

:root {
  --bg-0: #0a0a0f;
  --bg-1: #111118;
  --bg-2: #18181f;
  --bg-3: #1f1f28;
  --bg-4: #262630;
  --surface: rgba(255,255,255,0.025);
  --surface-hover: rgba(255,255,255,0.045);
  --border: rgba(255,255,255,0.06);
  --border-subtle: rgba(255,255,255,0.035);
  --text-0: #e8e8ed;
  --text-1: #a8a8b3;
  --text-2: #6e6e7a;
  --text-3: #44444f;
  --error: #f43f5e;
  --error-dim: rgba(244,63,94,0.12);
  --error-glow: rgba(244,63,94,0.06);
  --warning: #f59e0b;
  --warning-dim: rgba(245,158,11,0.12);
  --warning-glow: rgba(245,158,11,0.06);
  --note: #6366f1;
  --note-dim: rgba(99,102,241,0.12);
  --accent: #818cf8;
  --accent-dim: rgba(129,140,248,0.08);
  --green: #34d399;
  --green-dim: rgba(52,211,153,0.12);
  --radius: 12px;
  --radius-sm: 8px;
  --radius-xs: 6px;
  --font-sans: 'Geist', 'SF Pro Display', -apple-system, 'Segoe UI', sans-serif;
  --font-mono: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Fira Code', monospace;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.3), 0 1px 3px rgba(0,0,0,0.15);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.4), 0 2px 4px rgba(0,0,0,0.2);
  --shadow-lg: 0 8px 30px rgba(0,0,0,0.5), 0 4px 10px rgba(0,0,0,0.25);
  --transition: 180ms cubic-bezier(0.4,0,0.2,1);
}

html { font-size: 15px; }

body {
  font-family: var(--font-sans);
  background: var(--bg-0);
  color: var(--text-0);
  line-height: 1.6;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* ===== AMBIENT BACKGROUND ===== */
body::before {
  content: '';
  position: fixed;
  top: -40%; left: -20%;
  width: 80%; height: 80%;
  background: radial-gradient(ellipse, rgba(99,102,241,0.03) 0%, transparent 70%);
  pointer-events: none;
  z-index: 0;
}
body::after {
  content: '';
  position: fixed;
  bottom: -30%; right: -10%;
  width: 60%; height: 60%;
  background: radial-gradient(ellipse, rgba(244,63,94,0.02) 0%, transparent 70%);
  pointer-events: none;
  z-index: 0;
}

/* ===== LAYOUT ===== */
.shell { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; padding: 0 24px; }

/* ===== HEADER ===== */
.header {
  position: sticky; top: 0; z-index: 100;
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  background: rgba(10,10,15,0.82);
  border-bottom: 1px solid var(--border);
  padding: 0;
  margin-bottom: 32px;
}
.header-inner {
  max-width: 1100px; margin: 0 auto; padding: 16px 24px;
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 12px;
}
.brand {
  display: flex; align-items: center; gap: 10px;
}
.brand-icon {
  width: 28px; height: 28px;
  background: linear-gradient(135deg, var(--accent) 0%, var(--error) 100%);
  border-radius: 7px;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 0 16px rgba(129,140,248,0.2);
}
.brand-icon svg { width: 16px; height: 16px; fill: white; }
.brand-name {
  font-size: 1.1rem; font-weight: 600; letter-spacing: -0.02em;
  color: var(--text-0);
}
.brand-ver {
  font-size: 0.72rem; color: var(--text-2); font-family: var(--font-mono);
  background: var(--surface); padding: 2px 7px; border-radius: 4px;
  margin-left: 2px; letter-spacing: 0.02em;
}
.header-stats {
  display: flex; gap: 6px; flex-wrap: wrap;
}
.stat-chip {
  display: flex; align-items: center; gap: 5px;
  padding: 5px 11px; border-radius: 20px;
  font-size: 0.78rem; font-weight: 500; font-family: var(--font-mono);
  border: 1px solid var(--border);
  background: var(--surface);
  transition: background var(--transition);
  cursor: default;
  letter-spacing: 0.01em;
}
.stat-chip:hover { background: var(--surface-hover); }
.stat-chip .dot {
  width: 7px; height: 7px; border-radius: 50%;
  flex-shrink: 0;
}
.stat-chip.err .dot { background: var(--error); box-shadow: 0 0 6px var(--error); }
.stat-chip.warn .dot { background: var(--warning); box-shadow: 0 0 6px var(--warning); }
.stat-chip.clean .dot { background: var(--green); box-shadow: 0 0 6px var(--green); }
.stat-chip.meta { color: var(--text-2); }

/* ===== SCAN META ===== */
.scan-meta {
  display: flex; gap: 24px; flex-wrap: wrap;
  margin-bottom: 28px; padding: 0 2px;
  font-size: 0.8rem; color: var(--text-2); font-family: var(--font-mono);
}
.scan-meta span { display: flex; align-items: center; gap: 5px; }
.scan-meta svg { width: 13px; height: 13px; opacity: 0.5; fill: currentColor; }

/* ===== FILTER BAR ===== */
.filters {
  display: flex; gap: 6px; margin-bottom: 24px; flex-wrap: wrap;
}
.filter-btn {
  padding: 6px 14px; border-radius: 20px;
  font-size: 0.78rem; font-weight: 500;
  border: 1px solid var(--border);
  background: transparent; color: var(--text-1);
  cursor: pointer; transition: all var(--transition);
  font-family: var(--font-sans);
  letter-spacing: 0.01em;
}
.filter-btn:hover { background: var(--surface-hover); color: var(--text-0); }
.filter-btn.active {
  background: var(--accent-dim); color: var(--accent);
  border-color: rgba(129,140,248,0.25);
}
.filter-btn .cnt {
  font-family: var(--font-mono); margin-left: 4px;
  opacity: 0.6; font-size: 0.72rem;
}

/* ===== FINDINGS LIST ===== */
.findings { display: flex; flex-direction: column; gap: 10px; padding-bottom: 80px; }

/* ===== FINDING CARD ===== */
.card {
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  transition: all var(--transition);
  box-shadow: var(--shadow-sm);
}
.card:hover {
  border-color: rgba(255,255,255,0.09);
  box-shadow: var(--shadow-md);
  transform: translateY(-1px);
}
.card.sev-error { border-left: 3px solid var(--error); }
.card.sev-warning { border-left: 3px solid var(--warning); }
.card.sev-note { border-left: 3px solid var(--note); }

.card-head {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 16px 18px 12px;
  cursor: pointer; user-select: none;
}
.card-head:hover .card-toggle { color: var(--text-1); }

.sev-badge {
  flex-shrink: 0;
  padding: 3px 8px; border-radius: 5px;
  font-size: 0.68rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.06em; font-family: var(--font-mono);
}
.sev-badge.error { background: var(--error-dim); color: var(--error); }
.sev-badge.warning { background: var(--warning-dim); color: var(--warning); }
.sev-badge.note { background: var(--note-dim); color: var(--note); }

.card-main { flex: 1; min-width: 0; }
.card-rule {
  font-size: 0.72rem; font-family: var(--font-mono);
  color: var(--text-2); margin-bottom: 3px; letter-spacing: 0.02em;
}
.card-msg {
  font-size: 0.92rem; color: var(--text-0); line-height: 1.5;
  word-break: break-word;
}
.card-msg code {
  font-family: var(--font-mono); font-size: 0.85em;
  background: rgba(255,255,255,0.05); padding: 1px 5px;
  border-radius: 4px; color: var(--accent);
}
.card-loc {
  margin-top: 6px; font-size: 0.75rem; font-family: var(--font-mono);
  color: var(--text-2);
  display: flex; align-items: center; gap: 4px;
}
.card-loc svg { width: 12px; height: 12px; fill: currentColor; opacity: 0.4; }

.card-toggle {
  flex-shrink: 0; margin-top: 2px;
  color: var(--text-3); transition: color var(--transition), transform var(--transition);
}
.card-toggle svg { width: 16px; height: 16px; fill: currentColor; }
.card.open .card-toggle { transform: rotate(180deg); color: var(--text-1); }

/* ===== CARD DETAIL ===== */
.card-detail {
  max-height: 0; overflow: hidden;
  transition: max-height 300ms cubic-bezier(0.4,0,0.2,1);
}
.card.open .card-detail { max-height: 600px; }

.card-detail-inner {
  padding: 0 18px 18px;
  border-top: 1px solid var(--border-subtle);
  margin-top: 0; padding-top: 14px;
}
.evidence-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 8px; margin-bottom: 14px;
}
.ev-item {
  background: var(--bg-3); border-radius: var(--radius-xs);
  padding: 10px 12px;
}
.ev-label {
  font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.07em;
  color: var(--text-2); margin-bottom: 3px; font-weight: 500;
}
.ev-value {
  font-size: 0.82rem; color: var(--text-0); font-family: var(--font-mono);
  word-break: break-all;
}
.ev-value.yes { color: var(--green); }
.ev-value.no { color: var(--error); }

.rationale-box {
  background: var(--bg-3); border-radius: var(--radius-xs);
  padding: 12px 14px; margin-bottom: 10px;
  font-size: 0.82rem; color: var(--text-1); line-height: 1.6;
}
.rationale-box strong { color: var(--text-0); font-weight: 500; }

.fix-box {
  background: var(--green-dim); border-radius: var(--radius-xs);
  padding: 10px 14px;
  font-size: 0.82rem; color: var(--green); line-height: 1.5;
  display: flex; gap: 8px; align-items: flex-start;
  border: 1px solid rgba(52,211,153,0.1);
}
.fix-box svg { width: 14px; height: 14px; fill: currentColor; flex-shrink: 0; margin-top: 2px; }

/* ===== EMPTY STATE ===== */
.empty-state {
  text-align: center; padding: 80px 20px;
}
.empty-icon {
  width: 56px; height: 56px; margin: 0 auto 20px;
  background: var(--green-dim); border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 0 30px rgba(52,211,153,0.1);
}
.empty-icon svg { width: 28px; height: 28px; fill: var(--green); }
.empty-title { font-size: 1.2rem; font-weight: 600; color: var(--text-0); margin-bottom: 6px; }
.empty-sub { font-size: 0.88rem; color: var(--text-2); }

/* ===== FOOTER ===== */
.footer {
  text-align: center; padding: 40px 0;
  font-size: 0.72rem; color: var(--text-3);
  font-family: var(--font-mono);
  border-top: 1px solid var(--border-subtle);
}

/* ===== ANIMATIONS ===== */
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
.card { animation: fadeUp 400ms cubic-bezier(0.4,0,0.2,1) both; }
.card:nth-child(1) { animation-delay: 40ms; }
.card:nth-child(2) { animation-delay: 70ms; }
.card:nth-child(3) { animation-delay: 100ms; }
.card:nth-child(4) { animation-delay: 125ms; }
.card:nth-child(5) { animation-delay: 145ms; }
.card:nth-child(n+6) { animation-delay: 160ms; }

/* ===== RESPONSIVE ===== */
@media (max-width: 640px) {
  html { font-size: 14px; }
  .header-inner { padding: 12px 16px; }
  .shell { padding: 0 14px; }
  .card-head { padding: 14px 14px 10px; }
  .card-detail-inner { padding: 0 14px 14px; padding-top: 12px; }
  .evidence-grid { grid-template-columns: 1fr; }
}

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--bg-4); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-3); }
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-inner">
    <div class="brand">
      <div class="brand-icon">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.67-3.14 8.93-7 10.15-3.86-1.22-7-5.48-7-10.15V6.3l7-3.12z"/><path d="M12 7l-1.41 1.41L13.17 11H7v2h6.17l-2.58 2.59L12 17l5-5-5-5z"/></svg>
      </div>
      <span class="brand-name">aigis</span>
      <span class="brand-ver" id="version"></span>
    </div>
    <div class="header-stats" id="headerStats"></div>
  </div>
</div>

<!-- BODY -->
<div class="shell">
  <div class="scan-meta" id="scanMeta"></div>
  <div class="filters" id="filters"></div>
  <div class="findings" id="findings"></div>
  <div class="footer" id="footer"></div>
</div>

<script>
// ===== DATA (injected by Python) =====
const FINDINGS = /*__FINDINGS_DATA__*/[];
const SUMMARY = /*__SUMMARY_DATA__*/{};

// ===== RULE META =====
const RULES = {
  AEG001: { label: 'Unguarded Mutating Tool', short: 'No approval gate on side-effecting tool' },
  AEG002: { label: 'Privileged Without Consent', short: 'Privileged operation needs consent/policy wrapper' },
  AEG003: { label: 'Missing Execution Budget', short: 'Agent entry point has no iteration/budget limit' },
};

// ===== STATE =====
let activeFilter = 'all';

// ===== ICONS (inline SVG paths) =====
const ICO = {
  file: '<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6zM14 3.5L18.5 8H14V3.5zM6 20V4h7v5h5v11H6z"/></svg>',
  check: '<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg>',
  fix: '<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg>',
  chevron: '<svg viewBox="0 0 24 24"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z"/></svg>',
  clock: '<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 18a8 8 0 110-16 8 8 0 010 16zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z"/></svg>',
  target: '<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 18a8 8 0 110-16 8 8 0 010 16zm0-14a6 6 0 100 12 6 6 0 000-12zm0 10a4 4 0 110-8 4 4 0 010 8zm0-6a2 2 0 100 4 2 2 0 000-4z"/></svg>',
  shield: '<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>',
};

// ===== RENDER =====
function init() {
  document.getElementById('version').textContent = 'v' + SUMMARY.version;
  renderStats();
  renderMeta();
  renderFilters();
  renderFindings();
  renderFooter();
}

function renderStats() {
  const el = document.getElementById('headerStats');
  const chips = [];
  if (SUMMARY.errors > 0) {
    chips.push(`<div class="stat-chip err"><span class="dot"></span>${SUMMARY.errors} error${SUMMARY.errors !== 1 ? 's' : ''}</div>`);
  }
  if (SUMMARY.warnings > 0) {
    chips.push(`<div class="stat-chip warn"><span class="dot"></span>${SUMMARY.warnings} warning${SUMMARY.warnings !== 1 ? 's' : ''}</div>`);
  }
  if (SUMMARY.total === 0) {
    chips.push(`<div class="stat-chip clean"><span class="dot"></span>Clean</div>`);
  }
  if (SUMMARY.suppressed > 0) {
    chips.push(`<div class="stat-chip meta">${SUMMARY.suppressed} suppressed</div>`);
  }
  if (SUMMARY.baselined > 0) {
    chips.push(`<div class="stat-chip meta">${SUMMARY.baselined} baselined</div>`);
  }
  el.innerHTML = chips.join('');
}

function renderMeta() {
  const el = document.getElementById('scanMeta');
  const target = SUMMARY.target.length > 60 ? '...' + SUMMARY.target.slice(-57) : SUMMARY.target;
  el.innerHTML = `
    <span>${ICO.target} ${esc(target)}</span>
    <span>${ICO.clock} ${SUMMARY.timestamp}</span>
  `;
}

function renderFilters() {
  const el = document.getElementById('filters');
  if (FINDINGS.length === 0) { el.style.display = 'none'; return; }

  const rules = {};
  FINDINGS.forEach(f => { rules[f.rule_id] = (rules[f.rule_id] || 0) + 1; });

  let html = `<button class="filter-btn active" data-filter="all">All<span class="cnt">${FINDINGS.length}</span></button>`;
  for (const [rid, count] of Object.entries(rules).sort()) {
    const label = RULES[rid]?.label || rid;
    html += `<button class="filter-btn" data-filter="${rid}">${rid}<span class="cnt">${count}</span></button>`;
  }
  // Severity filters
  const sevs = {};
  FINDINGS.forEach(f => { sevs[f.severity] = (sevs[f.severity] || 0) + 1; });
  for (const [sev, count] of Object.entries(sevs).sort()) {
    html += `<button class="filter-btn" data-filter="sev:${sev}">${sev}<span class="cnt">${count}</span></button>`;
  }
  el.innerHTML = html;

  el.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activeFilter = btn.dataset.filter;
      el.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderFindings();
    });
  });
}

function renderFindings() {
  const el = document.getElementById('findings');

  const filtered = FINDINGS.filter(f => {
    if (activeFilter === 'all') return true;
    if (activeFilter.startsWith('sev:')) return f.severity === activeFilter.slice(4);
    return f.rule_id === activeFilter;
  });

  if (FINDINGS.length === 0) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${ICO.shield}</div>
        <div class="empty-title">No governance findings</div>
        <div class="empty-sub">All scanned code passed aigis checks.</div>
      </div>`;
    return;
  }

  if (filtered.length === 0) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="empty-title">No findings match this filter</div>
        <div class="empty-sub">Try a different filter or view all findings.</div>
      </div>`;
    return;
  }

  el.innerHTML = filtered.map((f, i) => renderCard(f, i)).join('');

  // Toggle detail on click
  el.querySelectorAll('.card-head').forEach(head => {
    head.addEventListener('click', () => {
      head.closest('.card').classList.toggle('open');
    });
  });
}

function renderCard(f) {
  const ev = f.evidence || {};
  const ruleMeta = RULES[f.rule_id] || {};

  // Format message: wrap quoted names in code tags
  const msg = esc(f.message).replace(/'([^']+)'/g, "'<code>$1</code>'");

  // Evidence items
  let evHtml = '';
  const evItems = [];
  if (ev.subject_name) evItems.push({ label: 'Subject', value: ev.subject_name });
  if (ev.sink_type) evItems.push({ label: 'Sink', value: ev.sink_type });
  if (ev.approval_signal_found && ev.approval_signal_found !== 'unknown') {
    evItems.push({ label: 'Approval', value: ev.approval_signal_found, cls: ev.approval_signal_found });
  }
  if (ev.approval_signal_kind) evItems.push({ label: 'Approval Via', value: ev.approval_signal_kind });
  if (ev.budget_signal_found && ev.budget_signal_found !== 'unknown') {
    evItems.push({ label: 'Budget', value: ev.budget_signal_found, cls: ev.budget_signal_found });
  }
  if (ev.confidence) evItems.push({ label: 'Confidence', value: ev.confidence });

  if (evItems.length) {
    evHtml = '<div class="evidence-grid">' +
      evItems.map(it => `<div class="ev-item"><div class="ev-label">${it.label}</div><div class="ev-value${it.cls ? ' ' + it.cls : ''}">${esc(it.value)}</div></div>`).join('') +
      '</div>';
  }

  let rationaleHtml = '';
  if (ev.rationale) {
    rationaleHtml = `<div class="rationale-box"><strong>Rationale</strong><br>${esc(ev.rationale)}</div>`;
  }

  let fixHtml = '';
  if (ev.remediation) {
    fixHtml = `<div class="fix-box">${ICO.fix}<span>${esc(ev.remediation)}</span></div>`;
  }

  return `
    <div class="card sev-${f.severity}">
      <div class="card-head">
        <span class="sev-badge ${f.severity}">${f.severity}</span>
        <div class="card-main">
          <div class="card-rule">${f.rule_id}${ruleMeta.label ? ' \u00b7 ' + esc(ruleMeta.label) : ''}</div>
          <div class="card-msg">${msg}</div>
          <div class="card-loc">${ICO.file}<span>${esc(f.file)}:${f.line}</span></div>
        </div>
        <div class="card-toggle">${ICO.chevron}</div>
      </div>
      <div class="card-detail"><div class="card-detail-inner">
        ${evHtml}${rationaleHtml}${fixHtml}
      </div></div>
    </div>`;
}

function renderFooter() {
  const el = document.getElementById('footer');
  const fileCount = Object.keys(SUMMARY.by_file || {}).length;
  el.innerHTML = `aigis v${SUMMARY.version} &middot; ${SUMMARY.total} finding${SUMMARY.total !== 1 ? 's' : ''} across ${fileCount} file${fileCount !== 1 ? 's' : ''} &middot; ${SUMMARY.timestamp}`;
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

// ===== BOOT =====
document.addEventListener('DOMContentLoaded', init);
</script>
</body>
</html>"""
