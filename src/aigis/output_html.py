"""HTML output formatter — premium single-file security report."""

from __future__ import annotations

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


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aigis governance report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
--c0:#08080c;--c1:#0e0e14;--c2:#14141c;--c3:#1a1a24;--c4:#22222e;--c5:#2c2c3a;
--s0:rgba(255,255,255,.02);--s1:rgba(255,255,255,.035);--s2:rgba(255,255,255,.055);
--b0:rgba(255,255,255,.05);--b1:rgba(255,255,255,.08);
--t0:#ededf2;--t1:#b0b0be;--t2:#78788a;--t3:#4e4e5e;--t4:#363644;
--red:#ef4444;--red-d:rgba(239,68,68,.10);--red-g:rgba(239,68,68,.04);
--amber:#f59e0b;--amber-d:rgba(245,158,11,.10);--amber-g:rgba(245,158,11,.04);
--indigo:#818cf8;--indigo-d:rgba(129,140,248,.08);
--emerald:#34d399;--emerald-d:rgba(52,211,153,.10);
--sky:#38bdf8;
--r:14px;--rs:10px;--rx:6px;
--sans:'Geist','SF Pro Display',-apple-system,'Segoe UI','Helvetica Neue',sans-serif;
--mono:'Geist Mono','SF Mono','Cascadia Code','JetBrains Mono','Fira Code','Consolas',monospace;
--ease:cubic-bezier(.4,0,.2,1);
}
html{font-size:15px;scroll-behavior:smooth}
body{font-family:var(--sans);background:var(--c0);color:var(--t0);line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh}

/* ambient light */
.ambient{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.ambient i{position:absolute;border-radius:50%;filter:blur(100px);opacity:.45}
.ambient .a1{width:600px;height:600px;top:-15%;left:-8%;background:radial-gradient(circle,rgba(129,140,248,.06),transparent 70%)}
.ambient .a2{width:500px;height:500px;bottom:-10%;right:-5%;background:radial-gradient(circle,rgba(239,68,68,.04),transparent 70%)}
.ambient .a3{width:400px;height:400px;top:40%;left:50%;background:radial-gradient(circle,rgba(52,211,153,.03),transparent 70%)}

.page{position:relative;z-index:1}

/* ── NAV ── */
.nav{position:sticky;top:0;z-index:200;backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);background:rgba(8,8,12,.78);border-bottom:1px solid var(--b0)}
.nav-inner{max-width:1140px;margin:0 auto;padding:12px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px}
.brand-mark{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--indigo),var(--red));display:flex;align-items:center;justify-content:center;box-shadow:0 0 20px rgba(129,140,248,.25)}
.brand-mark svg{width:16px;height:16px;fill:#fff}
.brand h1{font-size:1.05rem;font-weight:600;letter-spacing:-.02em}
.brand .ver{font-size:.68rem;color:var(--t3);font-family:var(--mono);background:var(--s0);padding:2px 7px;border-radius:4px;margin-left:2px}
.nav-pills{display:flex;gap:5px}
.nav-pill{padding:5px 12px;border-radius:20px;font-size:.73rem;font-weight:500;font-family:var(--mono);border:1px solid var(--b0);background:transparent;color:var(--t2);cursor:pointer;transition:all .18s var(--ease)}
.nav-pill:hover{background:var(--s1);color:var(--t1)}
.nav-pill .dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:5px;vertical-align:middle}
.nav-pill.e .dot{background:var(--red);box-shadow:0 0 6px var(--red)}
.nav-pill.w .dot{background:var(--amber);box-shadow:0 0 6px var(--amber)}
.nav-pill.ok .dot{background:var(--emerald);box-shadow:0 0 6px var(--emerald)}

/* ── HERO ── */
.hero{max-width:1140px;margin:0 auto;padding:48px 28px 40px}
.hero-top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;flex-wrap:wrap;margin-bottom:36px}
.hero-left{flex:1;min-width:240px}
.hero-title{font-size:1.65rem;font-weight:700;letter-spacing:-.03em;line-height:1.25;margin-bottom:6px}
.hero-sub{color:var(--t2);font-size:.88rem;line-height:1.5}
.hero-status{display:inline-flex;align-items:center;gap:7px;padding:6px 14px;border-radius:20px;font-size:.78rem;font-weight:600;margin-top:14px;letter-spacing:.01em}
.hero-status.fail{background:var(--red-d);color:var(--red);border:1px solid rgba(239,68,68,.15)}
.hero-status.pass{background:var(--emerald-d);color:var(--emerald);border:1px solid rgba(52,211,153,.15)}
.hero-status .pulse{width:8px;height:8px;border-radius:50%;animation:pulse 2s ease-in-out infinite}
.hero-status.fail .pulse{background:var(--red);box-shadow:0 0 8px var(--red)}
.hero-status.pass .pulse{background:var(--emerald);box-shadow:0 0 8px var(--emerald)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.hero-meta{font-size:.75rem;color:var(--t3);font-family:var(--mono);margin-top:12px;display:flex;gap:20px;flex-wrap:wrap}
.hero-meta span{display:flex;align-items:center;gap:5px}
.hero-meta svg{width:12px;height:12px;fill:currentColor;opacity:.5}

/* ── METRIC CARDS ── */
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:12px}
.metric{background:var(--c2);border:1px solid var(--b0);border-radius:var(--r);padding:20px;position:relative;overflow:hidden;transition:all .2s var(--ease)}
.metric:hover{border-color:var(--b1);transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.35)}
.metric::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;opacity:0;transition:opacity .2s}
.metric:hover::after{opacity:1}
.metric.red::after{background:linear-gradient(90deg,var(--red),transparent)}
.metric.amber::after{background:linear-gradient(90deg,var(--amber),transparent)}
.metric.emerald::after{background:linear-gradient(90deg,var(--emerald),transparent)}
.metric.indigo::after{background:linear-gradient(90deg,var(--indigo),transparent)}
.metric .num{font-size:2rem;font-weight:700;font-family:var(--mono);line-height:1;margin-bottom:4px;letter-spacing:-.03em}
.metric .num.red{color:var(--red)}.metric .num.amber{color:var(--amber)}.metric .num.emerald{color:var(--emerald)}.metric .num.indigo{color:var(--indigo)}
.metric .lbl{font-size:.73rem;color:var(--t2);text-transform:uppercase;letter-spacing:.06em;font-weight:500}
.metric .ico{position:absolute;top:16px;right:16px;width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;opacity:.6}
.metric .ico svg{width:15px;height:15px;fill:currentColor}
.metric.red .ico{background:var(--red-d);color:var(--red)}
.metric.amber .ico{background:var(--amber-d);color:var(--amber)}
.metric.emerald .ico{background:var(--emerald-d);color:var(--emerald)}
.metric.indigo .ico{background:var(--indigo-d);color:var(--indigo)}

/* ── RULE BREAKDOWN ── */
.breakdown{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:0}
.rule-card{background:var(--c2);border:1px solid var(--b0);border-radius:var(--r);padding:18px 20px;display:flex;align-items:center;gap:16px;transition:all .2s var(--ease)}
.rule-card:hover{border-color:var(--b1);transform:translateY(-1px);box-shadow:0 6px 20px rgba(0,0,0,.3)}
.rule-card .badge{width:44px;height:44px;border-radius:var(--rs);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-family:var(--mono);font-weight:700;font-size:.7rem;letter-spacing:.02em}
.rule-card .badge.e{background:var(--red-d);color:var(--red);border:1px solid rgba(239,68,68,.12)}
.rule-card .badge.w{background:var(--amber-d);color:var(--amber);border:1px solid rgba(245,158,11,.12)}
.rule-card .badge.m{background:var(--indigo-d);color:var(--indigo);border:1px solid rgba(129,140,248,.12)}
.rule-card .ri{flex:1;min-width:0}
.rule-card .rid{font-family:var(--mono);font-size:.78rem;font-weight:600;color:var(--t0);margin-bottom:2px}
.rule-card .rdesc{font-size:.78rem;color:var(--t2);line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rule-card .rcount{font-family:var(--mono);font-size:1.15rem;font-weight:700;color:var(--t0);flex-shrink:0}

/* ── SECTION ── */
.sec{max-width:1140px;margin:0 auto;padding:0 28px}
.sec-head{display:flex;align-items:center;justify-content:space-between;padding:36px 0 20px;border-top:1px solid var(--b0);margin-top:8px;flex-wrap:wrap;gap:12px}
.sec-title{font-size:1.1rem;font-weight:600;letter-spacing:-.01em}
.sec-title .cnt{color:var(--t3);font-weight:400;margin-left:6px;font-family:var(--mono);font-size:.85em}

/* ── FILTERS ── */
.filters{display:flex;gap:5px;flex-wrap:wrap}
.fbtn{padding:5px 13px;border-radius:20px;font-size:.73rem;font-weight:500;border:1px solid var(--b0);background:transparent;color:var(--t2);cursor:pointer;transition:all .16s var(--ease);font-family:var(--sans)}
.fbtn:hover{background:var(--s1);color:var(--t1)}
.fbtn.on{background:var(--indigo-d);color:var(--indigo);border-color:rgba(129,140,248,.2)}
.fbtn .n{font-family:var(--mono);margin-left:3px;opacity:.5;font-size:.68rem}

/* ── FILE GROUP ── */
.fgroup{margin-bottom:16px}
.fgroup-head{display:flex;align-items:center;gap:8px;padding:10px 0 8px;font-size:.78rem;font-family:var(--mono);color:var(--t2);cursor:pointer;user-select:none;transition:color .16s}
.fgroup-head:hover{color:var(--t1)}
.fgroup-head svg{width:14px;height:14px;fill:currentColor;transition:transform .2s var(--ease)}
.fgroup-head.collapsed svg{transform:rotate(-90deg)}
.fgroup-head .fc{background:var(--s1);padding:1px 7px;border-radius:10px;font-size:.68rem;margin-left:4px}
.fgroup-body{overflow:hidden}

/* ── CARDS ── */
.cards{display:flex;flex-direction:column;gap:8px;padding-bottom:4px}
.card{background:var(--c2);border:1px solid var(--b0);border-radius:var(--r);overflow:hidden;transition:all .18s var(--ease)}
.card:hover{border-color:var(--b1);box-shadow:0 4px 16px rgba(0,0,0,.3)}
.card.sev-error{border-left:3px solid var(--red)}
.card.sev-warning{border-left:3px solid var(--amber)}
.card.sev-note{border-left:3px solid var(--indigo)}

.card-row{display:flex;align-items:flex-start;gap:14px;padding:16px 20px 14px;cursor:pointer;user-select:none}
.card-row:hover .chev{color:var(--t2)}
.sev{flex-shrink:0;padding:3px 9px;border-radius:var(--rx);font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;font-family:var(--mono)}
.sev.error{background:var(--red-d);color:var(--red)}.sev.warning{background:var(--amber-d);color:var(--amber)}.sev.note{background:var(--indigo-d);color:var(--indigo)}
.card-body{flex:1;min-width:0}
.card-rid{font-size:.7rem;font-family:var(--mono);color:var(--t3);margin-bottom:2px;letter-spacing:.02em}
.card-msg{font-size:.9rem;line-height:1.5;color:var(--t0)}
.card-msg code{font-family:var(--mono);font-size:.84em;background:rgba(255,255,255,.04);padding:1px 5px;border-radius:4px;color:var(--indigo)}
.card-loc{margin-top:5px;font-size:.72rem;font-family:var(--mono);color:var(--t3);display:flex;align-items:center;gap:4px}
.card-loc svg{width:11px;height:11px;fill:currentColor;opacity:.4}
.chev{flex-shrink:0;color:var(--t4);transition:color .16s,transform .22s var(--ease);margin-top:2px}
.chev svg{width:15px;height:15px;fill:currentColor}
.card.open .chev{transform:rotate(180deg);color:var(--t2)}

/* ── CARD DETAIL ── */
.card-detail{display:grid;grid-template-rows:0fr;transition:grid-template-rows .28s var(--ease)}
.card.open .card-detail{grid-template-rows:1fr}
.card-detail>div{overflow:hidden}
.detail-inner{padding:0 20px 20px;border-top:1px solid var(--b0);margin-top:0;padding-top:16px}
.ev-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-bottom:14px}
.ev{background:var(--c3);border-radius:var(--rx);padding:10px 12px}
.ev-l{font-size:.65rem;text-transform:uppercase;letter-spacing:.07em;color:var(--t3);margin-bottom:2px;font-weight:600}
.ev-v{font-size:.8rem;color:var(--t0);font-family:var(--mono);word-break:break-all}
.ev-v.yes{color:var(--emerald)}.ev-v.no{color:var(--red)}
.rationale{background:var(--c3);border-radius:var(--rx);padding:14px 16px;margin-bottom:10px;font-size:.82rem;color:var(--t1);line-height:1.65}
.rationale b{color:var(--t0);font-weight:500}
.fix{background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.1);border-radius:var(--rx);padding:12px 16px;font-size:.82rem;color:var(--emerald);line-height:1.5;display:flex;gap:9px;align-items:flex-start}
.fix svg{width:14px;height:14px;fill:currentColor;flex-shrink:0;margin-top:3px}

/* ── EMPTY ── */
.empty{text-align:center;padding:80px 20px}
.empty-i{width:56px;height:56px;margin:0 auto 20px;background:var(--emerald-d);border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 0 40px rgba(52,211,153,.08)}
.empty-i svg{width:26px;height:26px;fill:var(--emerald)}
.empty h2{font-size:1.15rem;font-weight:600;margin-bottom:4px}
.empty p{font-size:.85rem;color:var(--t2)}

/* ── FOOTER ── */
.foot{max-width:1140px;margin:0 auto;padding:32px 28px 48px;text-align:center;font-size:.7rem;color:var(--t4);font-family:var(--mono);border-top:1px solid var(--b0);margin-top:24px}

/* ── ANIMATIONS ── */
@keyframes up{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.anim{animation:up .45s var(--ease) both}
.d1{animation-delay:60ms}.d2{animation-delay:110ms}.d3{animation-delay:150ms}.d4{animation-delay:185ms}.d5{animation-delay:215ms}

/* ── SCROLLBAR ── */
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--c5);border-radius:3px}::-webkit-scrollbar-thumb:hover{background:var(--t4)}

/* ── RESPONSIVE ── */
@media(max-width:700px){
html{font-size:14px}
.nav-inner,.hero,.sec{padding-left:16px;padding-right:16px}
.hero{padding-top:32px;padding-bottom:28px}
.hero-title{font-size:1.35rem}
.metrics{grid-template-columns:repeat(2,1fr)}
.breakdown{grid-template-columns:1fr}
.ev-grid{grid-template-columns:1fr}
.card-row{padding:14px 16px 12px}
.detail-inner{padding:0 16px 16px;padding-top:14px}
}
</style>
</head>
<body>

<div class="ambient"><i class="a1"></i><i class="a2"></i><i class="a3"></i></div>

<div class="page">
<nav class="nav"><div class="nav-inner">
<div class="brand">
<div class="brand-mark"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.67-3.14 8.93-7 10.15-3.86-1.22-7-5.48-7-10.15V6.3l7-3.12z"/></svg></div>
<h1>aigis</h1><span class="ver" id="ver"></span>
</div>
<div class="nav-pills" id="navPills"></div>
</div></nav>

<section class="hero" id="hero"></section>

<div class="sec" id="secFindings"></div>
<div class="foot" id="foot"></div>
</div>

<script>
const F=/*__FINDINGS_DATA__*/[];
const S=/*__SUMMARY_DATA__*/{};

const RM={
AIGIS001:{name:'Unguarded Mutating Tool',desc:'Side-effecting tool reachable without approval gate',sev:'e'},
AIGIS002:{name:'Privileged Without Consent',desc:'Privileged operation needs consent/policy wrapper',sev:'e'},
AIGIS003:{name:'Missing Execution Budget',desc:'Agent entry point without iteration or budget limit',sev:'w'},
};

const I={
shield:'<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>',
alert:'<svg viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
warn:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>',
check:'<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg>',
file:'<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6zm0 1.5L18.5 8H14V3.5zM6 20V4h7v5h5v11H6z"/></svg>',
chev:'<svg viewBox="0 0 24 24"><path d="M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6z"/></svg>',
folder:'<svg viewBox="0 0 24 24"><path d="M10 4H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V8a2 2 0 00-2-2h-8l-2-2z"/></svg>',
clock:'<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm.5 5v6l4.25 2.52-.75 1.23L11 13V7h1.5z"/></svg>',
layers:'<svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>',
};

let filter='all';

function init(){
document.getElementById('ver').textContent='v'+S.version;
renderNav();
renderHero();
renderFindings();
renderFoot();
}

function renderNav(){
const el=document.getElementById('navPills');
const pills=[];
if(S.errors)pills.push(`<span class="nav-pill e"><span class="dot"></span>${S.errors} error${S.errors>1?'s':''}</span>`);
if(S.warnings)pills.push(`<span class="nav-pill w"><span class="dot"></span>${S.warnings} warning${S.warnings>1?'s':''}</span>`);
if(!S.total)pills.push(`<span class="nav-pill ok"><span class="dot"></span>Clean</span>`);
el.innerHTML=pills.join('');
}

function renderHero(){
const el=document.getElementById('hero');
const target=S.target.length>55?'...'+S.target.slice(-52):S.target;
const fileCount=Object.keys(S.by_file||{}).length;
const hasFail=S.total>0;
const statusCls=hasFail?'fail':'pass';
const statusTxt=hasFail?'Governance issues detected':'All checks passed';
const ruleKeys=Object.keys(S.by_rule||{}).sort();

// metrics
let metricsHtml=`
<div class="metric red anim d1"><div class="num red" data-to="${S.errors}">${S.errors}</div><div class="lbl">Errors</div><div class="ico">${I.alert}</div></div>
<div class="metric amber anim d2"><div class="num amber" data-to="${S.warnings}">${S.warnings}</div><div class="lbl">Warnings</div><div class="ico">${I.warn}</div></div>
<div class="metric indigo anim d3"><div class="num indigo" data-to="${fileCount}">${fileCount}</div><div class="lbl">Files Affected</div><div class="ico">${I.file}</div></div>
<div class="metric emerald anim d4"><div class="num emerald" data-to="${S.suppressed+S.baselined}">${S.suppressed+S.baselined}</div><div class="lbl">Suppressed</div><div class="ico">${I.layers}</div></div>`;

// rule breakdown
let breakdownHtml='';
if(ruleKeys.length){
breakdownHtml='<div class="breakdown anim d5">';
for(const rid of ruleKeys){
const rc=S.by_rule[rid];
const total=(rc.error||0)+(rc.warning||0)+(rc.note||0);
const meta=RM[rid]||{name:rid,desc:'',sev:'e'};
const badgeCls=rc.error?'e':rc.warning?'w':'m';
breakdownHtml+=`<div class="rule-card"><div class="badge ${badgeCls}">${rid.replace('AIGIS','')}</div><div class="ri"><div class="rid">${rid}</div><div class="rdesc">${esc(meta.name)}</div></div><div class="rcount">${total}</div></div>`;
}
breakdownHtml+='</div>';
}

el.innerHTML=`
<div class="hero-top anim">
<div class="hero-left">
<div class="hero-title">Governance Report</div>
<div class="hero-sub">AI execution governance scan results</div>
<div class="hero-status ${statusCls}"><span class="pulse"></span>${statusTxt}</div>
<div class="hero-meta">
<span>${I.folder} ${esc(target)}</span>
<span>${I.clock} ${S.timestamp}</span>
</div>
</div>
</div>
<div class="metrics">${metricsHtml}</div>
${breakdownHtml}`;

animateCounters();
}

function animateCounters(){
document.querySelectorAll('.num[data-to]').forEach(el=>{
const to=parseInt(el.dataset.to);
if(to===0){el.textContent='0';return}
let current=0;
const step=Math.max(1,Math.ceil(to/30));
const iv=setInterval(()=>{current=Math.min(current+step,to);el.textContent=current;if(current>=to)clearInterval(iv)},25);
});
}

function renderFindings(){
const el=document.getElementById('secFindings');
if(!F.length){el.innerHTML=`<div class="empty"><div class="empty-i">${I.shield}</div><h2>No governance findings</h2><p>All scanned code passed aigis checks.</p></div>`;return}

// group by file
const byFile={};
F.forEach(f=>{(byFile[f.file]=byFile[f.file]||[]).push(f)});
const files=Object.keys(byFile).sort();

// filters
const ruleCount={};const sevCount={};
F.forEach(f=>{ruleCount[f.rule_id]=(ruleCount[f.rule_id]||0)+1;sevCount[f.severity]=(sevCount[f.severity]||0)+1});

let filterHtml=`<div class="sec-head"><div class="sec-title">Findings<span class="cnt">${F.length}</span></div><div class="filters" id="filterBar">`;
filterHtml+=`<button class="fbtn on" data-f="all">All<span class="n">${F.length}</span></button>`;
for(const[r,c] of Object.entries(ruleCount).sort())filterHtml+=`<button class="fbtn" data-f="${r}">${r}<span class="n">${c}</span></button>`;
for(const[s,c] of Object.entries(sevCount).sort())filterHtml+=`<button class="fbtn" data-f="s:${s}">${s}<span class="n">${c}</span></button>`;
filterHtml+=`</div></div>`;

el.innerHTML=filterHtml+`<div id="findingsList"></div>`;
renderFindingsList(files,byFile);

document.getElementById('filterBar').addEventListener('click',e=>{
const btn=e.target.closest('.fbtn');if(!btn)return;
filter=btn.dataset.f;
document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
renderFindingsList(files,byFile);
});
}

function renderFindingsList(files,byFile){
const el=document.getElementById('findingsList');
let html='';
for(const file of files){
const items=byFile[file].filter(f=>{
if(filter==='all')return true;
if(filter.startsWith('s:'))return f.severity===filter.slice(2);
return f.rule_id===filter;
});
if(!items.length)continue;
html+=`<div class="fgroup"><div class="fgroup-head" onclick="this.classList.toggle('collapsed');this.nextElementSibling.style.display=this.classList.contains('collapsed')?'none':''">
${I.chev}<span>${esc(file)}</span><span class="fc">${items.length}</span></div>
<div class="fgroup-body"><div class="cards">${items.map(f=>card(f)).join('')}</div></div></div>`;
}
if(!html)html=`<div class="empty"><h2>No findings match this filter</h2><p>Try a different filter or view all findings.</p></div>`;
el.innerHTML=html;
el.querySelectorAll('.card-row').forEach(r=>r.addEventListener('click',()=>r.closest('.card').classList.toggle('open')));
}

function card(f){
const ev=f.evidence||{};
const rm=RM[f.rule_id]||{};
const msg=esc(f.message).replace(/'([^']+)'/g,"'<code>$1</code>'");

const evItems=[];
if(ev.subject_name)evItems.push({l:'Subject',v:ev.subject_name});
if(ev.sink_type)evItems.push({l:'Sink',v:ev.sink_type});
if(ev.approval_signal_found&&ev.approval_signal_found!=='unknown')evItems.push({l:'Approval',v:ev.approval_signal_found,c:ev.approval_signal_found});
if(ev.approval_signal_kind)evItems.push({l:'Via',v:ev.approval_signal_kind});
if(ev.budget_signal_found&&ev.budget_signal_found!=='unknown')evItems.push({l:'Budget',v:ev.budget_signal_found,c:ev.budget_signal_found});
if(ev.confidence)evItems.push({l:'Confidence',v:ev.confidence});

const evHtml=evItems.length?'<div class="ev-grid">'+evItems.map(i=>`<div class="ev"><div class="ev-l">${i.l}</div><div class="ev-v${i.c?' '+i.c:''}">${esc(i.v)}</div></div>`).join('')+'</div>':'';
const ratHtml=ev.rationale?`<div class="rationale"><b>Rationale</b><br>${esc(ev.rationale)}</div>`:'';
const fixHtml=ev.remediation?`<div class="fix">${I.check}<span>${esc(ev.remediation)}</span></div>`:'';

return`<div class="card sev-${f.severity}">
<div class="card-row">
<span class="sev ${f.severity}">${f.severity}</span>
<div class="card-body">
<div class="card-rid">${f.rule_id}${rm.name?' \u00b7 '+esc(rm.name):''}</div>
<div class="card-msg">${msg}</div>
<div class="card-loc">${I.file}<span>${esc(f.file)}:${f.line}</span></div>
</div>
<span class="chev">${I.chev}</span>
</div>
<div class="card-detail"><div><div class="detail-inner">${evHtml}${ratHtml}${fixHtml}</div></div></div>
</div>`;
}

function renderFoot(){
const el=document.getElementById('foot');
const fc=Object.keys(S.by_file||{}).length;
el.innerHTML=`aigis v${S.version} &middot; ${S.total} finding${S.total!==1?'s':''} across ${fc} file${fc!==1?'s':''} &middot; ${S.timestamp}`;
}

function esc(s){if(!s)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}

document.addEventListener('DOMContentLoaded',init);
</script>
</body>
</html>"""
