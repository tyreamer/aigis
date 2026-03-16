"""CLI entry point — `aeg scan <path>`."""

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .analyzer import PythonAnalyzer
from .baseline import create_baseline, filter_by_baseline, load_baseline, save_baseline
from .config import AigisConfig
from .models import Severity, SEVERITY_RANK
from .output import format_console, format_json, format_sarif
from .rules import run_all_rules
from .suppression import SuppressionFilter

app = typer.Typer(help="aigis — AI Execution Governance Linter", add_completion=False)


class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


class SeverityThreshold(str, Enum):
    error = "error"
    warning = "warning"
    note = "note"


_FORMATTERS = {
    OutputFormat.console: format_console,
    OutputFormat.json: format_json,
    OutputFormat.sarif: format_sarif,
}

_THRESHOLD_MAP = {
    SeverityThreshold.error: Severity.ERROR,
    SeverityThreshold.warning: Severity.WARNING,
    SeverityThreshold.note: Severity.NOTE,
}


@app.command()
def scan(
    path: Path = typer.Argument(".", help="File or directory to scan"),
    fmt: OutputFormat = typer.Option(OutputFormat.console, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to file"),
    baseline_path: Optional[Path] = typer.Option(None, "--baseline", "-b", help="Baseline file — only report new findings"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file (default: .aigis.yaml)"),
    severity_threshold: SeverityThreshold = typer.Option(
        SeverityThreshold.error, "--severity-threshold", "-s",
        help="Minimum severity to cause non-zero exit (error, warning, note)",
    ),
):
    """Scan Python code for unsafe AI autonomy patterns."""
    target = path.resolve()
    if not target.exists():
        typer.echo(f"Error: {target} does not exist", err=True)
        raise typer.Exit(code=2)

    # Load config
    cfg = AigisConfig.load(config_path)

    # Analyze
    graph = PythonAnalyzer().analyze(target)
    results = run_all_rules(graph)

    # Collect all findings
    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    # Apply suppressions
    suppressor = SuppressionFilter(cfg.suppressions)
    active, suppressed = suppressor.filter(all_findings)

    # Apply baseline
    baselined_count = 0
    if baseline_path and baseline_path.exists():
        bl = load_baseline(baseline_path)
        active, baselined = filter_by_baseline(active, bl, str(target))
        baselined_count = len(baselined)

    # Build filtered results for output
    filtered_results = _rebuild_results(results, active)

    # Format
    formatter = _FORMATTERS[fmt]
    text = formatter(filtered_results, str(target), len(suppressed), baselined_count)

    if output:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Output written to {output}")
    else:
        typer.echo(text)

    # Exit code based on severity threshold
    threshold_sev = _THRESHOLD_MAP[severity_threshold]
    threshold_rank = SEVERITY_RANK[threshold_sev]
    has_failures = any(
        SEVERITY_RANK[f.severity] >= threshold_rank for f in active
    )
    if has_failures:
        raise typer.Exit(code=1)


@app.command()
def baseline(
    path: Path = typer.Argument(".", help="File or directory to scan"),
    output: Path = typer.Option("aigis-baseline.json", "--output", "-o", help="Baseline output file"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file"),
):
    """Create a baseline from current findings."""
    target = path.resolve()
    if not target.exists():
        typer.echo(f"Error: {target} does not exist", err=True)
        raise typer.Exit(code=2)

    cfg = AigisConfig.load(config_path)
    graph = PythonAnalyzer().analyze(target)
    results = run_all_rules(graph)

    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    # Apply suppressions before baselining
    suppressor = SuppressionFilter(cfg.suppressions)
    active, _ = suppressor.filter(all_findings)

    bl = create_baseline(active, str(target))
    save_baseline(bl, output)
    typer.echo(f"Baseline created with {bl['count']} finding(s) -> {output}")


@app.command()
def version():
    """Print version."""
    typer.echo(f"aigis {__version__}")


def _rebuild_results(
    original: list, active_findings: list
) -> list:
    """Rebuild RuleResult list containing only the active findings."""
    from .models import RuleResult
    active_set = set(id(f) for f in active_findings)
    rebuilt = []
    for r in original:
        filtered = [f for f in r.findings if id(f) in active_set]
        rebuilt.append(RuleResult(rule_id=r.rule_id, findings=filtered, nodes_checked=r.nodes_checked))
    return rebuilt
