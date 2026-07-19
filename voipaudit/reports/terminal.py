"""Terminal report rendering — Rich-based, matching the visual style
already established across this portfolio's other CLI tools."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from voipaudit.core.models import ModuleResult, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

console = Console()


def print_results(target: str, results: list[ModuleResult]) -> None:
    console.print(f"\n[bold]── {target} ──[/bold]\n")

    all_findings = [f for r in results for f in r.findings]
    counts = {sev: 0 for sev in Severity}
    for f in all_findings:
        counts[f.severity] += 1

    for r in results:
        status = "[green]✔[/green]" if r.error is None else "[red]✘[/red]"
        detail = f"{len(r.findings)} finding(s)" if r.error is None else r.error
        console.print(f"  {status} {r.module}: {detail} ({r.duration_ms:.0f}ms)")

    if not all_findings:
        console.print("\n  No findings.")
        return

    console.print()
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Severity")
    table.add_column("Module")
    table.add_column("Title")
    table.add_column("Target")

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for finding in sorted(all_findings, key=lambda f: order.index(f.severity)):
        style = _SEVERITY_STYLE[finding.severity]
        table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
            finding.module,
            finding.title,
            finding.target,
        )
    console.print(table)

    summary = "  ".join(
        f"[{_SEVERITY_STYLE[sev]}]{counts[sev]} {sev.value}[/{_SEVERITY_STYLE[sev]}]"
        for sev in order if counts[sev] > 0
    )
    console.print(f"\n{summary}\n")
