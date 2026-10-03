from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command(name="list")
def list_techniques(
    tactic: str | None = typer.Option(
        None, "--tactic", help="Filter by MITRE tactic ID (e.g. TA0001)"
    ),
) -> None:
    """List all supported MITRE ATT&CK techniques."""
    from purplestrike.techniques.registry import technique_registry

    techniques = technique_registry.list_techniques()
    if tactic:
        techniques = [t for t in techniques if t.tactic == tactic]

    if not techniques:
        console.print("[yellow]No techniques found.[/yellow]")
        return

    table = Table(title="Supported MITRE ATT&CK Techniques")
    table.add_column("Technique ID", style="bold")
    table.add_column("Name")
    table.add_column("Tactic")
    table.add_column("Executor")
    table.add_column("Emulation")
    table.add_column("Risk Level")

    for t in techniques:
        table.add_row(
            t.technique_id,
            t.name,
            t.tactic_name,
            t.executor,
            t.emulation_mode.value,
            t.risk_level,
        )

    console.print(table)


@app.command()
def show(technique_id: str) -> None:
    """Show technique details and detection mapping."""
    from purplestrike.techniques.registry import technique_registry

    technique = technique_registry.get_technique(technique_id)
    if technique is None:
        console.print(f"[red]Technique '{technique_id}' not found.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]{technique.technique_id} — {technique.name}[/bold]")
    console.print(f"Tactic: {technique.tactic_name}")
    console.print(f"Description: {technique.description or 'N/A'}")
    console.print(f"Target OS: {', '.join(technique.target_os)}")
    console.print(f"Executor: {technique.executor}")
    console.print(f"Risk Level: {technique.risk_level}")
    console.print(
        f"ATT&CK: v{technique.attack_version} / technique object "
        f"v{technique.attack_technique_version}"
    )
    console.print(f"ATT&CK URL: {technique.attack_url}")
    console.print(f"ATT&CK tactics: {', '.join(technique.attack_tactics)}")
    console.print(f"Emulation mode: {technique.emulation_mode.value}")
    console.print(f"Procedure: {technique.procedure}")
    if technique.validation_notes:
        console.print(f"Coverage limitation: {technique.validation_notes}")
    if technique.detection_strategy_id:
        console.print(
            f"Detection strategy: {technique.detection_strategy_id} "
            f"({', '.join(technique.analytic_ids)})"
        )
    if technique.required_log_sources:
        console.print(f"Required log sources: {', '.join(technique.required_log_sources)}")
    if technique.success_criteria:
        console.print("Success criteria: " + "; ".join(technique.success_criteria))

    if technique.parameters:
        console.print("\n[bold]Parameters:[/bold]")
        for p in technique.parameters:
            req = " (required)" if p.required else f" (default: {p.default})"
            console.print(f"  {p.name} [{p.type}]: {p.description}{req}")

    if technique.detection_mappings:
        console.print("\n[bold]Detection Mappings:[/bold]")
        table = Table()
        table.add_column("Rule ID")
        table.add_column("Confidence")
        table.add_column("Description")
        for dm in technique.detection_mappings:
            table.add_row(dm.rule_id, dm.confidence, dm.description)
        console.print(table)
