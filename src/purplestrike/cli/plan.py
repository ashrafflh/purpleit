from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from purplestrike.models.config import PurpleStrikeConfig

console = Console()


def plan(
    target_group: str = typer.Option(..., "--target-group", help="Target group name from config"),
    mode: str = typer.Option("agent", "--mode", help="Execution mode: agent | playbook"),
    playbook: Path | None = typer.Option(None, "--playbook", help="Path to playbook YAML"),
    tactics: str | None = typer.Option(None, "--tactics", help="Comma-separated MITRE tactic IDs"),
    output: Path | None = typer.Option(None, "--output", help="Save plan to file (YAML)"),
) -> None:
    """Generate an attack plan without executing it (dry-run)."""
    asyncio.run(_plan(target_group, mode, playbook, tactics, output))


async def _plan(
    target_group: str,
    mode: str,
    playbook: Path | None,
    tactics: str | None,
    output: Path | None,
) -> None:
    from purplestrike.core.orchestrator import Orchestrator

    config = _load_config()
    if config is None:
        return

    tactic_list = tactics.split(",") if tactics else None

    orchestrator = Orchestrator(config=config)
    plan_result = await orchestrator.generate_plan(
        mode=mode,
        target_group_name=target_group,
        playbook_path=playbook,
        tactics=tactic_list,
    )

    if plan_result is None:
        console.print("[red]Failed to generate plan.[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold]Plan: {plan_result.name}[/bold]")
    console.print(f"Total steps: {len(plan_result.steps)}\n")

    table = Table()
    table.add_column("#", style="bold")
    table.add_column("Technique ID")
    table.add_column("Technique Name")
    table.add_column("Target")
    table.add_column("Risk Level")

    for step in plan_result.steps:
        table.add_row(
            str(step.order),
            step.technique_id,
            step.technique_name,
            step.target,
            step.risk_level,
        )

    console.print(table)

    if output:
        import yaml

        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            yaml.dump(plan_result.model_dump(mode="json"), f, default_flow_style=False)
        console.print(f"\n[green]Plan saved to {output}[/green]")


def _load_config() -> PurpleStrikeConfig | None:
    from pathlib import Path

    config_path = Path.home() / ".purplestrike" / "config.yaml"
    if config_path.exists():
        return PurpleStrikeConfig.from_yaml(config_path)
    console.print("[yellow]No config found. Run 'purplestrike config init' first.[/yellow]")
    return None
