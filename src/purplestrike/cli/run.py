from __future__ import annotations

import asyncio
import logging

import typer
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


def run(
    target_group: str = typer.Option(..., "--target-group", help="Target group name from config"),
    mode: str = typer.Option("agent", "--mode", help="Execution mode: agent | playbook | default"),
    playbook: str | None = typer.Option(None, "--playbook", help="Playbook name or path"),
    tactics: str | None = typer.Option(None, "--tactics", help="Comma-separated MITRE tactic IDs"),
    techniques: str | None = typer.Option(None, "--techniques", help="Comma-separated technique IDs"),
    all_techniques: bool = typer.Option(False, "--all-techniques", help="Execute every technique applicable to the target OS"),
    max_steps: int = typer.Option(20, "--max-steps", help="Maximum attack steps"),
    detection_check_delay: int = typer.Option(30, "--detection-check-delay", help="Seconds to wait before querying SIEM"),
    output_dir: str = typer.Option("./results", "--output-dir", help="Directory for output reports"),
    format: str = typer.Option("both", "--format", help="Report format: json | csv | both"),
    llm_provider: str | None = typer.Option(None, "--llm-provider", help="LLM provider override"),
    skip_cleanup: bool = typer.Option(False, "--skip-cleanup", help="Skip cleanup after execution"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate plan only, no execution"),
) -> None:
    """Execute an attack simulation."""
    asyncio.run(_run(
        target_group=target_group,
        mode=mode,
        playbook=playbook,
        tactics=tactics,
        techniques=techniques,
        all_techniques=all_techniques,
        max_steps=max_steps,
        detection_check_delay=detection_check_delay,
        output_dir=output_dir,
        format=format,
        llm_provider=llm_provider,
        skip_cleanup=skip_cleanup,
        dry_run=dry_run,
    ))


async def _run(
    target_group: str,
    mode: str,
    playbook: str | None,
    tactics: str | None,
    techniques: str | None,
    all_techniques: bool,
    max_steps: int,
    detection_check_delay: int,
    output_dir: str,
    format: str,
    llm_provider: str | None,
    skip_cleanup: bool,
    dry_run: bool,
) -> None:
    from pathlib import Path

    from purplestrike.core.orchestrator import Orchestrator
    from purplestrike.models.config import PurpleStrikeConfig

    console.print("[bold]PurpleStrike — AI-Driven Breach & Attack Simulation[/bold]\n")

    config_path = Path.home() / ".purplestrike" / "config.yaml"
    if config_path.exists():
        config = PurpleStrikeConfig.from_yaml_or_env(config_path)
    else:
        config = PurpleStrikeConfig.from_env()

    if llm_provider:
        from purplestrike.models.config import LLMProviderType
        config.llm.provider = LLMProviderType(llm_provider)
    config.detection_check_delay = detection_check_delay
    config.output_dir = output_dir

    logger.info(
        "Run requested: target_group=%s mode=%s all_techniques=%s max_steps=%s "
        "detection_check_delay=%ss output_dir=%s report_format=%s skip_cleanup=%s dry_run=%s",
        target_group,
        mode,
        all_techniques,
        max_steps,
        detection_check_delay,
        output_dir,
        format,
        skip_cleanup,
        dry_run,
    )

    tactic_list = tactics.split(",") if tactics else None
    if all_techniques and techniques:
        console.print("\n[red]Use either --all-techniques or --techniques, not both.[/red]")
        raise typer.Exit(1)
    if all_techniques and mode == "playbook":
        console.print("\n[red]--all-techniques cannot be used with playbook mode.[/red]")
        raise typer.Exit(1)

    technique_list = techniques.split(",") if techniques else None
    if all_techniques:
        from purplestrike.techniques.registry import technique_registry

        technique_list = technique_registry.get_technique_ids()
        mode = "default"
        max_steps = max(max_steps, len(technique_list))

    config.max_steps = max_steps

    console.print(f"  Target group: [bold]{target_group}[/bold]")
    console.print(f"  Mode: {mode}")
    console.print(f"  LLM Provider: {config.llm.provider}")
    console.print(f"  SIEM Connector: {config.siem.connector}")

    if target_group not in config.target_groups:
        console.print(f"\n[red]Target group '{target_group}' not found in config.[/red]")
        console.print(f"Available groups: {', '.join(config.target_groups.keys()) or 'none'}")
        raise typer.Exit(1)

    orchestrator = Orchestrator(config=config)

    try:
        report = await orchestrator.execute(
            mode=mode,
            target_group_name=target_group,
            playbook_name=playbook,
            tactics=tactic_list,
            technique_ids=technique_list,
            skip_cleanup=skip_cleanup,
            dry_run=dry_run,
        )

        if report:
            console.print(f"\n[bold]Simulation {report.status.value}[/bold]")
            if report.metadata.get("reason"):
                console.print(f"  Reason: {report.metadata['reason']}", markup=False)
            console.print(f"  Techniques executed: {report.summary.total_techniques}")
            console.print(f"  Detected: [green]{report.summary.detected}[/green]")
            console.print(f"  Partially Detected: [yellow]{report.summary.partially_detected}[/yellow]")
            console.print(f"  Not Detected: [red]{report.summary.not_detected}[/red]")
            console.print(f"  Detection Rate: {report.summary.detection_rate:.0%}")
            console.print(f"  Total Annualized Risk: ${report.summary.total_annualized_risk:,.0f}")

            results_dir = Path(output_dir)
            console.print(f"\n  Reports saved to: {results_dir}")
        else:
            console.print("\n[yellow]No simulation report generated (dry-run or aborted).[/yellow]")

    except KeyboardInterrupt:
        logger.warning("Simulation interrupted by user")
        console.print("\n[yellow]Simulation interrupted. Generating partial report...[/yellow]")
    except Exception as e:
        logger.exception("Simulation failed")
        console.print(f"\n[red]Simulation failed: {e}[/red]")
        raise typer.Exit(1)
