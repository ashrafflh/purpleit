from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from purplestrike.models.config import PurpleStrikeConfig

app = typer.Typer(no_args_is_help=True)
console = Console()

DEFAULT_CONFIG_PATH = Path.home() / ".purplestrike" / "config.yaml"


@app.command()
def init() -> None:
    """Initialize PurpleStrike configuration with interactive wizard."""
    console.print("[bold]PurpleStrike Configuration Wizard[/bold]\n")

    config = PurpleStrikeConfig()

    siem_url = typer.prompt("Wazuh API URL", default="https://wazuh-manager:55000")
    siem_user = typer.prompt("Wazuh API username", default="purplestrike")
    siem_timeout = typer.prompt("Wazuh API timeout (seconds)", default=30, type=int)

    config.siem.api_url = siem_url
    config.siem.api_user = siem_user
    config.siem.api_timeout = siem_timeout

    config.detection_check_delay = typer.prompt(
        "Detection check delay (seconds)", default=30, type=int
    )
    config.max_steps = typer.prompt("Max attack steps per simulation", default=20, type=int)
    config.output_dir = typer.prompt("Output directory", default="./results")

    config_path = DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    PurpleStrikeConfig.to_yaml(config, config_path)

    console.print(f"\n[green]Configuration saved to {config_path}[/green]")
    console.print("[yellow]Remember to set environment variables for credentials (see .env.example)[/yellow]")


@app.command()
def show() -> None:
    """Display current configuration."""
    config = _load_config()
    if config is None:
        return

    table = Table(title="PurpleStrike Configuration")
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    table.add_row("SIEM Connector", config.siem.connector)
    table.add_row("SIEM API URL", config.siem.api_url or "(from env)")
    table.add_row("SIEM API User", config.siem.api_user or "(from env)")
    table.add_row("SIEM Timeout", str(config.siem.api_timeout))
    table.add_row("LLM Provider", config.llm.provider)
    table.add_row("Detection Check Delay", str(config.detection_check_delay))
    table.add_row("Max Steps", str(config.max_steps))
    table.add_row("Output Dir", config.output_dir)
    table.add_row("DB Path", config.db_path or "(default)")

    if config.target_groups:
        table.add_row("Target Groups", ", ".join(config.target_groups.keys()))

    console.print(table)


@app.command()
def set_value(key: str, value: str) -> None:
    """Set a configuration value."""
    config = _load_config()
    if config is None:
        config = PurpleStrikeConfig()

    parts = key.split(".")
    _set_nested(config, parts, value)

    config_path = DEFAULT_CONFIG_PATH
    PurpleStrikeConfig.to_yaml(config, config_path)
    console.print(f"[green]Set {key} = {value}[/green]")


@app.command(name="validate")
def validate_config() -> None:
    """Validate current configuration."""
    config = _load_config()
    if config is None:
        return

    issues: list[str] = []

    if not config.siem.api_url:
        issues.append("SIEM API URL not configured (set PURPLESTRIKE_WAZUH_API_URL)")
    if not config.siem.api_user:
        issues.append("SIEM API user not configured (set PURPLESTRIKE_WAZUH_API_USER)")

    if issues:
        console.print("[red]Configuration issues:[/red]")
        for issue in issues:
            console.print(f"  [red]- {issue}[/red]")
        raise typer.Exit(1)
    else:
        console.print("[green]Configuration is valid[/green]")


def _load_config() -> PurpleStrikeConfig | None:
    if DEFAULT_CONFIG_PATH.exists():
        return PurpleStrikeConfig.from_yaml(DEFAULT_CONFIG_PATH)
    console.print("[yellow]No configuration file found. Run 'purplestrike config init' first.[/yellow]")
    return None


def _set_nested(obj: object, parts: list[str], value: str) -> None:
    for part in parts[:-1]:
        obj = getattr(obj, part)
    field_name = parts[-1]
    current = getattr(obj, field_name, None)
    if isinstance(current, int):
        setattr(obj, field_name, int(value))
    elif isinstance(current, float):
        setattr(obj, field_name, float(value))
    else:
        setattr(obj, field_name, value)
