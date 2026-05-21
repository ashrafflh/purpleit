from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from purplestrike.models.config import PurpleStrikeConfig

app = typer.Typer(no_args_is_help=True)
console = Console()

DEFAULT_CONFIG_PATH = Path.home() / ".purplestrike" / "config.yaml"
DEFAULT_WAZUH_DASHBOARD_USER = "admin"


@app.command()
def init() -> None:
    """Initialize PurpleStrike configuration with interactive wizard."""
    console.print("[bold]PurpleStrike Configuration Wizard[/bold]\n")

    config = PurpleStrikeConfig()

    siem_url = typer.prompt("Wazuh API URL", default="https://wazuh-manager:55000")
    siem_user = typer.prompt("Wazuh Dashboard username", default=DEFAULT_WAZUH_DASHBOARD_USER)
    siem_password = typer.prompt(
        "Wazuh Dashboard password (blank to use PURPLESTRIKE_WAZUH_API_PASSWORD)",
        default="",
        hide_input=True,
        show_default=False,
    )
    dashboard_url = typer.prompt(
        "Wazuh Dashboard URL (blank to derive from Wazuh API URL)",
        default="",
        show_default=False,
    )
    siem_timeout = typer.prompt("Wazuh API timeout (seconds)", default=30, type=int)

    config.siem.api_url = siem_url
    config.siem.api_user = siem_user
    config.siem.api_password = siem_password
    config.siem.dashboard_url = dashboard_url
    config.siem.api_timeout = siem_timeout

    config.target_ad_domain = typer.prompt("Target AD domain", default="corp.local")
    config.target_username = typer.prompt("Target username", default="attack_user")
    config.target_password = typer.prompt(
        "Target password (blank to use PURPLESTRIKE_TARGET_PASSWORD)",
        default="",
        hide_input=True,
        show_default=False,
    )

    config.detection_check_delay = typer.prompt(
        "Detection check delay (seconds)", default=30, type=int
    )
    config.max_steps = typer.prompt("Max attack steps per simulation", default=20, type=int)
    config.output_dir = typer.prompt("Output directory", default="./results")

    config_path = DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    PurpleStrikeConfig.to_yaml(config, config_path)

    console.print(f"\n[green]Configuration saved to {config_path}[/green]")
    if not config.siem.api_password:
        console.print(
            "[yellow]Set PURPLESTRIKE_WAZUH_API_PASSWORD or run "
            "'purplestrike config set-value siem.api_password'.[/yellow]"
        )


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
    table.add_row("Wazuh Dashboard User", config.siem.api_user or "(from env)")
    table.add_row("SIEM Timeout", str(config.siem.api_timeout))
    table.add_row("Wazuh Dashboard URL", config.siem.dashboard_url or "(derived)")
    table.add_row("Wazuh Dashboard API ID", config.siem.dashboard_api_id)
    table.add_row("LLM Provider", config.llm.provider)
    table.add_row("Detection Check Delay", str(config.detection_check_delay))
    table.add_row("Max Steps", str(config.max_steps))
    table.add_row("Output Dir", config.output_dir)
    table.add_row("DB Path", config.db_path or "(default)")

    table.add_row("Target AD Domain", config.target_ad_domain or "(not set)")
    table.add_row("Target Username", config.target_username or "(not set)")
    table.add_row("Target Password", "***" if config.target_password else "(not set)")

    if config.target_groups:
        table.add_row("Target Groups", ", ".join(config.target_groups.keys()))

    console.print(table)


@app.command()
def set_value(key: str, value: str | None = typer.Argument(None)) -> None:
    """Set a configuration value."""
    config = _load_config()
    if config is None:
        config = PurpleStrikeConfig()

    if value is None:
        value = typer.prompt(
            key,
            hide_input=_is_secret_key(key),
            confirmation_prompt=_is_secret_key(key),
        )

    parts = key.split(".")
    _set_nested(config, parts, value)

    config_path = DEFAULT_CONFIG_PATH
    PurpleStrikeConfig.to_yaml(config, config_path)
    display_value = "***" if _is_secret_key(key) else value
    console.print(f"[green]Set {key} = {display_value}[/green]")


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
        issues.append("Wazuh Dashboard user not configured (set PURPLESTRIKE_WAZUH_API_USER)")
    if not config.target_password:
        issues.append("Target password not configured (set PURPLESTRIKE_TARGET_PASSWORD)")

    if issues:
        console.print("[red]Configuration issues:[/red]")
        for issue in issues:
            console.print(f"  [red]- {issue}[/red]")
        raise typer.Exit(1)
    else:
        console.print("[green]Configuration is valid[/green]")


def _load_config() -> PurpleStrikeConfig | None:
    if DEFAULT_CONFIG_PATH.exists():
        return PurpleStrikeConfig.from_yaml_or_env(DEFAULT_CONFIG_PATH)
    env_config = PurpleStrikeConfig.from_env()
    if env_config.siem.api_url or env_config.siem.api_user or env_config.siem.api_password:
        return env_config
    console.print(
        "[yellow]No configuration file found. Run 'purplestrike config init' first.[/yellow]"
    )
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


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return "password" in lowered or "api_key" in lowered or "secret" in lowered
