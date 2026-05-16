from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from purplestrike.models.config import PurpleStrikeConfig

app = typer.Typer(no_args_is_help=True)
console = Console()
DEFAULT_CONFIG_PATH = Path.home() / ".purplestrike" / "config.yaml"


@app.command()
def test() -> None:
    """Test SIEM connectivity."""
    asyncio.run(_test_siem())


@app.command(name="rules")
def list_rules(
    technique: str | None = typer.Option(None, "--technique", help="Filter by MITRE technique ID"),
) -> None:
    """List SIEM rules with MITRE mappings."""
    asyncio.run(_list_rules(technique))


async def _test_siem() -> None:
    from purplestrike.plugins.loader import PluginLoader
    from purplestrike.plugins.registry import plugin_registry

    console.print("[bold]Testing SIEM connectivity...[/bold]")

    config = _load_config()
    loader = PluginLoader(plugin_registry)
    await loader.load_siem_connectors(_plugin_config(config))

    connector = plugin_registry.get_siem_connector(config.siem.connector)
    if connector is None:
        console.print(f"[red]{config.siem.connector} connector not loaded.[/red]")
        raise typer.Exit(1)

    try:
        await connector.setup(config.siem.model_dump(mode="json"))
        test_connection = getattr(connector, "test_connection", None)
        if test_connection is not None:
            await test_connection()
        console.print("[green]SIEM connection successful.[/green]")
    except Exception as e:
        console.print(f"[red]SIEM connection failed: {e}[/red]")
        raise typer.Exit(1) from e
    finally:
        await connector.teardown()


async def _list_rules(technique: str | None) -> None:
    from rich.table import Table

    from purplestrike.plugins.loader import PluginLoader
    from purplestrike.plugins.registry import plugin_registry

    config = _load_config()
    loader = PluginLoader(plugin_registry)
    await loader.load_siem_connectors(_plugin_config(config))

    connector = plugin_registry.get_siem_connector(config.siem.connector)
    if connector is None:
        console.print(f"[red]{config.siem.connector} connector not loaded.[/red]")
        raise typer.Exit(1)

    try:
        await connector.setup(config.siem.model_dump(mode="json"))
        if technique:
            rules = await connector.get_rules_for_technique(technique)
        else:
            rules = await connector.get_rules_for_technique("")

        table = Table(title="SIEM Rules")
        table.add_column("Rule ID", style="bold")
        table.add_column("Severity")
        table.add_column("Description")
        table.add_column("MITRE Techniques")

        for rule in rules:
            table.add_row(
                rule.rule_id,
                rule.severity,
                rule.description[:80],
                ", ".join(rule.mitre_technique_ids[:3]),
            )

        console.print(table)
    except Exception as e:
        console.print(f"[red]Failed to list rules: {e}[/red]")
        raise typer.Exit(1) from e
    finally:
        await connector.teardown()


def _load_config() -> PurpleStrikeConfig:
    if DEFAULT_CONFIG_PATH.exists():
        return PurpleStrikeConfig.from_yaml_or_env(DEFAULT_CONFIG_PATH)
    return PurpleStrikeConfig.from_env()


def _plugin_config(config: PurpleStrikeConfig) -> dict[str, object]:
    return {
        "siem_connectors": {
            config.siem.connector: config.siem.model_dump(mode="json"),
        },
    }
