from __future__ import annotations

import asyncio

import typer
from rich.console import Console

app = typer.Typer(no_args_is_help=True)
console = Console()


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

    loader = PluginLoader(plugin_registry)
    await loader.load_all()

    connector = plugin_registry.get_siem_connector("wazuh")
    if connector is None:
        console.print("[red]Wazuh connector not loaded.[/red]")
        raise typer.Exit(1)

    try:
        await connector.setup({})
        console.print("[green]SIEM connection successful.[/green]")
    except Exception as e:
        console.print(f"[red]SIEM connection failed: {e}[/red]")
        raise typer.Exit(1)
    finally:
        await connector.teardown()


async def _list_rules(technique: str | None) -> None:
    from rich.table import Table

    from purplestrike.plugins.loader import PluginLoader
    from purplestrike.plugins.registry import plugin_registry

    loader = PluginLoader(plugin_registry)
    await loader.load_all()

    connector = plugin_registry.get_siem_connector("wazuh")
    if connector is None:
        console.print("[red]Wazuh connector not loaded.[/red]")
        raise typer.Exit(1)

    try:
        await connector.setup({})
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
        raise typer.Exit(1)
    finally:
        await connector.teardown()
