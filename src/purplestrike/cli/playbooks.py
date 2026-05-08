from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()

PLAYBOOK_DIRS = [
    Path.home() / ".purplestrike" / "playbooks",
    Path.cwd() / "playbooks",
    Path(__file__).parent.parent.parent / "playbooks",
]


@app.command(name="list")
def list_playbooks() -> None:
    """List all available playbooks."""
    playbooks = _discover_playbooks()
    if not playbooks:
        console.print("[yellow]No playbooks found.[/yellow]")
        return

    table = Table(title="Available Playbooks")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Tactics")

    for pb in playbooks:
        table.add_row(pb["name"], str(pb["path"]), pb.get("tactics", ""))

    console.print(table)


@app.command()
def show(name: str) -> None:
    """Show playbook details."""
    import yaml

    pb = _find_playbook(name)
    if pb is None:
        console.print(f"[red]Playbook '{name}' not found.[/red]")
        raise typer.Exit(1)

    with open(pb["path"]) as f:
        data = yaml.safe_load(f)

    console.print(f"[bold]{data.get('name', name)}[/bold]")
    console.print(f"Description: {data.get('description', 'N/A')}")
    console.print(f"Author: {data.get('author', 'N/A')}")
    console.print(f"Target OS: {', '.join(data.get('target_os', []))}")
    console.print(f"\nSteps: {len(data.get('steps', []))}")

    if data.get("steps"):
        table = Table(title="Playbook Steps")
        table.add_column("#", style="bold")
        table.add_column("Technique ID")
        table.add_column("Technique Name")
        table.add_column("Executor")
        for step in data["steps"]:
            table.add_row(
                str(step.get("order", "")),
                step.get("technique_id", ""),
                step.get("technique_name", ""),
                step.get("executor", ""),
            )
        console.print(table)


@app.command()
def validate(path: Path) -> None:
    """Validate a playbook YAML file."""
    import yaml
    from pydantic import BaseModel

    class PlaybookStep(BaseModel):
        order: int
        technique_id: str
        technique_name: str = ""
        executor: str = "custom_python"
        module: str = ""
        parameters: dict = {}
        expected_detection_rules: list[str] = []
        timeout_seconds: int = 60

    class Playbook(BaseModel):
        name: str
        description: str = ""
        author: str = ""
        mitre_attack_version: str = "14.1"
        target_os: list[str] = []
        steps: list[PlaybookStep]

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        pb = Playbook.model_validate(data)
        console.print(f"[green]Playbook '{pb.name}' is valid ({len(pb.steps)} steps)[/green]")
    except Exception as e:
        console.print(f"[red]Validation failed: {e}[/red]")
        raise typer.Exit(1)


def _discover_playbooks() -> list[dict]:
    import yaml

    playbooks: list[dict] = []
    for pb_dir in PLAYBOOK_DIRS:
        if not pb_dir.exists():
            continue
        for pb_file in pb_dir.glob("*.yaml"):
            try:
                with open(pb_file) as f:
                    data = yaml.safe_load(f)
                if data and "name" in data:
                    tactics = set()
                    for step in data.get("steps", []):
                        tid = step.get("technique_id", "")
                        if tid:
                            tactics.add(tid.split(".")[0] if "." in tid else tid[:6])
                    playbooks.append({
                        "name": data["name"],
                        "path": pb_file,
                        "tactics": ", ".join(sorted(tactics)),
                    })
            except Exception:
                continue
    return playbooks


def _find_playbook(name: str) -> dict | None:
    for pb in _discover_playbooks():
        if pb["name"] == name:
            return pb
    return None
