from __future__ import annotations

from dotenv import load_dotenv
import typer
from rich.console import Console

import purplestrike
from purplestrike.logging_config import configure_logging

load_dotenv()

app = typer.Typer(
    name="purplestrike",
    help="PurpleStrike — AI-Driven Breach & Attack Simulation for SIEM Detection Validation",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.callback()
def initialize_logging() -> None:
    """Initialize local persistent logging for every CLI command."""
    configure_logging()


@app.command()
def version() -> None:
    """Show PurpleStrike version information."""
    console.print(f"[bold]PurpleStrike[/bold] v{purplestrike.__version__}")
    console.print("AI-Driven Breach & Attack Simulation for SIEM Detection Validation")


from purplestrike.cli import config as config_cmd  # noqa: E402
from purplestrike.cli import plan as plan_cmd  # noqa: E402
from purplestrike.cli import playbooks as playbooks_cmd  # noqa: E402
from purplestrike.cli import run as run_cmd  # noqa: E402
from purplestrike.cli import siem as siem_cmd  # noqa: E402
from purplestrike.cli import techniques as techniques_cmd  # noqa: E402

app.add_typer(config_cmd.app, name="config", help="Manage PurpleStrike configuration")
app.add_typer(playbooks_cmd.app, name="playbooks", help="List and manage attack playbooks")
app.add_typer(siem_cmd.app, name="siem", help="SIEM connector management")
app.add_typer(techniques_cmd.app, name="techniques", help="List MITRE ATT&CK techniques")
app.command(name="plan")(plan_cmd.plan)
app.command(name="run")(run_cmd.run)
