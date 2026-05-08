from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from purplestrike.models.report import SimulationReport


class JsonFormatter:
    name = "json"
    file_extension = "json"

    async def setup(self, config: dict[str, Any]) -> None:
        pass

    async def format(self, report: SimulationReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{report.simulation_id}.json"

        report_dict = report.model_dump(mode="json")
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)

        return output_path
