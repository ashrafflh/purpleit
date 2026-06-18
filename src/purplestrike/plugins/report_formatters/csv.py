from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from purplestrike.models.report import SimulationReport


class CsvFormatter:
    name = "csv"
    file_extension = "csv"

    async def setup(self, config: dict[str, Any]) -> None:
        pass

    async def format(self, report: SimulationReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        results_path = output_dir / f"{report.simulation_id}_results.csv"
        remediation_path = output_dir / f"{report.simulation_id}_remediation.csv"

        self._write_results_csv(report, results_path)
        self._write_remediation_csv(report, remediation_path)

        return results_path

    def _write_results_csv(self, report: SimulationReport, path: Path) -> None:
        headers = [
            "step", "technique_id", "technique_name", "tactic", "target",
            "execution_status", "execution_time_seconds", "execution_error",
            "artifacts", "detection_result", "detection_confidence", "matched_rule_ids", "vulnerability_score",
            "threat_event_frequency", "loss_magnitude", "annualized_loss_expectancy",
            "risk_level",
        ]

        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for step in report.results:
                risk = step.detection_result.risk
                writer.writerow([
                    step.step,
                    step.technique_id,
                    step.technique_name,
                    step.tactic,
                    step.target,
                    step.execution_status.value,
                    f"{step.execution_time_seconds:.1f}",
                    step.execution_error or "",
                    ";".join(step.artifacts),
                    step.detection_result.status.value,
                    f"{step.detection_result.confidence:.2f}",
                    ";".join(step.detection_result.matched_rules),
                    f"{risk.vulnerability_score:.2f}",
                    f"{risk.threat_event_frequency:.1f}",
                    f"{risk.loss_magnitude:.0f}",
                    f"{risk.annualized_loss_expectancy:.0f}",
                    risk.risk_level,
                ])

    def _write_remediation_csv(self, report: SimulationReport, path: Path) -> None:
        headers = [
            "technique_id", "technique_name", "detection_result",
            "remediation_confidence", "suggested_rule_ids",
            "log_sources_required", "generic_detection_logic",
        ]

        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for rem in report.remediation:
                from purplestrike.models.remediation import RemediationEntry
                if not isinstance(rem, RemediationEntry):
                    continue

                confidence = rem.wazuh_remediation.confidence.value if rem.wazuh_remediation else ""
                log_sources = ";".join(rem.wazuh_remediation.log_sources_required) if rem.wazuh_remediation else ""
                detection_logic = rem.generic_guidance.detection_logic if rem.generic_guidance else ""

                writer.writerow([
                    rem.technique_id,
                    rem.technique_name,
                    rem.current_detection,
                    confidence,
                    "",
                    log_sources,
                    detection_logic,
                ])
