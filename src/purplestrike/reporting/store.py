from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

from purplestrike.models.simulation import Simulation

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS simulations (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    mode TEXT NOT NULL,
    target_group TEXT NOT NULL,
    llm_provider TEXT NOT NULL,
    siem_connector TEXT NOT NULL,
    plan_name TEXT,
    status TEXT NOT NULL,
    total_techniques INTEGER,
    detected INTEGER,
    partially_detected INTEGER,
    not_detected INTEGER,
    total_ale REAL,
    report_path_json TEXT,
    report_path_csv TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS simulation_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    simulation_id TEXT NOT NULL REFERENCES simulations(id),
    step_order INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    target TEXT NOT NULL,
    execution_status TEXT NOT NULL,
    execution_time_seconds REAL,
    detection_result TEXT NOT NULL,
    detection_confidence REAL,
    matched_rule_ids TEXT,
    vulnerability_score REAL,
    ale REAL,
    result_detail TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    simulation_id TEXT NOT NULL REFERENCES simulations(id),
    technique_id TEXT NOT NULL,
    detection_result TEXT NOT NULL,
    wazuh_remediation_confidence TEXT,
    wazuh_rule_xml TEXT,
    wazuh_decoder_xml TEXT,
    log_sources_required TEXT,
    generic_guidance TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class SimulationStore:
    """SQLite storage for simulation results."""

    def __init__(self, db_path: str = "") -> None:
        if not db_path:
            default_dir = Path.home() / ".purplestrike"
            default_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(default_dir / "purplestrike.db")
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.executescript(SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def save_simulation(self, simulation: Simulation) -> None:
        if self._db is None:
            await self.initialize()
            assert self._db is not None

        from purplestrike.models.report import SimulationSummary
        summary = SimulationSummary.from_steps(simulation.steps)

        await self._db.execute(
            """INSERT OR REPLACE INTO simulations
            (id, timestamp, mode, target_group, llm_provider, siem_connector,
             plan_name, status, total_techniques, detected, partially_detected,
             not_detected, total_ale)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                simulation.id,
                simulation.timestamp.isoformat(),
                simulation.mode,
                simulation.target_group,
                simulation.llm_provider,
                simulation.siem_connector,
                simulation.plan_name,
                simulation.status.value,
                summary.total_techniques,
                summary.detected,
                summary.partially_detected,
                summary.not_detected,
                summary.total_annualized_risk,
            ),
        )

        for step in simulation.steps:
            await self._db.execute(
                """INSERT INTO simulation_steps
                (simulation_id, step_order, technique_id, technique_name, tactic,
                 target, execution_status, execution_time_seconds, detection_result,
                 detection_confidence, matched_rule_ids, vulnerability_score, ale, result_detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    simulation.id,
                    step.step,
                    step.technique_id,
                    step.technique_name,
                    step.tactic,
                    step.target,
                    step.execution_status.value,
                    step.execution_time_seconds,
                    step.detection_result.status.value,
                    step.detection_result.confidence,
                    json.dumps(step.detection_result.matched_rules),
                    step.detection_result.risk.vulnerability_score,
                    step.detection_result.risk.annualized_loss_expectancy,
                    json.dumps(step.detection_result.model_dump(mode="json")),
                ),
            )

        await self._db.commit()

    async def get_simulation(self, simulation_id: str) -> Simulation | None:
        if self._db is None:
            await self.initialize()
            assert self._db is not None

        cursor = await self._db.execute(
            "SELECT * FROM simulations WHERE id = ?", (simulation_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None

        step_cursor = await self._db.execute(
            "SELECT * FROM simulation_steps WHERE simulation_id = ? ORDER BY step_order",
            (simulation_id,),
        )
        step_rows = await step_cursor.fetchall()

        return Simulation(
            id=row[0],
            mode=row[2],
            target_group=row[3],
            llm_provider=row[4],
            siem_connector=row[5],
            plan_name=row[6],
            status=row[7],
            steps=[],
        )
