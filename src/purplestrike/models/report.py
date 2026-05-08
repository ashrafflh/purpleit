from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .simulation import DetectionStatus, SimulationStatus, SimulationStep


class SimulationSummary(BaseModel):
    total_techniques: int = 0
    detected: int = 0
    partially_detected: int = 0
    not_detected: int = 0
    unknown: int = 0
    detection_rate: float = 0.0
    total_annualized_risk: float = 0.0
    risk_by_tactic: dict[str, float] = Field(default_factory=dict)

    @classmethod
    def from_steps(cls, steps: list[SimulationStep]) -> SimulationSummary:
        total = len(steps)
        if total == 0:
            return cls()

        detected = sum(1 for s in steps if s.detection_status == DetectionStatus.DETECTED)
        partial = sum(1 for s in steps if s.detection_status == DetectionStatus.PARTIALLY_DETECTED)
        not_det = sum(1 for s in steps if s.detection_status == DetectionStatus.NOT_DETECTED)
        unknown = sum(1 for s in steps if s.detection_status == DetectionStatus.UNKNOWN)

        total_risk = sum(s.detection_result.risk.annualized_loss_expectancy for s in steps)

        risk_by_tactic: dict[str, float] = {}
        for s in steps:
            tactic = s.tactic
            risk = s.detection_result.risk.annualized_loss_expectancy
            risk_by_tactic[tactic] = risk_by_tactic.get(tactic, 0.0) + risk

        return cls(
            total_techniques=total,
            detected=detected,
            partially_detected=partial,
            not_detected=not_det,
            unknown=unknown,
            detection_rate=(detected + partial) / total if total > 0 else 0.0,
            total_annualized_risk=total_risk,
            risk_by_tactic=risk_by_tactic,
        )


class SimulationReport(BaseModel):
    simulation_id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    mode: str = "agent"
    target_group: str = ""
    llm_provider: str = ""
    siem_connector: str = "wazuh"
    status: SimulationStatus = SimulationStatus.COMPLETED
    plan_name: str = ""
    results: list[SimulationStep] = Field(default_factory=list)
    summary: SimulationSummary = Field(default_factory=SimulationSummary)
    remediation: list = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
