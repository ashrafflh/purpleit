from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from .techniques import ExecutionStatus, TacticID


class DetectionStatus(StrEnum):
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"


DETECTION_VULNERABILITY_SCORES: dict[DetectionStatus, float] = {
    DetectionStatus.DETECTED: 0.05,
    DetectionStatus.PARTIALLY_DETECTED: 0.40,
    DetectionStatus.NOT_DETECTED: 0.90,
    DetectionStatus.UNKNOWN: 0.50,
}


class SIEMAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_description: str = ""
    severity: str = ""
    source: str = ""
    mitre_technique_ids: list[str] = Field(default_factory=list)
    raw_log: dict = Field(default_factory=dict)


class SIEMRule(BaseModel):
    rule_id: str
    description: str = ""
    severity: str = ""
    mitre_technique_ids: list[str] = Field(default_factory=list)
    rule_logic: str = ""


class RiskResult(BaseModel):
    vulnerability_score: float = 0.0
    threat_event_frequency: float = 0.0
    loss_magnitude: float = 0.0
    annualized_loss_expectancy: float = 0.0

    @property
    def risk_level(self) -> str:
        ale = self.annualized_loss_expectancy
        if ale >= 5_000_000:
            return "critical"
        if ale >= 1_000_000:
            return "high"
        if ale >= 100_000:
            return "medium"
        return "low"


class DetectionResult(BaseModel):
    status: DetectionStatus = DetectionStatus.UNKNOWN
    confidence: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    matched_alerts: list[SIEMAlert] = Field(default_factory=list)
    candidate_alerts: list[SIEMAlert] = Field(default_factory=list)
    ai_correlation_reasoning: str | None = None
    risk: RiskResult = Field(default_factory=RiskResult)


class SimulationStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    ABORTED = "aborted"
    FAILED = "failed"


class SimulationStep(BaseModel):
    step: int
    technique_id: str
    technique_name: str = ""
    tactic: TacticID = TacticID.INITIAL_ACCESS
    target: str = ""
    execution_status: ExecutionStatus = ExecutionStatus.SUCCESS
    execution_time_seconds: float = 0.0
    execution_started_at: datetime | None = None
    execution_ended_at: datetime | None = None
    validation_ended_at: datetime | None = None
    execution_output: str = ""
    execution_error: str | None = None
    artifacts: list[str] = Field(default_factory=list)
    detection_result: DetectionResult = Field(default_factory=DetectionResult)

    @property
    def detection_status(self) -> DetectionStatus:
        return self.detection_result.status


class Simulation(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    mode: str = "agent"
    target_group: str = ""
    llm_provider: str = ""
    siem_connector: str = "wazuh"
    plan_name: str = ""
    status: SimulationStatus = SimulationStatus.COMPLETED
    steps: list[SimulationStep] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
