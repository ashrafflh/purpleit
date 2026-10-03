from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TacticID(StrEnum):
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    COMMAND_AND_CONTROL = "TA0011"
    IMPACT = "TA0040"


TACTIC_NAMES: dict[TacticID, str] = {
    TacticID.INITIAL_ACCESS: "Initial Access",
    TacticID.EXECUTION: "Execution",
    TacticID.PERSISTENCE: "Persistence",
    TacticID.PRIVILEGE_ESCALATION: "Privilege Escalation",
    TacticID.DEFENSE_EVASION: "Defense Evasion",
    TacticID.CREDENTIAL_ACCESS: "Credential Access",
    TacticID.DISCOVERY: "Discovery",
    TacticID.LATERAL_MOVEMENT: "Lateral Movement",
    TacticID.COLLECTION: "Collection",
    TacticID.EXFILTRATION: "Exfiltration",
    TacticID.COMMAND_AND_CONTROL: "Command and Control",
    TacticID.IMPACT: "Impact",
}


class TechniqueParameter(BaseModel):
    name: str
    description: str
    type: str = "string"
    required: bool = False
    default: Any = None


class DetectionMapping(BaseModel):
    rule_id: str
    confidence: str = "medium"
    description: str = ""


class Technique(BaseModel):
    technique_id: str
    mitre_technique_id: str | None = None
    name: str
    tactic: TacticID
    description: str = ""
    target_os: list[str] = Field(default_factory=lambda: ["windows", "linux"])
    parameters: list[TechniqueParameter] = Field(default_factory=list)
    detection_mappings: list[DetectionMapping] = Field(default_factory=list)
    executor: str = "custom_python"
    module: str = ""
    risk_level: str = "medium"
    safe_to_execute: bool = True
    validation_notes: str = ""

    @property
    def detection_technique_id(self) -> str:
        return self.mitre_technique_id or self.technique_id

    @property
    def tactic_name(self) -> str:
        return TACTIC_NAMES.get(self.tactic, self.tactic)


class ExecutionStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class TechniqueResult(BaseModel):
    technique_id: str
    success: bool
    output: str = ""
    error: str | None = None
    artifacts: list[str] = Field(default_factory=list)
    execution_time_seconds: float = 0.0
    execution_status: ExecutionStatus = ExecutionStatus.SUCCESS
