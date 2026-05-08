from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RemediationConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class WazuhRemediation(BaseModel):
    confidence: RemediationConfidence = RemediationConfidence.MEDIUM
    rule_xml: str = ""
    decoder_xml: str | None = None
    log_sources_required: list[str] = Field(default_factory=list)
    testing_instructions: str = ""


class GenericGuidance(BaseModel):
    data_sources: list[str] = Field(default_factory=list)
    detection_logic: str = ""
    false_positive_considerations: str = ""
    references: list[str] = Field(default_factory=list)


class RemediationEntry(BaseModel):
    technique_id: str
    technique_name: str = ""
    current_detection: str = "not_detected"
    wazuh_remediation: WazuhRemediation | None = None
    generic_guidance: GenericGuidance | None = None
