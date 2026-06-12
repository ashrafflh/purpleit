from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AttackPlanStep(BaseModel):
    order: int
    technique_id: str
    technique_name: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_detection_rules: list[str] = Field(default_factory=list)
    risk_level: str = "medium"


class AttackPlan(BaseModel):
    name: str = "Unnamed Plan"
    description: str = ""
    steps: list[AttackPlanStep] = Field(default_factory=list)
    target_group: str = ""
    created_at: datetime = Field(default_factory=datetime.now)
