from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class AssetType(StrEnum):
    DOMAIN_CONTROLLER = "domain_controller"
    CRITICAL_SERVER = "critical_server"
    STANDARD_SERVER = "standard_server"
    WORKSTATION = "workstation"


class OSType(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"


ASSET_MULTIPLIERS: dict[AssetType, float] = {
    AssetType.DOMAIN_CONTROLLER: 3.0,
    AssetType.CRITICAL_SERVER: 2.0,
    AssetType.STANDARD_SERVER: 1.5,
    AssetType.WORKSTATION: 1.0,
}


class Industry(StrEnum):
    HEALTHCARE = "healthcare"
    FINANCIAL = "financial"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    OTHER = "other"


INDUSTRY_MULTIPLIERS: dict[Industry, float] = {
    Industry.HEALTHCARE: 1.5,
    Industry.FINANCIAL: 2.0,
    Industry.GOVERNMENT: 1.5,
    Industry.TECHNOLOGY: 1.2,
    Industry.RETAIL: 1.0,
    Industry.OTHER: 1.0,
}


class TargetHost(BaseModel):
    hostname: str
    ip: str
    os: OSType
    asset_type: AssetType = AssetType.WORKSTATION
    domain: str | None = None
    services: list[str] = Field(default_factory=list)

    @property
    def asset_multiplier(self) -> float:
        return ASSET_MULTIPLIERS[self.asset_type]


class TargetGroup(BaseModel):
    name: str
    hosts: list[TargetHost]
    domain: str = ""
    industry: Industry = Industry.OTHER

    @property
    def industry_multiplier(self) -> float:
        return INDUSTRY_MULTIPLIERS[self.industry]


class SIEMConfig(BaseModel):
    connector: str = "wazuh"
    api_url: str = ""
    api_user: str = ""
    api_password: str = ""
    api_timeout: int = 30
    extra: dict[str, Any] = Field(default_factory=dict)


class LLMProviderType(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    VLLM = "vllm"


class LLMConfig(BaseModel):
    provider: LLMProviderType = LLMProviderType.OPENAI
    model: str = ""
    api_key: str = ""
    base_url: str | None = None
    temperature: float = 0.3
    max_tokens: int = 4096
    extra: dict[str, Any] = Field(default_factory=dict)


class RiskParameters(BaseModel):
    vulnerability_detected: float = 0.05
    vulnerability_partially_detected: float = 0.40
    vulnerability_not_detected: float = 0.90
    vulnerability_unknown: float = 0.50
    threat_event_frequencies: dict[str, float] = Field(default_factory=dict)
    loss_magnitudes: dict[str, float] = Field(default_factory=dict)


class PurpleStrikeConfig(BaseModel):
    target_groups: dict[str, TargetGroup] = Field(default_factory=dict)
    siem: SIEMConfig = Field(default_factory=SIEMConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    risk: RiskParameters = Field(default_factory=RiskParameters)
    db_path: str = ""
    detection_check_delay: int = 30
    max_steps: int = 20
    output_dir: str = "./results"

    @classmethod
    def from_yaml(cls, path: Path) -> PurpleStrikeConfig:
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data)

    @classmethod
    def to_yaml(cls, config: PurpleStrikeConfig, path: Path) -> None:
        import yaml

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(config.model_dump(mode="json"), f, default_flow_style=False, sort_keys=False)
