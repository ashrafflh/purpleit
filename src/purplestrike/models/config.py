from __future__ import annotations

import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

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
    dashboard_url: str = ""
    dashboard_api_id: str = "default"
    extra: dict[str, Any] = Field(default_factory=dict)


class LLMProviderType(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    VLLM = "vllm"
    NVIDIA = "nvidia"
    DEEPSEEK = "deepseek"


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
    target_ad_domain: str = ""
    target_username: str = ""
    target_password: str = ""

    @classmethod
    def from_yaml(cls, path: Path) -> PurpleStrikeConfig:
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f) or {}
        data = cls._apply_env_overrides(data)
        return cls.model_validate(data)

    @classmethod
    def from_env(cls) -> PurpleStrikeConfig:
        return cls.model_validate(cls._apply_env_overrides({}))

    @classmethod
    def from_yaml_or_env(cls, path: Path) -> PurpleStrikeConfig:
        if path.exists():
            return cls.from_yaml(path)
        return cls.from_env()

    @classmethod
    def _apply_env_overrides(cls, data: dict[str, Any]) -> dict[str, Any]:
        def _get_nested(node: dict[str, Any], keys: list[str]) -> Any:
            for key in keys:
                if not isinstance(node, dict) or key not in node:
                    return None
                node = node[key]
            return node

        def _set_nested(node: dict[str, Any], keys: list[str], value: Any) -> None:
            for key in keys[:-1]:
                if key not in node or not isinstance(node[key], dict):
                    node[key] = {}
                node = node[key]
            node[keys[-1]] = value

        env_overrides: dict[str, tuple[list[str], Callable[[str], Any]]] = {
            "PURPLESTRIKE_SIEM_CONNECTOR": (["siem", "connector"], str),
            "PURPLESTRIKE_SIEM_API_URL": (["siem", "api_url"], str),
            "PURPLESTRIKE_WAZUH_API_URL": (["siem", "api_url"], str),
            "PURPLESTRIKE_SIEM_API_USER": (["siem", "api_user"], str),
            "PURPLESTRIKE_WAZUH_API_USER": (["siem", "api_user"], str),
            "PURPLESTRIKE_SIEM_API_PASSWORD": (["siem", "api_password"], str),
            "PURPLESTRIKE_WAZUH_API_PASSWORD": (["siem", "api_password"], str),
            "PURPLESTRIKE_SIEM_API_TIMEOUT": (["siem", "api_timeout"], int),
            "PURPLESTRIKE_WAZUH_API_TIMEOUT": (["siem", "api_timeout"], int),
            "PURPLESTRIKE_SIEM_DASHBOARD_URL": (["siem", "dashboard_url"], str),
            "PURPLESTRIKE_WAZUH_DASHBOARD_URL": (["siem", "dashboard_url"], str),
            "PURPLESTRIKE_SIEM_DASHBOARD_API_ID": (["siem", "dashboard_api_id"], str),
            "PURPLESTRIKE_WAZUH_DASHBOARD_API_ID": (["siem", "dashboard_api_id"], str),
            "PURPLESTRIKE_LLM_PROVIDER": (["llm", "provider"], str),
            "PURPLESTRIKE_LLM_MODEL": (["llm", "model"], str),
            "PURPLESTRIKE_LLM_API_KEY": (["llm", "api_key"], str),
            "PURPLESTRIKE_OPENAI_API_KEY": (["llm", "api_key"], str),
            "PURPLESTRIKE_ANTHROPIC_API_KEY": (["llm", "api_key"], str),
            "PURPLESTRIKE_LLM_BASE_URL": (["llm", "base_url"], str),
            "PURPLESTRIKE_OLLAMA_BASE_URL": (["llm", "base_url"], str),
            "PURPLESTRIKE_VLLM_BASE_URL": (["llm", "base_url"], str),
            "PURPLESTRIKE_NVIDIA_BASE_URL": (["llm", "base_url"], str),
            "PURPLESTRIKE_NVIDIA_API_KEY": (["llm", "api_key"], str),
            "PURPLESTRIKE_NVIDIA_MODEL": (["llm", "model"], str),
            "PURPLESTRIKE_DEEPSEEK_BASE_URL": (["llm", "base_url"], str),
            "PURPLESTRIKE_DEEPSEEK_API_KEY": (["llm", "api_key"], str),
            "PURPLESTRIKE_DEEPSEEK_MODEL": (["llm", "model"], str),
            "PURPLESTRIKE_LLM_TEMPERATURE": (["llm", "temperature"], float),
            "PURPLESTRIKE_LLM_MAX_TOKENS": (["llm", "max_tokens"], int),
            "PURPLESTRIKE_DB_PATH": (["db_path"], str),
            "PURPLESTRIKE_DETECTION_CHECK_DELAY": (["detection_check_delay"], int),
            "PURPLESTRIKE_MAX_STEPS": (["max_steps"], int),
            "PURPLESTRIKE_OUTPUT_DIR": (["output_dir"], str),
            "PURPLESTRIKE_TARGET_AD_DOMAIN": (["target_ad_domain"], str),
            "PURPLESTRIKE_TARGET_USERNAME": (["target_username"], str),
            "PURPLESTRIKE_TARGET_PASSWORD": (["target_password"], str),
            "PURPLESTRIKE_TARGET_GROUPS": (["target_groups"], json.loads),
        }

        for env_name, (keys, cast) in env_overrides.items():
            value = os.getenv(env_name)
            if value is None or value == "":
                continue
            # Always override with env vars when present.
            _set_nested(data, keys, cast(value))

        return data

    @classmethod
    def to_yaml(cls, config: PurpleStrikeConfig, path: Path) -> None:
        import yaml

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(config.model_dump(mode="json"), f, default_flow_style=False, sort_keys=False)
