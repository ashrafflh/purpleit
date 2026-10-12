from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from purplestrike.models.techniques import Technique, TechniqueResult

META_KEY = "purplestrike"


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)


class ToolOutput(TechniqueResult):
    detection_metadata: dict[str, Any] = Field(default_factory=dict)


def tool_name(technique: Technique) -> str:
    aliases = {
        "T1059.001": "run_powershell",
        "T1053.005": "execute_scheduled_task",
        "T1078.001": "probe_default_accounts",
    }
    return aliases.get(
        technique.technique_id,
        "run_" + re.sub(r"[^a-z0-9_]", "_", technique.technique_id.lower()),
    )


def input_schema(technique: Technique) -> dict[str, Any]:
    schema = ToolInput.model_json_schema()
    types = {"int": "integer", "float": "number", "bool": "boolean", "str": "string"}
    properties = {}
    required = []
    for param in technique.parameters:
        kind = types.get(param.type, param.type)
        if kind not in {"string", "integer", "number", "boolean", "array", "object"}:
            raise ValueError(f"Unsupported parameter type: {param.type}")
        item = {"type": kind, "description": param.description}
        if param.default is not None:
            item["default"] = param.default
        elif param.required:
            required.append(param.name)
        properties[param.name] = item
    schema["properties"]["parameters"] = {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }
    return schema
