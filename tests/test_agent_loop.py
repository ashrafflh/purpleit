from __future__ import annotations

import json

from purplestrike.core.agent_loop import AgentLoop
from purplestrike.models.config import (
    AssetType,
    OSType,
    PurpleStrikeConfig,
    TargetGroup,
    TargetHost,
)


def _agent(hostname: str = "10.10.1.108", ip: str = "10.10.1.108") -> AgentLoop:
    target_group = TargetGroup(
        name="purple.local",
        domain="purple.local",
        hosts=[
            TargetHost(
                hostname=hostname,
                ip=ip,
                os=OSType.WINDOWS,
                asset_type=AssetType.DOMAIN_CONTROLLER,
                domain="purple.local",
            ),
        ],
    )
    return AgentLoop(
        llm_provider=None,
        technique_registry=None,
        target_group=target_group,
        config=PurpleStrikeConfig(max_steps=5),
    )


def test_parse_response_ignores_llm_target_field() -> None:
    agent = _agent()
    response = json.dumps(
        {
            "name": "Bad Target Plan",
            "steps": [
                {
                    "order": 1,
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "target": "seif",
                },
            ],
        }
    )

    plan = agent._parse_response(response)

    assert plan is not None
    assert "target" not in plan.steps[0].model_dump()


def test_parse_response_does_not_require_target_field() -> None:
    agent = _agent()
    response = json.dumps(
        {
            "name": "No Target Plan",
            "steps": [
                {
                    "order": 1,
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                },
            ],
        }
    )

    plan = agent._parse_response(response)

    assert plan is not None
    assert plan.steps[0].technique_id == "T1059.001"
    assert "target" not in plan.steps[0].model_dump()
