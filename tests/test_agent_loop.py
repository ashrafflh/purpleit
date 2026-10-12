from __future__ import annotations

import json
from unittest.mock import AsyncMock

from purplestrike.core.agent_loop import AgentLoop
from purplestrike.models.config import (
    AssetType,
    OSType,
    PurpleStrikeConfig,
    TargetGroup,
    TargetHost,
)
from purplestrike.techniques.registry import technique_registry


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


def test_available_techniques_match_primary_target_os() -> None:
    agent = _agent()
    agent.technique_registry = technique_registry

    techniques = agent._get_available_techniques(
        tactics=None,
        technique_ids=["T1059.001", "T1059.004", "T1569.003"],
    )

    assert [technique.technique_id for technique in techniques] == ["T1059.001"]


async def test_agent_rejects_plan_outside_requested_mcp_selection() -> None:
    agent = _agent()
    agent.technique_registry = technique_registry
    agent.llm_provider = AsyncMock()
    agent.llm_provider.complete.return_value = json.dumps(
        {
            "steps": [{"technique_id": "T1047"}],
        }
    )
    assert await agent.generate_plan(technique_ids=["T1059.001"]) is None
