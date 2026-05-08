from __future__ import annotations

import json
import logging
from typing import Any

from purplestrike.core.plan import AttackPlan, AttackPlanStep
from purplestrike.models.config import PurpleStrikeConfig, TargetGroup
from purplestrike.models.techniques import Technique
from purplestrike.techniques.registry import TechniqueRegistry

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an adversary emulation planner for PurpleStrike, a breach and attack simulation tool.
Your job is to select and chain MITRE ATT&CK techniques to simulate a realistic attack against the specified target environment.

SAFETY CONSTRAINTS (you MUST follow these):
- NEVER suggest techniques that destroy data or cause denial of service
- NEVER suggest real data exfiltration (simulate only)
- NEVER suggest techniques that would make systems permanently unavailable
- All techniques must be safe to execute in a test environment
- Rate-limit brute force techniques

OUTPUT FORMAT:
You must respond with a valid JSON object matching this structure:
{
  "name": "Attack plan name",
  "description": "Brief description of the attack chain",
  "steps": [
    {
      "order": 1,
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "target": "target_hostname",
      "parameters": {},
      "expected_detection_rules": [],
      "risk_level": "medium"
    }
  ]
}
"""


class AgentLoop:
    """AI-driven attack plan generation using LLM reasoning."""

    def __init__(
        self,
        llm_provider: Any,
        technique_registry: TechniqueRegistry,
        target_group: TargetGroup,
        config: PurpleStrikeConfig,
    ) -> None:
        self.llm_provider = llm_provider
        self.technique_registry = technique_registry
        self.target_group = target_group
        self.config = config

    async def generate_plan(
        self,
        tactics: list[str] | None = None,
        technique_ids: list[str] | None = None,
    ) -> AttackPlan | None:
        try:
            messages = self._build_messages(tactics, technique_ids)
            response = await self.llm_provider.complete(messages)
            return self._parse_response(response)
        except Exception as e:
            logger.error(f"Agent failed to generate plan: {e}")
            return None

    def _build_messages(
        self,
        tactics: list[str] | None,
        technique_ids: list[str] | None,
    ) -> list[dict[str, str]]:
        techniques = self._get_available_techniques(tactics, technique_ids)
        technique_list_str = self._format_techniques(techniques)
        target_context = self._format_target_context()

        user_message = f"""Generate an attack plan for the following target environment:

TARGET ENVIRONMENT:
{target_context}

AVAILABLE TECHNIQUES:
{technique_list_str}

CONSTRAINTS:
- Maximum {self.config.max_steps} steps
- Only use techniques from the available list above
- Chain techniques in a realistic attack progression
- Each step must target a host from the target group

Generate the plan now."""

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

    def _get_available_techniques(
        self,
        tactics: list[str] | None,
        technique_ids: list[str] | None,
    ) -> list[Technique]:
        techniques = self.technique_registry.list_techniques()
        if tactics:
            techniques = [t for t in techniques if t.tactic in tactics]
        if technique_ids:
            techniques = [t for t in techniques if t.technique_id in technique_ids]
        return [t for t in techniques if t.safe_to_execute]

    def _format_techniques(self, techniques: list[Technique]) -> str:
        lines = []
        for t in techniques:
            params_str = ""
            if t.parameters:
                param_names = [p.name for p in t.parameters if p.required]
                params_str = f" (required params: {', '.join(param_names)})" if param_names else ""
            lines.append(f"- {t.technique_id}: {t.name} [{t.tactic}]{params_str}")
        return "\n".join(lines)

    def _format_target_context(self) -> str:
        lines = [
            f"Domain: {self.target_group.domain}",
            f"Industry: {self.target_group.industry.value}",
            "Hosts:",
        ]
        for host in self.target_group.hosts:
            lines.append(
                f"  - {host.hostname} ({host.ip}) | OS: {host.os.value} | "
                f"Type: {host.asset_type.value} | Services: {', '.join(host.services) or 'unknown'}"
            )
        return "\n".join(lines)

    def _parse_response(self, response: str) -> AttackPlan | None:
        try:
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]

            data = json.loads(json_str.strip())

            steps = []
            for step_data in data.get("steps", []):
                steps.append(AttackPlanStep(
                    order=step_data.get("order", len(steps) + 1),
                    technique_id=step_data.get("technique_id", ""),
                    technique_name=step_data.get("technique_name", ""),
                    target=step_data.get("target", ""),
                    parameters=step_data.get("parameters", {}),
                    expected_detection_rules=step_data.get("expected_detection_rules", []),
                    risk_level=step_data.get("risk_level", "medium"),
                ))

            return AttackPlan(
                name=data.get("name", "AI-Generated Plan"),
                description=data.get("description", ""),
                steps=steps[: self.config.max_steps],
                target_group=self.target_group.name,
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse LLM response as plan: {e}")
            return None
