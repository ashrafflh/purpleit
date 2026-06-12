from __future__ import annotations

from typing import Any, ClassVar

import pytest

from purplestrike.core.orchestrator import Orchestrator
from purplestrike.core.plan import AttackPlan, AttackPlanStep
from purplestrike.models.config import (
    AssetType,
    OSType,
    PurpleStrikeConfig,
    TargetGroup,
    TargetHost,
)
from purplestrike.models.techniques import TechniqueResult


def _config(hostname: str = "10.10.1.108", ip: str = "10.10.1.108") -> PurpleStrikeConfig:
    return PurpleStrikeConfig(
        target_groups={
            "purple.local": TargetGroup(
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
        },
    )


class RecordingExecutor:
    name = "recording"
    supported_techniques: ClassVar[list[str]] = ["T1059.001"]

    def __init__(self) -> None:
        self.received_target = ""

    async def execute(
        self,
        technique_id: str,
        target: str,
        parameters: dict[str, Any],
    ) -> TechniqueResult:
        self.received_target = target
        return TechniqueResult(technique_id=technique_id, success=True)


class RecordingRegistry:
    def __init__(self, executor: RecordingExecutor) -> None:
        self.executor = executor

    def find_executor_for_technique(self, technique_id: str) -> RecordingExecutor | None:
        return self.executor if technique_id == "T1059.001" else None

    def get_attack_executor(self, name: str) -> RecordingExecutor | None:
        return self.executor if name == "recording" else None


@pytest.mark.asyncio
async def test_generate_playbook_plan_ignores_step_target_field(tmp_path) -> None:
    playbook = tmp_path / "plan.yaml"
    playbook.write_text(
        """
name: Bad Target Playbook
target_group: purple.local
steps:
  - order: 1
    technique_id: T1059.001
    technique_name: PowerShell
    target: seif
""".strip()
    )
    orchestrator = Orchestrator(config=_config())

    plan = await orchestrator.generate_plan(
        mode="playbook",
        target_group_name="purple.local",
        playbook_path=playbook,
    )

    assert plan is not None
    assert "target" not in plan.steps[0].model_dump()


def test_target_for_group_uses_configured_hostname() -> None:
    orchestrator = Orchestrator(config=_config(hostname="configured-host", ip="10.10.1.108"))

    assert orchestrator._target_for_group("purple.local") == "configured-host"


@pytest.mark.asyncio
async def test_execute_step_passes_configured_target_to_executor() -> None:
    orchestrator = Orchestrator(config=_config())
    executor = RecordingExecutor()
    step = AttackPlanStep(
        order=1,
        technique_id="T1059.001",
        technique_name="PowerShell",
    )

    await orchestrator._execute_step(
        step,
        RecordingRegistry(executor),
        target=orchestrator._target_for_group("purple.local"),
    )

    assert executor.received_target == "10.10.1.108"


@pytest.mark.asyncio
async def test_execute_loop_uses_config_target_group_for_execute_step() -> None:
    class RecordingOrchestrator(Orchestrator):
        def __init__(self, config: PurpleStrikeConfig) -> None:
            super().__init__(config)
            self.received_target = ""

        async def generate_plan(
            self,
            mode: str = "agent",
            target_group_name: str = "",
            playbook_path: Any = None,
            playbook_name: str | None = None,
            tactics: list[str] | None = None,
            technique_ids: list[str] | None = None,
        ) -> AttackPlan | None:
            return AttackPlan(
                name="No Step Target Plan",
                target_group="purple.local",
                steps=[
                    AttackPlanStep(
                        order=1,
                        technique_id="T1059.001",
                        technique_name="PowerShell",
                    ),
                ],
            )

        def display_plan(self, plan: AttackPlan) -> bool:
            return True

        async def _execute_step(
            self,
            plan_step: AttackPlanStep,
            plugin_registry: Any,
            target: str,
        ) -> TechniqueResult:
            self.received_target = target
            return TechniqueResult(technique_id=plan_step.technique_id, success=True)

    config = _config()
    config.siem.connector = "none"
    config.output_dir = ""
    orchestrator = RecordingOrchestrator(config=config)

    report = await orchestrator.execute(target_group_name="purple.local", skip_cleanup=True)

    assert orchestrator.received_target == "10.10.1.108"
    assert report is not None
    assert report.results[0].target == "10.10.1.108"
