from __future__ import annotations

from datetime import UTC, datetime
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
from purplestrike.models.simulation import DetectionResult, DetectionStatus


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


class FailingSIEMConnector:
    name = "wazuh"

    def __init__(self) -> None:
        self.query_called = False
        self.teardown_called = False

    async def setup(self, config: dict[str, Any]) -> None:
        raise OSError("[Errno 11001] getaddrinfo failed")

    async def query_alerts(self, *args: Any, **kwargs: Any) -> list[Any]:
        self.query_called = True
        return []

    async def get_rule(self, rule_id: str) -> None:
        return None

    async def teardown(self) -> None:
        self.teardown_called = True


class FailingSIEMRegistry:
    def __init__(self, executor: RecordingExecutor, siem: FailingSIEMConnector) -> None:
        self.executor = executor
        self.siem = siem

    def find_executor_for_technique(self, technique_id: str) -> RecordingExecutor | None:
        return self.executor if technique_id == "T1059.001" else None

    def get_attack_executor(self, name: str) -> RecordingExecutor | None:
        return self.executor if name == "recording" else None

    def list_attack_executors(self) -> list[str]:
        return ["recording"]

    def get_siem_connector(self, name: str) -> FailingSIEMConnector | None:
        return self.siem if name == "wazuh" else None

    def get_report_formatter(self, name: str) -> None:
        return None

    def list_llm_providers(self) -> list[str]:
        return []


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


@pytest.mark.asyncio
async def test_execute_disables_siem_validation_when_setup_fails(monkeypatch) -> None:
    class RecordingOrchestrator(Orchestrator):
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
                name="SIEM Failure Plan",
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

    async def noop_load_all(self: Any, config: dict[str, Any] | None = None) -> None:
        return None

    from purplestrike.plugins import loader as loader_module
    from purplestrike.plugins import registry as registry_module

    executor = RecordingExecutor()
    siem = FailingSIEMConnector()
    monkeypatch.setattr(loader_module.PluginLoader, "load_all", noop_load_all)
    monkeypatch.setattr(registry_module, "plugin_registry", FailingSIEMRegistry(executor, siem))

    config = _config()
    config.siem.connector = "wazuh"
    config.detection_check_delay = 0
    config.output_dir = ""
    orchestrator = RecordingOrchestrator(config=config)

    report = await orchestrator.execute(target_group_name="purple.local", skip_cleanup=True)

    assert report is not None
    assert siem.teardown_called is True
    assert siem.query_called is False


@pytest.mark.asyncio
async def test_execute_validation_window_includes_detection_delay(monkeypatch) -> None:
    class RecordingSIEMConnector:
        name = "wazuh"

        async def setup(self, config: dict[str, Any]) -> None:
            return None

        async def teardown(self) -> None:
            return None

    class RecordingSIEMRegistry:
        def __init__(self, executor: RecordingExecutor, siem: RecordingSIEMConnector) -> None:
            self.executor = executor
            self.siem = siem

        def find_executor_for_technique(self, technique_id: str) -> RecordingExecutor | None:
            return self.executor if technique_id == "T1059.001" else None

        def get_attack_executor(self, name: str) -> RecordingExecutor | None:
            return self.executor if name == "recording" else None

        def list_attack_executors(self) -> list[str]:
            return ["recording"]

        def get_siem_connector(self, name: str) -> RecordingSIEMConnector | None:
            return self.siem if name == "wazuh" else None

        def get_report_formatter(self, name: str) -> None:
            return None

        def list_llm_providers(self) -> list[str]:
            return []

    class RecordingOrchestrator(Orchestrator):
        def __init__(self, config: PurpleStrikeConfig) -> None:
            super().__init__(config)
            self.step_end_seen: datetime | None = None
            self.validation_end_seen: datetime | None = None

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
                name="Timing Plan",
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
            self.step_end_seen = datetime.now(UTC)
            return TechniqueResult(technique_id=plan_step.technique_id, success=True)

        async def _validate_detection(
            self,
            siem_connector: Any,
            plan_step: AttackPlanStep,
            target: str,
            start_time: datetime,
            end_time: datetime,
            plugin_registry: Any,
        ) -> DetectionResult:
            self.validation_end_seen = end_time
            return DetectionResult(status=DetectionStatus.UNKNOWN)

    async def noop_load_all(self: Any, config: dict[str, Any] | None = None) -> None:
        return None

    async def fast_sleep(seconds: float) -> None:
        return None

    from purplestrike.plugins import loader as loader_module
    from purplestrike.plugins import registry as registry_module
    import asyncio

    executor = RecordingExecutor()
    siem = RecordingSIEMConnector()
    monkeypatch.setattr(loader_module.PluginLoader, "load_all", noop_load_all)
    monkeypatch.setattr(registry_module, "plugin_registry", RecordingSIEMRegistry(executor, siem))
    monkeypatch.setattr(asyncio, "sleep", fast_sleep)

    config = _config()
    config.siem.connector = "wazuh"
    config.detection_check_delay = 30
    config.output_dir = ""
    orchestrator = RecordingOrchestrator(config=config)

    report = await orchestrator.execute(target_group_name="purple.local", skip_cleanup=True)

    assert report is not None
    assert orchestrator.step_end_seen is not None
    assert orchestrator.validation_end_seen is not None
    assert orchestrator.validation_end_seen >= orchestrator.step_end_seen
