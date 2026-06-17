from __future__ import annotations

import logging
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from purplestrike.core.plan import AttackPlan, AttackPlanStep
from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.models.remediation import RemediationEntry
from purplestrike.models.report import SimulationReport, SimulationSummary
from purplestrike.models.simulation import (
    DetectionResult,
    DetectionStatus,
    ExecutionStatus,
    RiskResult,
    Simulation,
    SimulationStatus,
    SimulationStep,
)
from purplestrike.models.techniques import Technique, TechniqueResult
from purplestrike.techniques.registry import technique_registry

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """Top-level coordinator for PurpleStrike simulation runs."""

    def __init__(self, config: PurpleStrikeConfig) -> None:
        self.config = config
        self._technique_registry = technique_registry
        self._plan: AttackPlan | None = None
        self._simulation: Simulation | None = None
        self._stop_requested = False
        self._set_target_credentials()

    def _set_target_credentials(self) -> None:
        from purplestrike.techniques.connection import set_target_credentials
        set_target_credentials(
            domain=self.config.target_ad_domain,
            username=self.config.target_username,
            password=self.config.target_password,
        )

    async def generate_plan(
        self,
        mode: str = "agent",
        target_group_name: str = "",
        playbook_path: Path | None = None,
        playbook_name: str | None = None,
        tactics: list[str] | None = None,
        technique_ids: list[str] | None = None,
    ) -> AttackPlan | None:
        if mode == "playbook":
            plan = await self._generate_playbook_plan(playbook_path, playbook_name)
        elif mode == "default":
            plan = self._generate_default_plan(target_group_name, tactics, technique_ids)
        else:
            plan = await self._generate_agent_plan(target_group_name, tactics, technique_ids)

        if plan is None:
            return None
        plan = self._normalize_plan_targets(plan, target_group_name)
        return self._filter_plan_for_target_os(plan)

    async def _generate_playbook_plan(
        self,
        playbook_path: Path | None = None,
        playbook_name: str | None = None,
    ) -> AttackPlan | None:
        import yaml

        path = playbook_path
        if path is None and playbook_name:
            for pb_dir in [
                Path.home() / ".purplestrike" / "playbooks",
                Path.cwd() / "playbooks",
                Path(__file__).parent.parent.parent / "playbooks",
            ]:
                candidate = pb_dir / f"{playbook_name}.yaml"
                if candidate.exists():
                    path = candidate
                    break

        if path is None or not Path(path).exists():
            logger.error("Playbook not found")
            return None

        with open(path) as f:
            data = yaml.safe_load(f)

        steps = []
        for step_data in data.get("steps", []):
            steps.append(AttackPlanStep(
                order=step_data.get("order", len(steps) + 1),
                technique_id=step_data.get("technique_id", ""),
                technique_name=step_data.get("technique_name", ""),
                parameters=step_data.get("parameters", {}),
                expected_detection_rules=step_data.get("expected_detection_rules", []),
                risk_level=step_data.get("risk_level", "medium"),
            ))

        return AttackPlan(
            name=data.get("name", "Playbook"),
            description=data.get("description", ""),
            steps=steps,
            target_group=data.get("target_group", ""),
        )

    async def _generate_agent_plan(
        self,
        target_group_name: str,
        tactics: list[str] | None,
        technique_ids: list[str] | None,
    ) -> AttackPlan | None:
        from purplestrike.plugins.loader import PluginLoader
        from purplestrike.plugins.registry import plugin_registry

        target_group = self.config.target_groups.get(target_group_name)
        if target_group is None:
            logger.error(f"Target group '{target_group_name}' not found")
            return None

        loader = PluginLoader(plugin_registry)
        await loader.load_all(self._plugin_config())

        llm_provider = plugin_registry.get_llm_provider(self.config.llm.provider.value)
        if llm_provider is None:
            logger.warning("No LLM provider available, falling back to technique selection")
            return self._generate_default_plan(target_group_name, tactics, technique_ids)

        from purplestrike.core.agent_loop import AgentLoop

        agent = AgentLoop(
            llm_provider=llm_provider,
            technique_registry=self._technique_registry,
            target_group=target_group,
            config=self.config,
        )

        plan = await agent.generate_plan(tactics=tactics, technique_ids=technique_ids)
        if plan is None:
            logger.warning("Agent failed to generate plan, falling back to default selection")
            return self._generate_default_plan(target_group_name, tactics, technique_ids)

        return plan

    def _generate_default_plan(
        self,
        target_group_name: str,
        tactics: list[str] | None,
        technique_ids: list[str] | None,
    ) -> AttackPlan:
        techniques = self._technique_registry.list_techniques()
        if tactics:
            techniques = [t for t in techniques if t.tactic in tactics]
        if technique_ids:
            techniques = [t for t in techniques if t.technique_id in technique_ids]
        target_os = self._target_os_for_group(target_group_name)
        if target_os:
            techniques = [t for t in techniques if target_os in t.target_os]

        steps = []
        for i, t in enumerate(techniques[: self.config.max_steps], 1):
            steps.append(AttackPlanStep(
                order=i,
                technique_id=t.technique_id,
                technique_name=t.name,
                parameters=self._default_parameters_for_technique(t, target_group_name),
                expected_detection_rules=[dm.rule_id for dm in t.detection_mappings],
                risk_level=t.risk_level,
            ))

        return AttackPlan(
            name="Default Technique Selection",
            steps=steps,
            target_group=target_group_name,
        )

    def _target_os_for_group(self, target_group_name: str) -> str | None:
        target_group = self.config.target_groups.get(target_group_name)
        if target_group is None or not target_group.hosts:
            return None
        return str(target_group.hosts[0].os)

    def _filter_plan_for_target_os(self, plan: AttackPlan) -> AttackPlan:
        target_os = self._target_os_for_group(plan.target_group)
        if not target_os:
            return plan

        filtered_steps = []
        for step in plan.steps:
            technique = self._technique_registry.get_technique(step.technique_id)
            if technique is None or target_os in technique.target_os:
                filtered_steps.append(step)

        if len(filtered_steps) == len(plan.steps):
            return plan

        return AttackPlan(
            name=plan.name,
            description=plan.description,
            steps=[
                step.model_copy(update={"order": i})
                for i, step in enumerate(filtered_steps, 1)
            ],
            target_group=plan.target_group,
            created_at=plan.created_at,
        )

    def _default_parameters_for_technique(
        self,
        technique: Technique,
        target_group_name: str,
    ) -> dict[str, Any]:
        parameters = {
            p.name: p.default
            for p in technique.parameters
            if p.default is not None
        }
        target_group = self.config.target_groups.get(target_group_name)

        if target_group and target_group.domain and "domain" not in parameters:
            if any(p.name == "domain" for p in technique.parameters):
                parameters["domain"] = target_group.domain

        if self.config.target_username:
            for account_param in ("target_account", "account_list"):
                if account_param not in parameters and any(
                    p.name == account_param for p in technique.parameters
                ):
                    parameters[account_param] = self.config.target_username

        return parameters

    def _normalize_plan_targets(
        self,
        plan: AttackPlan,
        target_group_name: str,
    ) -> AttackPlan:
        effective_group_name = target_group_name or plan.target_group
        plan.target_group = effective_group_name
        return plan

    def _target_for_group(self, target_group_name: str = "") -> str:
        if not target_group_name:
            raise ValueError("Target group name is required")
        target_group = self.config.target_groups.get(target_group_name)
        if target_group is None:
            available = ", ".join(self.config.target_groups.keys()) or "none"
            raise ValueError(
                f"Target group '{target_group_name}' not found in config. "
                f"Available groups: {available}"
            )
        if not target_group.hosts:
            raise ValueError(f"Target group '{target_group_name}' has no hosts configured")
        return target_group.hosts[0].hostname

    def display_plan(self, plan: AttackPlan) -> bool:
        console.print(f"\n[bold]Plan: {plan.name}[/bold]")
        target = self._target_for_group(plan.target_group)
        if target:
            console.print(f"Target host: {target}")
        console.print(f"Total steps: {len(plan.steps)}\n")

        table = Table()
        table.add_column("#", style="bold")
        table.add_column("Technique ID")
        table.add_column("Technique Name")
        table.add_column("Risk")

        for step in plan.steps:
            risk_style = {"high": "red", "medium": "yellow", "low": "green"}.get(
                step.risk_level, ""
            )
            table.add_row(
                str(step.order),
                step.technique_id,
                step.technique_name,
                (
                    f"[{risk_style}]{step.risk_level}[/{risk_style}]"
                    if risk_style
                    else step.risk_level
                ),
            )

        console.print(table)
        console.print(f"\nEstimated time: ~{len(plan.steps) * 2} minutes\n")

        response = input("Approve this plan? [y/n/e(edit)]: ").strip().lower()
        return response == "y"

    async def execute(
        self,
        mode: str = "agent",
        target_group_name: str = "",
        playbook_name: str | None = None,
        tactics: list[str] | None = None,
        technique_ids: list[str] | None = None,
        skip_cleanup: bool = False,
        dry_run: bool = False,
    ) -> SimulationReport | None:
        from purplestrike.techniques.registry import load_default_techniques
        load_default_techniques()

        plan = await self.generate_plan(
            mode=mode,
            target_group_name=target_group_name,
            playbook_name=playbook_name,
            tactics=tactics,
            technique_ids=technique_ids,
        )

        if plan is None:
            logger.error("Failed to generate plan")
            return None

        self._plan = plan

        if not self.display_plan(plan):
            console.print("[yellow]Plan rejected. Aborting.[/yellow]")
            return None

        if dry_run:
            console.print("[yellow]Dry-run mode — plan generated but not executed.[/yellow]")
            return None

        from purplestrike.plugins.loader import PluginLoader
        from purplestrike.plugins.registry import plugin_registry

        loader = PluginLoader(plugin_registry)
        await loader.load_all(self._plugin_config())

        sim_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        simulation = Simulation(
            id=sim_id,
            timestamp=datetime.now(UTC),
            mode=mode,
            target_group=target_group_name,
            llm_provider=self.config.llm.provider.value,
            siem_connector=self.config.siem.connector,
            plan_name=plan.name,
            status=SimulationStatus.COMPLETED,
        )

        siem_connector = plugin_registry.get_siem_connector(self.config.siem.connector)
        if siem_connector:
            try:
                await siem_connector.setup(self.config.siem.model_dump())
            except Exception as e:
                logger.error(f"Failed to connect to SIEM: {e}")
                with suppress(Exception):
                    await siem_connector.teardown()
                siem_connector = None

        sim_steps: list[SimulationStep] = []
        execution_target = self._target_for_group(target_group_name or plan.target_group)
        for i, plan_step in enumerate(plan.steps, 1):
            if self._stop_requested:
                simulation.status = SimulationStatus.ABORTED
                break

            console.print(f"\n[*] Executing step {i}/{len(plan.steps)}: "
                          f"{plan_step.technique_id} {plan_step.technique_name}...")

            step_start = datetime.now(UTC)
            technique_result = await self._execute_step(
                plan_step,
                plugin_registry,
                target=execution_target,
            )
            step_end = datetime.now(UTC)

            exec_status = (
                ExecutionStatus.SUCCESS
                if technique_result.success
                else ExecutionStatus.FAILURE
            )

            detection_result = DetectionResult(status=DetectionStatus.UNKNOWN)
            if siem_connector:
                import asyncio
                await asyncio.sleep(self.config.detection_check_delay)
                validation_end = datetime.now(UTC)
                detection_result = await self._validate_detection(
                    siem_connector=siem_connector,
                    plan_step=plan_step,
                    target=execution_target,
                    start_time=step_start,
                    end_time=validation_end,
                    plugin_registry=plugin_registry,
                )

            det_status = detection_result.status
            det_icon = {
                "detected": "[green]DETECTED[/green]",
                "partially_detected": "[yellow]PARTIALLY DETECTED[/yellow]",
                "not_detected": "[red]NOT DETECTED[/red]",
                "unknown": "[dim]UNKNOWN[/dim]",
            }
            status_icon = "OK" if technique_result.success else "FAIL"
            status_text = "successfully" if technique_result.success else "failed"
            console.print(
                f"    [{status_icon}] Executed {status_text} "
                f"({technique_result.execution_time_seconds:.1f}s)"
            )
            console.print(f"    {det_icon.get(det_status, det_status)}")

            sim_step = SimulationStep(
                step=i,
                technique_id=plan_step.technique_id,
                technique_name=plan_step.technique_name,
                tactic=self._get_tactic_for_technique(plan_step.technique_id),
                target=execution_target,
                execution_status=exec_status,
                execution_time_seconds=technique_result.execution_time_seconds,
                execution_output=technique_result.output,
                execution_error=technique_result.error,
                artifacts=technique_result.artifacts,
                detection_result=detection_result,
            )
            sim_steps.append(sim_step)

        if siem_connector:
            with suppress(Exception):
                await siem_connector.teardown()

        if not skip_cleanup:
            await self._cleanup_all(plan, plugin_registry, target=execution_target)

        simulation.steps = sim_steps
        summary = SimulationSummary.from_steps(sim_steps)

        remediation_entries = self._generate_remediation(sim_steps)

        report = SimulationReport(
            simulation_id=sim_id,
            timestamp=simulation.timestamp,
            mode=mode,
            target_group=target_group_name,
            llm_provider=self.config.llm.provider.value,
            siem_connector=self.config.siem.connector,
            status=simulation.status,
            plan_name=plan.name,
            results=sim_steps,
            summary=summary,
            remediation=remediation_entries,
        )

        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt_name in (["json", "csv"] if self.config.output_dir else []):
            formatter = plugin_registry.get_report_formatter(fmt_name)
            if formatter:
                try:
                    await formatter.format(report, output_dir)
                except Exception as e:
                    logger.error(f"Failed to generate {fmt_name} report: {e}")

        return report

    async def _execute_step(
        self,
        plan_step: AttackPlanStep,
        plugin_registry: Any,
        target: str,
    ) -> TechniqueResult:
        import time

        executor = plugin_registry.find_executor_for_technique(plan_step.technique_id)

        if executor is None:
            executor = plugin_registry.get_attack_executor("custom_python")

        if executor is None:
            return TechniqueResult(
                technique_id=plan_step.technique_id,
                success=False,
                error="No executor available",
                execution_status=ExecutionStatus.FAILURE,
            )

        start = time.monotonic()
        try:
            result = await executor.execute(
                technique_id=plan_step.technique_id,
                target=target,
                parameters=plan_step.parameters,
            )
        except Exception as e:
            result = TechniqueResult(
                technique_id=plan_step.technique_id,
                success=False,
                error=str(e),
                execution_status=ExecutionStatus.FAILURE,
            )
        result.execution_time_seconds = time.monotonic() - start
        return result

    async def _validate_detection(
        self,
        siem_connector: Any,
        plan_step: AttackPlanStep,
        target: str,
        start_time: datetime,
        end_time: datetime,
        plugin_registry: Any,
    ) -> DetectionResult:
        from purplestrike.validation.engine import DetectionValidationEngine

        engine = DetectionValidationEngine(
            siem_connector=siem_connector,
            plugin_registry=plugin_registry,
            config=self.config,
        )

        return await engine.validate_step(
            technique_id=plan_step.technique_id,
            expected_rules=plan_step.expected_detection_rules,
            target=target,
            start_time=start_time,
            end_time=end_time,
        )

    def _calculate_risk(self, technique_id: str, detection_status: DetectionStatus) -> RiskResult:
        from purplestrike.risk.quantifier import RiskQuantifier

        quantifier = RiskQuantifier(self.config.risk)
        return quantifier.calculate(technique_id, detection_status)

    def _get_tactic_for_technique(self, technique_id: str) -> Any:
        technique = self._technique_registry.get_technique(technique_id)
        if technique:
            return technique.tactic
        from purplestrike.models.techniques import TacticID
        return TacticID.INITIAL_ACCESS

    async def _cleanup_all(self, plan: AttackPlan, plugin_registry: Any, target: str) -> None:
        for step in plan.steps:
            for executor_name in plugin_registry.list_attack_executors():
                executor = plugin_registry.get_attack_executor(executor_name)
                if executor and step.technique_id in executor.supported_techniques:
                    try:
                        await executor.cleanup(step.technique_id, target, step.parameters)
                    except Exception as e:
                        logger.warning(
                            f"Cleanup failed for {step.technique_id} on {target}: {e}"
                        )

    def _generate_remediation(self, steps: list[SimulationStep]) -> list[RemediationEntry]:
        from purplestrike.remediation.engine import RemediationEngine

        engine = RemediationEngine()
        return engine.generate_remediation(steps)

    def request_stop(self) -> None:
        self._stop_requested = True

    def _plugin_config(self) -> dict[str, Any]:
        return {
            "siem_connectors": {
                self.config.siem.connector: self.config.siem.model_dump(mode="json"),
            },
            "llm_providers": {
                self.config.llm.provider.value: self.config.llm.model_dump(mode="json"),
            },
        }
