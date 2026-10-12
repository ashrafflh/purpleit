from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from rich.console import Console
from rich.table import Table

from purplestrike.core.plan import AttackPlan, AttackPlanStep
from purplestrike.mcp.client import MCPToolClient
from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.models.remediation import RemediationEntry
from purplestrike.models.report import SimulationReport, SimulationSummary
from purplestrike.models.simulation import (
    CoverageStatus,
    DetectionResult,
    DetectionStatus,
    RiskResult,
    Simulation,
    SimulationStatus,
    SimulationStep,
)
from purplestrike.models.techniques import (
    EmulationMode,
    ExecutionStatus,
    Technique,
    TechniqueResult,
)
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
        self._mcp: MCPToolClient | None = None
        self._execution_environment: dict[str, Any] = {}

    @asynccontextmanager
    async def _tool_session(self) -> AsyncIterator[None]:
        if self._mcp is not None:
            yield
            return
        previous_registry = self._technique_registry
        try:
            async with MCPToolClient(self.config) as client:
                self._mcp = client
                self._technique_registry = client.registry
                yield
        finally:
            self._mcp = None
            self._technique_registry = previous_registry

    async def generate_plan(
        self,
        mode: str = "agent",
        target_group_name: str = "",
        playbook_path: Path | None = None,
        playbook_name: str | None = None,
        tactics: list[str] | None = None,
        technique_ids: list[str] | None = None,
    ) -> AttackPlan | None:
        async with self._tool_session():
            return await self._generate_plan(
                mode,
                target_group_name,
                playbook_path,
                playbook_name,
                tactics,
                technique_ids,
            )

    async def _generate_plan(
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
        plan = self._filter_plan_for_target_os(plan)
        if len(plan.steps) > self.config.max_steps:
            raise ValueError("Plan exceeds max_steps")
        available = {t.technique_id for t in self._technique_registry.list_techniques()}
        if any(step.technique_id not in available for step in plan.steps):
            raise ValueError("Plan references a technique not exposed by configured MCP servers")
        logger.info(
            "Plan generated: name=%s mode=%s target_group=%s steps=%s techniques=%s",
            plan.name,
            mode,
            plan.target_group,
            len(plan.steps),
            [step.technique_id for step in plan.steps],
        )
        return plan

    async def _generate_playbook_plan(
        self,
        playbook_path: Path | None = None,
        playbook_name: str | None = None,
    ) -> AttackPlan | None:
        import yaml

        path = playbook_path
        if path is None and playbook_name:
            supplied_path = Path(playbook_name)
            if supplied_path.is_file():
                path = supplied_path
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

        steps: list[AttackPlanStep] = []
        for step_data in data.get("steps", []):
            steps.append(
                AttackPlanStep(
                    order=step_data.get("order", len(steps) + 1),
                    technique_id=step_data.get("technique_id", ""),
                    technique_name=step_data.get("technique_name", ""),
                    parameters=step_data.get("parameters", {}),
                    expected_detection_rules=step_data.get("expected_detection_rules", []),
                    risk_level=step_data.get("risk_level", "medium"),
                )
            )

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
            tool_catalog=self._mcp.tools if self._mcp else {},
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
            steps.append(
                AttackPlanStep(
                    order=i,
                    technique_id=t.technique_id,
                    technique_name=t.name,
                    parameters=self._default_parameters_for_technique(t, target_group_name),
                    expected_detection_rules=[dm.rule_id for dm in t.detection_mappings],
                    risk_level=t.risk_level,
                )
            )

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
                step.model_copy(update={"order": i}) for i, step in enumerate(filtered_steps, 1)
            ],
            target_group=plan.target_group,
            created_at=plan.created_at,
        )

    def _default_parameters_for_technique(
        self,
        technique: Technique,
        target_group_name: str,
    ) -> dict[str, Any]:
        parameters = {p.name: p.default for p in technique.parameters if p.default is not None}
        for resource_name in ("task_name", "service_name"):
            if resource_name in parameters:
                parameters[resource_name] = f"{parameters[resource_name]}_{uuid4().hex[:10]}"
        target_group = self.config.target_groups.get(target_group_name)

        if (
            target_group
            and target_group.domain
            and "domain" not in parameters
            and any(p.name == "domain" for p in technique.parameters)
        ):
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
        console.print(
            "Agent execution may retry with changed parameters or reorder these approved steps. "
            f"Limit: {self.config.max_steps} total attempts, "
            f"{self.config.execution.max_retries_per_step} retries per step."
        )
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
        if mode not in {"agent", "default", "playbook"}:
            raise ValueError(f"Unknown execution mode: {mode}")
        async with self._tool_session():
            return await self._execute_with_tools(
                mode,
                target_group_name,
                playbook_name,
                tactics,
                technique_ids,
                skip_cleanup,
                dry_run,
            )

    async def _execute_with_tools(
        self,
        mode: str = "agent",
        target_group_name: str = "",
        playbook_name: str | None = None,
        tactics: list[str] | None = None,
        technique_ids: list[str] | None = None,
        skip_cleanup: bool = False,
        dry_run: bool = False,
    ) -> SimulationReport | None:
        logger.info(
            "Preparing simulation: mode=%s target_group=%s tactics=%s techniques=%s "
            "skip_cleanup=%s dry_run=%s",
            mode,
            target_group_name,
            tactics or [],
            technique_ids or [],
            skip_cleanup,
            dry_run,
        )

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
            logger.warning("Plan rejected by user: name=%s", plan.name)
            console.print("[yellow]Plan rejected. Aborting.[/yellow]")
            return None

        if dry_run:
            logger.info("Dry run complete; no techniques executed")
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
            target_group=plan.target_group,
            llm_provider=self.config.llm.provider.value,
            siem_connector=self.config.siem.connector,
            plan_name=plan.name,
            status=SimulationStatus.COMPLETED,
        )
        logger.info(
            "Simulation started: simulation_id=%s plan=%s target_group=%s steps=%s "
            "llm_provider=%s siem_connector=%s",
            sim_id,
            plan.name,
            target_group_name,
            len(plan.steps),
            self.config.llm.provider.value,
            self.config.siem.connector,
        )

        siem_connector = plugin_registry.get_siem_connector(self.config.siem.connector)
        if siem_connector:
            try:
                await siem_connector.setup(self.config.siem.model_dump())
                logger.info("SIEM connector ready: %s", self.config.siem.connector)
            except Exception as e:
                logger.exception("Failed to connect to SIEM: %s", e)
                with suppress(Exception):
                    await siem_connector.teardown()
                siem_connector = None
        else:
            logger.warning("SIEM connector unavailable: %s", self.config.siem.connector)

        from purplestrike.core.execution_graph import ExecutionGraph, graph_metadata

        self._simulation = simulation
        execution_target = self._target_for_group(plan.target_group)
        runner = ExecutionGraph(
            self,
            plan,
            plugin_registry,
            siem_connector,
            execution_target,
            mode,
            skip_cleanup,
        )
        metadata: dict[str, Any] = {}
        try:
            state = await runner.run()
            sim_steps = state["results"]
            simulation.status = SimulationStatus(state["status"])
            metadata = graph_metadata(state)
        except Exception as exc:
            logger.exception("Execution graph failed")
            sim_steps = runner.results
            simulation.status = SimulationStatus.FAILED
            metadata = {"engine": "langgraph", "transport": "mcp", "reason": str(exc)}
        finally:
            if siem_connector:
                with suppress(Exception):
                    await siem_connector.teardown()

        simulation.steps = sim_steps
        if simulation.status == SimulationStatus.COMPLETED and any(
            step.execution_status != ExecutionStatus.SUCCESS for step in sim_steps
        ):
            simulation.status = SimulationStatus.PARTIAL
        summary = SimulationSummary.from_steps(sim_steps)

        remediation_entries = self._generate_remediation(sim_steps)

        report = SimulationReport(
            simulation_id=sim_id,
            timestamp=simulation.timestamp,
            mode=mode,
            target_group=plan.target_group,
            llm_provider=self.config.llm.provider.value,
            siem_connector=self.config.siem.connector,
            status=simulation.status,
            plan_name=plan.name,
            results=sim_steps,
            summary=summary,
            remediation=remediation_entries,
            metadata=metadata,
        )

        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt_name in ["json", "csv"] if self.config.output_dir else []:
            formatter = plugin_registry.get_report_formatter(fmt_name)
            if formatter:
                try:
                    await formatter.format(report, output_dir)
                    logger.info(
                        "Report saved: simulation_id=%s format=%s output_dir=%s",
                        sim_id,
                        fmt_name,
                        output_dir.resolve(),
                    )
                except Exception as e:
                    logger.exception("Failed to generate %s report: %s", fmt_name, e)

        logger.info(
            "Simulation finished: simulation_id=%s status=%s total_techniques=%s "
            "detected=%s partially_detected=%s not_detected=%s unknown=%s "
            "detection_rate=%.3f",
            sim_id,
            simulation.status,
            summary.total_techniques,
            summary.detected,
            summary.partially_detected,
            summary.not_detected,
            summary.unknown,
            summary.detection_rate,
        )

        return report

    async def _execute_step(
        self,
        plan_step: AttackPlanStep,
        plugin_registry: Any,
        target: str,
    ) -> TechniqueResult:
        if self._mcp is None:
            raise RuntimeError("Technique execution requires an active MCP session")
        return await self._mcp.execute(
            plan_step.technique_id,
            target,
            plan_step.parameters,
            self._execution_environment,
        )

    @staticmethod
    def _account_for_execution(result: DetectionResult, success: bool) -> DetectionResult:
        if success:
            return result
        if result.status == DetectionStatus.DETECTED:
            result.status = DetectionStatus.PARTIALLY_DETECTED
            result.confidence = min(result.confidence, 0.7)
        elif result.status == DetectionStatus.NOT_DETECTED:
            result.status = DetectionStatus.UNKNOWN
        result.ai_correlation_reasoning = " ".join(
            filter(
                None,
                [
                    result.ai_correlation_reasoning,
                    "Execution failed. Any matched alerts describe the attempted activity; "
                    "this run cannot establish detection coverage for successful execution.",
                ],
            )
        )
        return result

    def _assess_coverage(
        self,
        result: DetectionResult,
        technique_result: TechniqueResult,
    ) -> DetectionResult:
        technique = self._technique_registry.get_technique(technique_result.technique_id)
        mode = technique_result.emulation_mode or (
            technique.emulation_mode if technique else EmulationMode.PREREQUISITE
        )

        if not technique_result.success:
            result.coverage_status = CoverageStatus.NOT_ASSESSED
            result.coverage_eligible = False
            result.coverage_reason = (
                "The executor did not meet its success criteria; ATT&CK coverage was not assessed."
            )
            return result

        limitation = technique.validation_notes if technique else ""
        if mode == EmulationMode.PROCEDURE:
            if result.status == DetectionStatus.DETECTED:
                result.coverage_status = CoverageStatus.VALIDATED
            elif result.status == DetectionStatus.PARTIALLY_DETECTED:
                result.coverage_status = CoverageStatus.PARTIAL
            elif result.status == DetectionStatus.NOT_DETECTED:
                result.coverage_status = CoverageStatus.GAP
            else:
                result.coverage_status = CoverageStatus.NOT_ASSESSED
            result.coverage_eligible = result.status != DetectionStatus.UNKNOWN
            result.coverage_reason = (
                "The built-in executor completed an ATT&CK-aligned procedure."
                if result.coverage_eligible
                else "No conclusive SIEM result was available for the completed procedure."
            )
            return result

        result.coverage_eligible = False
        if mode == EmulationMode.TELEMETRY:
            result.coverage_status = CoverageStatus.PARTIAL
            prefix = "The run exercised detection-relevant telemetry only."
        elif mode == EmulationMode.ARTIFACT:
            result.coverage_status = CoverageStatus.NOT_ASSESSED
            prefix = "The run created a representative artifact only."
        else:
            result.coverage_status = CoverageStatus.NOT_ASSESSED
            prefix = "The run checked prerequisites only."
        result.coverage_reason = " ".join(part for part in (prefix, limitation) if part)
        return result

    async def _validate_detection(
        self,
        siem_connector: Any,
        plan_step: AttackPlanStep,
        target: str,
        start_time: datetime,
        end_time: datetime,
        plugin_registry: Any,
        execution_output: str = "",
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
            command=plan_step.parameters.get("command"),
            execution_output=execution_output,
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
        if self._mcp is None:
            raise RuntimeError("Technique cleanup requires an active MCP session")
        for step in plan.steps:
            await self._mcp.cleanup(
                step.technique_id,
                target,
                step.parameters,
                {
                    "target_group": plan.target_group,
                },
            )

    def _generate_remediation(self, steps: list[SimulationStep]) -> list[RemediationEntry]:
        from purplestrike.remediation.engine import RemediationEngine

        engine = RemediationEngine()
        return engine.generate_remediation(steps)

    def request_stop(self) -> None:
        self._stop_requested = True

    def _plugin_config(self) -> dict[str, Any]:
        return {
            "load_attack_executors": False,
            "siem_connectors": {
                self.config.siem.connector: self.config.siem.model_dump(mode="json"),
            },
            "llm_providers": {
                self.config.llm.provider.value: self.config.llm.model_dump(mode="json"),
            },
        }
