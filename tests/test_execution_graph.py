from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from purplestrike.core.execution_graph import ExecutionGraph
from purplestrike.core.orchestrator import Orchestrator
from purplestrike.core.plan import AttackPlan, AttackPlanStep
from purplestrike.mcp.client import MCPToolClient
from purplestrike.mcp.server import create_server
from purplestrike.models.config import PurpleStrikeConfig, TargetGroup, TargetHost
from purplestrike.models.simulation import DetectionResult, DetectionStatus
from purplestrike.models.techniques import TechniqueResult
from purplestrike.plugins.registry import PluginRegistry


class Executor:
    name = "test"
    supported_techniques = ("T1059.001", "T1047", "T1053.005")

    def __init__(self):
        self.calls = []
        self.cleanups = []

    async def execute(self, technique_id, target, parameters):
        self.calls.append((technique_id, target, dict(parameters)))
        return TechniqueResult(
            technique_id=technique_id,
            success=True,
            output="sample telemetry",
            evidence=["test execution only"],
        )

    async def cleanup(self, technique_id, target, parameters):
        self.cleanups.append((technique_id, target, dict(parameters)))


@asynccontextmanager
async def harness(decisions=(), count=2, mode="agent", max_steps=10):
    config = PurpleStrikeConfig(
        target_groups={
            "lab": TargetGroup(
                name="lab",
                hosts=[
                    TargetHost(hostname="lab-host", ip="192.0.2.1", os="windows"),
                ],
            )
        },
        max_steps=max_steps,
        detection_check_delay=0,
    )
    executor = Executor()
    plugins = PluginRegistry()
    plugins.register_attack_executor(executor)
    llm = SimpleNamespace(
        name="openai",
        complete=AsyncMock(
            side_effect=[json.dumps(d) if isinstance(d, dict) else d for d in decisions]
        ),
    )
    if mode == "agent":
        plugins.register_llm_provider(llm)
    client = MCPToolClient(config)
    server = create_server(config, plugins)
    async with create_connected_server_and_client_session(server) as session:
        listed = await session.list_tools()
        client._register("test", {tool.name: tool for tool in listed.tools})
        client.sessions["test"] = session
        orchestrator = Orchestrator(config)
        orchestrator._mcp = client
        orchestrator._technique_registry = client.registry
        orchestrator._validate_detection = AsyncMock(
            return_value=DetectionResult(
                status=DetectionStatus.DETECTED,
                matched_rules=["test-rule"],
                confidence=1,
            )
        )
        plan = AttackPlan(
            target_group="lab",
            steps=[
                AttackPlanStep(order=i, technique_id=tid, parameters={"command": "whoami"})
                for i, tid in enumerate(executor.supported_techniques[:count], 1)
            ],
        )
        # Scheduled task uses different parameters.
        if count == 3:
            plan.steps[2].parameters = {}
        graph = ExecutionGraph(orchestrator, plan, plugins, object(), "lab-host", mode, False)
        yield SimpleNamespace(
            graph=graph,
            executor=executor,
            client=client,
            llm=llm,
            orchestrator=orchestrator,
            session=session,
        )


def decision(action, **kwargs):
    return {"action": action, "reason": "Test feedback decision", **kwargs}


async def test_mcp_graph_retries_with_changed_parameters_and_full_feedback():
    async with harness(
        [
            decision("retry", parameters={"command": "hostname"}),
            decision("continue"),
            decision("continue"),
        ]
    ) as h:
        state = await h.graph.run()
        assert state["status"] == "completed"
        assert [r.attempt for r in state["results"]] == [1, 2, 1]
        assert [c[2]["command"] for c in h.executor.calls] == ["whoami", "hostname", "whoami"]
        assert h.executor.calls == h.executor.cleanups
        feedback = json.loads(h.llm.complete.call_args_list[0].args[0][1]["content"])
        assert feedback["latest_result"]["execution_output"] == "sample telemetry"
        assert feedback["latest_result"]["detection_result"]["matched_rules"] == ["test-rule"]
        assert feedback["environment"]["os"] == "windows"
        assert feedback["latest_result"]["tool_detection_metadata"]["expected_rules"]
        assert len(h.graph.graph.get_graph().nodes) == 7


async def test_switch_reorders_only_pending_approved_steps():
    async with harness(
        [
            decision("switch", next_step=3),
            decision("continue"),
            decision("continue"),
        ],
        count=3,
    ) as h:
        state = await h.graph.run()
        assert [r.plan_step for r in state["results"]] == [1, 3, 2]
        assert state["status"] == "completed"


async def test_continue_with_matching_next_step_runs_remaining_plan():
    async with harness(
        [decision("continue"), decision("continue", next_step=3), decision("continue")],
        count=3,
    ) as h:
        state = await h.graph.run()
        assert state["status"] == "completed"
        assert [r.plan_step for r in state["results"]] == [1, 2, 3]
        assert len(h.executor.calls) == len(h.executor.cleanups) == 3


async def test_continue_after_switch_uses_next_pending_position_not_current_plus_one():
    async with harness(
        [decision("switch", next_step=3), decision("continue", next_step=2), decision("continue")],
        count=3,
    ) as h:
        state = await h.graph.run()
        assert state["status"] == "completed"
        assert [r.plan_step for r in state["results"]] == [1, 3, 2]


@pytest.mark.parametrize("next_step", [1, 3, 99])
async def test_continue_cannot_override_next_pending_step(next_step):
    async with harness([decision("continue", next_step=next_step)], count=3) as h:
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert state["pending"] == [1, 2]
        assert len(h.executor.calls) == 1
        assert "next pending step" in state["reason"]


async def test_final_continue_cannot_name_another_step():
    async with harness([decision("continue", next_step=2)], count=1) as h:
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert len(h.executor.calls) == 1


async def test_continue_allows_empty_parameter_object():
    async with harness(
        [
            decision("continue", next_step=2, parameters={}),
            decision("continue", parameters={}),
        ]
    ) as h:
        state = await h.graph.run()
        assert state["status"] == "completed"
        assert [call[2] for call in h.executor.calls] == [{"command": "whoami"}] * 2


async def test_rejected_decision_is_retained_with_secrets_redacted(caplog):
    response = decision("continue", next_step=99, parameters={"password": "private-value"})
    async with harness([response]) as h:
        h.graph.config.target_password = "private-value"
        state = await h.graph.run()
        audit = state["results"][0].decision
        assert audit["action"] == "pause"
        assert audit["rejected_decision"]["action"] == "continue"
        assert audit["rejected_decision"]["next_step"] == 99
        assert audit["rejected_decision"]["parameters"]["password"] == "[REDACTED]"
        assert "private-value" not in json.dumps(audit)
        assert "private-value" not in caplog.text


@pytest.mark.parametrize(
    "response, status",
    [
        (decision("abort"), "aborted"),
        (decision("pause"), "paused"),
        (decision("switch", next_step=99), "paused"),
        (decision("retry", parameters={"_technique_id": "T1047"}), "paused"),
        (decision("retry", parameters={"command": 123}), "paused"),
        (decision("retry", parameters={}), "paused"),
        (decision("continue", parameters={"command": "hostname"}), "paused"),
        ({**decision("continue"), "target": "other-host"}, "paused"),
        ("not JSON", "paused"),
        (RuntimeError("LLM offline"), "paused"),
    ],
)
async def test_terminal_and_invalid_decisions_never_execute_another_tool(response, status):
    async with harness([response]) as h:
        state = await h.graph.run()
        assert state["status"] == status
        assert len(h.executor.calls) == len(h.executor.cleanups) == 1
        assert state["pending"] == [1]


async def test_retry_limit_is_enforced_independently_of_llm():
    async with harness(
        [
            decision("retry", parameters={"command": "hostname"}),
            decision("retry", parameters={"command": "whoami"}),
        ]
    ) as h:
        h.graph.config.execution.max_retries_per_step = 1
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert "Retry limit" in state["reason"]
        assert len(h.executor.calls) == 2


async def test_total_budget_still_sends_last_result_to_ai():
    async with harness([decision("continue")], max_steps=1) as h:
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert len(h.executor.calls) == h.llm.complete.await_count == 1


async def test_default_mode_uses_mcp_graph_without_llm():
    async with harness(mode="default") as h:
        state = await h.graph.run()
        assert state["status"] == "completed"
        assert len(h.executor.calls) == len(h.executor.cleanups) == 2


async def test_detection_failure_remains_unknown_and_cleanup_runs():
    async with harness([decision("pause")]) as h:
        h.orchestrator._validate_detection.side_effect = OSError("SIEM offline")
        state = await h.graph.run()
        assert state["results"][0].detection_status == DetectionStatus.UNKNOWN
        assert len(h.executor.cleanups) == 1
        assert "SIEM offline" in h.llm.complete.call_args.args[0][1]["content"]


async def test_uncertain_transport_outcome_forces_pause_after_feedback():
    async with harness([decision("continue")]) as h:
        h.client.execute = AsyncMock(side_effect=TimeoutError("MCP timeout"))
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert h.llm.complete.await_count == 1
        assert len(h.executor.calls) == 0


async def test_cleanup_failure_forces_pause_after_feedback():
    async with harness([decision("continue")]) as h:
        h.executor.cleanup = AsyncMock(side_effect=RuntimeError("cleanup denied"))
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert state["results"][0].cleanup_error
        assert len(h.executor.calls) == 1


async def test_missing_llm_pauses_before_execution():
    async with harness() as h:
        h.graph.llm = None
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert not h.executor.calls


async def test_operator_stop_wins_over_ai_continue():
    async with harness([decision("continue")]) as h:

        async def stop(*args, **kwargs):
            h.orchestrator.request_stop()
            return DetectionResult()

        h.orchestrator._validate_detection = stop
        state = await h.graph.run()
        assert state["status"] == "aborted"
        assert len(h.executor.cleanups) == len(h.executor.calls) == 1


async def test_cancellation_during_detection_cleans_current_attempt():
    async with harness() as h:
        started = asyncio.Event()

        async def wait_for_cancel(*args, **kwargs):
            started.set()
            await asyncio.Event().wait()

        h.orchestrator._validate_detection.side_effect = wait_for_cancel
        task = asyncio.create_task(h.graph.run())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(h.executor.cleanups) == 1


async def test_mcp_boundary_rejects_wrong_target_and_reserved_parameters():
    async with harness() as h:
        tool = h.client.tools["T1059.001"]
        for arguments in [
            {"target": "other-host", "parameters": {}, "environment": {}},
            {"target": "lab-host", "parameters": {"_run_id": "fake"}, "environment": {}},
        ]:
            response = await h.session.call_tool(tool.tool.name, arguments)
            assert response.isError
        assert not h.executor.calls


async def test_secrets_are_redacted_from_ai_feedback():
    async with harness([decision("pause")]) as h:
        h.graph.config.target_password = "secret-example"
        original = h.executor.execute

        async def with_secret(*args):
            result = await original(*args)
            result.output = "output contains secret-example"
            return result

        h.executor.execute = with_secret
        await h.graph.run()
        prompt = h.llm.complete.call_args.args[0][1]["content"]
        assert "secret-example" not in prompt
        assert "[REDACTED]" in prompt


async def test_orchestrator_agent_run_saves_pause_and_decision_audit(monkeypatch, tmp_path):
    from purplestrike.plugins.report_formatters.csv import CsvFormatter
    from purplestrike.plugins.report_formatters.json import JsonFormatter

    async with harness([decision("pause")]) as h:
        orchestrator = h.orchestrator
        orchestrator.config.output_dir = str(tmp_path)
        orchestrator.generate_plan = AsyncMock(return_value=h.graph.plan)
        orchestrator.display_plan = lambda plan: True
        plugins = h.graph.plugins
        plugins.register_report_formatter(JsonFormatter())
        plugins.register_report_formatter(CsvFormatter())
        monkeypatch.setattr("purplestrike.plugins.registry.plugin_registry", plugins)
        monkeypatch.setattr("purplestrike.plugins.loader.PluginLoader.load_all", AsyncMock())
        report = await orchestrator.execute(mode="agent", target_group_name="lab")
        assert report.status == "paused"
        assert report.metadata["pending_steps"] == [2]
        assert report.results[0].decision["action"] == "pause"
        assert len(h.executor.calls) == len(h.executor.cleanups) == 1
        saved = json.loads((tmp_path / f"{report.simulation_id}.json").read_text())
        assert saved["results"][0]["tool_name"] == "test/run_powershell"
        csv_text = (tmp_path / f"{report.simulation_id}_results.csv").read_text()
        assert "decision" in csv_text and "run_powershell" in csv_text


async def test_dry_run_never_calls_technique_tools():
    async with harness() as h:
        h.orchestrator.generate_plan = AsyncMock(return_value=h.graph.plan)
        h.orchestrator.display_plan = lambda plan: True
        assert await h.orchestrator.execute(target_group_name="lab", dry_run=True) is None
        assert not h.executor.calls


async def test_decision_timeout_pauses_after_cleanup():
    async with harness() as h:

        async def no_response(*args, **kwargs):
            await asyncio.Event().wait()

        h.llm.complete.side_effect = no_response
        h.graph.config.execution.decision_timeout_seconds = 0.01
        state = await h.graph.run()
        assert state["status"] == "paused"
        assert len(h.executor.cleanups) == 1


async def test_skip_cleanup_is_explicit_feedback():
    async with harness([decision("pause")]) as h:
        h.graph.skip_cleanup = True
        state = await h.graph.run()
        assert state["environment"]["cleanup"] == "skipped"
        assert not h.executor.cleanups
