from __future__ import annotations

import json
import logging
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

from purplestrike.logging_config import configure_logging
from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.observability import AuditLogger, log_context
from tests.test_execution_graph import decision, harness
from tests.test_logging_config import isolated_logging


async def test_full_execution_trace_reaches_console_and_file(tmp_path, capsys):
    with isolated_logging():
        path = configure_logging(tmp_path)
        async with harness([decision("continue", next_step=2), decision("pause")]) as h:
            h.orchestrator._simulation = SimpleNamespace(id="sim_logging")
            state = await h.graph.run()
        assert state["status"] == "paused"
        console = capsys.readouterr().err
        file_text = path.read_text(encoding="utf-8")
        for output in (console, file_text):
            for event in (
                "execution.graph.started",
                "execution.step.started",
                "mcp.tool.call",
                "mcp.tool.result",
                "execution.step.result",
                "detection.check.started",
                "detection.check.result",
                "execution.cleanup.completed",
                "ai.decision.request",
                "ai.decision.response",
                "ai.decision.applied",
                "execution.graph.finished",
            ):
                assert event in output
            for value in (
                '"simulation_id": "sim_logging"',
                '"plan_step": 1',
                '"attempt": 1',
                '"tool": "test/run_powershell"',
                '"command": "whoami"',
                "sample telemetry",
                "test/run_powershell_cleanup",
                "test-rule",
                '"action": "continue"',
                '"next_plan_step": 2',
                "Test feedback decision",
            ):
                assert value in output
            call_ids = re.findall(r'"call_id": "([a-f0-9]+)"', output)
            assert len(set(call_ids)) == 4  # Two attempts and their cleanup calls.
            assert all(call_ids.count(call_id) == 2 for call_id in set(call_ids))
        assert "ai.decision.prompt" in file_text
        assert "ai.decision.prompt" not in console


async def test_logs_keep_full_results_and_redact_echoes_and_model_secrets(tmp_path, capsys):
    with isolated_logging():
        path = configure_logging(tmp_path)
        response = decision("continue", next_step=99, parameters={"password": "model-private"})
        async with harness([response]) as h:
            h.graph.config.target_password = "configured-private"
            original = h.executor.execute

            async def output_with_secret(*args):
                result = await original(*args)
                result.output = "configured-private " + "x" * 9000 + " OUTPUT_END"
                return result

            h.executor.execute = output_with_secret
            await h.graph.run()
        console = capsys.readouterr()
        for output in (console.err, path.read_text(encoding="utf-8")):
            assert "OUTPUT_END" in output
            assert "configured-private" not in output
            assert "model-private" not in output
            assert "[REDACTED]" in output
            assert "ai.decision.response" in output
            assert "rejected_decision" in output
        assert "configured-private" not in console.out


async def test_malformed_ai_reply_and_transport_failure_are_logged(tmp_path, capsys):
    with isolated_logging():
        path = configure_logging(tmp_path)
        async with harness(["this is not JSON"]) as h:
            await h.graph.run()
        async with harness([decision("pause")]) as h:
            h.client.sessions["test"] = SimpleNamespace(
                call_tool=AsyncMock(side_effect=TimeoutError("test MCP timeout")),
            )
            await h.graph.run()
        for output in (capsys.readouterr().err, path.read_text(encoding="utf-8")):
            assert "this is not JSON" in output
            assert "ai.decision.response" in output
            assert "mcp.tool.error" in output
            assert '"error_type": "TimeoutError"' in output
            assert "test MCP timeout" in output
            assert "execution.cleanup.failed" in output


def test_redaction_remembers_sensitive_arguments_for_echoes_and_tracebacks(tmp_path, capsys):
    config = PurpleStrikeConfig(target_password="config-secret")
    logger = logging.getLogger("purplestrike.test")
    audit = AuditLogger(logger, config)
    arguments = {"password_list": ["generated-secret"], "command": "whoami"}
    with isolated_logging():
        path = configure_logging(tmp_path)
        with log_context(redactor=audit.redactor, simulation_id="redaction-test"):
            audit.event("test.arguments", arguments=arguments)
            audit.event("test.result", output="generated-secret config-secret")
            try:
                raise ValueError("generated-secret config-secret")
            except ValueError:
                logger.exception("legacy exception")
        for output in (capsys.readouterr().err, path.read_text(encoding="utf-8")):
            assert "generated-secret" not in output
            assert "config-secret" not in output
            assert "legacy exception" in output
            assert "whoami" in output
    assert json.dumps(arguments) == '{"password_list": ["generated-secret"], "command": "whoami"}'
