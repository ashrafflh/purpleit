from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from jsonschema import ValidationError
from mcp import types

from purplestrike.mcp.client import MCPToolClient
from purplestrike.mcp.contracts import ToolOutput
from purplestrike.models.config import PurpleStrikeConfig
from tests.test_execution_graph import harness


async def test_builtin_stdio_server_discovers_without_executing():
    async with MCPToolClient(PurpleStrikeConfig()) as client:
        assert client.tools["T1059.001"].tool.name == "run_powershell"
        assert client.tools["T1053.005"].tool.name == "execute_scheduled_task"
        assert client.tools["T1078.001"].tool.name == "probe_default_accounts"
        assert all(t.tool.outputSchema for t in client.tools.values())


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"success": True},
        {"technique_id": "T1047", "success": True},
        {"technique_id": "T1059.001", "success": "true"},
    ],
)
async def test_invalid_mcp_result_is_rejected(body):
    async with harness() as h:
        h.client.sessions["test"] = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=types.CallToolResult(
                    content=[],
                    structuredContent=body,
                )
            )
        )
        with pytest.raises((ValueError, ValidationError)):
            await h.client.execute("T1059.001", "lab-host", {}, {})


async def test_mcp_is_error_becomes_failure_feedback():
    async with harness() as h:
        h.client.sessions["test"] = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=types.CallToolResult(
                    content=[types.TextContent(type="text", text="parameter rejected")],
                    isError=True,
                )
            )
        )
        result = await h.client.execute("T1059.001", "lab-host", {}, {})
        assert not result.success
        assert result.execution_status == "failure"
        assert result.error == "parameter rejected"


async def test_duplicate_technique_mapping_and_missing_cleanup_fail_closed():
    async with harness() as h:
        listed = await h.session.list_tools()
        tools = {t.name: t for t in listed.tools}
        with pytest.raises(ValueError, match="Ambiguous"):
            h.client._register("duplicate", tools)
        fresh = MCPToolClient(h.client.config)
        tools.pop("run_powershell_cleanup")
        with pytest.raises(ValueError, match="Missing cleanup"):
            fresh._register("incomplete", tools)


async def test_missing_mcp_session_never_falls_back_to_local_executor():
    from purplestrike.core.orchestrator import Orchestrator
    from purplestrike.core.plan import AttackPlanStep

    local = AsyncMock()
    with pytest.raises(RuntimeError, match="active MCP session"):
        await Orchestrator(PurpleStrikeConfig())._execute_step(
            AttackPlanStep(order=1, technique_id="T1059.001"),
            local,
            "lab-host",
        )
    local.find_executor_for_technique.assert_not_called()


async def test_failed_result_preserves_timeout_status():
    async with harness() as h:
        body = ToolOutput(technique_id="T1059.001", success=False, execution_status="timeout")
        h.client.sessions["test"] = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=types.CallToolResult(
                    content=[],
                    structuredContent=body.model_dump(mode="json"),
                )
            )
        )
        result = await h.client.execute("T1059.001", "lab-host", {}, {})
        assert result.execution_status == "timeout"


async def test_cleanup_requires_boolean_success_and_preserves_error():
    async with harness() as h:
        h.client.sessions["test"] = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=types.CallToolResult(
                    content=[],
                    structuredContent={"success": "false", "error": "access denied"},
                ),
            )
        )
        with pytest.raises(RuntimeError, match="access denied"):
            await h.client.cleanup("T1059.001", "lab-host", {}, {})


@pytest.mark.parametrize("repeat_cursor", [False, True])
async def test_discovery_pagination_and_session_cleanup(monkeypatch, repeat_cursor):
    import purplestrike.mcp.client as module

    async with harness() as h:
        tools = (await h.session.list_tools()).tools[:2]
        closed = []

        @asynccontextmanager
        async def transport(*args, **kwargs):
            try:
                yield (None, None)
            finally:
                closed.append("transport")

        class Session:
            def __init__(self, *args, **kwargs):
                self.cursors = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                closed.append("session")

            async def initialize(self):
                pass

            async def list_tools(self, cursor=None):
                self.cursors.append(cursor)
                return types.ListToolsResult(
                    tools=[tools[0 if cursor is None else 1]],
                    nextCursor="page-2" if cursor is None or repeat_cursor else None,
                )

        monkeypatch.setattr(module, "stdio_client", transport)
        monkeypatch.setattr(module, "ClientSession", Session)
        client = MCPToolClient(h.client.config)
        if repeat_cursor:
            with pytest.raises(ValueError, match="Repeated"):
                await client.__aenter__()
        else:
            async with client:
                assert len(client.tools) == 1
                assert client.sessions["builtin"].cursors == [None, "page-2"]
        assert closed == ["session", "transport"]
