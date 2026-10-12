from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from jsonschema import Draft202012Validator, validate
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from purplestrike.mcp.contracts import META_KEY, ToolInput, ToolOutput
from purplestrike.models.config import MCPServerConfig, PurpleStrikeConfig
from purplestrike.models.techniques import ExecutionStatus, Technique
from purplestrike.observability import AuditLogger
from purplestrike.techniques.registry import TechniqueRegistry

logger = logging.getLogger(__name__)


@dataclass
class TechniqueTool:
    server: str
    tool: types.Tool
    technique: Technique
    cleanup_tool: str

    @property
    def name(self) -> str:
        return f"{self.server}/{self.tool.name}"


class MCPToolClient:
    """Keep MCP sessions alive for the full run, including cleanup and retries."""

    def __init__(self, config: PurpleStrikeConfig) -> None:
        self.config = config
        self.sessions: dict[str, ClientSession] = {}
        self.tools: dict[str, TechniqueTool] = {}
        self.registry = TechniqueRegistry(autoload=False)
        self._stack = AsyncExitStack()
        self.audit = AuditLogger(logger, config)

    def _servers(self) -> dict[str, MCPServerConfig]:
        if self.config.mcp.servers:
            return self.config.mcp.servers
        executor_config = self.config.model_dump(
            mode="json",
            include={
                "target_groups",
                "target_ad_domain",
                "target_username",
                "target_password",
                "connection",
            },
        )
        return {
            "builtin": MCPServerConfig(
                command=sys.executable,
                args=["-m", "purplestrike.mcp.server"],
                env={"PURPLESTRIKE_MCP_CONFIG": json.dumps(executor_config)},
            )
        }

    async def __aenter__(self) -> MCPToolClient:
        try:
            for name, config in self._servers().items():
                endpoint = urlsplit(config.url)
                self.audit.event(
                    "mcp.server.connect",
                    server=name,
                    transport=config.transport,
                    command=config.command,
                    endpoint_host=endpoint.hostname,
                    endpoint_path=endpoint.path,
                )
                if config.transport == "stdio":
                    if not config.command:
                        raise ValueError(f"MCP server {name} needs a command")
                    read, write = await self._stack.enter_async_context(
                        stdio_client(
                            StdioServerParameters(
                                command=config.command,
                                args=config.args,
                                env=config.env,
                            )
                        )
                    )
                else:
                    if not config.url:
                        raise ValueError(f"MCP server {name} needs a URL")
                    read, write, _ = await self._stack.enter_async_context(
                        streamablehttp_client(
                            config.url,
                            headers=config.headers,
                            timeout=timedelta(seconds=self.config.mcp.timeout_seconds),
                        )
                    )
                session = await self._stack.enter_async_context(
                    ClientSession(
                        read,
                        write,
                        read_timeout_seconds=timedelta(seconds=self.config.mcp.timeout_seconds),
                    )
                )
                self.sessions[name] = session
                await session.initialize()
                self.audit.event("mcp.server.initialized", server=name)
                discovered: dict[str, types.Tool] = {}
                cursor = None
                seen_cursors = set()
                while True:
                    page = await session.list_tools(cursor=cursor)
                    self.audit.event(
                        "mcp.tools.list",
                        server=name,
                        cursor=cursor,
                        tool_names=[tool.name for tool in page.tools],
                        next_cursor=page.nextCursor,
                    )
                    for tool in page.tools:
                        if tool.name in discovered:
                            raise ValueError(f"Duplicate MCP tool: {name}/{tool.name}")
                        discovered[tool.name] = tool
                    cursor = page.nextCursor
                    if not cursor:
                        break
                    if cursor in seen_cursors:
                        raise ValueError(f"Repeated tools/list cursor from {name}")
                    seen_cursors.add(cursor)
                self._register(name, discovered)
                self.audit.event(
                    "mcp.tools.ready",
                    server=name,
                    techniques=[
                        {
                            "technique_id": tid,
                            "tool": binding.name,
                            "cleanup_tool": binding.cleanup_tool,
                        }
                        for tid, binding in self.tools.items()
                        if binding.server == name
                    ],
                )
            return self
        except BaseException as exc:
            self.audit.event(
                "mcp.server.error",
                level=logging.ERROR,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            await self._stack.aclose()
            raise

    async def __aexit__(self, *exc: Any) -> None:
        try:
            await self._stack.aclose()
        finally:
            self.audit.event("mcp.sessions.closed", servers=list(self.sessions))

    async def _call_tool(
        self,
        binding: TechniqueTool,
        name: str,
        arguments: dict[str, Any],
    ) -> types.CallToolResult:
        call_id = uuid4().hex
        details: dict[str, Any] = {
            "call_id": call_id,
            "server": binding.server,
            "tool": f"{binding.server}/{name}",
            "technique_id": binding.technique.technique_id,
        }
        self.audit.event("mcp.tool.call", **details, arguments=arguments)
        started = time.monotonic()
        try:
            response = await self.sessions[binding.server].call_tool(name, arguments)
        except BaseException as exc:
            self.audit.event(
                "mcp.tool.error",
                level=logging.ERROR,
                **details,
                duration_seconds=round(time.monotonic() - started, 3),
                error_type=type(exc).__name__,
                error=str(exc),
            )
            raise
        self.audit.event(
            "mcp.tool.result",
            **details,
            duration_seconds=round(time.monotonic() - started, 3),
            result=response.model_dump(mode="json", by_alias=True, exclude_none=True),
        )
        return response

    def _register(self, server: str, discovered: dict[str, types.Tool]) -> None:
        for tool in discovered.values():
            meta = (tool.meta or {}).get(META_KEY)
            if not meta:
                continue  # Non-technique tools are never exposed to the planner.
            technique = Technique.model_validate(meta["technique"])
            if not technique.safe_to_execute:
                continue
            if technique.technique_id in self.tools:
                raise ValueError(f"Ambiguous MCP mapping for {technique.technique_id}")
            cleanup = meta.get("cleanup_tool", "")
            if cleanup not in discovered:
                raise ValueError(f"Missing cleanup tool for {server}/{tool.name}")
            if not tool.outputSchema:
                raise ValueError(f"Missing output schema for {server}/{tool.name}")
            Draft202012Validator.check_schema(tool.inputSchema)
            Draft202012Validator.check_schema(tool.outputSchema)
            self.tools[technique.technique_id] = TechniqueTool(server, tool, technique, cleanup)
            self.registry.register(technique)

    def validate_call(self, technique_id: str, arguments: dict[str, Any]) -> None:
        binding = self.tools[technique_id]
        request = ToolInput.model_validate(arguments)
        hosts = {
            address: host
            for group in self.config.target_groups.values()
            for host in group.hosts
            for address in (host.hostname, host.ip)
        }
        host = hosts.get(request.target)
        if host is None or host.os not in binding.technique.target_os:
            raise ValueError("Unconfigured or incompatible target")
        validate(arguments, binding.tool.inputSchema)

    async def execute(
        self,
        technique_id: str,
        target: str,
        parameters: dict[str, Any],
        environment: dict[str, Any],
    ) -> ToolOutput:
        arguments = {"target": target, "parameters": parameters, "environment": environment}
        try:
            self.validate_call(technique_id, arguments)
        except Exception as exc:
            self.audit.event(
                "mcp.tool.rejected",
                level=logging.ERROR,
                technique_id=technique_id,
                arguments=arguments,
                error=str(exc),
            )
            raise
        binding = self.tools[technique_id]
        response = await self._call_tool(binding, binding.tool.name, arguments)
        if response.isError:
            message = "\n".join(
                c.text for c in response.content if isinstance(c, types.TextContent)
            )
            return ToolOutput(
                technique_id=technique_id,
                success=False,
                error=message,
                execution_status=ExecutionStatus.FAILURE,
            )
        if response.structuredContent is None:
            raise ValueError(f"{binding.name} returned no structured result")
        if binding.tool.outputSchema is None:
            raise ValueError(f"{binding.name} has no output schema")
        validate(response.structuredContent, binding.tool.outputSchema)
        result = ToolOutput.model_validate(response.structuredContent)
        if result.technique_id != technique_id:
            raise ValueError(f"{binding.name} returned a different technique ID")
        result.emulation_mode = result.emulation_mode or binding.technique.emulation_mode
        if not result.success and result.execution_status == ExecutionStatus.SUCCESS:
            result.execution_status = ExecutionStatus.FAILURE
        return result

    async def cleanup(
        self,
        technique_id: str,
        target: str,
        parameters: dict[str, Any],
        environment: dict[str, Any],
    ) -> None:
        binding = self.tools[technique_id]
        response = await self._call_tool(
            binding,
            binding.cleanup_tool,
            {
                "target": target,
                "parameters": parameters,
                "environment": environment,
            },
        )
        body = response.structuredContent or {}
        if response.isError or body.get("success") is not True:
            detail = body.get("error") or "\n".join(
                c.text for c in response.content if isinstance(c, types.TextContent)
            )
            raise RuntimeError(f"MCP cleanup failed: {binding.name}: {detail}")
