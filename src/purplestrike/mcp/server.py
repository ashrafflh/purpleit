"""Expose existing executor plugins as schema-validated MCP technique tools."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from jsonschema import validate
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from purplestrike.mcp.contracts import META_KEY, ToolInput, ToolOutput, input_schema, tool_name
from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.models.techniques import ExecutionStatus
from purplestrike.techniques.registry import technique_registry


def create_server(config: PurpleStrikeConfig, plugins: Any) -> Server:
    server = Server("purplestrike-techniques")
    techniques = {
        tool_name(t): t
        for t in technique_registry.list_techniques()
        if t.safe_to_execute and plugins.find_executor_for_technique(t.technique_id)
    }
    hosts = {
        address: host
        for group in config.target_groups.values()
        for host in group.hosts
        for address in (host.hostname, host.ip)
    }

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        tools = []
        for name, technique in techniques.items():
            description = (
                f"{technique.name}: {technique.description}\n"
                f"Safe execution: authorized configured hosts only; "
                f"{technique.emulation_mode.value} emulation. "
                f"{technique.validation_notes} Cleanup removes this session's owned artifacts."
            )
            tools.append(
                types.Tool(
                    name=name,
                    description=description,
                    inputSchema=input_schema(technique),
                    outputSchema=ToolOutput.model_json_schema(),
                    _meta={
                        META_KEY: {
                            "technique": technique.model_dump(mode="json"),
                            "cleanup_tool": name + "_cleanup",
                        }
                    },
                )
            )
            tools.append(
                types.Tool(
                    name=name + "_cleanup",
                    description=f"Clean up owned resources from {name} in this server session.",
                    inputSchema=input_schema(technique),
                    outputSchema=ToolOutput.model_json_schema(),
                )
            )
        return tools

    @server.call_tool()  # type: ignore[untyped-decorator]
    async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        cleanup = name.endswith("_cleanup")
        technique = techniques.get(name.removesuffix("_cleanup") if cleanup else name)
        if technique is None:
            raise ValueError(f"Unknown technique tool: {name}")
        validate(arguments, input_schema(technique))
        request = ToolInput.model_validate(arguments)
        host = hosts.get(request.target)
        if host is None or host.os not in technique.target_os:
            raise ValueError("Target is not configured or its OS is incompatible with this tool")
        executor = plugins.find_executor_for_technique(technique.technique_id)
        try:
            if cleanup:
                await executor.cleanup(technique.technique_id, request.target, request.parameters)
                result = ToolOutput(technique_id=technique.technique_id, success=True)
            else:
                executed = await executor.execute(
                    technique.technique_id,
                    request.target,
                    request.parameters,
                )
                result = ToolOutput.model_validate(executed.model_dump())
                result.emulation_mode = result.emulation_mode or technique.emulation_mode
                if not result.success and result.execution_status == ExecutionStatus.SUCCESS:
                    result.execution_status = ExecutionStatus.FAILURE
                result.detection_metadata = {
                    "expected_rules": [m.rule_id for m in technique.detection_mappings],
                    "required_log_sources": technique.required_log_sources,
                }
        except Exception as exc:
            result = ToolOutput(
                technique_id=technique.technique_id,
                success=False,
                execution_status=ExecutionStatus.FAILURE,
                error=str(exc),
            )
        return result.model_dump(mode="json")

    return server


async def serve() -> None:
    from purplestrike.plugins.loader import PluginLoader
    from purplestrike.plugins.registry import PluginRegistry
    from purplestrike.techniques.connection import (
        set_connection_settings,
        set_target_credentials,
        set_target_platforms,
    )

    # The parent passes only executor configuration, never its LLM/SIEM secrets.
    config_json = os.environ.get("PURPLESTRIKE_MCP_CONFIG")
    config = (
        PurpleStrikeConfig.model_validate(json.loads(config_json))
        if config_json
        else PurpleStrikeConfig.from_env()
    )
    set_target_credentials(
        domain=config.target_ad_domain,
        username=config.target_username,
        password=config.target_password,
    )
    hosts = [host for group in config.target_groups.values() for host in group.hosts]
    set_connection_settings(
        config.connection,
        {
            address: host.connection_method
            for host in hosts
            for address in (host.hostname, host.ip)
            if host.connection_method is not None
        },
    )
    set_target_platforms(
        {address: str(host.os) for host in hosts for address in (host.hostname, host.ip)}
    )
    plugins = PluginRegistry()
    await PluginLoader(plugins)._load_builtin_executors({})
    server = create_server(config, plugins)
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        for name in plugins.list_attack_executors():
            executor = plugins.get_attack_executor(name)
            if executor:
                await executor.teardown()


def main() -> None:
    logging.basicConfig(level=logging.WARNING)  # stderr; stdout belongs to MCP.
    asyncio.run(serve())


if __name__ == "__main__":
    main()
