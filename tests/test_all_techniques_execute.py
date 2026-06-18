from __future__ import annotations

import asyncio
import importlib
import inspect
from typing import Any

import pytest

from purplestrike.core.orchestrator import Orchestrator
from purplestrike.models.config import (
    AssetType,
    OSType,
    PurpleStrikeConfig,
    TargetGroup,
    TargetHost,
)
from purplestrike.models.techniques import Technique
from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.registry import technique_registry


class FakeConnection:
    is_windows = True
    os_type = "windows"

    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.commands: list[str] = []

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        self.scripts.append(script)
        if "Test-Path" in script:
            return CommandResult(stdout="True\n", stderr="", exit_code=0)
        if "Get-Content" in script:
            return CommandResult(stdout="PurpleStrike output\n", stderr="", exit_code=0)
        if "Get-Process" in script:
            return CommandResult(stdout="explorer\nlsass\n", stderr="", exit_code=0)
        if "Get-Service" in script:
            return CommandResult(stdout="Name : PurpleStrikeSvc\nStatus : Stopped\n", stderr="", exit_code=0)
        if "Get-ScheduledTask" in script:
            return CommandResult(stdout="PurpleStrikeTask\n", stderr="", exit_code=0)
        if "Get-WmiObject" in script:
            return CommandResult(stdout="", stderr="", exit_code=0)
        return CommandResult(stdout="ok\n", stderr="", exit_code=0)

    async def run_command(
        self,
        command: str,
        timeout: int = 60,
        cwd: str | None = None,
    ) -> CommandResult:
        self.commands.append(command)
        return CommandResult(stdout="ok\n", stderr="", exit_code=0)

    async def disconnect(self) -> None:
        return None


class FailingConnection:
    is_windows = True
    os_type = "windows"

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        return CommandResult(
            stdout="",
            stderr="HTTPConnectionPool: ConnectTimeoutError: Max retries exceeded",
            exit_code=1,
        )

    async def run_command(
        self,
        command: str,
        timeout: int = 60,
        cwd: str | None = None,
    ) -> CommandResult:
        return CommandResult(
            stdout="",
            stderr="HTTPConnectionPool: ConnectTimeoutError: Max retries exceeded",
            exit_code=1,
        )

    async def disconnect(self) -> None:
        return None


def _config() -> PurpleStrikeConfig:
    return PurpleStrikeConfig(
        target_username="seif.hassine",
        target_ad_domain="purple.local",
        target_groups={
            "purple.local": TargetGroup(
                name="purple.local",
                domain="purple.local",
                hosts=[
                    TargetHost(
                        hostname="10.10.1.108",
                        ip="10.10.1.108",
                        os=OSType.WINDOWS,
                        asset_type=AssetType.DOMAIN_CONTROLLER,
                        domain="purple.local",
                    ),
                ],
            )
        },
    )


def _module_for(technique: Technique) -> Any:
    return importlib.import_module(f"purplestrike.techniques.{technique.module}")


@pytest.mark.asyncio
async def test_all_registered_techniques_execute_with_default_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fast_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    orchestrator = Orchestrator(config=_config())
    failures: list[str] = []

    for technique in technique_registry.list_techniques():
        module = _module_for(technique)
        fake = FakeConnection()

        async def fake_get_connection(target: str, fake: FakeConnection = fake) -> FakeConnection:
            return fake

        if hasattr(module, "get_connection"):
            monkeypatch.setattr(module, "get_connection", fake_get_connection)

        parameters = orchestrator._default_parameters_for_technique(
            technique,
            "purple.local",
        )
        result = await module.execute("10.10.1.108", parameters)
        if not result.success:
            failures.append(f"{technique.technique_id}: {result.error}")

        if hasattr(module, "cleanup"):
            cleanup_params = inspect.signature(module.cleanup).parameters
            if "parameters" in cleanup_params:
                await module.cleanup("10.10.1.108", parameters)
            else:
                await module.cleanup("10.10.1.108")

    assert failures == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "technique_id",
    [
        "T1003.001",
        "T1003.002",
        "T1055.001",
        "T1068",
        "T1110.001",
        "T1110.003",
        "T1134.001",
        "T1134.002",
        "T1484.001",
        "T1543.003",
        "T1548.002",
    ],
)
async def test_techniques_fail_on_transport_command_errors(
    monkeypatch: pytest.MonkeyPatch,
    technique_id: str,
) -> None:
    async def fast_sleep(seconds: float) -> None:
        return None

    async def fake_get_connection(target: str) -> FailingConnection:
        return FailingConnection()

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    technique = technique_registry.get_technique(technique_id)
    assert technique is not None
    module = _module_for(technique)
    monkeypatch.setattr(module, "get_connection", fake_get_connection)

    parameters = Orchestrator(config=_config())._default_parameters_for_technique(
        technique,
        "purple.local",
    )
    result = await module.execute("10.10.1.108", parameters)

    assert not result.success
    assert result.execution_status == "failure"
    assert result.error
