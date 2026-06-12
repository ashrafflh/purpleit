from __future__ import annotations

from typing import Any

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.execution import powershell


class FakeConnection:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.disconnected = False

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        self.scripts.append(script)
        return CommandResult(stdout="purple\\seif.hassine", stderr="", exit_code=0)

    async def disconnect(self) -> None:
        self.disconnected = True


@pytest.mark.asyncio
async def test_powershell_uses_default_command_when_plan_has_no_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_conn = FakeConnection()

    async def fake_get_connection(target: str) -> FakeConnection:
        assert target == "10.10.1.108"
        return fake_conn

    monkeypatch.setattr(powershell, "get_connection", fake_get_connection)

    result = await powershell.execute("10.10.1.108", {})

    assert result.success is True
    assert result.output == "purple\\seif.hassine"
    assert fake_conn.scripts == [powershell.DEFAULT_COMMAND]
    assert fake_conn.disconnected is True


@pytest.mark.asyncio
async def test_powershell_preserves_supplied_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_conn = FakeConnection()

    async def fake_get_connection(target: str) -> FakeConnection:
        return fake_conn

    monkeypatch.setattr(powershell, "get_connection", fake_get_connection)

    await powershell.execute("10.10.1.108", {"command": "hostname"})

    assert fake_conn.scripts == ["hostname"]
