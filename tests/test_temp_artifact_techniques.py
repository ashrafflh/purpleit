from __future__ import annotations

from typing import Any

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.execution import malicious_file, malicious_link, visual_basic
from purplestrike.techniques.initial_access import phishing_attachment, phishing_link


class FakeConnection:
    def __init__(self) -> None:
        self.scripts: list[str] = []

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        self.scripts.append(script)
        if "Test-Path -LiteralPath" in script:
            return CommandResult(stdout="True\n", stderr="", exit_code=0)
        if "Get-Content -LiteralPath" in script:
            return CommandResult(
                stdout="VBScript executed successfully\n",
                stderr="",
                exit_code=0,
            )
        return CommandResult(stdout="ok\n", stderr="", exit_code=0)

    async def disconnect(self) -> None:
        return None


async def _run_with_fake_connection(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> tuple[FakeConnection, Any]:
    fake = FakeConnection()

    async def fake_get_connection(target: str) -> FakeConnection:
        return fake

    monkeypatch.setattr(module, "get_connection", fake_get_connection)
    result = await module.execute("10.10.1.108", {})
    await module.cleanup("10.10.1.108")
    return fake, result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("module", "technique_id"),
    [
        (phishing_link, "T1566.002"),
        (phishing_attachment, "T1566.001"),
        (malicious_link, "T1204.001"),
        (malicious_file, "T1204.002"),
        (visual_basic, "T1059.005"),
    ],
)
async def test_temp_artifact_techniques_use_stable_powershell(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    technique_id: str,
) -> None:
    fake, result = await _run_with_fake_connection(monkeypatch, module)

    assert result.technique_id == technique_id
    assert result.success

    scripts = "\n".join(fake.scripts)
    assert "Join-Path $env:TEMP" in scripts
    assert "-LiteralPath" in scripts
    assert "@'" not in scripts
    assert "'@" not in scripts
    assert '@"' not in scripts
    assert '"@' not in scripts
