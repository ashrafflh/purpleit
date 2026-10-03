from __future__ import annotations

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.persistence import accessibility_features, file_association
from purplestrike.techniques.privilege_escalation import bypass_uac
from purplestrike.techniques.shared import v19_controls


class MarkerConnection:
    is_windows = True
    os_type = "windows"

    def __init__(self) -> None:
        self.scripts: list[str] = []

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        self.scripts.append(script)
        if "$launchers = @(" in script:
            return CommandResult("High Mandatory Level S-1-16-12288", "", 0)
        return CommandResult("PurpleStrike marker", "", 0)

    async def disconnect(self) -> None:
        return None


async def _patch_connection(
    monkeypatch: pytest.MonkeyPatch,
    module: object,
) -> MarkerConnection:
    connection = MarkerConnection()

    async def fake_get_connection(target: str) -> MarkerConnection:
        return connection

    monkeypatch.setattr(module, "get_connection", fake_get_connection)
    return connection


@pytest.mark.asyncio
async def test_file_association_uses_native_shell_execute_and_vbs_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = await _patch_connection(monkeypatch, file_association)

    result = await file_association.execute("association-host", {})
    await file_association.cleanup("association-host")

    assert result.success
    setup = connection.scripts[0]
    assert "ShellExecute" in setup
    assert "SHChangeNotify" in setup
    assert "purplestrike_assoc_handler.vbs" in setup
    assert ".SetValue('', $payload" in setup
    assert "-lt 60" in setup


@pytest.mark.asyncio
async def test_accessibility_ifeo_uses_verified_vbs_debugger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = await _patch_connection(monkeypatch, accessibility_features)

    result = await accessibility_features.execute("accessibility-host", {})
    await accessibility_features.cleanup("accessibility-host")

    assert result.success
    setup, trigger = connection.scripts[:2]
    assert "purplestrike_sethc_handler.vbs" in setup
    assert "$actual -ne $debugger" in setup
    assert "-PassThru" in trigger
    assert "-lt 60" in trigger


@pytest.mark.asyncio
async def test_fodhelper_sets_real_default_value_and_runs_vbs_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = await _patch_connection(monkeypatch, bypass_uac)

    result = await bypass_uac.execute("uac-host", {"method": "fodhelper"})
    await bypass_uac.cleanup("uac-host")

    assert result.success
    setup, trigger = connection.scripts[:2]
    assert "purplestrike_uac_handler.vbs" in setup
    assert ".SetValue('', $payload" in setup
    assert "-Name '(Default)'" not in setup
    assert "fodhelper.exe" in trigger
    assert "computerdefaults.exe" in trigger
    assert "-lt 30" in trigger


@pytest.mark.asyncio
async def test_t1690_uses_supported_psreadline_history_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = await _patch_connection(monkeypatch, v19_controls)

    result = await v19_controls.execute(
        "history-host",
        {"_technique_id": "T1690"},
    )

    assert result.success
    script = connection.scripts[0]
    assert "$MaximumHistoryCount" not in script
    assert "Set-PSReadLineOption -HistorySaveStyle SaveNothing" in script
    assert "Get-PSReadLineOption" in script
