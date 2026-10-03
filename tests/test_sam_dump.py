from __future__ import annotations

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.credential_access import sam_dump

pytestmark = pytest.mark.asyncio


class FakeConnection:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.disconnected = False

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        self.scripts.append(script)
        if "reg.exe save HKLM\\SAM" in script:
            return CommandResult("SAM hive saved (4096 bytes) and removed", "", 0)
        if "HKLM\\SAM\\SAM" in script:
            return CommandResult("HKEY_LOCAL_MACHINE\\SAM\\SAM", "", 0)
        if "HKLM\\SAM" in script:
            return CommandResult("ERROR: Access is denied.", "", 1)
        if "vssadmin.exe list" in script:
            return CommandResult("No items found that satisfy the query.", "", 0)
        return CommandResult("", "", 0)

    async def disconnect(self) -> None:
        self.disconnected = True


def _patch_connection(monkeypatch, fake_conn: FakeConnection) -> None:
    async def fake_get_connection(target: str) -> FakeConnection:
        assert target == "10.10.1.108"
        return fake_conn

    monkeypatch.setattr(sam_dump, "get_connection", fake_get_connection)


async def test_sam_dump_registry_method_builds_output(monkeypatch) -> None:
    fake_conn = FakeConnection()
    _patch_connection(monkeypatch, fake_conn)

    result = await sam_dump.execute("10.10.1.108", {})

    assert result.success is True
    assert "SAM registry access check: Access denied" in result.output
    assert "ERROR: Access is denied." in result.output
    assert "Registry method:" in result.output
    assert fake_conn.scripts[0].startswith("reg.exe query HKLM\\SAM")
    assert "reg.exe save HKLM\\SAM" in fake_conn.scripts[1]
    assert fake_conn.disconnected is True


async def test_sam_dump_shadow_copy_method_lists_artifacts(monkeypatch) -> None:
    fake_conn = FakeConnection()
    _patch_connection(monkeypatch, fake_conn)

    result = await sam_dump.execute("10.10.1.108", {"method": "shadow_copy"})

    assert result.success is True
    assert "Shadow copy method simulation:" in result.output
    assert any("vssadmin.exe list shadows" in script for script in fake_conn.scripts)


async def test_sam_dump_rejects_unknown_method(monkeypatch) -> None:
    fake_conn = FakeConnection()
    _patch_connection(monkeypatch, fake_conn)

    result = await sam_dump.execute("10.10.1.108", {"method": "bogus"})

    assert result.success is False
    assert result.error == "Unsupported SAM dump method: bogus"
    assert fake_conn.disconnected is True


async def test_sam_dump_cleanup_removes_only_purplestrike_temp_artifacts(monkeypatch) -> None:
    fake_conn = FakeConnection()
    _patch_connection(monkeypatch, fake_conn)

    sam_dump._artifacts["10.10.1.108"] = "purplestrike_sam_test"
    await sam_dump.cleanup("10.10.1.108")

    assert len(fake_conn.scripts) == 1
    assert "[IO.File]::Delete" in fake_conn.scripts[0]
    assert "purplestrike_sam_test.hive" in fake_conn.scripts[0]
    assert "SAM_*" not in fake_conn.scripts[0]
    assert "vssadmin delete shadows" not in fake_conn.scripts[0]
    assert fake_conn.disconnected is True
