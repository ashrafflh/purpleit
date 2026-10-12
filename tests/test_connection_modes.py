from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from purplestrike.models.config import ConnectionMethod, ConnectionSettings, PurpleStrikeConfig
from purplestrike.techniques import connection, wmi_connection
from purplestrike.techniques.connection import CommandResult, TargetConnection


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch):
    monkeypatch.setattr(connection, "_connection_settings", ConnectionSettings())
    monkeypatch.setattr(connection, "_target_methods", {})
    monkeypatch.setattr(connection, "_target_platforms", {})
    monkeypatch.setattr(connection, "_target_credentials", {})
    for prefix in ("TARGET", "WINRM_NONADMIN", "SSH", "WMI"):
        for suffix in ("USERNAME", "PASSWORD", "DOMAIN", "AD_DOMAIN"):
            monkeypatch.delenv("PURPLESTRIKE_" + prefix + "_" + suffix, raising=False)


def test_transport_is_independent_of_os_and_per_host_override():
    connection.set_target_platforms({"windows": "windows", "linux": "linux"})
    assert TargetConnection("windows").method == ConnectionMethod.WINRM
    assert TargetConnection("linux").method == ConnectionMethod.SSH
    connection.set_connection_settings(ConnectionSettings(method="ssh"), {"windows": "wmi"})
    assert TargetConnection("windows").method == ConnectionMethod.WMI
    assert TargetConnection("windows", method="ssh").is_windows
    with pytest.raises(connection.ConnectionError, match="Windows"):
        TargetConnection("linux", method="wmi")


def test_env_config_and_invalid_modes(monkeypatch):
    monkeypatch.setenv("PURPLESTRIKE_CONNECTION_METHOD", "winrm_nonadmin")
    monkeypatch.setenv("PURPLESTRIKE_SSH_PORT", "2222")
    monkeypatch.setenv("PURPLESTRIKE_SSH_CLIENT_KEYS", '["key with spaces"]')
    settings = PurpleStrikeConfig.from_env().connection
    assert settings.method == "winrm_nonadmin"
    assert settings.ssh_port == 2222
    assert settings.ssh_client_keys == ["key with spaces"]
    monkeypatch.setenv("PURPLESTRIKE_CONNECTION_METHOD", "typo")
    with pytest.raises(ValueError):
        PurpleStrikeConfig.from_env()


def test_separate_credentials_are_used_and_redacted(monkeypatch):
    connection.set_target_credentials("CORP", "admin", "admin-secret")
    monkeypatch.setenv("PURPLESTRIKE_WINRM_NONADMIN_USERNAME", r"HOST\testuser")
    monkeypatch.setenv("PURPLESTRIKE_WINRM_NONADMIN_PASSWORD", "user-secret")
    conn = TargetConnection("host", method="winrm_nonadmin")
    user, password, domain = conn._credentials()
    assert (user, password) == (r"HOST\testuser", "user-secret")
    assert conn._qualified_username(user, domain) == r"HOST\testuser"
    assert connection._redact_target_password("admin-secret user-secret") == "[REDACTED] [REDACTED]"


def test_winrs_nonadmin_sets_shell_profile_option():
    options = []
    protocol = SimpleNamespace(
        open_shell=lambda **kwargs: options.append(kwargs) or "shell",
        run_command=lambda *args, **kwargs: "command",
        get_command_output_raw=lambda *args: (b"ok", b"", 0, True),
        cleanup_command=lambda *args: None,
        close_shell=lambda *args: None,
    )
    result = connection._run_ps_with_deadline(SimpleNamespace(protocol=protocol), "whoami", 5, True)
    assert options == [{"noprofile": True}]
    assert result.status_code == 0


async def test_nonadmin_mode_rejects_admin_account(monkeypatch):
    conn = TargetConnection("host", method="winrm_nonadmin")
    monkeypatch.setattr(conn, "_connect_winrm", AsyncMock())
    probe = AsyncMock(return_value=CommandResult("", "requires non-admin", 1))
    monkeypatch.setattr(conn, "run_ps", probe)
    with pytest.raises(connection.ConnectionError, match="requires non-admin"):
        await conn.connect()
    assert "S-1-5-32-544" in probe.call_args.args[0]


async def test_ssh_defaults_to_host_key_verification_and_linux_username(monkeypatch):
    connect = AsyncMock()
    monkeypatch.setitem(__import__("sys").modules, "asyncssh", SimpleNamespace(connect=connect))
    connection.set_target_credentials("CORP", "testuser", "password")
    connection.set_target_platforms({"linux": "linux"})
    await TargetConnection("linux").connect()
    kwargs = connect.call_args.kwargs
    assert kwargs["username"] == "testuser"
    assert "known_hosts" not in kwargs
    assert kwargs["connect_timeout"] == 15


def fake_ssh_process(result=None):
    data = []
    events = []
    process = SimpleNamespace(
        stdin=SimpleNamespace(write=data.append, write_eof=lambda: events.append("eof")),
        wait=AsyncMock(
            return_value=result or SimpleNamespace(stdout="Grüße", stderr="", exit_status=0)
        ),
        kill=lambda: events.append("kill"),
        close=lambda: events.append("close"),
    )
    return process, data, events


async def test_windows_ssh_streams_unicode_long_scripts_and_preserves_status():
    conn = TargetConnection("host", method="ssh")
    process, data, events = fake_ssh_process(
        SimpleNamespace(stdout="out", stderr="err", exit_status=7)
    )
    conn._ssh_conn = SimpleNamespace(create_process=AsyncMock(return_value=process))
    script = "Write-Output 'Grüße; $quoted'\n" + "# more\n" * 2000
    result = await conn.run_ps(script)
    decoded = base64.b64decode(data[0]).decode("utf-16-le")
    assert script in decoded
    assert "$LASTEXITCODE" in decoded
    assert result.exit_code == 7
    assert events == ["eof", "close"]
    assert len(conn._ssh_conn.create_process.call_args.args[0]) < 2000


async def test_windows_ssh_timeout_requests_termination():
    conn = TargetConnection("host", method="ssh")
    process, _, events = fake_ssh_process()
    process.wait.side_effect = asyncio.TimeoutError
    conn._ssh_conn = SimpleNamespace(create_process=AsyncMock(return_value=process))
    result = await conn.run_ps("Start-Sleep 100", timeout=1)
    assert result.exit_code == 124
    assert events == ["eof", "kill", "close"]


async def test_wmi_routing_does_not_touch_winrm(monkeypatch):
    backend = SimpleNamespace(
        connect=lambda: None, disconnect=lambda: None, run_ps=lambda script, timeout: ("ok", "", 0)
    )
    monkeypatch.setattr(wmi_connection, "WmiConnection", lambda *args: backend)
    conn = TargetConnection("host", method="wmi")
    monkeypatch.setattr(conn, "_connect_winrm", AsyncMock(side_effect=AssertionError("WinRM used")))
    await conn.connect()
    assert (await conn.run_ps("whoami")).stdout == "ok"
    await conn.disconnect()


@pytest.mark.parametrize(
    "settings",
    [
        {"wmi_share": r"\\host\share"},
        {"wmi_share_path": r"..\outside"},
        {"wmi_share_path": r"C:\outside"},
        {"wmi_remote_path": "relative"},
    ],
)
def test_wmi_rejects_unsafe_staging_paths(settings):
    with pytest.raises(ValueError):
        wmi_connection.WmiConnection("host", ("user", "secret", ""), ConnectionSettings(**settings))


def test_wmi_worker_keeps_credentials_out_of_arguments_and_preserves_exit(monkeypatch):
    calls = []
    monkeypatch.setattr(wmi_connection.sys, "platform", "win32")

    def run(args, **kwargs):
        calls.append((args, kwargs, Path(args[-1]).read_text(encoding="utf-8-sig")))
        return SimpleNamespace(stdout=json.dumps({"stdout": "ok", "stderr": "", "exit_code": 7}))

    monkeypatch.setattr(wmi_connection.subprocess, "run", run)
    conn = wmi_connection.WmiConnection("host", ("user", "secret", ""), ConnectionSettings())
    assert conn.run_ps("exit 7", 10) == ("ok", "", 7)
    args, kwargs, worker_source = calls[0]
    assert "secret" not in " ".join(args)
    request = json.loads(kwargs["input"])
    assert request["credentials"][1] == "secret"
    assert "System.Management.ManagementScope" in worker_source
    assert "secret" not in worker_source
    assert not Path(args[-1]).exists()
    assert request["job"].startswith("purplestrike_")
    assert "10000" in base64.b64decode(request["wrapper"]).decode("utf-16-le")


def test_wmi_timeout_reports_unknown_state_without_resubmitting(monkeypatch):
    monkeypatch.setattr(wmi_connection.sys, "platform", "win32")
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise subprocess.TimeoutExpired("powershell", 1)

    monkeypatch.setattr(wmi_connection.subprocess, "run", fail)
    conn = wmi_connection.WmiConnection("host", ("user", "secret", ""), ConnectionSettings())
    with pytest.raises(TimeoutError, match="status is unknown"):
        conn.run_ps("whoami", 1)
    assert len(calls) == 1


def test_wmi_reports_native_worker_errors(monkeypatch):
    monkeypatch.setattr(wmi_connection.sys, "platform", "win32")
    monkeypatch.setattr(
        wmi_connection.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout=json.dumps({"error": "Access is denied"}),
        ),
    )
    conn = wmi_connection.WmiConnection("host", ("user", "secret", ""), ConnectionSettings())
    with pytest.raises(RuntimeError, match="Access is denied"):
        conn.connect()


@pytest.mark.skipif(sys.platform != "win32", reason="Exercises local Windows COM error handling")
def test_native_wmi_worker_surfaces_com_errors():
    # Windows rejects explicit credentials on a local ManagementScope. No remote
    # host, account mutation, or share creation is involved in this error probe.
    conn = wmi_connection.WmiConnection(
        ".", ("unused", "unused", ""), ConnectionSettings(connect_timeout=5)
    )
    with pytest.raises(RuntimeError, match="Connect"):
        conn.connect()


@pytest.mark.skipif(sys.platform != "win32", reason="Exercises Windows PowerShell stdin execution")
@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("Write-Output 'Grüße'; exit 7", 7),
        ("cmd.exe /c exit 9", 9),
        ("throw 'expected error'", 1),
    ],
)
async def test_windows_ssh_bootstrap_preserves_real_process_status(script, expected):
    conn = TargetConnection("host", method="ssh")
    process, data, _ = fake_ssh_process()
    conn._ssh_conn = SimpleNamespace(create_process=AsyncMock(return_value=process))
    await conn.run_ps(script)
    command = conn._ssh_conn.create_process.call_args.args[0]
    exe = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [str(exe), *command.split()[1:]],
        input=data[0],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == expected, result.stderr
    if expected == 7:
        assert "Grüße" in result.stdout


async def test_download_handles_empty_files_and_remote_failures(tmp_path, monkeypatch):
    conn = TargetConnection("host")
    execute = AsyncMock(return_value=CommandResult("", "", 0))
    monkeypatch.setattr(conn, "run_ps", execute)
    output = tmp_path / "empty"
    await conn.download("C:\\user's file", str(output))
    assert output.read_bytes() == b""
    assert "user''s file" in execute.call_args.args[0]
    execute.return_value = CommandResult("", "Access denied", 1)
    with pytest.raises(connection.ConnectionError, match="Access denied"):
        await conn.download("missing", str(output))


@pytest.mark.skipif(sys.platform != "win32", reason="Exercises Windows PowerShell child execution")
@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("Write-Output 'Grüße'; exit 7", 7),
        ("cmd.exe /c exit 9", 9),
        ("throw 'expected error'", 1),
        ("Start-Sleep -Seconds 5", 124),
    ],
)
def test_native_wmi_wrapper_runs_real_child_and_records_status(tmp_path, script, expected):
    (tmp_path / "input.ps1").write_text(connection._powershell_script(script), encoding="utf-8-sig")
    wrapper = wmi_connection._REMOTE_WRAPPER.replace(
        "__DIRECTORY__",
        "'" + str(tmp_path).replace("'", "''") + "'",
    ).replace("__TIMEOUT__", "1000" if expected == 124 else "10000")
    exe = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [
            str(exe),
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(wrapper.encode("utf-16-le")).decode(),
        ],
        capture_output=True,
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    status = json.loads((tmp_path / "result.json").read_text(encoding="utf-8-sig"))
    assert status["exit_code"] == expected
    if expected == 7:
        assert "Grüße" in (tmp_path / "stdout.txt").read_text(encoding="utf-8-sig")
