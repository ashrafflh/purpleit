from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.credential_access import lsass_dump
from purplestrike.techniques.execution import scheduled_task
from purplestrike.techniques.privilege_escalation import dll_injection
from purplestrike.techniques.scripts import ps_quote


@pytest.fixture(autouse=True)
def isolated_task_ownership(monkeypatch):
    monkeypatch.setattr(scheduled_task, "_created_tasks", set())
    monkeypatch.setattr(scheduled_task, "_output_files", {})


def connect(monkeypatch, module, *results):
    conn = AsyncMock()
    conn.run_ps.side_effect = results
    monkeypatch.setattr(module, "get_connection", AsyncMock(return_value=conn))
    return conn


@pytest.mark.parametrize("success", [False, True])
async def test_lsass_evidence_matches_handle_result(monkeypatch, success):
    diagnostics = "LSASS access context: identity=lab\\tester; elevated=True\n"
    conn = connect(
        monkeypatch, lsass_dump,
        CommandResult(
            diagnostics + ("Opened LSASS handle; pid=123; access=0x0410" if success else ""),
            "" if success else "OpenProcess failed with Win32 error 5: Access denied",
            0 if success else 1,
        ),
    )
    result = await lsass_dump.execute("host", {})
    assert result.success is success
    assert bool(result.evidence) is success
    assert diagnostics in result.output
    if not success:
        assert result.execution_status == "failure"
        assert "Access denied" in result.error
    conn.disconnect.assert_awaited_once()


async def test_missing_target_is_a_clear_prerequisite_skip(monkeypatch):
    conn = connect(monkeypatch, dll_injection, CommandResult("", "", 0))
    result = await dll_injection.execute(
        "host", {"target_process": "explorer", "dll_path": "kernel32.dll"},
    )
    assert not result.success
    assert result.execution_status == "skipped"
    assert "explorer" in result.error
    assert "Prerequisite not met" in result.error
    assert not result.evidence
    assert conn.run_ps.await_count == 1
    conn.disconnect.assert_awaited_once()


async def test_target_lookup_failure_is_not_a_missing_process(monkeypatch):
    connect(monkeypatch, dll_injection, CommandResult("", "WinRM connection failed", 1))
    result = await dll_injection.execute(
        "host", {"target_process": "explorer", "dll_path": "kernel32.dll"},
    )
    assert result.execution_status == "failure"
    assert "WinRM connection failed" in result.error


async def test_target_lookup_success_keeps_prerequisite_evidence(monkeypatch):
    connect(
        monkeypatch, dll_injection,
        CommandResult("Id : 123\nName : explorer", "", 0),
        CommandResult("explorer\nlsass", "", 0),
    )
    result = await dll_injection.execute(
        "host", {"target_process": "explorer", "dll_path": "kernel32.dll"},
    )
    assert result.success
    assert "Target Process Match" in result.output
    assert "No DLL injection" in result.evidence[0]


@pytest.mark.parametrize(
    ("exit_code", "status"), [(0, "success"), (1, "failure"), (124, "timeout")],
)
async def test_task_result_and_artifacts_require_verified_completion(
    monkeypatch, exit_code, status,
):
    conn = connect(
        monkeypatch, scheduled_task,
        CommandResult("created", "", 0),
        CommandResult("lab\\tester" if exit_code == 0 else "", "task diagnostic", exit_code),
        CommandResult("", "", 0),
        CommandResult("", "", 0),
    )
    params = {"task_name": "OwnedTask", "execution_timeout_seconds": 45}
    result = await scheduled_task.execute("host", params)
    assert result.execution_status == status
    assert result.success is (exit_code == 0)
    assert bool(result.artifacts) is (exit_code == 0)
    assert bool(result.evidence) is (exit_code == 0)
    assert conn.run_ps.await_args_list[1].kwargs["timeout"] > 45
    assert ("host", "OwnedTask") in scheduled_task._created_tasks
    await scheduled_task.cleanup("host", params)
    cleanup = conn.run_ps.await_args_list[2].args[0]
    assert "Stop-ScheduledTask -TaskName 'OwnedTask'" in cleanup
    assert "Unregister-ScheduledTask -TaskName 'OwnedTask'" in cleanup
    assert not scheduled_task._created_tasks
    assert not scheduled_task._output_files


async def test_task_registration_failure_does_not_claim_ownership(monkeypatch):
    conn = connect(monkeypatch, scheduled_task, CommandResult("", "Registration denied", 1))
    result = await scheduled_task.execute("host", {"task_name": "ExistingTask"})
    assert not result.success
    assert "Registration denied" in result.error
    assert not result.artifacts
    await scheduled_task.cleanup("host", {"task_name": "ExistingTask"})
    assert conn.run_ps.await_count == 1


@pytest.mark.parametrize("timeout", [0, -1, 301, "invalid"])
async def test_invalid_task_timeout_does_not_connect(monkeypatch, timeout):
    get_connection = AsyncMock()
    monkeypatch.setattr(scheduled_task, "get_connection", get_connection)
    result = await scheduled_task.execute("host", {"execution_timeout_seconds": timeout})
    assert not result.success
    get_connection.assert_not_awaited()


def run_powershell(script: str) -> CommandResult:
    """Execute generated scripts with test doubles; never contact a remote host."""
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        pytest.skip("PowerShell is required for generated-script regression tests")
    wrapped = (
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; "
        "$global:LASTEXITCODE = 0;\n" + script + "\n"
        "if (-not $?) { exit 1 }; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
    )
    encoded = base64.b64encode(wrapped.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return CommandResult(result.stdout, result.stderr, result.returncode)


@pytest.mark.parametrize("configured", [False, True])
async def test_lsass_diagnostics_and_script_syntax_without_opening_lsass(monkeypatch, configured):
    conn = connect(monkeypatch, lsass_dump, CommandResult("", "denied", 1))
    await lsass_dump.execute("host", {})
    generated = conn.run_ps.await_args.args[0]
    registry_response = (
        "[pscustomobject]@{ RunAsPPL=1 }" if configured else "throw 'Not configured'"
    )
    script = f"""
        $tokens = $null; $parseErrors = $null
        [void][Management.Automation.Language.Parser]::ParseInput(
            {ps_quote(generated)}, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count) {{ throw ($parseErrors | Out-String) }}
        function Get-ItemProperty {{
            param($LiteralPath, $Name, $ErrorAction)
            {registry_response}
        }}
        function whoami.exe {{ 'SeDebugPrivilege Disabled' }}
    """
    # Only run the diagnostics prefix. The handle-opening code is parsed, never executed.
    script += generated.split("$source = ", 1)[0]
    result = run_powershell(script)
    assert result.success, result.stderr
    assert "LSASS access context:" in result.stdout
    assert "SeDebugPrivilege Disabled" in result.stdout
    expected = (
        "runtime protection is not verified" if configured else "runtime protection is unknown"
    )
    assert expected in result.stdout


def task_harness(tmp_path: Path, states, *, output: str | None = "verified output") -> str:
    """Model scheduler transitions, including stale metadata and delayed starts."""
    if output is not None:
        (tmp_path / "output.txt").write_text(output, encoding="utf-8")
    return f"""
        $env:TEMP = {ps_quote(str(tmp_path))}
        $script:states = ConvertFrom-Json {ps_quote(json.dumps(states))}
        $script:poll = -1
        function Start-ScheduledTask {{ param($TaskName, $ErrorAction) }}
        function Get-ScheduledTask {{
            param($TaskName, $ErrorAction)
            $script:poll = [Math]::Min($script:poll + 1, $script:states.Count - 1)
            [pscustomobject]@{{
                State = $script:states[$script:poll][0]
                Principal = [pscustomobject]@{{ LogonType = 'S4U' }}
            }}
        }}
        function Get-ScheduledTaskInfo {{
            param($TaskName, $ErrorAction)
            if ($script:poll -eq -1) {{
                return [pscustomobject]@{{
                    LastRunTime = [datetime]'2026-01-01'; LastTaskResult = 267011
                }}
            }}
            [pscustomobject]@{{
                LastRunTime = ([datetime]'2026-01-01').AddSeconds(
                    $script:states[$script:poll][2])
                LastTaskResult = $script:states[$script:poll][1]
            }}
        }}
    """


@pytest.mark.parametrize("initial", [
    ["Ready", 267011, 0],       # Task has not run yet.
    ["Queued", 267045, 0],      # Start request queued.
    ["Running", 267009, 1],     # Task still running.
    ["Running", 0, 1],          # Result lags behind task state.
    ["Ready", 0, 0],            # Old result, not a new run.
])
def test_task_polls_pending_or_stale_status_before_success(tmp_path, initial):
    states = [initial, initial, ["Ready", 0, 1]]
    script = task_harness(tmp_path, states)
    script += scheduled_task._run_task_script("TestTask", "output.txt", 5)
    script += "\nif ($script:poll -ne 2) { throw 'Returned before the new run completed' }"
    result = run_powershell(script)
    assert result.success, result.stderr
    assert "verified output" in result.stdout


@pytest.mark.parametrize("state", [
    ["Ready", 267011, 0], ["Queued", 267045, 0], ["Running", 267009, 1], ["Ready", 0, 0],
])
def test_task_pending_status_times_out_with_diagnostics(tmp_path, state):
    script = task_harness(tmp_path, [state, state])
    script += scheduled_task._run_task_script("TestTask", "output.txt", 1)
    result = run_powershell(script)
    assert result.exit_code == 124, result.stderr
    assert "Timed out waiting for scheduled task" in result.stderr
    assert f"LastTaskResult={state[1]}" in result.stderr
    assert f"State={state[0]}" in result.stderr
    assert not result.stdout.strip()


@pytest.mark.parametrize("code", [1, 2147943785])  # Action failure or denied batch logon.
def test_task_terminal_failure_reports_result_without_waiting_for_timeout(tmp_path, code):
    script = task_harness(tmp_path, [["Ready", code, 0], ["Ready", code, 0]])
    script += scheduled_task._run_task_script("TestTask", "output.txt", 5)
    result = run_powershell(script)
    assert result.exit_code == 1
    assert f"LastTaskResult={code}" in result.stderr
    assert "Scheduled task failed" in result.stderr


@pytest.mark.parametrize("output", [None, ""])
def test_task_requires_output_file_but_allows_empty_output(tmp_path, output):
    script = task_harness(tmp_path, [["Ready", 0, 1], ["Ready", 0, 1]], output=output)
    script += scheduled_task._run_task_script("TestTask", "output.txt", 5)
    result = run_powershell(script)
    assert result.success is (output is not None), result.stderr
    if output is None:
        assert "expected output file was not created" in result.stderr


async def test_registration_uses_same_account_s4u_without_interactive_login(monkeypatch):
    conn = connect(
        monkeypatch, scheduled_task,
        CommandResult("created", "", 0), CommandResult("output", "", 0),
    )
    await scheduled_task.execute("host", {"task_name": "TestTask"})
    script = """
        function New-ScheduledTaskAction { param($Execute, $Argument) }
        function New-ScheduledTaskPrincipal {
            param($UserId, $LogonType, $RunLevel)
            if ($UserId -ne [Security.Principal.WindowsIdentity]::GetCurrent().Name) {
                throw 'Task changed account'
            }
            if ($LogonType -ne 'S4U') { throw 'Task depends on an interactive login' }
            [pscustomobject]@{ UserId=$UserId; LogonType=$LogonType; RunLevel=$RunLevel }
        }
        function Register-ScheduledTask {
            param($TaskName, $Action, $Principal, $ErrorAction)
            if ($Principal.LogonType -ne 'S4U') { throw 'Missing explicit S4U principal' }
            'registered'
        }
    """ + conn.run_ps.await_args_list[0].args[0]
    result = run_powershell(script)
    assert result.success, result.stderr
    assert "registered" in result.stdout


@pytest.mark.parametrize(("name", "found"), [
    ("explorer", True), ("Explorer.EXE", True), ("123", True),
    ("missing", False), ("expl*", False), ("absent'; throw 'injected", False),
])
async def test_process_lookup_handles_names_pids_and_literal_quoting(monkeypatch, name, found):
    conn = connect(monkeypatch, dll_injection, CommandResult("", "", 0))
    await dll_injection.execute("host", {"target_process": name, "dll_path": "kernel32.dll"})
    script = """
        function Get-Process {
            param($ErrorAction)
            [pscustomobject]@{
                Id=123; ProcessName='explorer'; Name='explorer'; Path='explorer.exe'
            }
        }
    """ + conn.run_ps.await_args_list[0].args[0]
    result = run_powershell(script)
    assert result.success, result.stderr
    assert bool(result.stdout.strip()) is found
