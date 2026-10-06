from __future__ import annotations

import logging
from textwrap import dedent
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection
from purplestrike.techniques.scripts import delete_temp_files, ps_quote

logger = logging.getLogger(__name__)
_created_tasks: set[tuple[str, str]] = set()
_output_files: dict[tuple[str, str], str] = {}


def _run_task_script(task_name: str, output_file: str, timeout_seconds: int) -> str:
    """Wait for a new completed run, not just an accepted start request."""
    return dedent(f"""
        $ErrorActionPreference = 'Stop'
        $name = {ps_quote(task_name)}
        $outPath = Join-Path $env:TEMP {ps_quote(output_file)}
        $baseline = (Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop).LastRunTime
        Start-ScheduledTask -TaskName $name -ErrorAction Stop
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {{
            $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop
            $state = [string]$task.State
            $code = $info.LastTaskResult
            $details = "Task '$name': State=$state; LastTaskResult=$code (0x{{0:X8}}); " -f $code
            $details += "LastRunTime=$($info.LastRunTime); LogonType=$($task.Principal.LogonType)"
            # Ready, running, never run, and queued are scheduler statuses, not exit codes.
            $pending = $state -in @('Running', 'Queued') -or
                $code -in @(0x41300, 0x41301, 0x41303, 0x41325)
            if (-not $pending) {{
                if ($code -ne 0) {{
                    throw ("Scheduled task failed; " + $details +
                        '. Check TaskScheduler/Operational history and batch-logon rights.')
                }}
                if ($info.LastRunTime -gt $baseline) {{
                    if (-not (Test-Path -LiteralPath $outPath -PathType Leaf)) {{
                        throw "Task completed but expected output file was not created: $outPath"
                    }}
                    Get-Content -LiteralPath $outPath -ErrorAction Stop
                    break
                }}
            }}
            if ($timer.Elapsed.TotalSeconds -ge {timeout_seconds}) {{
                Write-Error ("Timed out waiting for scheduled task after {timeout_seconds}s; " +
                    $details + '. Check TaskScheduler/Operational history and ' +
                    'batch-logon rights.') -ErrorAction Continue
                exit 124
            }}
            Start-Sleep -Milliseconds 250
        }}
    """).strip()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and run the test task, checking its actual execution result."""
    conn: TargetConnection | None = None
    try:
        timeout_seconds = int(parameters.get("execution_timeout_seconds", 30))
        if not 1 <= timeout_seconds <= 300:
            raise ValueError("execution_timeout_seconds must be between 1 and 300")
        conn = await get_connection(target)
        task_name = parameters.get("task_name", "PurpleStrikeTask")
        command = parameters.get("command") or "whoami"
        output_file = f"purplestrike_scheduled_task_{uuid4().hex}.txt"
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            f"$command = {ps_quote(command)}; "
            f"$outPath = Join-Path $env:TEMP {ps_quote(output_file)}; "
            "$arguments = '/d /s /c \"' + $command + ' > \"' + $outPath + '\" 2>&1\"'; "
            "$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $arguments; "
            "$principal = New-ScheduledTaskPrincipal "
            "-UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) "
            "-LogonType S4U -RunLevel Highest; "
            f"Register-ScheduledTask -TaskName {ps_quote(task_name)} -Action $action "
            "-Principal $principal -ErrorAction Stop"
        )
        if not result.success:
            raise RuntimeError(f"Task creation failed (S4U logon): {command_error(result)}")
        _created_tasks.add((target, task_name))
        _output_files[(target, task_name)] = output_file
        result = await conn.run_ps(
            _run_task_script(task_name, output_file, timeout_seconds),
            timeout=timeout_seconds + 30,
        )
        success = result.success
        status = ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE
        if result.exit_code == 124:
            status = ExecutionStatus.TIMEOUT
        return TechniqueResult(
            technique_id="T1053.005",
            success=success,
            output=result.stdout[:4096],
            error=command_error(result)[:1024] if not success else None,
            execution_status=status,
            artifacts=[f"%TEMP%\\{output_file}"] if success else [],
            evidence=["A new task run completed with exit code 0 and its output file was read."]
            if success else [],
        )
    except Exception as e:
        logger.error(f"T1053.005 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1053.005",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str, parameters: dict[str, Any] | None = None) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        name = (parameters or {}).get("task_name", "PurpleStrikeTask")
        if (target, name) not in _created_tasks and (target, name) not in _output_files:
            return
        conn = await get_connection(target)
        if (target, name) in _created_tasks:
            result = await conn.run_ps(
                f"$task = Get-ScheduledTask -TaskName {ps_quote(name)} -ErrorAction Stop; "
                "if ($task.State -in @('Running', 'Queued')) { "
                f"Stop-ScheduledTask -TaskName {ps_quote(name)} -ErrorAction Stop }}; "
                f"Unregister-ScheduledTask -TaskName {ps_quote(name)} "
                "-Confirm:$false -ErrorAction Stop"
            )
            if not result.success:
                raise RuntimeError(result.stderr or result.stdout)
            _created_tasks.discard((target, name))
        output_file = _output_files.get((target, name))
        if output_file:
            result = await conn.run_ps(delete_temp_files(output_file))
            if not result.success:
                raise RuntimeError(result.stderr or result.stdout)
            del _output_files[(target, name)]
    except Exception as e:
        logger.warning(f"T1053.005 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
