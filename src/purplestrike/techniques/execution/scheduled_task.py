from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import delete_temp_files, ps_quote

logger = logging.getLogger(__name__)
_created_tasks: set[tuple[str, str]] = set()
_output_files: dict[tuple[str, str], str] = {}


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and run the test task, checking its actual execution result."""
    conn: TargetConnection | None = None
    try:
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
            f"Register-ScheduledTask -TaskName {ps_quote(task_name)} -Action $action "
            "-User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) "
            "-RunLevel Highest -ErrorAction Stop"
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout or "Task creation failed")
        _created_tasks.add((target, task_name))
        _output_files[(target, task_name)] = output_file
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            f"$name = {ps_quote(task_name)}; Start-ScheduledTask -TaskName $name; "
            "Start-Sleep -Seconds 3; "
            "$info = Get-ScheduledTaskInfo -TaskName $name; "
            "if ($info.LastTaskResult -ne 0) { throw ('Task execution failed: ' + "
            "$info.LastTaskResult) }; "
            "Get-Content -LiteralPath (Join-Path $env:TEMP "
            f"{ps_quote(output_file)}) -ErrorAction Stop"
        )
        success = result.success
        return TechniqueResult(
            technique_id="T1053.005",
            success=success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
            artifacts=[f"%TEMP%\\{output_file}"],
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
                f"Unregister-ScheduledTask -TaskName {ps_quote(name)} -Confirm:$false -ErrorAction Stop"
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
