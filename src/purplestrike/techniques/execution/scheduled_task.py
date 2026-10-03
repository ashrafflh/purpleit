from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import delete_temp_files, ps_quote

logger = logging.getLogger(__name__)
_created_tasks: set[tuple[str, str]] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and run the test task, checking its actual execution result."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        task_name = parameters.get("task_name", "PurpleStrikeTask")
        command = parameters.get("command") or "whoami"
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            f"$command = {ps_quote(command)}; "
            "$outPath = Join-Path $env:TEMP 'purplestrike_scheduled_task_output.txt'; "
            "[IO.File]::Delete($outPath); "
            "$arguments = '/d /s /c \"' + $command + ' > \"' + $outPath + '\" 2>&1\"'; "
            "$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $arguments; "
            f"Register-ScheduledTask -TaskName {ps_quote(task_name)} -Action $action "
            "-User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) "
            "-RunLevel Highest -ErrorAction Stop"
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout or "Task creation failed")
        _created_tasks.add((target, task_name))
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            f"$name = {ps_quote(task_name)}; Start-ScheduledTask -TaskName $name; "
            "Start-Sleep -Seconds 3; "
            "$info = Get-ScheduledTaskInfo -TaskName $name; "
            "if ($info.LastTaskResult -ne 0) { throw ('Task execution failed: ' + "
            "$info.LastTaskResult) }; "
            "Get-Content -LiteralPath (Join-Path $env:TEMP "
            "'purplestrike_scheduled_task_output.txt') -ErrorAction Stop"
        )
        success = result.success
        return TechniqueResult(
            technique_id="T1053.005",
            success=success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
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
        if (target, name) not in _created_tasks:
            return
        conn = await get_connection(target)
        result = await conn.run_ps(
            f"Unregister-ScheduledTask -TaskName {ps_quote(name)} -Confirm:$false -ErrorAction Stop"
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
        _created_tasks.discard((target, name))
        result = await conn.run_ps(delete_temp_files('purplestrike_scheduled_task_output.txt'))
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
    except Exception as e:
        logger.warning(f"T1053.005 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
