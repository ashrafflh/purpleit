from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import ps_quote

logger = logging.getLogger(__name__)
_created_tasks: set[tuple[str, str]] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a scheduled task for persistence via Register-ScheduledTask."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        task_name = parameters.get("task_name", "PurpleStrikeTask")
        command = parameters.get("command") or "cmd.exe /c echo PurpleStrike"
        ps_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            f"$Action = New-ScheduledTaskAction -Execute 'cmd.exe' "
            f"-Argument {ps_quote('/d /c ' + command)};"
            f"$Trigger = New-ScheduledTaskTrigger -AtLogOn;"
            f"Register-ScheduledTask -TaskName {ps_quote(task_name)} "
            f"-Action $Action -Trigger $Trigger -RunLevel Highest"
        )
        result = await conn.run_ps(ps_cmd)
        if result.success:
            _created_tasks.add((target, task_name))
        return TechniqueResult(
            technique_id="T1053.005p",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1053.005p execution failed: {e}")
        return TechniqueResult(
            technique_id="T1053.005p",
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
    except Exception as e:
        logger.warning(f"T1053.005p cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
