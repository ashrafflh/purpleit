from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a scheduled task for persistence via Register-ScheduledTask."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        task_name = parameters.get("task_name", "PurpleStrikeTask")
        command = parameters.get("command", "")
        ps_cmd = (
            f'$Action = New-ScheduledTaskAction -Execute "{command}";'
            f"$Trigger = New-ScheduledTaskTrigger -AtLogOn;"
            f"Register-ScheduledTask -TaskName '{task_name}' "
            f"-Action $Action -Trigger $Trigger -RunLevel Highest"
        )
        result = await conn.run_ps(ps_cmd)
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


async def cleanup(target: str) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        await conn.run_ps("Unregister-ScheduledTask -TaskName 'PurpleStrikeTask' -Confirm:$false")
    except Exception as e:
        logger.warning(f"T1053.005p cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
