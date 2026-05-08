from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a scheduled task to test detection without running it."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        task_name = parameters.get("task_name", "PurpleStrikeTask")
        command = parameters.get("command", "")
        out_path = "$env:TEMP\\purplestrike_scheduled_task_output.txt"
        full_cmd = f'cmd /c {command} > {out_path} 2>&1'
        result = await conn.run_ps(
            f'schtasks /create /tn "{task_name}" /tr "{full_cmd}" '
            f'/sc once /st 00:00 /f'
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


async def cleanup(target: str) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        task_list = await conn.run_ps(
            'Get-ScheduledTask | Where-Object { $_.TaskName -like "PurpleStrike*" } '
            '| Select-Object -ExpandProperty TaskName'
        )
        for name in task_list.stdout.strip().splitlines():
            name = name.strip()
            if name:
                await conn.run_ps(f'schtasks /delete /tn "{name}" /f')
        await conn.run_ps(
            "Remove-Item $env:TEMP\\purplestrike_scheduled_task_output.txt "
            "-ErrorAction SilentlyContinue"
        )
    except Exception as e:
        logger.warning(f"T1053.005 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
