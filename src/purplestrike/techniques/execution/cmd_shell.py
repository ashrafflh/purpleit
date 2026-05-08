from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Execute a cmd.exe command via PowerShell's cmd /c."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        command = parameters.get("command", "")
        ps_command = f"cmd /c {command}"
        result = await conn.run_ps(ps_command)
        return TechniqueResult(
            technique_id="T1059.003",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1059.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1059.003",
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
        await conn.run_ps("Remove-Item HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU -ErrorAction SilentlyContinue")
    except Exception as e:
        logger.warning(f"T1059.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
