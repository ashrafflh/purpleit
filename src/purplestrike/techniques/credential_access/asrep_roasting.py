from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        tool = parameters.get("tool", "rubeus")
        ps_cmd = (
            "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} "
            "-Properties DoesNotRequirePreAuth, SamAccountName | "
            'Select-Object SamAccountName, DoesNotRequirePreAuth | '
            "Format-Table -AutoSize"
        )
        result = await conn.run_ps(ps_cmd)
        return TechniqueResult(
            technique_id="T1558.002",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1558.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1558.002",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        await conn.run_ps("klist purge")
    except Exception as e:
        logger.warning(f"T1558.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
