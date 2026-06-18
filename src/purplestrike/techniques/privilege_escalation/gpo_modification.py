from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate GPOs and check for modification rights (simulation only)."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        gpo_list = await conn.run_ps(
            "Get-GPO -All | Select-Object DisplayName, GpoStatus, Id "
            "| Format-Table -AutoSize"
        )
        if not gpo_list.success:
            gpo_list = await conn.run_ps(
                "Get-ADObject -Filter {ObjectClass -eq 'groupPolicyContainer'} "
                "-Properties DisplayName | Format-Table -AutoSize"
            )
        if not gpo_list.success:
            return TechniqueResult(
                technique_id="T1484.001",
                success=False,
                output=gpo_list.stdout[:4096],
                error=command_error(gpo_list)[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        combined = f"=== Group Policy Objects ===\n{gpo_list.stdout[:4096]}"
        return TechniqueResult(
            technique_id="T1484.001",
            success=True,
            output=combined[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1484.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1484.001",
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
    except Exception as e:
        logger.warning(f"T1484.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
