from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate processes that could be DLL injection targets (simulation only)."""
    conn: TargetConnection | None = None
    try:
        target_process = parameters.get("target_process", None)
        dll_path = parameters.get("dll_path", None)
        if not target_process or not dll_path:
            return TechniqueResult(
                technique_id="T1055.001",
                success=False,
                error="Missing required parameters: target_process and dll_path",
                execution_status=ExecutionStatus.FAILURE,
            )
        conn = await get_connection(target)
        processes = await conn.run_ps(
            "Get-Process | Select-Object Id, Name, Path, "
            "@{N='Modules';E={$_.Modules.Count}} "
            "| Format-Table -AutoSize"
        )
        target_match = await conn.run_ps(
            f"Get-Process -Name '{target_process}' -ErrorAction SilentlyContinue "
            "| Select-Object Id, Name, Path | Format-List"
        )
        combined = (
            f"=== All Processes ===\n{processes.stdout[:3072]}\n\n"
            f"=== Target Process Match ===\n{target_match.stdout[:1024]}"
        )
        return TechniqueResult(
            technique_id="T1055.001",
            success=True,
            output=combined[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1055.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1055.001",
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
        logger.warning(f"T1055.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
