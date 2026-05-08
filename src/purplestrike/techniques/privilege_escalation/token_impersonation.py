from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate running processes and their token information (simulation only)."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        processes = await conn.run_ps(
            "Get-Process | Select-Object Id, Name, Path | Format-Table -AutoSize"
        )
        whoami_all = await conn.run_ps("whoami /all")
        whoami_priv = await conn.run_ps("whoami /priv")
        combined = (
            f"=== Running Processes ===\n{processes.stdout[:2048]}\n\n"
            f"=== Token Information ===\n{whoami_all.stdout[:1024]}\n\n"
            f"=== Current Privileges ===\n{whoami_priv.stdout[:1024]}"
        )
        return TechniqueResult(
            technique_id="T1134.001",
            success=True,
            output=combined[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1134.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1134.001",
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
        logger.warning(f"T1134.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
