from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate current token privileges (simulation only)."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        priv_result = await conn.run_ps("whoami /priv")
        whoami_result = await conn.run_ps("whoami")
        combined = (
            f"=== Current User ===\n{whoami_result.stdout[:512]}\n\n"
            f"=== Token Privileges ===\n{priv_result.stdout[:3584]}"
        )
        return TechniqueResult(
            technique_id="T1134.002",
            success=True,
            output=combined[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1134.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1134.002",
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
        logger.warning(f"T1134.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
