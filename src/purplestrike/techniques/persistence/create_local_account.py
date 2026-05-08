from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a local account for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        username = parameters.get("username", "")
        os_type = parameters.get("os", "windows")
        if os_type == "linux":
            result = await conn.run_command(f"useradd {username}")
        else:
            result = await conn.run_ps(
                f"net user {username} PurpleStrike123! /add"
            )
        return TechniqueResult(
            technique_id="T1136.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1136.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1136.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str, parameters: dict[str, Any] | None = None) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        username = parameters.get("username", "") if parameters else ""
        os_type = parameters.get("os", "windows") if parameters else "windows"
        if os_type == "linux":
            await conn.run_command(f"userdel -r {username}")
        else:
            await conn.run_ps(f"net user {username} /delete")
    except Exception as e:
        logger.warning(f"T1136.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
