from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Exercise the configured remote-management session and capture session evidence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        service_type = parameters.get("service_type", "auto")
        if conn.is_windows:
            result = await conn.run_ps(
                "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); "
                "[PSCustomObject]@{Identity=$identity.Name; AuthenticationType="
                "$identity.AuthenticationType; IsAuthenticated=$identity.IsAuthenticated; "
                f"RequestedService='{service_type}'; Transport='WinRM'}} | Format-List"
            )
        else:
            result = await conn.run_command(
                "id; printf 'Transport=SSH\\n'; "
                "printf 'SSH_CONNECTION=%s\\n' \"${SSH_CONNECTION:-unavailable}\""
            )
        return TechniqueResult(
            technique_id="T1133",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            evidence=[
                "The configured remote service authenticated and executed an identity check."
            ],
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1133 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1133",
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
        logger.warning(f"T1133 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
