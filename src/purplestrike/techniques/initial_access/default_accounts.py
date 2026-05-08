from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Check for default accounts such as Guest and Administrator on the target."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        if conn.is_windows:
            result = await conn.run_ps(
                "net user Guest 2>&1; Write-Output '---'; "
                "net user Administrator 2>&1; Write-Output '---'; "
                "net user DefaultAccount 2>&1; Write-Output '---'; "
                "Get-LocalUser | Select-Object Name,Enabled,Description | Format-Table -AutoSize"
            )
        else:
            result = await conn.run_command(
                "cat /etc/passwd 2>/dev/null | awk -F: '$3 < 1000 {print $1,$3,$7}'; "
                "echo '---'; "
                "grep -E '^(root|nobody|daemon|bin|sys|adm|lp|sync|shutdown|halt|mail)' "
                "/etc/passwd 2>/dev/null; echo '---'; "
                "passwd -S root 2>/dev/null || echo 'root account status unavailable'"
            )
        return TechniqueResult(
            technique_id="T1078.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1078.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1078.001",
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
        logger.warning(f"T1078.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
