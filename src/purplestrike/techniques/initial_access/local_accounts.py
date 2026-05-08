from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate local accounts and test authentication."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        if conn.is_windows:
            result = await conn.run_ps(
                "net user; Write-Output '---'; "
                "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired | "
                "Format-Table -AutoSize; Write-Output '---'; "
                "whoami; Write-Output '---'; "
                "net user Administrator 2>&1; Write-Output '---'; "
                "net user Guest 2>&1"
            )
        else:
            result = await conn.run_command(
                "cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false; "
                "echo '---'; "
                "cat /etc/shadow 2>/dev/null | cut -d: -f1,2 | "
                "grep -v '!!\\|!\\|*\\|x' || echo 'No shadow access'; "
                "echo '---'; "
                "id; echo '---'; "
                "awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null"
            )
        return TechniqueResult(
            technique_id="T1078.003",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1078.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1078.003",
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
        logger.warning(f"T1078.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
