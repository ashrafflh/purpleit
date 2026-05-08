from __future__ import annotations

import asyncio
import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Test authentication using valid credentials to verify access."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        account_type = parameters.get("account_type", "local")
        if conn.is_windows:
            if account_type == "domain":
                result = await conn.run_ps(
                    "whoami /all; Write-Output '---'; "
                    "whoami /groups; Write-Output '---'; "
                    "net use 2>&1"
                )
            else:
                result = await conn.run_ps(
                    "whoami; Write-Output '---'; "
                    "whoami /priv; Write-Output '---'; "
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"
                )
        else:
            if account_type == "domain":
                result = await conn.run_command(
                    "id; echo '---'; groups; echo '---'; "
                    "klist 2>/dev/null || echo 'No Kerberos tickets'"
                )
            else:
                result = await conn.run_command(
                    "id; echo '---'; groups; echo '---'; "
                    "cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false"
                )
        logger.info(f"T1078 auth event logged for account_type={account_type}")
        return TechniqueResult(
            technique_id="T1078",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1078 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1078",
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
        logger.warning(f"T1078 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
