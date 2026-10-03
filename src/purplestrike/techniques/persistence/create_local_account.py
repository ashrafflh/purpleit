from __future__ import annotations

import logging
import shlex
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import ps_quote

logger = logging.getLogger(__name__)
_created_accounts: set[tuple[str, str]] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a local account for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        username = parameters.get("username") or "purplestrike_local"
        os_type = conn.os_type
        if os_type == "linux":
            result = await conn.run_command(f"sudo -n useradd -- {shlex.quote(username)}")
        else:
            result = await conn.run_ps(
                f"net user {ps_quote(username)} 'PurpleStrike1!' /add"
            )
        if result.success:
            _created_accounts.add((target, username))
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
        username = (parameters or {}).get("username") or "purplestrike_local"
        if (target, username) not in _created_accounts:
            return
        conn = await get_connection(target)
        os_type = conn.os_type
        if os_type == "linux":
            result = await conn.run_command(f"sudo -n userdel -- {shlex.quote(username)}")
        else:
            result = await conn.run_ps(f"net user {ps_quote(username)} /delete")
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
        _created_accounts.discard((target, username))
    except Exception as e:
        logger.warning(f"T1136.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
