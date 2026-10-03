from __future__ import annotations

import asyncio
import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import (
    TargetConnection,
    command_error,
    get_connection,
    is_transport_failure,
)

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        target_account = parameters.get("target_account")
        if not target_account:
            return TechniqueResult(
                technique_id="T1110.001",
                success=False,
                error="target_account parameter is required",
                execution_status=ExecutionStatus.FAILURE,
            )
        password_list = parameters.get("password_list", "PurpleStrikeInvalid123!")
        max_attempts = parameters.get("max_attempts", 5)
        passwords = password_list.split(",")
        passwords = passwords[:max_attempts]
        results = []
        attempt_results = []
        is_windows = conn.is_windows if hasattr(conn, "is_windows") else True
        for pwd in passwords:
            pwd = pwd.strip()
            if not pwd:
                continue
            if is_windows:
                cmd = f"net use \\\\{target}\\ipc$ /user:{target_account} {pwd}"
                result = await conn.run_ps(cmd)
            else:
                result = await conn.run_command(f"echo {pwd} | su - {target_account} -c echo 2>&1")
            attempt_results.append(result)
            results.append(f"Password '{pwd[:3]}***': {'success' if result.success else 'failed'}")
            await asyncio.sleep(3)
        output = "\n".join(results)
        if not attempt_results:
            return TechniqueResult(
                technique_id="T1110.001",
                success=False,
                error="password_list did not contain any valid passwords",
                execution_status=ExecutionStatus.FAILURE,
            )
        if all(is_transport_failure(result) for result in attempt_results):
            return TechniqueResult(
                technique_id="T1110.001",
                success=False,
                output=output[:4096],
                error=command_error(attempt_results[-1])[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        return TechniqueResult(
            technique_id="T1110.001",
            success=True,
            output=output[:4096],
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1110.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1110.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    pass
