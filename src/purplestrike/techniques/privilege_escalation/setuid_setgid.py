from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate setuid/setgid binaries and check privilege escalation paths."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        find_result = await conn.run_command(
            "find / -perm -4000 -o -perm -2000 2>/dev/null"
        )
        if not find_result.success:
            return TechniqueResult(
                technique_id="T1548.001",
                success=False,
                output=find_result.stdout[:4096],
                error=find_result.stderr[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        pkexec_result = await conn.run_command("pkexec --version 2>/dev/null")
        sudo_result = await conn.run_command("sudo -V 2>/dev/null | head -1")
        combined = (
            f"=== Setuid/Setgid Binaries ===\n{find_result.stdout[:3072]}\n\n"
            f"=== pkexec version ===\n{pkexec_result.stdout[:512]}\n\n"
            f"=== sudo version ===\n{sudo_result.stdout[:512]}"
        )
        return TechniqueResult(
            technique_id="T1548.001",
            success=True,
            output=combined[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1548.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1548.001",
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
        logger.warning(f"T1548.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
