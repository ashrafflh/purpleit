from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Execute a harmless allowlisted setuid utility to generate realistic telemetry."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        result = await conn.run_command(
            "candidate=''; "
            "for path in /usr/bin/passwd /bin/passwd /usr/bin/chsh /usr/bin/chfn; do "
            'if [ -u "$path" ] && [ -x "$path" ]; then candidate="$path"; break; fi; '
            "done; "
            "[ -n \"$candidate\" ] || { echo 'No allowlisted setuid utility found' >&2; exit 1; }; "
            "printf 'candidate=%s\\n' \"$candidate\"; "
            "stat -c 'mode=%A owner=%U:%G' \"$candidate\"; "
            '"$candidate" --help >/dev/null 2>&1 || true; '
            "printf 'real/effective identity after execution: '; id"
        )
        if not result.success:
            return TechniqueResult(
                technique_id="T1548.001",
                success=False,
                output=result.stdout[:4096],
                error=result.stderr[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        return TechniqueResult(
            technique_id="T1548.001",
            success=True,
            output=result.stdout[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
            evidence=["An allowlisted setuid utility executed and identity evidence was captured."],
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
