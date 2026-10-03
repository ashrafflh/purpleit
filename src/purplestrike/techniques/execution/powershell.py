from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)

DEFAULT_COMMAND = "Invoke-Command -ScriptBlock { whoami }"


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Execute a PowerShell command on the target."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        command = (parameters.get("command") or DEFAULT_COMMAND).strip()
        encoded = parameters.get("encoded", False)
        if encoded:
            import base64
            encoded_cmd = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
            ps_command = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded_cmd}"
        else:
            ps_command = command
        result = await conn.run_ps(ps_command)
        return TechniqueResult(
            technique_id="T1059.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1059.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1059.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    """The default command creates no artifacts; preserve the user's history."""
