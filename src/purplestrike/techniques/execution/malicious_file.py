from __future__ import annotations

import logging
from typing import Any
from purplestrike.techniques.scripts import delete_temp_files

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """SIMULATION: Create a suspicious file to test detection without executing it."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        file_name = "purplestrike_test.scr"
        command = (
            f"$filePath = Join-Path $env:TEMP '{file_name}'; "
            "$fileContent = 'REM PurpleStrike simulation file - benign content - not executable'; "
            "Set-Content -LiteralPath $filePath -Value $fileContent -Encoding ASCII; "
            "Test-Path -LiteralPath $filePath"
        )
        result = await conn.run_ps(command)
        success = result.success and result.stdout.strip() == "True"
        return TechniqueResult(
            technique_id="T1204.002",
            success=success,
            output=f"Simulated malicious file created at $env:TEMP\\{file_name}",
            error=result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1204.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1204.002",
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
        result = await conn.run_ps(delete_temp_files('purplestrike_test.scr'))
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
    except Exception as e:
        logger.warning(f"T1204.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
