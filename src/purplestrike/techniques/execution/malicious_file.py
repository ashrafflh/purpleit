from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import delete_temp_files

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and launch a benign script-shaped file to emulate user execution."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        file_name = "purplestrike_user_execution.cmd"
        marker_name = "purplestrike_user_execution.txt"
        command = (
            "$ErrorActionPreference = 'Stop'; "
            f"$filePath = Join-Path $env:TEMP '{file_name}'; "
            f"$markerPath = Join-Path $env:TEMP '{marker_name}'; "
            "[IO.File]::Delete($markerPath); "
            "$fileContent = 'echo off' + [Environment]::NewLine + "
            "'echo PurpleStrike-T1204.002>%TEMP%\\purplestrike_user_execution.txt'; "
            "Set-Content -LiteralPath $filePath -Value $fileContent -Encoding ASCII; "
            "$process = Start-Process -FilePath $filePath -WindowStyle Hidden -PassThru -Wait; "
            "if ($process.ExitCode -ne 0) { throw ('File exited with ' + $process.ExitCode) }; "
            "Get-Content -LiteralPath $markerPath -ErrorAction Stop"
        )
        result = await conn.run_ps(command)
        success = result.success
        return TechniqueResult(
            technique_id="T1204.002",
            success=success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not success else None,
            artifacts=[f"%TEMP%\\{file_name}", f"%TEMP%\\{marker_name}"],
            evidence=["The benign script file was launched and wrote its execution marker."],
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
        result = await conn.run_ps(
            delete_temp_files(
                "purplestrike_user_execution.cmd",
                "purplestrike_user_execution.txt",
            )
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
    except Exception as e:
        logger.warning(f"T1204.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
