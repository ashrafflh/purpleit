from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import delete_temp_files

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Open a reserved-domain URL through the Windows protocol handler."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        url_name = "purplestrike_test.url"
        command = (
            "$ErrorActionPreference = 'Stop'; "
            f"$urlPath = Join-Path $env:TEMP '{url_name}'; "
            "$urlContent = '[InternetShortcut]' + [Environment]::NewLine + "
            "'URL=https://example.invalid/purplestrike-test' + [Environment]::NewLine + "
            "'IconIndex=0' + [Environment]::NewLine; "
            "Set-Content -LiteralPath $urlPath -Value $urlContent -Encoding ASCII; "
            "$process = Start-Process -FilePath 'rundll32.exe' "
            "-ArgumentList 'url.dll,FileProtocolHandler', "
            "'https://example.invalid/purplestrike-test' -PassThru -Wait; "
            "if ($process.ExitCode -ne 0) { throw ('Protocol handler exited with ' + "
            "$process.ExitCode) }; "
            "'Protocol handler launched; ProcessId=' + $process.Id"
        )
        result = await conn.run_ps(command)
        success = result.success
        return TechniqueResult(
            technique_id="T1204.001",
            success=success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not success else None,
            artifacts=[f"%TEMP%\\{url_name}"],
            evidence=["The reserved-domain URL was opened through the protocol handler."],
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1204.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1204.001",
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
        result = await conn.run_ps(delete_temp_files("purplestrike_test.url"))
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
    except Exception as e:
        logger.warning(f"T1204.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
