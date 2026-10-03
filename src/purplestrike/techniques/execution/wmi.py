from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import delete_temp_files, ps_quote

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Execute a command via WMI Win32_Process Create method."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        command = parameters.get("command") or "whoami"
        ps_command = (
            "$ErrorActionPreference = 'Stop'; "
            "$outPath = Join-Path $env:TEMP 'purplestrike_wmi_output.txt'; "
            "[IO.File]::Delete($outPath); "
            f"$command = {ps_quote(command)}; "
            "$line = 'cmd.exe /d /s /c \"' + $command + ' > \"' + $outPath + '\" 2>&1\"'; "
            "$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
            "-Arguments @{CommandLine=$line}; "
            "if ($created.ReturnValue -ne 0) { throw ('WMI process creation failed: ' + "
            "$created.ReturnValue) }; Start-Sleep -Seconds 3; "
            "Get-Content -LiteralPath $outPath -ErrorAction Stop"
        )
        result = await conn.run_ps(ps_command)
        combined_output = result.stdout
        success = result.success
        return TechniqueResult(
            technique_id="T1047",
            success=success,
            output=combined_output[:4096],
            error=result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1047 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1047",
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
        result = await conn.run_ps(delete_temp_files('purplestrike_wmi_output.txt'))
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
    except Exception as e:
        logger.warning(f"T1047 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
