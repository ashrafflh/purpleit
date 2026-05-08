from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Execute a command via WMI Win32_Process Create method."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        command = parameters.get("command", "")
        out_path = "$env:TEMP\\purplestrike_wmi_output.txt"
        full_cmd = f'cmd /c {command} > {out_path} 2>&1'
        ps_command = (
            f'Invoke-WmiMethod -Class Win32_Process -Name Create '
            f'-ArgumentList "{full_cmd}"'
        )
        result = await conn.run_ps(ps_command)
        await conn.run_ps("Start-Sleep -Seconds 3")
        output_result = await conn.run_ps(
            f"Get-Content {out_path} -ErrorAction SilentlyContinue"
        )
        combined_output = result.stdout + "\n" + output_result.stdout
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
        await conn.run_ps(
            "Remove-Item $env:TEMP\\purplestrike_wmi_output.txt -ErrorAction SilentlyContinue"
        )
        proc_result = await conn.run_ps(
            'Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*purplestrike*" } | '
            'Select-Object -ExpandProperty ProcessId'
        )
        if proc_result.stdout.strip():
            for pid in proc_result.stdout.strip().split("\n"):
                pid = pid.strip()
                if pid:
                    await conn.run_ps(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue")
    except Exception as e:
        logger.warning(f"T1047 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
