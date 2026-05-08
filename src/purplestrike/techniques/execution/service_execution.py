from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and start a Windows service to execute a command."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        service_name = parameters.get("service_name", "PurpleStrikeSvc")
        command = parameters.get("command", "")
        out_path = "$env:TEMP\\purplestrike_svc_output.txt"
        bin_path = f'cmd /c {command} > {out_path} 2>&1'
        create_result = await conn.run_ps(
            f'sc.exe create "{service_name}" binPath= "{bin_path}" start= demand'
        )
        start_result = await conn.run_ps(f'sc.exe start "{service_name}"')
        await conn.run_ps("Start-Sleep -Seconds 3")
        output_result = await conn.run_ps(
            f"Get-Content {out_path} -ErrorAction SilentlyContinue"
        )
        combined_output = create_result.stdout + "\n" + start_result.stdout + "\n" + output_result.stdout
        success = create_result.success
        return TechniqueResult(
            technique_id="T1569.002",
            success=success,
            output=combined_output[:4096],
            error=create_result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1569.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1569.002",
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
        svc_list = await conn.run_ps(
            'Get-Service | Where-Object { $_.DisplayName -like "PurpleStrike*" } '
            '| Select-Object -ExpandProperty Name'
        )
        for name in svc_list.stdout.strip().splitlines():
            name = name.strip()
            if name:
                await conn.run_ps(f'sc.exe stop "{name}" 2>$null; sc.exe delete "{name}"')
        await conn.run_ps(
            "Remove-Item $env:TEMP\\purplestrike_svc_output.txt -ErrorAction SilentlyContinue"
        )
    except Exception as e:
        logger.warning(f"T1569.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
