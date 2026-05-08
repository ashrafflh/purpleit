from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        method = parameters.get("method", "procdump")
        check_result = await conn.run_ps("Get-Process lsass -ErrorAction SilentlyContinue | "
                                          "Select-Object Id, ProcessName, Path | Format-List")
        if not check_result.success or not check_result.stdout.strip():
            return TechniqueResult(
                technique_id="T1003.001",
                success=False,
                error="LSASS process not found or not accessible",
                execution_status=ExecutionStatus.FAILURE,
            )
        output = f"LSASS process enumeration:\n{check_result.stdout[:2048]}\n"
        if method == "procdump":
            sim_result = await conn.run_ps(
                "Test-Path 'C:\\ProgramData\\procdump.exe'; "
                "if (Test-Path 'C:\\ProgramData\\procdump.exe') "
                "{ 'procdump binary found' } else { 'procdump binary not found' }"
            )
            output += f"Procdump simulation: {sim_result.stdout.strip()}"
        elif method == "comsvcs":
            sim_result = await conn.run_ps(
                "Test-Path 'C:\\Windows\\System32\\comsvcs.dll'; "
                "if (Test-Path 'C:\\Windows\\System32\\comsvcs.dll') "
                "{ 'comsvcs.dll found - MiniDump method available' } "
                "else { 'comsvcs.dll not found' }"
            )
            output += f"Comsvcs simulation: {sim_result.stdout.strip()}"
        else:
            output += f"Unknown method: {method}"
        return TechniqueResult(
            technique_id="T1003.001",
            success=True,
            output=output[:4096],
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1003.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1003.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        await conn.run_ps("Remove-Item -Path 'C:\\ProgramData\\lsass_*.dmp' "
                          "-Force -ErrorAction SilentlyContinue; "
                          "Remove-Item -Path 'C:\\Windows\\Temp\\lsass_*.dmp' "
                          "-Force -ErrorAction SilentlyContinue")
    except Exception as e:
        logger.warning(f"T1003.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
