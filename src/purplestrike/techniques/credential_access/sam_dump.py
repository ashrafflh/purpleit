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
        method = parameters.get("method", "registry")
        access_result = await conn.run_ps("reg query HKLM\\SAM 2>&1; "
                                           "reg query HKLM\\SECURITY 2>&1")
        sam_accessible = access_result.success and "ERROR" not in access_result.stdout
        output = f"SAM registry access check: "
        f"{'Accessible' if sam_accessible else 'Access denied'}\n"
        f"{access_result.stdout[:1024]}\n"
        if method == "registry":
            sim_result = await conn.run_ps(
                "reg query HKLM\\SAM\\SAM 2>&1 | Select-Object -First 10"
            )
            output += f"Registry method simulation:\n{sim_result.stdout[:2048]}"
        elif method == "shadow_copy":
            sim_result = await conn.run_ps(
                "vssadmin list shadows 2>&1; "
                "vssadmin list volumes 2>&1 | Select-Object -First 5"
            )
            output += f"Shadow copy method simulation:\n{sim_result.stdout[:2048]}"
        else:
            output += f"Unknown method: {method}"
        return TechniqueResult(
            technique_id="T1003.002",
            success=True,
            output=output[:4096],
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1003.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1003.002",
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
        await conn.run_ps("Remove-Item -Path 'C:\\Windows\\Temp\\SAM_*' "
                          "-Force -ErrorAction SilentlyContinue; "
                          "Remove-Item -Path 'C:\\Windows\\Temp\\SYSTEM_*' "
                          "-Force -ErrorAction SilentlyContinue; "
                          "Remove-Item -Path 'C:\\Windows\\Temp\\SECURITY_*' "
                          "-Force -ErrorAction SilentlyContinue")
        await conn.run_ps("vssadmin delete shadows /all /quiet 2>$null")
    except Exception as e:
        logger.warning(f"T1003.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
