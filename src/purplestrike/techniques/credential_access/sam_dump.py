from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import (
    TargetConnection,
    command_error,
    get_connection,
    is_transport_failure,
)

logger = logging.getLogger(__name__)


def _command_output(result: Any, limit: int) -> str:
    text = "\n".join(part for part in (result.stdout, result.stderr) if part)
    return text[:limit]


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        method = (parameters.get("method") or "registry").strip().lower()
        access_result = await conn.run_ps(
            "reg.exe query HKLM\\SAM 2>&1; "
            "reg.exe query HKLM\\SECURITY 2>&1"
        )
        access_output = _command_output(access_result, 1024)
        sam_accessible = access_result.success and "ERROR" not in access_output.upper()
        output_parts = [
            "SAM registry access check: "
            f"{'Accessible' if sam_accessible else 'Access denied'}"
        ]
        if access_output:
            output_parts.append(access_output)
        if is_transport_failure(access_result):
            return TechniqueResult(
                technique_id="T1003.002",
                success=False,
                output="\n".join(output_parts)[:4096],
                error=command_error(access_result)[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )

        if method == "registry":
            sim_result = await conn.run_ps(
                "reg.exe query HKLM\\SAM\\SAM 2>&1 | Select-Object -First 10"
            )
            output_parts.append(
                f"Registry method simulation:\n{_command_output(sim_result, 2048)}"
            )
        elif method == "shadow_copy":
            sim_result = await conn.run_ps(
                "vssadmin.exe list shadows 2>&1; "
                "vssadmin.exe list volumes 2>&1 | Select-Object -First 5"
            )
            output_parts.append(
                f"Shadow copy method simulation:\n{_command_output(sim_result, 2048)}"
            )
        else:
            return TechniqueResult(
                technique_id="T1003.002",
                success=False,
                error=f"Unsupported SAM dump method: {method}",
                output="\n".join(output_parts)[:4096],
                execution_status=ExecutionStatus.FAILURE,
            )
        if is_transport_failure(sim_result):
            return TechniqueResult(
                technique_id="T1003.002",
                success=False,
                output="\n".join(output_parts)[:4096],
                error=command_error(sim_result)[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )

        return TechniqueResult(
            technique_id="T1003.002",
            success=True,
            output="\n".join(output_parts)[:4096],
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
    except Exception as e:
        logger.warning(f"T1003.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
