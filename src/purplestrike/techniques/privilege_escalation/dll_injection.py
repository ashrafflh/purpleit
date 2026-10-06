from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection
from purplestrike.techniques.scripts import ps_quote

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Enumerate processes that could be DLL injection targets (simulation only)."""
    conn: TargetConnection | None = None
    try:
        target_process = parameters.get("target_process")
        dll_path = parameters.get("dll_path")
        if not target_process or not dll_path:
            return TechniqueResult(
                technique_id="T1055.001",
                success=False,
                error="Missing required parameters: target_process and dll_path",
                execution_status=ExecutionStatus.FAILURE,
            )
        process_name = str(target_process).strip()
        if process_name.lower().endswith(".exe"):
            process_name = process_name[:-4]
        conn = await get_connection(target)
        target_match = await conn.run_ps(
            f"$targetProcess = {ps_quote(process_name)}; "
            "Get-Process -ErrorAction Stop | Where-Object { "
            "$_.ProcessName -eq $targetProcess -or [string]$_.Id -eq $targetProcess "
            "} | Select-Object Id, Name, Path | Format-List"
        )
        if not target_match.success:
            return TechniqueResult(
                technique_id="T1055.001",
                success=False,
                output=target_match.stdout[:4096],
                error=f"Target process lookup failed: {command_error(target_match)}"[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        if not target_match.stdout.strip():
            return TechniqueResult(
                technique_id="T1055.001",
                success=False,
                error=(
                    f"Prerequisite not met: target process {target_process!r} is not running "
                    "or visible to this session. Select an existing process name or PID. "
                    "No DLL injection was performed."
                ),
                execution_status=ExecutionStatus.SKIPPED,
            )
        processes = await conn.run_ps(
            "Get-Process -ErrorAction Stop | Select-Object Id, Name, Path | Format-Table -AutoSize"
        )
        if not processes.success:
            return TechniqueResult(
                technique_id="T1055.001",
                success=False,
                output=target_match.stdout[:1024],
                error=f"Process inventory failed: {command_error(processes)}"[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        combined = (
            f"=== All Processes ===\n{processes.stdout[:3072]}\n\n"
            f"=== Target Process Match ===\n{target_match.stdout[:1024]}"
        )
        return TechniqueResult(
            technique_id="T1055.001",
            success=True,
            output=combined[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
            evidence=["The target process was found. No DLL injection was performed."],
        )
    except Exception as e:
        logger.error(f"T1055.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1055.001",
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
    except Exception as e:
        logger.warning(f"T1055.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
