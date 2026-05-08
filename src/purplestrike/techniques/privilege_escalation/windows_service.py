from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a Windows service for persistence and privilege escalation."""
    conn: TargetConnection | None = None
    try:
        service_name = parameters.get("service_name", None)
        binary_path = parameters.get("binary_path", None)
        if not service_name or not binary_path:
            return TechniqueResult(
                technique_id="T1543.003",
                success=False,
                error="Missing required parameters: service_name and binary_path",
                execution_status=ExecutionStatus.FAILURE,
            )
        conn = await get_connection(target)
        create_result = await conn.run_ps(
            f"New-Service -Name '{service_name}' "
            f"-BinaryPathName '{binary_path}' "
            f"-DisplayName '{service_name}' -StartupType Manual"
        )
        if not create_result.success:
            return TechniqueResult(
                technique_id="T1543.003",
                success=False,
                output=create_result.stdout[:4096],
                error=create_result.stderr[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        verify = await conn.run_ps(
            f"Get-Service -Name '{service_name}' | Format-List Name,Status,StartType"
        )
        return TechniqueResult(
            technique_id="T1543.003",
            success=True,
            output=verify.stdout[:4096],
            error=None,
            execution_status=ExecutionStatus.SUCCESS,
        )
    except Exception as e:
        logger.error(f"T1543.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1543.003",
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
            "$services = Get-Service | Where-Object { $_.StartType -eq 'Manual' "
            "-and $_.Status -eq 'Stopped' }; foreach ($svc in $services) { "
            "sc.exe delete $svc.Name 2>$null }"
        )
    except Exception as e:
        logger.warning(f"T1543.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
