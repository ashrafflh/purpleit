from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection
from purplestrike.techniques.scripts import ps_quote

logger = logging.getLogger(__name__)
_created_services: set[tuple[str, str]] = set()


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
            f"New-Service -Name {ps_quote(service_name)} "
            f"-BinaryPathName {ps_quote(binary_path)} "
            f"-DisplayName {ps_quote(service_name)} -StartupType Manual -ErrorAction Stop"
        )
        if not create_result.success:
            return TechniqueResult(
                technique_id="T1543.003",
                success=False,
                output=create_result.stdout[:4096],
                error=create_result.stderr[:1024],
                execution_status=ExecutionStatus.FAILURE,
            )
        _created_services.add((target, service_name))
        verify = await conn.run_ps(
            f"Get-Service -Name {ps_quote(service_name)} | Format-List Name,Status,StartType"
        )
        if not verify.success:
            return TechniqueResult(
                technique_id="T1543.003",
                success=False,
                output=verify.stdout[:4096],
                error=command_error(verify)[:1024],
                execution_status=ExecutionStatus.FAILURE,
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


async def cleanup(target: str, parameters: dict[str, Any] | None = None) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        name = (parameters or {}).get("service_name", "PurpleStrikePrivEscSvc")
        if (target, name) not in _created_services:
            return
        conn = await get_connection(target)
        result = await conn.run_ps(f"sc.exe delete {ps_quote(name)}")
        if not result.success:
            raise RuntimeError(command_error(result))
        _created_services.discard((target, name))
    except Exception as e:
        logger.warning(f"T1543.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
