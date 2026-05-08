from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)

ARTIFACT_NAME = "purplestrike_sim_phishing_attachment.docm"


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """SIMULATION ONLY: Create a benign .docm artifact with a macro marker for detection."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        tmp_dir = (
            f"$env:TEMP\\purplestrike; "
            f"if (-not (Test-Path $env:TEMP\\purplestrike)) "
            f"{{ New-Item -ItemType Directory -Path $env:TEMP\\purplestrike }}"
        )
        artifact_content = (
            "PK\\x00\\x00\\x00\\x00"
        )
        create_cmd = (
            f"{tmp_dir}; "
            f"$macroMarker = 'Sub AutoOpen()`n"
            f"' PurpleStrike-SIMULATION-Marker-DO-NOT-EXECUTE `n"
            f"' End Sub'; "
            f"$docmContent = @"
            f"\nPURPLESTRIKE PHISHING SIMULATION ARTIFACT`n"
            f"This file is a simulation marker created by PurpleStrike.`n"
            f"technique_id: T1566.001`n"
            f"NO REAL MALICIOUS CONTENT`n`n"
            f"$macroMarker`n"
            f"@; "
            f"Set-Content -Path '$env:TEMP\\purplestrike\\{ARTIFACT_NAME}' "
            f"-Value $docmContent -Encoding UTF8; "
            f"Write-Output 'Artifact created:'; "
            f"Get-Item '$env:TEMP\\purplestrike\\{ARTIFACT_NAME}' | "
            f"Select-Object FullName,Length,LastWriteTime | Format-List"
        )
        result = await conn.run_ps(create_cmd)
        return TechniqueResult(
            technique_id="T1566.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1566.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1566.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    """Delete the phishing simulation artifact from the target."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        await conn.run_ps(
            f"Remove-Item -Path '$env:TEMP\\purplestrike\\{ARTIFACT_NAME}' "
            f"-Force -ErrorAction SilentlyContinue; "
            f"if ((Get-ChildItem '$env:TEMP\\purplestrike' -ErrorAction SilentlyContinue "
            f"| Measure-Object).Count -eq 0) {{ "
            f"Remove-Item -Path '$env:TEMP\\purplestrike' -Force -Recurse "
            f"-ErrorAction SilentlyContinue }}"
        )
    except Exception as e:
        logger.warning(f"T1566.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
