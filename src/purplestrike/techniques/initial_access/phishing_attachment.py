from __future__ import annotations

import logging
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
        create_cmd = (
            "$artifactDir = Join-Path $env:TEMP 'purplestrike'; "
            "if (-not (Test-Path -LiteralPath $artifactDir)) { "
            "New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null }; "
            f"$artifactPath = Join-Path $artifactDir '{ARTIFACT_NAME}'; "
            "$macroMarker = 'Sub AutoOpen()' + [Environment]::NewLine + "
            "'PurpleStrike-SIMULATION-Marker-DO-NOT-EXECUTE' + [Environment]::NewLine + "
            "'End Sub'; "
            "$docmContent = 'PURPLESTRIKE PHISHING SIMULATION ARTIFACT' + [Environment]::NewLine + "
            "'This file is a simulation marker created by PurpleStrike.' + [Environment]::NewLine + "
            "'technique_id: T1566.001' + [Environment]::NewLine + "
            "'NO REAL MALICIOUS CONTENT' + [Environment]::NewLine + "
            "[Environment]::NewLine + $macroMarker + [Environment]::NewLine; "
            "Set-Content -LiteralPath $artifactPath -Value $docmContent -Encoding UTF8; "
            "Write-Output 'Artifact created:'; "
            "Get-Item -LiteralPath $artifactPath | "
            "Select-Object FullName,Length,LastWriteTime | Format-List"
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
        result = await conn.run_ps(
            "$artifactDir = Join-Path $env:TEMP 'purplestrike'; "
            f"$artifactPath = Join-Path $artifactDir '{ARTIFACT_NAME}'; "
            "[IO.File]::Delete($artifactPath); "
            "if ((Test-Path -LiteralPath $artifactDir) -and "
            "((Get-ChildItem -LiteralPath $artifactDir -ErrorAction SilentlyContinue | "
            "Measure-Object).Count -eq 0)) { "
            "[IO.Directory]::Delete($artifactDir) }"
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
    except Exception as e:
        logger.warning(f"T1566.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
