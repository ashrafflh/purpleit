from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)

ARTIFACT_NAME = "purplestrike_sim_phishing_link.url"


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """SIMULATION ONLY: Create a benign .url shortcut artifact pointing to a test URL."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        create_cmd = (
            "if (-not (Test-Path $env:TEMP\\purplestrike)) "
            "{ New-Item -ItemType Directory -Path $env:TEMP\\purplestrike }; "
            "$urlContent = @\"\n"
            "[InternetShortcut]\n"
            "URL=https://purplestrike-simulation.example.invalid/\n"
            "IconIndex=0\n"
            "IconFile=C:\\Windows\\System32\\SHELL32.dll\n"
            "\"@; "
            f"Set-Content -Path '$env:TEMP\\purplestrike\\{ARTIFACT_NAME}' "
            f"-Value $urlContent -Encoding ASCII; "
            f"Write-Output 'Artifact created:'; "
            f"Get-Item '$env:TEMP\\purplestrike\\{ARTIFACT_NAME}' | "
            f"Select-Object FullName,Length,LastWriteTime | Format-List"
        )
        result = await conn.run_ps(create_cmd)
        return TechniqueResult(
            technique_id="T1566.002",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1566.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1566.002",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    """Delete the phishing link simulation artifact from the target."""
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
        logger.warning(f"T1566.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
