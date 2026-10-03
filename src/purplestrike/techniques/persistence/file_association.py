from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)
_created_targets: set[str] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and invoke an isolated per-user file association."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            "$extension = 'HKCU:\\Software\\Classes\\.purplestrike'; "
            "$class = 'HKCU:\\Software\\Classes\\PurpleStrikeFile'; "
            "if ((Test-Path -LiteralPath $extension) -or (Test-Path -LiteralPath $class)) { "
            "throw 'Existing PurpleStrike test association will not be overwritten' }; "
            "New-Item -Path $extension -Force | Out-Null; "
            "Set-Item -LiteralPath $extension -Value 'PurpleStrikeFile'; "
            "$commandKey = Join-Path $class 'shell\\open\\command'; "
            "New-Item -Path $commandKey -Force | Out-Null; "
            "Set-Item -LiteralPath $commandKey -Value "
            "'cmd.exe /d /c \"echo PurpleStrike-T1546.001>"
            "%TEMP%\\purplestrike_assoc_marker.txt\"'; "
            "$testFile = Join-Path $env:TEMP 'purplestrike_test.purplestrike'; "
            "$marker = Join-Path $env:TEMP 'purplestrike_assoc_marker.txt'; "
            "[IO.File]::WriteAllText($testFile, 'PurpleStrike association test'); "
            "[IO.File]::Delete($marker); "
            "Start-Process -FilePath $testFile -Wait; "
            "for ($i=0; $i -lt 20 -and !(Test-Path -LiteralPath $marker); $i++) "
            "{ Start-Sleep -Milliseconds 250 }; "
            "Get-Content -LiteralPath $marker -ErrorAction Stop"
        )
        if result.success:
            _created_targets.add(target)
        return TechniqueResult(
            technique_id="T1546.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
            artifacts=[
                "%TEMP%\\purplestrike_test.purplestrike",
                "%TEMP%\\purplestrike_assoc_marker.txt",
            ],
            evidence=["Opening the isolated extension invoked its registered handler."],
        )
    except Exception as e:
        logger.error(f"T1546.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1546.001",
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
        cleanup_cmd = (
            "Remove-Item -LiteralPath 'HKCU:\\Software\\Classes\\.purplestrike', "
            "'HKCU:\\Software\\Classes\\PurpleStrikeFile' -Recurse -Force "
            "-ErrorAction SilentlyContinue; "
            "Remove-Item -LiteralPath (Join-Path $env:TEMP "
            "'purplestrike_test.purplestrike'), (Join-Path $env:TEMP "
            "'purplestrike_assoc_marker.txt') -Force -ErrorAction SilentlyContinue"
        )
        removed = await conn.run_ps(cleanup_cmd)
        if not removed.success:
            raise RuntimeError(removed.stderr or removed.stdout or "Association cleanup failed")
        _created_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1546.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
