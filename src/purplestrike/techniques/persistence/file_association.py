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
            "$handler = Join-Path $env:TEMP 'purplestrike_assoc_handler.vbs'; "
            "$testFile = Join-Path $env:TEMP 'purplestrike_test.purplestrike'; "
            "$marker = Join-Path $env:TEMP 'purplestrike_assoc_marker.txt'; "
            "[IO.File]::Delete($marker); "
            "$vbs = @("
            "'Set shell = CreateObject(\"WScript.Shell\")',"
            "'marker = shell.ExpandEnvironmentStrings(\"%TEMP%\\purplestrike_assoc_marker.txt\")',"
            "'Set stream = CreateObject(\"Scripting.FileSystemObject\")"
            ".CreateTextFile(marker, True)',"
            "'stream.WriteLine \"PurpleStrike-T1546.001\"',"
            "'stream.Close'); "
            "Set-Content -LiteralPath $handler -Encoding ASCII -Value $vbs; "
            "$wscript = Join-Path $env:SystemRoot 'System32\\wscript.exe'; "
            "$payload = '\"' + $wscript + '\" //B //NoLogo \"' + "
            "$handler + '\" \"%1\"'; "
            "(Get-Item -LiteralPath $commandKey).SetValue('', $payload, "
            "[Microsoft.Win32.RegistryValueKind]::String); "
            "[IO.File]::WriteAllText($testFile, 'PurpleStrike association test'); "
            "if (-not ('PurpleStrike.ShellNative' -as [type])) { "
            "Add-Type -Namespace PurpleStrike -Name ShellNative -MemberDefinition '"
            "[DllImport(\"shell32.dll\", CharSet=CharSet.Unicode, SetLastError=true)] "
            "public static extern IntPtr ShellExecute(IntPtr window, string operation, "
            "string file, string parameters, string directory, int showCommand); "
            "[DllImport(\"shell32.dll\")] public static extern void SHChangeNotify("
            "uint eventId, uint flags, IntPtr item1, IntPtr item2);' }; "
            "[PurpleStrike.ShellNative]::SHChangeNotify(0x08000000, 0, "
            "[IntPtr]::Zero, [IntPtr]::Zero); "
            "$launch = [PurpleStrike.ShellNative]::ShellExecute("
            "[IntPtr]::Zero, 'open', $testFile, $null, $env:TEMP, 0); "
            "if ($launch.ToInt64() -le 32) { "
            "throw ('ShellExecute failed with code ' + $launch.ToInt64()) }; "
            "for ($i=0; $i -lt 60 -and !(Test-Path -LiteralPath $marker); $i++) "
            "{ Start-Sleep -Milliseconds 250 }; "
            "if (!(Test-Path -LiteralPath $marker)) { "
            "throw 'Registered file-association handler did not produce its marker' }; "
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
                "%TEMP%\\purplestrike_assoc_handler.vbs",
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
            "'purplestrike_assoc_marker.txt'), (Join-Path $env:TEMP "
            "'purplestrike_assoc_handler.vbs') -Force -ErrorAction SilentlyContinue"
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
