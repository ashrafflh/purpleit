from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Open and close an LSASS read handle without copying credential material."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); "
            "$principal = New-Object Security.Principal.WindowsPrincipal($identity); "
            "'LSASS access context: identity=' + $identity.Name + '; elevated=' + "
            "$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
            "try { $ppl = Get-ItemProperty -LiteralPath "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction Stop; "
            "'RunAsPPL configuration=' + $ppl.RunAsPPL + "
            "' (configuration only; runtime protection is not verified)' } "
            "catch { 'RunAsPPL configuration unavailable; runtime protection is unknown' }; "
            "'Effective token privileges:'; whoami.exe /priv; "
            "if ($LASTEXITCODE -ne 0) { 'Token privilege query failed' }; "
            "$global:LASTEXITCODE = 0; "
            "$source = 'using System; using System.Runtime.InteropServices; "
            "public static class PurpleStrikeLsass { "
            '[DllImport("kernel32.dll", SetLastError=true)] '
            "public static extern IntPtr OpenProcess(uint access, bool inherit, int pid); "
            '[DllImport("kernel32.dll")] '
            "public static extern bool CloseHandle(IntPtr handle); }'; "
            "Add-Type -TypeDefinition $source -ErrorAction Stop; "
            "$lsass = Get-Process -Name lsass -ErrorAction Stop; "
            "$access = 0x0410; "
            "$handle = [PurpleStrikeLsass]::OpenProcess($access, $false, $lsass.Id); "
            "if ($handle -eq [IntPtr]::Zero) { "
            "$code = [Runtime.InteropServices.Marshal]::GetLastWin32Error(); "
            "if ($code -eq 5) { throw ('OpenProcess failed with Win32 error 5: Access denied. ' + "
            "'Effective token permissions or LSASS protection may prevent this access; ' + "
            "'the exact cause is not established. No LSASS memory was read.') }; "
            "throw ('OpenProcess failed with Win32 error ' + $code) }; "
            "try { 'Opened LSASS handle; pid=' + $lsass.Id + '; access=0x0410' } "
            "finally { [void][PurpleStrikeLsass]::CloseHandle($handle) }"
        )
        return TechniqueResult(
            technique_id="T1003.001",
            success=result.success,
            output=result.stdout[:4096],
            error=command_error(result)[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
            evidence=(
                ["LSASS was opened with PROCESS_QUERY_INFORMATION and PROCESS_VM_READ."]
                if result.success else []
            ),
        )
    except Exception as e:
        logger.error(f"T1003.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1003.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    """The LSASS handle is closed in the same command and no dump is created."""
