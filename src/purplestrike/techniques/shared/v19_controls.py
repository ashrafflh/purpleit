from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import command_error, get_connection

logger = logging.getLogger(__name__)


_WINDOWS_ARTIFACTS: dict[str, str] = {
    "T1684": r"$env:TEMP\purplestrike_social_engineering.txt",
    "T1684.001": r"$env:TEMP\purplestrike_impersonation.txt",
    "T1684.002": r"$env:TEMP\purplestrike_spoofed_message.eml",
    "T1685.003": r"$env:TEMP\purplestrike_security_status.html",
}

_LINUX_ARTIFACTS: dict[str, str] = {
    "T1684": "/tmp/purplestrike_social_engineering.txt",
    "T1684.001": "/tmp/purplestrike_impersonation.txt",
    "T1684.002": "/tmp/purplestrike_spoofed_message.eml",
    "T1685.003": "/tmp/purplestrike_security_status.html",
    "T1685.006": "/tmp/purplestrike_system.log",
}


def _windows_script(technique_id: str) -> str:
    scripts = {
        "T1027.018": (
            "$ErrorActionPreference='Stop'; $i=[char]0x2063; "
            "$p=Join-Path $env:TEMP ('purple'+$i+'strike.ps1'); "
            "Set-Content -LiteralPath $p -Encoding UTF8 "
            "-Value \"Write-Output 'PurpleStrike invisible Unicode executed'\"; "
            "$content=Get-Content -LiteralPath $p -Raw; Invoke-Expression $content; "
            "Write-Output ('artifact=' + $p); "
            "Write-Output ('codepoint=U+{0:X4}' -f [int][char]$i)"
        ),
        "T1684": (
            "$ErrorActionPreference='Stop'; $p=Join-Path $env:TEMP "
            "'purplestrike_social_engineering.txt'; "
            "Set-Content -LiteralPath $p -Encoding UTF8 "
            "-Value 'SIMULATION ONLY: contact support and run the supplied diagnostic.'; "
            "Get-Item -LiteralPath $p | Select-Object FullName,Length"
        ),
        "T1684.001": (
            "$ErrorActionPreference='Stop'; $p=Join-Path $env:TEMP "
            "'purplestrike_impersonation.txt'; "
            "Set-Content -LiteralPath $p -Encoding UTF8 "
            "-Value 'SIMULATION ONLY: message claiming to be the internal help desk.'; "
            "Get-Item -LiteralPath $p | Select-Object FullName,Length"
        ),
        "T1684.002": (
            "$ErrorActionPreference='Stop'; $p=Join-Path $env:TEMP "
            "'purplestrike_spoofed_message.eml'; "
            "$body=@('From: helpdesk@example.invalid','Return-Path: attacker@example.invalid',"
            "'To: test@example.invalid','Subject: PurpleStrike simulation','',"
            "'No message was transmitted.'); "
            "Set-Content -LiteralPath $p -Encoding ASCII -Value $body; "
            "Get-Item -LiteralPath $p | Select-Object FullName,Length"
        ),
        "T1685": (
            "$ErrorActionPreference='Stop'; "
            "Get-Service -Name EventLog,MpsSvc,WinDefend -ErrorAction SilentlyContinue | "
            "Select-Object Name,Status,StartType; Write-Output 'security-tool-inventory-complete'"
        ),
        "T1685.001": (
            "$ErrorActionPreference='Stop'; Get-Service -Name EventLog | "
            "Select-Object Name,Status,StartType; wevtutil gl Security"
        ),
        "T1685.002": (
            "$ErrorActionPreference='Stop'; Get-Command aws,az,gcloud "
            "-ErrorAction SilentlyContinue | Select-Object Name,Source; "
            "Write-Output 'cloud-log-tool-prerequisite-check-complete'"
        ),
        "T1685.003": (
            "$ErrorActionPreference='Stop'; $p=Join-Path $env:TEMP "
            "'purplestrike_security_status.html'; "
            "Set-Content -LiteralPath $p -Encoding UTF8 -Value "
            "'<html><body><h1>SIMULATION</h1><p>Security status: healthy</p></body></html>'; "
            "Get-Item -LiteralPath $p | Select-Object FullName,Length"
        ),
        "T1685.005": (
            "$ErrorActionPreference='Stop'; wevtutil gl Security; "
            "Write-Output 'No event log was cleared by this safety-bounded probe.'"
        ),
        "T1686": (
            "$ErrorActionPreference='Stop'; Get-NetFirewallProfile | "
            "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction"
        ),
        "T1686.001": (
            "$ErrorActionPreference='Stop'; Get-Command aws,az,gcloud "
            "-ErrorAction SilentlyContinue | Select-Object Name,Source; "
            "Write-Output 'cloud-firewall-prerequisite-check-complete'"
        ),
        "T1686.002": (
            "$ErrorActionPreference='Stop'; Get-NetRoute -ErrorAction SilentlyContinue | "
            "Select-Object -First 10 DestinationPrefix,NextHop,InterfaceAlias; "
            "Write-Output 'network-firewall-prerequisite-check-complete'"
        ),
        "T1686.003": (
            "$ErrorActionPreference='Stop'; $name='PurpleStrike T1686.003'; "
            "Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue; "
            "New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Allow "
            "-RemoteAddress 192.0.2.1 -Protocol TCP -RemotePort 9 | Out-Null; "
            "$rule=Get-NetFirewallRule -DisplayName $name -ErrorAction Stop; "
            "Write-Output ('temporary-rule=' + $rule.DisplayName); "
            "Write-Output ('enabled=' + $rule.Enabled)"
        ),
        "T1687": (
            "$ErrorActionPreference='Stop'; Get-Service -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -match 'Defend|Sense|EventLog|Sysmon|MpsSvc' } | "
            "Select-Object Name,Status,StartType; "
            "Write-Output 'No vulnerability was exploited.'"
        ),
        "T1688": (
            "$ErrorActionPreference='Stop'; bcdedit /enum '{current}'; "
            "Write-Output 'Boot configuration was not modified.'"
        ),
        "T1689": (
            "$ErrorActionPreference='Stop'; $PSVersionTable | Format-List; "
            "Get-Command powershell,pwsh,python,python2 -ErrorAction SilentlyContinue | "
            "Select-Object Name,Version,Source; Write-Output 'No runtime was downgraded.'"
        ),
        "T1690": (
            "$ErrorActionPreference='Stop'; $MaximumHistoryCount=0; "
            "Import-Module PSReadLine -ErrorAction SilentlyContinue; "
            "if (Get-Command Set-PSReadLineOption -ErrorAction SilentlyContinue) { "
            "Set-PSReadLineOption -HistorySaveStyle SaveNothing }; "
            "Write-Output 'history-saving-disabled-for-this-PurpleStrike-process'"
        ),
    }
    return scripts.get(technique_id, "")


def _linux_command(technique_id: str) -> str:
    commands = {
        "T1027.018": (
            "name=\"/tmp/purple$(printf '\\342\\201\\243')strike.sh\"; "
            "printf '%s\\n' '#!/bin/sh' "
            "\"printf '%s\\n' 'PurpleStrike invisible Unicode executed'\" > \"$name\"; "
            "chmod 700 \"$name\"; \"$name\"; "
            "printf 'artifact=%s\\ncodepoint=U+2063\\n' \"$name\""
        ),
        "T1684": (
            "printf '%s\\n' 'SIMULATION ONLY: contact support and run the supplied diagnostic.' "
            "> /tmp/purplestrike_social_engineering.txt; "
            "stat /tmp/purplestrike_social_engineering.txt"
        ),
        "T1684.001": (
            "printf '%s\\n' 'SIMULATION ONLY: message claiming to be the internal help desk.' "
            "> /tmp/purplestrike_impersonation.txt; "
            "stat /tmp/purplestrike_impersonation.txt"
        ),
        "T1684.002": (
            "printf '%s\\n' 'From: helpdesk@example.invalid' "
            "'Return-Path: attacker@example.invalid' 'To: test@example.invalid' "
            "'Subject: PurpleStrike simulation' '' 'No message was transmitted.' "
            "> /tmp/purplestrike_spoofed_message.eml; "
            "stat /tmp/purplestrike_spoofed_message.eml"
        ),
        "T1685": (
            "for service in auditd rsyslog syslog-ng; do "
            "systemctl is-active \"$service\" 2>/dev/null || true; done; "
            "printf '%s\\n' security-tool-inventory-complete"
        ),
        "T1685.002": (
            "for tool in aws az gcloud; do command -v \"$tool\" 2>/dev/null || true; done; "
            "printf '%s\\n' cloud-log-tool-prerequisite-check-complete"
        ),
        "T1685.003": (
            "printf '%s\\n' '<html><body><h1>SIMULATION</h1>"
            "<p>Security status: healthy</p></body></html>' "
            "> /tmp/purplestrike_security_status.html; "
            "stat /tmp/purplestrike_security_status.html"
        ),
        "T1685.004": (
            "auditctl -s 2>/dev/null || true; systemctl is-active auditd 2>/dev/null || true; "
            "printf '%s\\n' 'Linux audit configuration was not modified.'"
        ),
        "T1685.006": (
            "printf '%s\\n' 'PurpleStrike isolated log marker' "
            "> /tmp/purplestrike_system.log; : > /tmp/purplestrike_system.log; "
            "test ! -s /tmp/purplestrike_system.log; "
            "printf '%s\\n' 'isolated-log-truncated=/tmp/purplestrike_system.log'"
        ),
        "T1686": (
            "(nft list ruleset 2>/dev/null || iptables -S 2>/dev/null || true) | head -n 30; "
            "printf '%s\\n' 'Firewall configuration was not modified.'"
        ),
        "T1686.001": (
            "for tool in aws az gcloud; do command -v \"$tool\" 2>/dev/null || true; done; "
            "printf '%s\\n' cloud-firewall-prerequisite-check-complete"
        ),
        "T1686.002": (
            "ip route 2>/dev/null | head -n 10 || true; "
            "printf '%s\\n' network-firewall-prerequisite-check-complete"
        ),
        "T1687": (
            "ps -eo pid,comm,args | grep -E 'auditd|falcon|defender|sysmon' | "
            "grep -v grep || true; printf '%s\\n' 'No vulnerability was exploited.'"
        ),
        "T1689": (
            "for tool in python2 python3 openssl; do "
            "command -v \"$tool\" 2>/dev/null || true; done; "
            "printf '%s\\n' 'No runtime or protocol was downgraded.'"
        ),
        "T1690": (
            "HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 bash -c "
            "'unset HISTFILE; history -c 2>/dev/null || true; "
            "printf \"%s\\n\" history-logging-disabled-for-this-PurpleStrike-shell'"
        ),
    }
    return commands.get(technique_id, "")


def _artifact_paths(technique_id: str, windows: bool) -> list[str]:
    mapping = _WINDOWS_ARTIFACTS if windows else _LINUX_ARTIFACTS
    path = mapping.get(technique_id)
    return [path] if path else []


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Execute safe v19 Stealth and Defense Impairment BAS scenarios."""
    technique_id = str(parameters.get("_technique_id", ""))
    conn = None
    try:
        conn = await get_connection(target)
        command = (
            _windows_script(technique_id) if conn.is_windows else _linux_command(technique_id)
        )
        if not command:
            return TechniqueResult(
                technique_id=technique_id or "unknown",
                success=False,
                error=f"No safe procedure is defined for {technique_id} on {conn.os_type}",
                execution_status=ExecutionStatus.FAILURE,
            )

        result = await conn.run_ps(command) if conn.is_windows else await conn.run_command(command)
        output = result.stdout[:4096]
        return TechniqueResult(
            technique_id=technique_id,
            success=result.success,
            output=output,
            error=command_error(result)[:1024] if not result.success else None,
            artifacts=_artifact_paths(technique_id, conn.is_windows),
            evidence=[
                f"scenario={technique_id}",
                f"platform={conn.os_type}",
                output[:1024],
            ],
            execution_status=(
                ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE
            ),
        )
    except Exception as error:
        logger.error("%s execution failed: %s", technique_id, error)
        return TechniqueResult(
            technique_id=technique_id or "unknown",
            success=False,
            error=str(error),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str, parameters: dict[str, Any] | None = None) -> None:
    """Remove only artifacts and firewall rules created by this executor."""
    conn = None
    try:
        conn = await get_connection(target)
        if conn.is_windows:
            command = (
                "$i=[char]0x2063; "
                "$paths=@("
                "(Join-Path $env:TEMP ('purple'+$i+'strike.ps1')) ,"
                "(Join-Path $env:TEMP 'purplestrike_social_engineering.txt') ,"
                "(Join-Path $env:TEMP 'purplestrike_impersonation.txt') ,"
                "(Join-Path $env:TEMP 'purplestrike_spoofed_message.eml') ,"
                "(Join-Path $env:TEMP 'purplestrike_security_status.html')); "
                "foreach($p in $paths){ Remove-Item -LiteralPath $p -Force "
                "-ErrorAction SilentlyContinue }; "
                "Remove-NetFirewallRule -DisplayName 'PurpleStrike T1686.003' "
                "-ErrorAction SilentlyContinue"
            )
            result = await conn.run_ps(command)
        else:
            command = (
                "unicode_name=\"/tmp/purple$(printf '\\342\\201\\243')strike.sh\"; "
                "rm -f -- \"$unicode_name\" "
                "/tmp/purplestrike_social_engineering.txt "
                "/tmp/purplestrike_impersonation.txt "
                "/tmp/purplestrike_spoofed_message.eml "
                "/tmp/purplestrike_security_status.html "
                "/tmp/purplestrike_system.log"
            )
            result = await conn.run_command(command)
        if not result.success:
            raise RuntimeError(command_error(result, "v19 scenario cleanup failed"))
    except Exception as error:
        logger.warning("v19 scenario cleanup failed on %s: %s", target, error)
    finally:
        if conn:
            await conn.disconnect()
