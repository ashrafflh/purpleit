from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Simulate access via external remote services such as VPN, RDP, or Citrix."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        service_type = parameters.get("service_type", "rdp")
        if conn.is_windows:
            if service_type == "rdp":
                result = await conn.run_ps(
                    "Get-Service TermService -ErrorAction SilentlyContinue | "
                    "Select-Object Name,Status,StartType | Format-List; "
                    "Test-Connection -ComputerName localhost -Count 1 -Quiet; "
                    "query termserver 2>$null"
                )
            elif service_type == "vpn":
                result = await conn.run_ps(
                    "Get-Service -Name '*vpn*','*ras*' -ErrorAction SilentlyContinue | "
                    "Select-Object Name,Status,StartType | Format-List; "
                    "Get-NetAdapter | "
                    "Where-Object { $_.InterfaceDescription -match 'VPN|tunnel' } | "
                    "Select-Object Name,Status | Format-List"
                )
            else:
                result = await conn.run_ps(
                    "Get-Service -Name '*citrix*','*ica*' -ErrorAction SilentlyContinue | "
                    "Select-Object Name,Status,StartType | Format-List; "
                    "Test-Connection -ComputerName localhost -Count 1 -Quiet"
                )
        else:
            if service_type == "vpn":
                result = await conn.run_command(
                    "systemctl list-units --type=service --all 2>/dev/null | "
                    "grep -iE 'vpn|openvpn|ipsec|strongswan|libreswan' ; "
                    "ip link show 2>/dev/null | grep -iE 'tun|tap|vpn'"
                )
            elif service_type == "rdp":
                result = await conn.run_command(
                    "systemctl list-units --type=service --all 2>/dev/null | "
                    "grep -iE 'xrdp|vnc|x11rdp' ; "
                    "ss -tlnp 2>/dev/null | grep -E '3389|3390|5900'"
                )
            else:
                result = await conn.run_command(
                    "systemctl list-units --type=service --all 2>/dev/null | "
                    "grep -iE 'citrix|ica' ; "
                    "ss -tlnp 2>/dev/null | grep -E '1494|2598'"
                )
        return TechniqueResult(
            technique_id="T1133",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1133 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1133",
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
        conn = await get_connection(target)
    except Exception as e:
        logger.warning(f"T1133 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
