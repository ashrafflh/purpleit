from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import ps_quote, registry_path

logger = logging.getLogger(__name__)
DEFAULT_KEY = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
_created_keys: set[tuple[str, str]] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Add a registry run key for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        key_path = registry_path(parameters.get("key_path") or DEFAULT_KEY)
        value = parameters.get("value") or "cmd.exe /c echo PurpleStrike"
        ps_cmd = (
            f"$keyPath = {ps_quote(key_path)}; "
            "if (-not (Test-Path -LiteralPath $keyPath)) { "
            "New-Item -Path $keyPath -Force | Out-Null }; "
            "New-ItemProperty -LiteralPath $keyPath "
            f"-Name 'PurpleStrike' -Value {ps_quote(value)} -PropertyType String -ErrorAction Stop"
        )
        result = await conn.run_ps(ps_cmd)
        if result.success:
            _created_keys.add((target, key_path))
        return TechniqueResult(
            technique_id="T1547.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1547.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1547.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str, parameters: dict[str, Any] | None = None) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        ps_path = registry_path((parameters or {}).get("key_path") or DEFAULT_KEY)
        if (target, ps_path) not in _created_keys:
            return
        conn = await get_connection(target)
        result = await conn.run_ps(
            f"Remove-ItemProperty -LiteralPath {ps_quote(ps_path)} "
            f"-Name 'PurpleStrike' -ErrorAction SilentlyContinue"
        )
        if result.success:
            _created_keys.discard((target, ps_path))
    except Exception as e:
        logger.warning(f"T1547.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
