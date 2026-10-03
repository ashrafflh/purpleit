from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import ps_quote, registry_path

logger = logging.getLogger(__name__)
DEFAULT_KEY = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
_created_values: dict[tuple[str, str, str], str] = {}


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Add a registry run key for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        key_path = registry_path(parameters.get("key_path") or DEFAULT_KEY)
        value = parameters.get("value") or "cmd.exe /c echo PurpleStrike"
        name = parameters.get("value_name") or f"PurpleStrike_{uuid4().hex}"
        ps_cmd = (
            f"$keyPath = {ps_quote(key_path)}; "
            "if (-not (Test-Path -LiteralPath $keyPath)) { "
            "New-Item -Path $keyPath -Force | Out-Null }; "
            "New-ItemProperty -LiteralPath $keyPath "
            f"-Name {ps_quote(name)} -Value {ps_quote(value)} -PropertyType String -ErrorAction Stop"
        )
        result = await conn.run_ps(ps_cmd)
        if result.success:
            _created_values[(target, key_path, name)] = value
        return TechniqueResult(
            technique_id="T1547.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
            artifacts=[f"{key_path}\\{name}"] if result.success else [],
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
        name = (parameters or {}).get("value_name")
        owned = [(key, value) for key, value in _created_values.items()
                 if key[:2] == (target, ps_path) and (name is None or key[2] == name)]
        if not owned:
            return
        conn = await get_connection(target)
        for key, value in owned:
            result = await conn.run_ps(
                "$ErrorActionPreference = 'Stop'; "
                f"$key = Get-Item -LiteralPath {ps_quote(ps_path)} -ErrorAction SilentlyContinue; "
                f"$name = {ps_quote(key[2])}; "
                "if ($key -and $key.GetValueNames() -contains $name) { "
                f"if ($key.GetValue($name) -ne {ps_quote(value)}) {{ "
                "throw 'Run value changed since execution; preserving it' }; "
                f"Remove-ItemProperty -LiteralPath {ps_quote(ps_path)} -Name $name }}"
            )
            if result.success:
                del _created_values[key]
    except Exception as e:
        logger.warning(f"T1547.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
