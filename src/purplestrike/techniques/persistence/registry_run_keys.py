from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Add a registry run key for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        key_path = parameters.get("key_path", "")
        value = parameters.get("value", "")
        ps_cmd = (
            f"New-ItemProperty -Path '{key_path}' "
            f"-Name 'PurpleStrike' -Value '{value}' -PropertyType String -Force"
        )
        result = await conn.run_ps(ps_cmd)
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
        conn = await get_connection(target)
        key_path = parameters.get("key_path", "") if parameters else ""
        if key_path:
            ps_path = key_path.replace("HKLM\\", "HKLM:\\").replace(
                "HKLM\\\\", "HKLM:\\"
            )
        else:
            ps_path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        await conn.run_ps(
            f"Remove-ItemProperty -Path '{ps_path}' "
            f"-Name 'PurpleStrike' -ErrorAction SilentlyContinue"
        )
    except Exception as e:
        logger.warning(f"T1547.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
