from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """SIMULATION: Create a .url shortcut file to test detection."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        url_path = "$env:TEMP\\purplestrike_test.url"
        url_content = (
            "[InternetShortcut]\n"
            "URL=https://example.invalid/purplestrike-test\n"
            "IconIndex=0\n"
        )
        result = await conn.run_ps(f'Set-Content -Path "{url_path}" -Value @\'{url_content}\'@')
        verify = await conn.run_ps(f"Test-Path {url_path}")
        success = verify.success and verify.stdout.strip() == "True"
        return TechniqueResult(
            technique_id="T1204.001",
            success=success,
            output=f"URL shortcut created at {url_path}",
            error=result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1204.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1204.001",
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
        await conn.run_ps(
            "Remove-Item $env:TEMP\\purplestrike_test.url -ErrorAction SilentlyContinue"
        )
    except Exception as e:
        logger.warning(f"T1204.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
