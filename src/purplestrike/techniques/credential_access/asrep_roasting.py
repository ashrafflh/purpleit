from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import (
    TargetConnection,
    get_connection,
)
from purplestrike.techniques.scripts import ldap_directory_entry

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        ps_cmd = (
            ldap_directory_entry() +
            "$searcher = New-Object System.DirectoryServices.DirectorySearcher($de); "
            "$searcher.PageSize = 1000; "
            "$searcher.Filter = "
            "'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'; "
            "$searcher.PropertiesToLoad.AddRange(@('samAccountName','userAccountControl')); "
            "$searcher.FindAll() | ForEach-Object { "
            "[PSCustomObject]@{SamAccountName=$_.Properties.samaccountname[0]; "
            "DoesNotRequirePreAuth=$true} } | Format-Table -AutoSize"
        )
        result = await conn.run_ps(ps_cmd)
        return TechniqueResult(
            technique_id="T1558.004",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1558.004 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1558.004",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    """Account enumeration creates no tickets; preserve the existing ticket cache."""
