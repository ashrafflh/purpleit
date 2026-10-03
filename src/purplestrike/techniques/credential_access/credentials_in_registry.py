from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection
from purplestrike.techniques.scripts import ps_quote, registry_path

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        registry_paths = parameters.get("registry_paths", "HKLM\\SOFTWARE;HKCU\\SOFTWARE")
        paths = registry_paths.split(";")
        path_filter = ",".join(ps_quote(registry_path(p.strip())) for p in paths)
        max_depth = max(0, min(int(parameters.get("max_depth", 2)), 5))
        max_keys = max(1, min(int(parameters.get("max_keys", 500)), 5000))
        ps_cmd = (
            f"$regPaths = @({path_filter}); "
            f"$maxKeys = {max_keys}; $maxDepth = {max_depth}; "
            "$results = @(); $visited = 0; $unreadable = 0; $limited = $false; "
            "$queue = [Collections.Generic.Queue[object]]::new(); "
            "foreach ($path in $regPaths) { $queue.Enqueue(@{Path=$path;Depth=0}) }; "
            "$watch = [Diagnostics.Stopwatch]::StartNew(); "
            "while ($queue.Count -gt 0 -and $visited -lt $maxKeys "
            "-and $watch.Elapsed.TotalSeconds -lt 40) { "
            "$node = $queue.Dequeue(); $key = $null; $visited++; "
            "try { $key = Get-Item -LiteralPath $node.Path -ErrorAction Stop; "
            "foreach ($name in $key.GetValueNames()) { "
            "if ($name -match 'Password|PWD|Credential|SecureString|Pass|Key|Secret|Token') { "
            '$results += "Key: $($node.Path) | Name: $name" } }; '
            "if ($node.Depth -lt $maxDepth) { foreach ($child in $key.GetSubKeyNames()) { "
            "if ($visited + $queue.Count -ge $maxKeys) { $limited = $true; break }; "
            "$queue.Enqueue(@{Path=($node.Path + '\\' + $child);Depth=($node.Depth + 1)}) "
            "} } } catch { $unreadable++ } finally { if ($key) { $key.Close() } } }; "
            '"Registry keys inspected: " + $visited; '
            '"Unreadable keys: " + $unreadable; '
            '"Scan limit reached: " + ($limited -or $queue.Count -gt 0); '
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
