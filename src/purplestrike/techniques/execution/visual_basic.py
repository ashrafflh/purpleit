from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and execute a VBScript via cscript on the target."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        vbs_path = "$env:TEMP\\purplestrike_test.vbs"
        out_path = "$env:TEMP\\purplestrike_vbs_output.txt"
        vbs_content = (
            'Set objFSO = CreateObject("Scripting.FileSystemObject")\n'
            'Set objFile = objFSO.CreateTextFile(objFSO.BuildPath('
            'objFSO.GetSpecialFolder(2), "purplestrike_vbs_output.txt"))\n'
            'objFile.WriteLine "VBScript executed successfully"\n'
            'objFile.Close'
        )
        await conn.run_ps(f'Set-Content -Path "{vbs_path}" -Value @\'{vbs_content}\'@')
        result = await conn.run_ps(f"cscript //nologo {vbs_path}")
        output_result = await conn.run_ps(f"Get-Content {out_path} -ErrorAction SilentlyContinue")
        combined_output = result.stdout + "\n" + output_result.stdout
        return TechniqueResult(
            technique_id="T1059.005",
            success=result.success,
            output=combined_output[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1059.005 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1059.005",
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
            "Remove-Item $env:TEMP\\purplestrike_test.vbs -ErrorAction SilentlyContinue"
        )
        await conn.run_ps(
            "Remove-Item $env:TEMP\\purplestrike_vbs_output.txt -ErrorAction SilentlyContinue"
        )
    except Exception as e:
        logger.warning(f"T1059.005 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
