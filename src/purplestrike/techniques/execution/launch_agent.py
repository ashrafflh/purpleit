from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)

SERVICE_NAME = "purplestrike-launch-agent"
SERVICE_PATH = f"/etc/systemd/system/{SERVICE_NAME}.service"


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and start a systemd service as a launch agent."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        service_content = (
            f"[Unit]\n"
            f"Description=PurpleStrike Launch Agent Test\n\n"
            f"[Service]\n"
            f"Type=oneshot\n"
            f"ExecStart=/usr/bin/date +%s > /tmp/purplestrike_launch_agent_output\n\n"
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )
        await conn.run_command(f"echo '{service_content}' | sudo tee {SERVICE_PATH}")
        await conn.run_command("sudo systemctl daemon-reload")
        await conn.run_command(f"sudo systemctl enable {SERVICE_NAME}")
        start_result = await conn.run_command(f"sudo systemctl start {SERVICE_NAME}")
        await conn.run_command("sleep 2")
        output_result = await conn.run_command(
            "cat /tmp/purplestrike_launch_agent_output 2>/dev/null || echo 'no output yet'"
        )
        combined_output = start_result.stdout + "\n" + output_result.stdout
        success = start_result.success
        return TechniqueResult(
            technique_id="T1569.001",
            success=success,
            output=combined_output[:4096],
            error=start_result.stderr[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1569.001 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1569.001",
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
        await conn.run_command(f"sudo systemctl stop {SERVICE_NAME} 2>/dev/null || true")
        await conn.run_command(f"sudo systemctl disable {SERVICE_NAME} 2>/dev/null || true")
        await conn.run_command(f"sudo rm -f {SERVICE_PATH}")
        await conn.run_command("sudo systemctl daemon-reload")
        await conn.run_command(
            "rm -f /tmp/purplestrike_launch_agent_output"
        )
    except Exception as e:
        logger.warning(f"T1569.001 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
