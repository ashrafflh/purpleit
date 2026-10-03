from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)

SERVICE_NAME = "purplestrike-launch-agent"
SERVICE_PATH = f"/etc/systemd/system/{SERVICE_NAME}.service"
_created_targets: set[str] = set()


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
            'ExecStart=/bin/sh -c "/usr/bin/date +%%s > /tmp/purplestrike_launch_agent_output"\n\n'
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )
        created = await conn.run_command(
            f"test ! -e {SERVICE_PATH} || exit 1; printf '%s' '{service_content}' | "
            f"sudo -n tee {SERVICE_PATH}"
        )
        if not created.success:
            raise RuntimeError(created.stderr or created.stdout or "Systemd creation failed")
        _created_targets.add(target)
        for command in (
            "sudo -n systemctl daemon-reload",
            f"sudo -n systemctl enable {SERVICE_NAME}",
        ):
            result = await conn.run_command(command)
            if not result.success:
                raise RuntimeError(result.stderr or result.stdout or "Systemd setup failed")
        start_result = await conn.run_command(f"sudo -n systemctl start {SERVICE_NAME}")
        await conn.run_command("sleep 2")
        output_result = await conn.run_command(
            "cat /tmp/purplestrike_launch_agent_output"
        )
        combined_output = start_result.stdout + "\n" + output_result.stdout
        success = start_result.success and output_result.success
        return TechniqueResult(
            technique_id="T1569.003",
            success=success,
            output=combined_output[:4096],
            error=(start_result.stderr or output_result.stderr)[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1569.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1569.003",
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
        if target not in _created_targets:
            return
        conn = await get_connection(target)
        result = await conn.run_command(
            f"sudo -n systemctl stop {SERVICE_NAME} && "
            f"sudo -n systemctl disable {SERVICE_NAME} && "
            f"sudo -n rm -f {SERVICE_PATH} /tmp/purplestrike_launch_agent_output && "
            "sudo -n systemctl daemon-reload"
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout or "Systemd cleanup failed")
        _created_targets.discard(target)
    except Exception as e:
        logger.warning(f"T1569.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
