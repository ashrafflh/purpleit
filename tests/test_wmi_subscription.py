from unittest.mock import AsyncMock

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.persistence import wmi_event_subscription


@pytest.mark.asyncio
@pytest.mark.parametrize("output,success", [
    ("PurpleStrike-T1546.003\nWMI trigger cleanup complete", True),
    ("WMI trigger cleanup complete", False),
    ("unrelated marker", False),
])
async def test_wmi_requires_actual_consumer_marker(monkeypatch, output, success):
    conn = AsyncMock()
    conn.run_ps.side_effect = [CommandResult("binding created", "", 0),
                               CommandResult(output, "", 0)]
    monkeypatch.setattr(wmi_event_subscription, "get_connection", AsyncMock(return_value=conn))
    result = await wmi_event_subscription.execute("wmi-marker-host", {})
    assert result.success is success
    assert bool(result.evidence) is success
    if not success:
        assert "expected marker" in result.error
    conn.run_ps.side_effect = None
    conn.run_ps.return_value = CommandResult("", "", 0)
    await wmi_event_subscription.cleanup("wmi-marker-host")
