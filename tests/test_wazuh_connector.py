from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from purplestrike.plugins.siem_connectors.wazuh.connector import WazuhConnector

pytestmark = pytest.mark.asyncio


class FakeResponse:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"rawResponse": {"hits": {"hits": []}}}


async def test_query_alerts_matches_source_by_agent_name_ip_or_id(monkeypatch) -> None:
    connector = WazuhConnector()
    connector._dashboard_client = object()
    captured_payload: dict[str, Any] = {}

    async def fake_dashboard_request(
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> FakeResponse:
        assert method == "POST"
        assert endpoint == "/internal/search/opensearch"
        captured_payload.update(kwargs["json"])
        return FakeResponse()

    monkeypatch.setattr(connector, "_dashboard_request", fake_dashboard_request)

    await connector.query_alerts(
        start_time=datetime.now(UTC),
        end_time=datetime.now(UTC),
        source="10.10.1.108",
    )

    filters = captured_payload["params"]["body"]["query"]["bool"]["filter"]
    source_filter = filters[-1]["bool"]

    assert source_filter["minimum_should_match"] == 1
    assert source_filter["should"] == [
        {"term": {"agent.name": "10.10.1.108"}},
        {"term": {"agent.ip": "10.10.1.108"}},
        {"term": {"agent.id": "10.10.1.108"}},
    ]


async def test_parse_alert_accepts_numeric_wazuh_rule_level() -> None:
    connector = WazuhConnector()

    alert = connector._parse_alert(
        {
            "id": "alert-1",
            "timestamp": "2026-06-12T16:00:00+00:00",
            "agent": {"name": "seif", "ip": "10.10.1.108"},
            "rule": {
                "id": 92900,
                "level": 3,
                "description": "Lsass process was accessed",
                "mitre": {"id": ["T1003.001"]},
            },
        }
    )

    assert alert.rule_id == "92900"
    assert alert.severity == "3"
    assert alert.mitre_technique_ids == ["T1003.001"]
