from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from purplestrike.plugins.siem_connectors.wazuh.connector import WazuhConnector

pytestmark = pytest.mark.asyncio


class FakeResponse:
    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        self._payload = payload or {"rawResponse": {"hits": {"hits": []}}}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class FakeHTTPErrorResponse:
    def __init__(self, status_code: int) -> None:
        self._request = httpx.Request("GET", "https://wazuh.example/rules")
        self._response = httpx.Response(status_code, request=self._request)

    def raise_for_status(self) -> None:
        self._response.raise_for_status()


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


async def test_get_rules_for_technique_uses_wazuh_mitre_filter(monkeypatch) -> None:
    connector = WazuhConnector()
    connector._client = object()
    captured_params: dict[str, Any] = {}

    async def fake_request(
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> FakeResponse:
        assert method == "GET"
        assert endpoint == "/rules"
        captured_params.update(kwargs["params"])
        return FakeResponse(
            {
                "data": {
                    "affected_items": [
                        {
                            "id": "100005",
                            "description": "Domain account activity",
                            "level": 5,
                            "mitre": {"id": ["T1078.002"]},
                        }
                    ]
                }
            }
        )

    monkeypatch.setattr(connector, "_request", fake_request)

    rules = await connector.get_rules_for_technique("T1078.002")

    assert captured_params == {"limit": 500, "mitre": "T1078.002"}
    assert len(rules) == 1
    assert rules[0].mitre_technique_ids == ["T1078.002"]


async def test_get_rules_for_technique_falls_back_when_wazuh_mitre_filter_500(
    monkeypatch,
) -> None:
    connector = WazuhConnector()
    connector._client = object()
    calls: list[dict[str, Any]] = []

    async def fake_request(
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> FakeResponse | FakeHTTPErrorResponse:
        assert method == "GET"
        assert endpoint == "/rules"
        params = dict(kwargs["params"])
        calls.append(params)
        if "mitre" in params:
            return FakeHTTPErrorResponse(500)
        return FakeResponse(
            {
                "data": {
                    "affected_items": [
                        {
                            "id": "100005",
                            "description": "Domain account activity",
                            "level": 5,
                            "mitre": {"id": ["T1078.002"]},
                        },
                        {
                            "id": "100006",
                            "description": "PowerShell activity",
                            "level": 5,
                            "mitre": {"id": ["T1059.001"]},
                        },
                    ]
                }
            }
        )

    monkeypatch.setattr(connector, "_request", fake_request)

    rules = await connector.get_rules_for_technique("T1078.002")

    assert calls == [
        {"limit": 500, "mitre": "T1078.002"},
        {"limit": 500},
    ]
    assert len(rules) == 1
    assert rules[0].mitre_technique_ids == ["T1078.002"]
