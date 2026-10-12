from __future__ import annotations

from datetime import UTC, datetime, timedelta
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


async def test_catalog_cache_is_shared_across_techniques(monkeypatch) -> None:
    connector = WazuhConnector()
    connector._client = object()
    calls = []

    async def request(method, endpoint, **kwargs):
        calls.append(endpoint)
        return FakeResponse({"data": {"affected_items": [
            {"id": 1, "mitre": ["T1059.001"]},
            {"id": 2, "mitre": ["T1053.005"]},
        ], "total_affected_items": 2}})

    monkeypatch.setattr(connector, "_request", request)
    await connector.get_rules_for_technique("")
    assert [r.rule_id for r in await connector.get_rules_for_technique("T1053.005")] == ["2"]
    assert [r.rule_id for r in await connector.get_rules_for_technique("T1059.001")] == ["1"]
    assert calls == ["/rules"]


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


async def test_rule_lookup_reads_later_pages(monkeypatch) -> None:
    connector = WazuhConnector()
    connector._client = object()
    offsets = []

    async def request(method, endpoint, **kwargs):
        offset = kwargs["params"].get("offset", 0)
        offsets.append(offset)
        items = ([{"id": i, "mitre": ["T1059.001"]} for i in range(500)]
                 if offset == 0 else [{"id": 91815, "mitre": ["T1059.001"]}])
        return FakeResponse({"data": {"affected_items": items, "total_affected_items": 501}})

    monkeypatch.setattr(connector, "_request", request)
    rules = await connector.get_rules_for_technique("T1059.001")
    assert offsets == [0, 500]
    assert rules[-1].rule_id == "91815"


async def test_alert_query_failure_is_not_an_empty_result(monkeypatch) -> None:
    connector = WazuhConnector()
    connector._dashboard_client = object()

    async def request(*args, **kwargs):
        raise httpx.ConnectError("SIEM unavailable")

    monkeypatch.setattr(connector, "_dashboard_request", request)
    with pytest.raises(httpx.ConnectError, match="SIEM unavailable"):
        await connector.query_alerts(datetime.now(UTC), datetime.now(UTC))


async def test_alert_query_reads_later_pages(monkeypatch) -> None:
    connector = WazuhConnector()
    connector._dashboard_client = object()
    offsets = []

    async def request(*args, **kwargs):
        offset = kwargs["json"]["params"]["body"].get("from", 0)
        offsets.append(offset)
        ids = range(500) if offset == 0 else [500]
        hits = [{"_source": {"id": str(i), "timestamp": "2026-10-03T09:43:44Z",
                             "rule": {"id": "91815"}}} for i in ids]
        return FakeResponse({"rawResponse": {"hits": {"hits": hits}}})

    monkeypatch.setattr(connector, "_dashboard_request", request)
    alerts = await connector.query_alerts(datetime.now(UTC), datetime.now(UTC))
    assert offsets == [0, 500]
    assert len(alerts) == 501


@pytest.mark.parametrize("manager_offset", [-120, -6, 120])
async def test_live_clock_offset_regression_keeps_current_alert_and_excludes_prior_event(
    monkeypatch, manager_offset,
):
    from purplestrike.validation.engine import DetectionValidationEngine

    start = datetime(2026, 10, 12, 19, 10, 2, tzinfo=UTC)
    end = start + timedelta(seconds=30)
    occurrence = start + timedelta(seconds=1)
    documents = [
        {
            "id": "current-service",
            "timestamp": (occurrence + timedelta(seconds=manager_offset)).isoformat(),
            "rule": {"id": "91818", "mitre": {"id": ["T1543.003"]}},
            "data": {"win": {"system": {"systemTime": occurrence.isoformat()}}},
        },
        {
            "id": "previous-step",
            "timestamp": occurrence.isoformat(),
            "rule": {"id": "91818", "mitre": {"id": ["T1543.003"]}},
            "data": {"win": {"system": {
                "systemTime": (start - timedelta(seconds=5)).isoformat(),
            }}},
        },
        {
            "id": "without-windows-time",
            "timestamp": occurrence.isoformat(),
            "rule": {"id": "91818", "mitre": {"id": ["T1543.003"]}},
        },
        {
            "id": "routine-logon",
            "timestamp": occurrence.isoformat(),
            "rule": {"id": "92657"},
        },
    ]

    def matches_time_query(query, document):
        if "bool" in query:
            return sum(matches_time_query(q, document) for q in query["bool"]["should"]) >= (
                query["bool"]["minimum_should_match"]
            )
        field, bounds = next(iter(query["range"].items()))
        value = document
        for key in field.split("."):
            value = value.get(key, {})
        if not value:
            return False
        return (
            datetime.fromisoformat(bounds["gte"])
            <= datetime.fromisoformat(value)
            <= datetime.fromisoformat(bounds["lte"])
        )

    async def search(method, endpoint, **kwargs):
        time_query = kwargs["json"]["params"]["body"]["query"]["bool"]["filter"][0]
        return FakeResponse({"rawResponse": {"hits": {"hits": [
            {"_source": doc} for doc in documents if matches_time_query(time_query, doc)
        ]}}})

    connector = WazuhConnector()
    connector._dashboard_client = object()
    monkeypatch.setattr(connector, "_dashboard_request", search)
    result = await DetectionValidationEngine(connector).validate_step(
        "T1543.003", [], "test-host", start, end,
    )
    assert result.status.value == "detected"
    assert {alert.alert_id for alert in result.matched_alerts} == {
        "current-service", "without-windows-time",
    }
    assert [alert.alert_id for alert in result.excluded_alerts] == ["routine-logon"]
