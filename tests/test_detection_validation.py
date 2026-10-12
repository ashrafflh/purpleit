from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from purplestrike.models.config import LLMProviderType, PurpleStrikeConfig
from purplestrike.models.simulation import DetectionStatus, SIEMAlert, SIEMRule
from purplestrike.plugins.protocols import LLMProvider
from purplestrike.validation.engine import DetectionValidationEngine

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize(("rule_id", "event_id"), [
    ("92657", None), ("60106", None), ("60137", None), ("67028", None),
    ("custom-logon", "4624"), ("custom-logoff", 4634),
    ("custom-logoff", "4647"), ("custom-privileges", "4672"),
])
async def test_routine_auth_never_counts_even_with_expected_rule_and_mitre(rule_id, event_id):
    alert = SIEMAlert(
        alert_id="routine", timestamp=datetime.now(UTC), rule_id=rule_id,
        mitre_technique_ids=["T1078.002"],
        raw_log={"data": {"win": {"system": {"eventID": event_id}}}},
    )
    registry = Mock()
    engine = DetectionValidationEngine(FakeSIEMConnector([alert], []), registry)
    result = await engine.validate_step(
        "T1078.002", [rule_id], "host", alert.timestamp, alert.timestamp,
    )
    assert result.status == DetectionStatus.NOT_DETECTED
    assert result.matched_rules == result.matched_alerts == result.candidate_alerts == []
    assert result.excluded_alerts == [alert]
    assert engine._rule_based_check([alert], [rule_id], "T1078.002") == ([], [])
    registry.get_llm_provider.assert_not_called()


async def test_failed_logon_and_technique_alerts_remain_eligible(powershell_alert):
    failed = SIEMAlert(
        alert_id="failed", timestamp=powershell_alert.timestamp, rule_id="60122",
        mitre_technique_ids=["T1110.001"],
        raw_log={"data": {"win": {"system": {"eventID": "4625"}}}},
    )
    routine = failed.model_copy(update={"alert_id": "routine", "rule_id": "92657"})
    engine = DetectionValidationEngine(FakeSIEMConnector([routine, failed, powershell_alert], []))
    for technique, expected in (("T1110.001", failed), ("T1059.001", powershell_alert)):
        result = await engine.validate_step(
            technique, [], "host", failed.timestamp, failed.timestamp,
        )
        assert result.status == DetectionStatus.DETECTED
        assert result.matched_alerts == [expected]
        assert routine not in result.candidate_alerts
        assert result.excluded_alerts == [routine]


async def test_ai_cannot_see_or_cite_excluded_logon():
    routine = SIEMAlert(alert_id="excluded-logon", timestamp=datetime.now(UTC), rule_id="92657")
    candidate = routine.model_copy(update={"alert_id": "candidate", "rule_id": "unmapped"})
    provider = Mock(spec=LLMProvider)
    provider.complete = AsyncMock(return_value=(
        '{"detection_status":"detected","confidence":1,"matched_alerts":["excluded-logon"]}'
    ))
    registry = Mock()
    registry.get_llm_provider.return_value = provider
    engine = DetectionValidationEngine(FakeSIEMConnector([], []), registry)
    result = await engine._ai_correlate(
        "T1078", "host", routine.timestamp, routine.timestamp, [routine, candidate],
    )
    assert "excluded-logon" not in provider.complete.call_args.args[0][1]["content"]
    assert result.status == DetectionStatus.UNKNOWN
    assert result.matched_alerts == []
    assert result.excluded_alerts == [routine]


class FakeSIEMConnector:
    def __init__(self, alerts: list[SIEMAlert], rules: list[SIEMRule]) -> None:
        self.alerts = alerts
        self.rules = rules
        self.queried_source = ""
        self.rules_technique = ""

    async def query_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        rule_ids: list[str] | None = None,
        source: str | None = None,
    ) -> list[SIEMAlert]:
        self.queried_source = source or ""
        return self.alerts

    async def get_rules_for_technique(self, technique_id: str) -> list[SIEMRule]:
        self.rules_technique = technique_id
        return self.rules


@pytest.fixture
def powershell_alert() -> SIEMAlert:
    return SIEMAlert(
        alert_id="1791020624.793495",
        timestamp=datetime.fromisoformat("2026-10-03T09:43:44.007+00:00"),
        rule_id="91815",
        rule_description="Powershell executing process discovery",
        severity="4",
        source="DESKTOP-54IL91M",
        mitre_technique_ids=["T1057"],
        raw_log={
            "agent": {"ip": "10.10.1.107", "name": "DESKTOP-54IL91M", "id": "001"},
            "data": {
                "win": {
                    "eventdata": {
                        "scriptBlockText": (
                            "Write-Output 'PurpleStrike PowerShell simulation'; Get-Process"
                        ),
                        "scriptBlockId": "3717af11-bf2b-43ce-a013-97ca2d5dc271",
                    },
                    "system": {
                        "eventID": "4104",
                        "providerName": "Microsoft-Windows-PowerShell",
                        "channel": "Microsoft-Windows-PowerShell/Operational",
                        "computer": "DESKTOP-54IL91M.purple.local",
                        "processID": "11612",
                    },
                },
            },
        },
    )


@pytest.mark.parametrize("expected_rules", [[], ["100100"], ["91815"]])
async def test_powershell_discovery_matches_with_missing_or_old_plan_rules(
    powershell_alert: SIEMAlert,
    expected_rules: list[str],
) -> None:
    connector = FakeSIEMConnector(alerts=[powershell_alert], rules=[])
    engine = DetectionValidationEngine(connector)

    result = await engine.validate_step(
        technique_id="T1059.001",
        expected_rules=expected_rules,
        target="10.10.1.107",
        start_time=powershell_alert.timestamp,
        end_time=powershell_alert.timestamp,
    )

    assert result.status == DetectionStatus.DETECTED
    assert result.confidence == 0.7
    assert result.matched_rules == ["91815"]
    assert result.matched_alerts == [powershell_alert]
    assert powershell_alert.mitre_technique_ids == ["T1057"]


async def test_powershell_rules_merge_plan_builtin_and_runtime_mappings() -> None:
    connector = FakeSIEMConnector(
        alerts=[],
        rules=[SIEMRule(rule_id="91815"), SIEMRule(rule_id="runtime-rule")],
    )
    engine = DetectionValidationEngine(connector)

    rules = await engine._expected_rules_for_technique(
        "T1059.001", ["custom-rule", "100100", "custom-rule"]
    )

    assert rules == ["custom-rule", "100100", "91815", "runtime-rule"]


@pytest.mark.parametrize(
    ("technique_id", "rule_id"),
    [("T1059.001", "unmapped-rule"), ("T1059.003", "91815")],
)
async def test_process_discovery_is_not_a_general_execution_technique_match(
    powershell_alert: SIEMAlert,
    technique_id: str,
    rule_id: str,
) -> None:
    powershell_alert.rule_id = rule_id
    connector = FakeSIEMConnector(alerts=[powershell_alert], rules=[])
    engine = DetectionValidationEngine(connector)

    result = await engine.validate_step(
        technique_id=technique_id,
        expected_rules=[],
        target="10.10.1.107",
        start_time=powershell_alert.timestamp,
        end_time=powershell_alert.timestamp,
    )

    assert result.status == DetectionStatus.UNKNOWN
    assert result.matched_rules == []


async def test_ai_fallback_receives_script_and_raw_event_context(
    powershell_alert: SIEMAlert,
) -> None:
    # An unmapped rule exercises the fallback instead of the explicit 91815 mapping.
    powershell_alert.rule_id = "unmapped-rule"
    provider = Mock(spec=LLMProvider)
    provider.complete = AsyncMock(
        return_value=(
            '{"detection_status": "detected", "confidence": 0.8, '
            '"matched_alerts": ["1791020624.793495"], "reasoning": "Script evidence"}'
        )
    )
    registry = Mock()
    registry.get_llm_provider.return_value = provider
    engine = DetectionValidationEngine(
        FakeSIEMConnector(alerts=[powershell_alert], rules=[]), plugin_registry=registry
    )

    result = await engine.validate_step(
        technique_id="T1059.001",
        expected_rules=[],
        target="10.10.1.107",
        start_time=powershell_alert.timestamp,
        end_time=powershell_alert.timestamp,
    )

    provider.complete.assert_awaited_once()
    prompt = provider.complete.call_args.args[0][1]["content"]
    for evidence in (
        "1791020624.793495",
        "T1059.001",
        "T1057",
        "DESKTOP-54IL91M",
        "scriptBlockText",
        "Write-Output 'PurpleStrike PowerShell simulation'; Get-Process",
        "4104",
        "Microsoft-Windows-PowerShell/Operational",
        "11612",
    ):
        assert evidence in prompt
    assert result.status == DetectionStatus.DETECTED
    assert result.matched_alerts == [powershell_alert]


async def test_ai_alert_context_bounds_large_logs_without_mutating_alerts(
    powershell_alert: SIEMAlert,
) -> None:
    powershell_alert.raw_log["large_field"] = "x" * 100_000
    engine = DetectionValidationEngine(FakeSIEMConnector(alerts=[], rules=[]))

    summary = engine._format_alerts([powershell_alert])

    assert "Get-Process" in summary
    assert "[truncated]" in summary
    assert len(summary) < 9000
    assert len(powershell_alert.raw_log["large_field"]) == 100_000


async def test_persistence_task_matches_real_mitre_id() -> None:
    alert = SIEMAlert(
        alert_id="task",
        timestamp=datetime.now(UTC),
        rule_id="task-rule",
        mitre_technique_ids=["T1053.005"],
    )
    connector = FakeSIEMConnector([alert], [])
    result = await DetectionValidationEngine(connector).validate_step(
        "T1053.005p", [], "host", alert.timestamp, alert.timestamp
    )
    assert connector.rules_technique == "T1053.005"
    assert result.status == DetectionStatus.DETECTED


@pytest.mark.parametrize("reported_id", ["invented-alert", ""])
async def test_ai_cannot_claim_detection_without_matching_evidence(reported_id) -> None:
    alert = SIEMAlert(alert_id="real-alert", timestamp=datetime.now(UTC), rule_id="unmapped")
    provider = Mock(spec=LLMProvider)
    provider.complete = AsyncMock(
        return_value=(
            '{"detection_status":"detected","confidence":0.9,"matched_alerts":["'
            + reported_id
            + '"]}'
        )
    )
    registry = Mock()
    registry.get_llm_provider.return_value = provider
    result = await DetectionValidationEngine(
        FakeSIEMConnector([alert], []), plugin_registry=registry
    ).validate_step("T1059.001", [], "host", alert.timestamp, alert.timestamp)
    assert result.status == DetectionStatus.UNKNOWN


async def test_no_alerts_does_not_ask_ai_to_invent_a_detection() -> None:
    registry = Mock()
    result = await DetectionValidationEngine(
        FakeSIEMConnector([], []), plugin_registry=registry
    ).validate_step("T1059.001", [], "host", datetime.now(UTC), datetime.now(UTC))
    assert result.status == DetectionStatus.NOT_DETECTED
    registry.get_llm_provider.assert_not_called()


async def test_raw_alert_context_redacts_configured_credentials(powershell_alert) -> None:
    config = PurpleStrikeConfig(target_password="private-password")
    powershell_alert.raw_log["message"] = "LDAP credential: private-password"
    summary = DetectionValidationEngine(FakeSIEMConnector([], []), config=config)._format_alerts(
        [powershell_alert]
    )
    assert "private-password" not in summary
    assert "[REDACTED]" in summary


async def test_saved_candidate_alerts_redact_configured_credentials(powershell_alert) -> None:
    config = PurpleStrikeConfig(target_password="private-password")
    powershell_alert.raw_log["message"] = "LDAP credential: private-password"
    engine = DetectionValidationEngine(FakeSIEMConnector([powershell_alert], []), config=config)
    result = await engine.validate_step(
        "T1059.001", [], "host", powershell_alert.timestamp, powershell_alert.timestamp
    )
    assert result.status == DetectionStatus.DETECTED
    assert "private-password" not in result.model_dump_json()
    assert "[REDACTED]" in result.candidate_alerts[0].raw_log["message"]


async def test_manager_clock_skew_matches_current_event_but_excludes_prior_cleanup(
    powershell_alert,
):
    start = datetime.now(UTC)
    current = powershell_alert.model_copy(deep=True)
    current.timestamp = start - timedelta(milliseconds=500)
    current.raw_log["data"]["win"]["system"]["systemTime"] = (
        start + timedelta(milliseconds=100)
    ).isoformat()
    previous = current.model_copy(deep=True)
    previous.alert_id = "previous-cleanup"
    previous.raw_log["data"]["win"]["system"]["systemTime"] = (
        start - timedelta(milliseconds=100)
    ).isoformat()

    class TimeFilteredConnector(FakeSIEMConnector):
        async def query_alerts(self, start_time, end_time, **kwargs):
            return [a for a in self.alerts if start_time <= a.timestamp <= end_time]

    engine = DetectionValidationEngine(TimeFilteredConnector([current, previous], []))
    result = await engine.validate_step(
        "T1059.001", [], "host", start, start + timedelta(seconds=30)
    )
    assert result.status == DetectionStatus.DETECTED
    assert [a.alert_id for a in result.matched_alerts] == [current.alert_id]


async def test_validation_matches_runtime_wazuh_rule_for_technique() -> None:
    alert = SIEMAlert(
        alert_id="alert-1",
        timestamp=datetime.now(UTC),
        rule_id="92900",
        rule_description="Lsass process was accessed",
        severity="12",
        source="seif",
        mitre_technique_ids=["T1003.001"],
    )
    rule = SIEMRule(
        rule_id="92900",
        description="Lsass process was accessed",
        severity="12",
        mitre_technique_ids=["T1003.001"],
    )
    connector = FakeSIEMConnector(alerts=[alert], rules=[rule])
    engine = DetectionValidationEngine(connector)

    result = await engine.validate_step(
        technique_id="T1003.001",
        expected_rules=["100407"],
        target="10.10.1.108",
        start_time=alert.timestamp,
        end_time=alert.timestamp,
    )

    assert connector.rules_technique == "T1003.001"
    assert connector.queried_source == "10.10.1.108"
    assert result.status == DetectionStatus.DETECTED
    assert result.confidence == 1.0
    assert result.matched_rules == ["92900"]
    assert result.matched_alerts == [alert]


@pytest.mark.parametrize("source_time", [None, "invalid", 123])
async def test_out_of_window_alert_without_valid_source_time_is_excluded(source_time):
    start = datetime.now(UTC)
    alert = SIEMAlert(
        alert_id="old", timestamp=start - timedelta(seconds=1), rule_id="91815",
        raw_log={"data": {"win": {"system": {"systemTime": source_time}}}},
    )
    result = await DetectionValidationEngine(FakeSIEMConnector([alert], [])).validate_step(
        "T1059.001", [], "host", start, start + timedelta(seconds=5)
    )
    assert result.status == DetectionStatus.NOT_DETECTED
    assert result.matched_alerts == []


async def test_delayed_prior_event_is_excluded_even_when_ingestion_is_in_window():
    start = datetime.now(UTC)
    alert = SIEMAlert(
        alert_id="delayed-cleanup", timestamp=start + timedelta(seconds=1), rule_id="91815",
        raw_log={"data": {"win": {"system": {
            "systemTime": (start - timedelta(seconds=5)).isoformat(),
        }}}},
    )
    result = await DetectionValidationEngine(FakeSIEMConnector([alert], [])).validate_step(
        "T1059.001", [], "host", start, start + timedelta(seconds=5)
    )
    assert result.status == DetectionStatus.NOT_DETECTED
    assert result.matched_alerts == []


async def test_empty_candidate_reason_and_logs_distinguish_stale_and_routine_events(caplog):
    import json
    import logging

    start = datetime.now(UTC)
    stale = SIEMAlert(
        alert_id="previous-step", timestamp=start, rule_id="91818",
        raw_log={"data": {"win": {"system": {
            "systemTime": (start - timedelta(seconds=10)).isoformat(),
        }}}},
    )
    routine = SIEMAlert(alert_id="logon", timestamp=start, rule_id="92657")
    caplog.set_level(logging.INFO, logger="purplestrike.validation.engine")
    result = await DetectionValidationEngine(FakeSIEMConnector([stale, routine], [])).validate_step(
        "T1543.003", [], "test-host", start, start + timedelta(seconds=30),
    )
    assert result.status == DetectionStatus.NOT_DETECTED
    assert "SIEM returned 2; 1 outside the event window; 1 routine" in (
        result.ai_correlation_reasoning
    )
    events = [r.getMessage() for r in caplog.records]
    query_result = next(e for e in events if e.startswith("detection.query.result\n"))
    details = json.loads(query_result.split("\n", 1)[1])
    assert details["returned_count"] == 2
    assert details["outside_event_window_count"] == 1
    assert details["routine_auth_count"] == 1
    assert details["candidate_count"] == 0


async def test_validation_matches_alert_mitre_even_without_expected_rule() -> None:
    alert = SIEMAlert(
        alert_id="alert-2",
        timestamp=datetime.now(UTC),
        rule_id="92900",
        mitre_technique_ids=["T1003.001"],
    )
    connector = FakeSIEMConnector(alerts=[alert], rules=[])
    engine = DetectionValidationEngine(connector)

    result = await engine.validate_step(
        technique_id="T1003.001",
        expected_rules=[],
        target="10.10.1.108",
        start_time=alert.timestamp,
        end_time=alert.timestamp,
    )

    assert result.status == DetectionStatus.DETECTED
    assert result.matched_rules == ["92900"]


async def test_ai_failure_with_alerts_returns_unknown_and_preserves_alerts() -> None:
    class BrokenProvider:
        name = "openai"
        model = "test"

        async def setup(self, config: dict[str, Any]) -> None:
            return None

        async def complete(self, messages: list[dict[str, str]]) -> str:
            raise RuntimeError("client not initialized")

        async def complete_structured(
            self,
            messages: list[dict[str, str]],
            schema: type,
            **kwargs: Any,
        ) -> Any:
            raise RuntimeError("client not initialized")

        async def teardown(self) -> None:
            return None

    class Registry:
        def list_llm_providers(self) -> list[str]:
            return ["openai"]

        def get_llm_provider(self, name: str) -> Any:
            return BrokenProvider()

    alert = SIEMAlert(
        alert_id="alert-3",
        timestamp=datetime.now(UTC),
        rule_id="99999",
    )
    connector = FakeSIEMConnector(alerts=[alert], rules=[])
    engine = DetectionValidationEngine(connector, plugin_registry=Registry())

    result = await engine.validate_step(
        technique_id="T1003.001",
        expected_rules=["100407"],
        target="10.10.1.108",
        start_time=alert.timestamp,
        end_time=alert.timestamp,
    )

    assert result.status == DetectionStatus.UNKNOWN
    assert result.matched_alerts == []
    assert result.candidate_alerts == [alert]


async def test_ai_correlation_uses_configured_deepseek_provider() -> None:
    class BrokenOpenAIProvider:
        name = "openai"
        model = "test"

        async def setup(self, config: dict[str, Any]) -> None:
            return None

        async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
            raise AssertionError("OpenAI provider should not be used")

        async def complete_structured(
            self,
            messages: list[dict[str, str]],
            schema: type,
            **kwargs: Any,
        ) -> Any:
            raise AssertionError("OpenAI provider should not be used")

        async def teardown(self) -> None:
            return None

    class DeepSeekProvider:
        name = "deepseek"
        model = "deepseek-chat"

        async def setup(self, config: dict[str, Any]) -> None:
            return None

        async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
            return (
                '{"detection_status": "detected", "confidence": 0.9, '
                '"matched_alerts": ["alert-6"], "reasoning": "deepseek matched"}'
            )

        async def complete_structured(
            self,
            messages: list[dict[str, str]],
            schema: type,
            **kwargs: Any,
        ) -> Any:
            return None

        async def teardown(self) -> None:
            return None

    class Registry:
        def __init__(self) -> None:
            self.providers = {
                "openai": BrokenOpenAIProvider(),
                "deepseek": DeepSeekProvider(),
            }

        def get_llm_provider(self, name: str) -> Any:
            return self.providers.get(name)

    alert = SIEMAlert(
        alert_id="alert-6",
        timestamp=datetime.now(UTC),
        rule_id="99999",
    )
    config = PurpleStrikeConfig()
    config.llm.provider = LLMProviderType.DEEPSEEK
    connector = FakeSIEMConnector(alerts=[alert], rules=[])
    engine = DetectionValidationEngine(connector, plugin_registry=Registry(), config=config)

    result = await engine.validate_step(
        technique_id="T1003.001",
        expected_rules=[],
        target="10.10.1.108",
        start_time=alert.timestamp,
        end_time=alert.timestamp,
    )

    assert result.status == DetectionStatus.DETECTED
    assert result.confidence == 0.9
    assert result.matched_alerts == [alert]
    assert "deepseek matched" in result.ai_correlation_reasoning
