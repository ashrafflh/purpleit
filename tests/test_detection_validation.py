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
        rule_id="92657",
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
        "T1059.001", [], "host", datetime.now(UTC), datetime.now(UTC)
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
        start_time=datetime.now(UTC),
        end_time=datetime.now(UTC),
    )

    assert connector.rules_technique == "T1003.001"
    assert connector.queried_source == "10.10.1.108"
    assert result.status == DetectionStatus.DETECTED
    assert result.confidence == 1.0
    assert result.matched_rules == ["92900"]
    assert result.matched_alerts == [alert]


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
        start_time=datetime.now(UTC),
        end_time=datetime.now(UTC),
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
        start_time=datetime.now(UTC),
        end_time=datetime.now(UTC),
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
        start_time=datetime.now(UTC),
        end_time=datetime.now(UTC),
    )

    assert result.status == DetectionStatus.DETECTED
    assert result.confidence == 0.9
    assert result.matched_alerts == [alert]
    assert "deepseek matched" in result.ai_correlation_reasoning
