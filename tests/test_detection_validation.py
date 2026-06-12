from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from purplestrike.models.simulation import DetectionStatus, SIEMAlert, SIEMRule
from purplestrike.models.config import LLMProviderType, PurpleStrikeConfig
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
    assert result.matched_alerts == [alert]


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
    assert result.ai_correlation_reasoning == "deepseek matched"
