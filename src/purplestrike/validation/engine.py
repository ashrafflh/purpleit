from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.models.simulation import (
    DetectionResult,
    DetectionStatus,
    SIEMAlert,
)
from purplestrike.plugins.protocols import SIEMConnector

logger = logging.getLogger(__name__)


class DetectionValidationEngine:
    """Hybrid detection validation: rule-based mapping + AI alert correlation."""

    def __init__(
        self,
        siem_connector: SIEMConnector,
        plugin_registry: Any = None,
        config: PurpleStrikeConfig | None = None,
    ) -> None:
        self.siem_connector = siem_connector
        self.plugin_registry = plugin_registry
        self.config = config or PurpleStrikeConfig()

    async def validate_step(
        self,
        technique_id: str,
        expected_rules: list[str],
        target: str,
        start_time: datetime,
        end_time: datetime,
    ) -> DetectionResult:
        try:
            alerts = await self.siem_connector.query_alerts(
                start_time=start_time,
                end_time=end_time,
                source=target,
            )
        except Exception as e:
            logger.error(f"SIEM query failed: {e}")
            return DetectionResult(status=DetectionStatus.UNKNOWN, confidence=0.0)

        if not alerts:
            return await self._ai_correlate(
                technique_id=technique_id,
                target=target,
                start_time=start_time,
                end_time=end_time,
                alerts=[],
            )

        matched_rules, matched_alerts = self._rule_based_check(alerts, expected_rules)

        if matched_rules:
            status = DetectionStatus.DETECTED
            confidence = 1.0 if len(matched_rules) == len(expected_rules) else 0.7
            return DetectionResult(
                status=status,
                confidence=confidence,
                matched_rules=matched_rules,
                matched_alerts=matched_alerts,
            )

        return await self._ai_correlate(
            technique_id=technique_id,
            target=target,
            start_time=start_time,
            end_time=end_time,
            alerts=alerts,
        )

    def _rule_based_check(
        self,
        alerts: list[SIEMAlert],
        expected_rules: list[str],
    ) -> tuple[list[str], list[SIEMAlert]]:
        matched_rules: list[str] = []
        matched_alerts: list[SIEMAlert] = []

        for alert in alerts:
            if alert.rule_id in expected_rules:
                if alert.rule_id not in matched_rules:
                    matched_rules.append(alert.rule_id)
                matched_alerts.append(alert)

        return matched_rules, matched_alerts

    async def _ai_correlate(
        self,
        technique_id: str,
        target: str,
        start_time: datetime,
        end_time: datetime,
        alerts: list[SIEMAlert],
    ) -> DetectionResult:
        if self.plugin_registry is None:
            return DetectionResult(
                status=DetectionStatus.NOT_DETECTED if not alerts else DetectionStatus.UNKNOWN,
                confidence=0.0,
                matched_alerts=alerts if alerts else [],
            )

        from purplestrike.plugins.protocols import LLMProvider

        llm_provider = None
        for provider_name in self.plugin_registry.list_llm_providers():
            candidate = self.plugin_registry.get_llm_provider(provider_name)
            if isinstance(candidate, LLMProvider):
                llm_provider = candidate
                break

        if llm_provider is None:
            return DetectionResult(
                status=DetectionStatus.NOT_DETECTED if not alerts else DetectionStatus.UNKNOWN,
                confidence=0.0,
                matched_alerts=alerts if alerts else [],
            )

        technique_info = self._get_technique_info(technique_id)
        alerts_summary = self._format_alerts(alerts)

        prompt = f"""Analyze the following SIEM alerts to determine if they indicate detection of the executed attack technique.

Attack Context:
- Technique: {technique_id} - {technique_info}
- Target: {target}
- Execution time: {start_time.isoformat()} to {end_time.isoformat()}

SIEM Alerts in Time Window:
{alerts_summary if alerts_summary else "No alerts found in time window."}

Respond with a JSON object:
{{"detection_status": "detected"|"partially_detected"|"not_detected", "confidence": 0.0-1.0, "matched_alerts": [], "reasoning": "brief explanation"}}"""

        try:
            import json

            messages = [
                {"role": "system", "content": "You are a detection validation analyst. Be conservative — only flag as detected if alerts clearly relate to the attack indicators."},
                {"role": "user", "content": prompt},
            ]
            response = await llm_provider.complete(messages)
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]

            result = json.loads(json_str.strip())
            status_str = result.get("detection_status", "not_detected")
            status_map = {
                "detected": DetectionStatus.DETECTED,
                "partially_detected": DetectionStatus.PARTIALLY_DETECTED,
                "not_detected": DetectionStatus.NOT_DETECTED,
            }

            matched_ids = result.get("matched_alerts", [])
            matched = [a for a in alerts if a.alert_id in matched_ids]

            return DetectionResult(
                status=status_map.get(status_str, DetectionStatus.NOT_DETECTED),
                confidence=result.get("confidence", 0.0),
                matched_alerts=matched,
                ai_correlation_reasoning=result.get("reasoning"),
            )
        except Exception as e:
            logger.error(f"AI alert correlation failed: {e}")
            return DetectionResult(
                status=DetectionStatus.NOT_DETECTED if not alerts else DetectionStatus.UNKNOWN,
                confidence=0.0,
            )

    def _get_technique_info(self, technique_id: str) -> str:
        from purplestrike.techniques.registry import technique_registry

        technique = technique_registry.get_technique(technique_id)
        if technique:
            return f"{technique.name} ({technique.tactic_name})"
        return technique_id

    def _format_alerts(self, alerts: list[SIEMAlert]) -> str:
        if not alerts:
            return "No alerts found."
        lines = []
        for alert in alerts[:20]:
            lines.append(
                f"- Alert {alert.alert_id}: Rule {alert.rule_id} "
                f"({alert.rule_description[:60]}) | Severity: {alert.severity} | "
                f"Time: {alert.timestamp.isoformat()}"
            )
        return "\n".join(lines)
