from __future__ import annotations

from purplestrike.models.config import RiskParameters
from purplestrike.models.simulation import (
    DETECTION_VULNERABILITY_SCORES,
    DetectionStatus,
    RiskResult,
)

DEFAULT_THREAT_FREQUENCIES: dict[str, float] = {
    "T1190": 4.0,
    "T1078": 52.0,
    "T1078.001": 52.0,
    "T1078.002": 52.0,
    "T1078.003": 52.0,
    "T1133": 26.0,
    "T1566.001": 52.0,
    "T1566.002": 52.0,
    "T1059.001": 52.0,
    "T1059.003": 52.0,
    "T1059.004": 52.0,
    "T1059.005": 12.0,
    "T1047": 26.0,
    "T1569.003": 12.0,
    "T1569.002": 26.0,
    "T1204.001": 12.0,
    "T1204.002": 12.0,
    "T1053.005": 26.0,
    "T1053.005p": 26.0,
    "T1547.001": 12.0,
    "T1547.004": 4.0,
    "T1546.001": 8.0,
    "T1546.003": 8.0,
    "T1546.008": 12.0,
    "T1136.001": 8.0,
    "T1136.002": 4.0,
    "T1548.001": 8.0,
    "T1548.002": 12.0,
    "T1068": 4.0,
    "T1543.003": 8.0,
    "T1134.001": 12.0,
    "T1134.002": 8.0,
    "T1484.001": 4.0,
    "T1055.001": 8.0,
    "T1558.003": 12.0,
    "T1558.004": 8.0,
    "T1110.001": 26.0,
    "T1110.003": 12.0,
    "T1552.001": 12.0,
    "T1552.002": 8.0,
    "T1003.001": 12.0,
    "T1003.002": 8.0,
}

DEFAULT_LOSS_MAGNITUDES: dict[str, float] = {
    "TA0001": 215_000,
    "TA0002": 110_000,
    "TA0003": 215_000,
    "TA0004": 525_000,
    "TA0006": 550_000,
}


class RiskQuantifier:
    """FAIR-inspired financial risk quantification for detection gaps."""

    def __init__(self, params: RiskParameters) -> None:
        self.params = params
        self._threat_freq = {**DEFAULT_THREAT_FREQUENCIES, **params.threat_event_frequencies}
        self._loss_mag = {**DEFAULT_LOSS_MAGNITUDES, **params.loss_magnitudes}

    def calculate(self, technique_id: str, detection_status: DetectionStatus) -> RiskResult:
        vuln_score = DETECTION_VULNERABILITY_SCORES.get(detection_status, 0.5)

        if detection_status == DetectionStatus.DETECTED:
            return RiskResult(
                vulnerability_score=vuln_score,
                threat_event_frequency=self._get_tef(technique_id),
                loss_magnitude=self._get_loss_magnitude(technique_id),
                annualized_loss_expectancy=0.0,
            )

        tef = self._get_tef(technique_id)
        loss_mag = self._get_loss_magnitude(technique_id)
        ale = tef * vuln_score * loss_mag

        return RiskResult(
            vulnerability_score=vuln_score,
            threat_event_frequency=tef,
            loss_magnitude=loss_mag,
            annualized_loss_expectancy=ale,
        )

    def _get_tef(self, technique_id: str) -> float:
        return self._threat_freq.get(technique_id, 12.0)

    def _get_loss_magnitude(self, technique_id: str) -> float:
        from purplestrike.techniques.registry import technique_registry

        technique = technique_registry.get_technique(technique_id)
        if technique:
            return self._loss_mag.get(technique.tactic, 200_000)
        return 200_000
