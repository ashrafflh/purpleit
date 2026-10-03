from purplestrike.core.orchestrator import Orchestrator
from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.models.report import SimulationSummary
from purplestrike.models.simulation import (
    CoverageStatus,
    DetectionResult,
    DetectionStatus,
    SimulationStep,
)
from purplestrike.models.techniques import ATTACK_VERSION, EmulationMode, TacticID, TechniqueResult
from purplestrike.techniques.catalog import ATTACK_CATALOG, EMULATION_PROFILES
from purplestrike.techniques.registry import technique_registry

V19_STEALTH_AND_DEFENSE_IMPAIRMENT = {
    "T1027.018",
    "T1684",
    "T1684.001",
    "T1684.002",
    "T1685",
    "T1685.001",
    "T1685.002",
    "T1685.003",
    "T1685.004",
    "T1685.005",
    "T1685.006",
    "T1686",
    "T1686.001",
    "T1686.002",
    "T1686.003",
    "T1687",
    "T1688",
    "T1689",
    "T1690",
}


def test_all_registered_scenarios_have_attack_and_emulation_metadata() -> None:
    techniques = technique_registry.list_techniques()

    assert len(techniques) == 61
    assert set(EMULATION_PROFILES) == {technique.technique_id for technique in techniques}
    assert len(ATTACK_CATALOG) == 60

    for technique in techniques:
        assert technique.attack_version == ATTACK_VERSION
        assert technique.attack_technique_version
        assert technique.attack_url.startswith("https://attack.mitre.org/techniques/")
        assert technique.attack_tactics
        assert technique.official_name
        assert technique.detection_strategy_id.startswith("DET")
        assert technique.analytic_ids
        assert technique.required_log_sources
        assert technique.procedure
        assert technique.success_criteria


def test_attack_v19_tactic_names_are_current() -> None:
    assert TacticID.STEALTH == "TA0005"
    assert TacticID.DEFENSE_IMPAIRMENT == "TA0112"
    assert TacticID.DEFENSE_EVASION is TacticID.STEALTH


def test_attack_v19_stealth_and_defense_impairment_additions_are_registered() -> None:
    registered = set(technique_registry.get_technique_ids())
    assert registered >= V19_STEALTH_AND_DEFENSE_IMPAIRMENT


def test_destructive_v19_scenarios_cannot_claim_procedure_coverage() -> None:
    for technique_id in (
        "T1685",
        "T1685.001",
        "T1685.002",
        "T1685.003",
        "T1685.004",
        "T1685.005",
        "T1685.006",
        "T1686",
        "T1686.001",
        "T1686.002",
        "T1687",
        "T1688",
        "T1689",
    ):
        technique = technique_registry.get_technique(technique_id)
        assert technique is not None
        assert technique.emulation_mode != EmulationMode.PROCEDURE

    for technique_id in ("T1027.018", "T1686.003", "T1690"):
        technique = technique_registry.get_technique(technique_id)
        assert technique is not None
        assert technique.emulation_mode == EmulationMode.PROCEDURE


def test_probe_and_artifact_scenarios_are_not_procedure_eligible() -> None:
    for technique_id in (
        "T1078.001",
        "T1078.002",
        "T1078.003",
        "T1068",
        "T1134.001",
        "T1134.002",
        "T1484.001",
        "T1055.001",
        "T1558.004",
        "T1566.001",
        "T1566.002",
    ):
        technique = technique_registry.get_technique(technique_id)
        assert technique is not None
        assert technique.emulation_mode in {
            EmulationMode.PREREQUISITE,
            EmulationMode.ARTIFACT,
        }


def test_artifact_detection_does_not_become_attack_coverage() -> None:
    orchestrator = Orchestrator(PurpleStrikeConfig())
    activity = DetectionResult(status=DetectionStatus.DETECTED, confidence=1.0)
    execution = TechniqueResult(
        technique_id="T1566.001",
        success=True,
        emulation_mode=EmulationMode.ARTIFACT,
    )

    assessed = orchestrator._assess_coverage(activity, execution)

    assert assessed.status == DetectionStatus.DETECTED
    assert assessed.coverage_status == CoverageStatus.NOT_ASSESSED
    assert not assessed.coverage_eligible


def test_summary_rate_excludes_non_procedure_activity() -> None:
    procedure = SimulationStep(
        step=1,
        technique_id="T1059.001",
        emulation_mode=EmulationMode.PROCEDURE,
        detection_result=DetectionResult(
            status=DetectionStatus.DETECTED,
            coverage_status=CoverageStatus.VALIDATED,
            coverage_eligible=True,
        ),
    )
    artifact = SimulationStep(
        step=2,
        technique_id="T1566.001",
        emulation_mode=EmulationMode.ARTIFACT,
        detection_result=DetectionResult(
            status=DetectionStatus.DETECTED,
            coverage_status=CoverageStatus.NOT_ASSESSED,
            coverage_eligible=False,
        ),
    )

    summary = SimulationSummary.from_steps([procedure, artifact])

    assert summary.detected == 2
    assert summary.coverage_validated == 1
    assert summary.coverage_not_assessed == 1
    assert summary.coverage_eligible_techniques == 1
    assert summary.detection_rate == 1.0
