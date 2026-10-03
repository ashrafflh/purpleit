from __future__ import annotations

import logging

from purplestrike.models.techniques import Technique

logger = logging.getLogger(__name__)


class TechniqueRegistry:
    """Registry of all available MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        self._techniques: dict[str, Technique] = {}
        self._loaded = False

    def register(self, technique: Technique) -> None:
        self._techniques[technique.technique_id] = technique

    def register_batch(self, techniques: list[Technique]) -> None:
        for t in techniques:
            self.register(t)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._loaded = True
            load_default_techniques()

    def get_technique(self, technique_id: str) -> Technique | None:
        self._ensure_loaded()
        return self._techniques.get(technique_id)

    def list_techniques(self) -> list[Technique]:
        self._ensure_loaded()
        return sorted(self._techniques.values(), key=lambda t: t.technique_id)

    def list_techniques_by_tactic(self, tactic: str) -> list[Technique]:
        self._ensure_loaded()
        return [t for t in self._techniques.values() if t.tactic == tactic]

    def get_technique_ids(self) -> list[str]:
        self._ensure_loaded()
        return sorted(self._techniques.keys())

    def technique_exists(self, technique_id: str) -> bool:
        self._ensure_loaded()
        return technique_id in self._techniques


technique_registry = TechniqueRegistry()

# These implementations exercise prerequisites or artifacts, not the complete behavior.
_VALIDATION_NOTES = {
    "T1003.001": "Enumerates LSASS and checks dump-tool availability; does not read LSASS memory.",
    "T1003.002": "Can return after registry/shadow-copy enumeration; that alone does not prove a SAM dump.",
    "T1055.001": "Enumerates candidate processes; does not inject a DLL.",
    "T1068": "Enumerates potential escalation paths; does not exploit a vulnerability.",
    "T1078.001": "Enumerates default accounts; does not authenticate as those accounts.",
    "T1078.002": "Enumerates domain accounts using the connection identity.",
    "T1078.003": "Enumerates local accounts using the connection identity.",
    "T1133": "Checks remote-service availability; does not establish an external service session.",
    "T1134.001": "Enumerates tokens and privileges; does not steal or impersonate a token.",
    "T1134.002": "Enumerates privileges; does not create a process with another token.",
    "T1190": "Probes a local HTTP endpoint; does not exploit the application.",
    "T1204.001": "Creates a benign URL artifact; does not simulate the user opening a link.",
    "T1204.002": "Creates a benign file artifact; does not execute the file.",
    "T1484.001": "Enumerates group policy; does not modify a GPO.",
    "T1548.001": "Enumerates setuid/setgid binaries; does not execute an escalation.",
    "T1548.002": "Configures and launches fodhelper; does not verify an elevated child token.",
    "T1558.004": "Enumerates accounts without preauthentication; does not request AS-REP material.",
    "T1566.001": "Creates a benign local attachment artifact; no phishing message is delivered.",
    "T1566.002": "Creates a benign local URL artifact; no phishing message is delivered.",
}


def load_default_techniques() -> None:
    """Load all built-in techniques into the global registry."""
    from purplestrike.techniques.credential_access.techniques import CREDENTIAL_ACCESS_TECHNIQUES
    from purplestrike.techniques.execution.techniques import EXECUTION_TECHNIQUES
    from purplestrike.techniques.initial_access.techniques import INITIAL_ACCESS_TECHNIQUES
    from purplestrike.techniques.persistence.techniques import PERSISTENCE_TECHNIQUES
    from purplestrike.techniques.privilege_escalation.techniques import PRIV_ESC_TECHNIQUES

    technique_registry.register_batch(INITIAL_ACCESS_TECHNIQUES)
    technique_registry.register_batch(EXECUTION_TECHNIQUES)
    technique_registry.register_batch(PERSISTENCE_TECHNIQUES)
    technique_registry.register_batch(PRIV_ESC_TECHNIQUES)
    technique_registry.register_batch(CREDENTIAL_ACCESS_TECHNIQUES)
    for technique_id, notes in _VALIDATION_NOTES.items():
        technique = technique_registry._techniques.get(technique_id)
        if technique is not None:
            technique.validation_notes = notes

    logger.info(f"Loaded {len(technique_registry.get_technique_ids())} techniques into registry")
