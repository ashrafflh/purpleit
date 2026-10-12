from __future__ import annotations

import logging

from purplestrike.models.techniques import Technique

logger = logging.getLogger(__name__)


class TechniqueRegistry:
    """Registry of all available MITRE ATT&CK techniques."""

    def __init__(self, autoload: bool = True) -> None:
        self._techniques: dict[str, Technique] = {}
        self._loaded = not autoload

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


def load_default_techniques() -> None:
    """Load all built-in techniques into the global registry."""
    from purplestrike.techniques.catalog import apply_catalog_metadata
    from purplestrike.techniques.credential_access.techniques import CREDENTIAL_ACCESS_TECHNIQUES
    from purplestrike.techniques.defense_impairment.techniques import (
        DEFENSE_IMPAIRMENT_TECHNIQUES,
    )
    from purplestrike.techniques.execution.techniques import EXECUTION_TECHNIQUES
    from purplestrike.techniques.initial_access.techniques import INITIAL_ACCESS_TECHNIQUES
    from purplestrike.techniques.persistence.techniques import PERSISTENCE_TECHNIQUES
    from purplestrike.techniques.privilege_escalation.techniques import PRIV_ESC_TECHNIQUES
    from purplestrike.techniques.stealth.techniques import STEALTH_TECHNIQUES

    technique_registry.register_batch(INITIAL_ACCESS_TECHNIQUES)
    technique_registry.register_batch(EXECUTION_TECHNIQUES)
    technique_registry.register_batch(PERSISTENCE_TECHNIQUES)
    technique_registry.register_batch(PRIV_ESC_TECHNIQUES)
    technique_registry.register_batch(CREDENTIAL_ACCESS_TECHNIQUES)
    technique_registry.register_batch(STEALTH_TECHNIQUES)
    technique_registry.register_batch(DEFENSE_IMPAIRMENT_TECHNIQUES)
    for technique in technique_registry._techniques.values():
        apply_catalog_metadata(technique)

    logger.info(f"Loaded {len(technique_registry.get_technique_ids())} techniques into registry")
