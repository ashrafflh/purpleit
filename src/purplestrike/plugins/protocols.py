from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime

    from purplestrike.models.simulation import SIEMAlert, SIEMRule
    from purplestrike.models.techniques import TechniqueResult


@runtime_checkable
class AttackExecutor(Protocol):
    """Protocol for attack execution plugins."""

    name: str
    supported_techniques: list[str]

    async def setup(self, config: dict[str, Any]) -> None: ...

    async def execute(
        self, technique_id: str, target: str, parameters: dict[str, Any]
    ) -> TechniqueResult: ...

    async def cleanup(
        self,
        technique_id: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> None: ...

    async def teardown(self) -> None: ...


@runtime_checkable
class SIEMConnector(Protocol):
    """Protocol for SIEM integration plugins."""

    name: str

    async def setup(self, config: dict[str, Any]) -> None: ...

    async def query_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        rule_ids: list[str] | None = None,
        source: str | None = None,
    ) -> list[SIEMAlert]: ...

    async def get_rule(self, rule_id: str) -> SIEMRule | None: ...

    async def get_rules_for_technique(self, technique_id: str) -> list[SIEMRule]: ...

    async def teardown(self) -> None: ...


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for LLM provider plugins."""

    name: str
    model: str

    async def setup(self, config: dict[str, Any]) -> None: ...

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str: ...

    async def complete_structured(
        self,
        messages: list[dict[str, str]],
        schema: type,
        **kwargs: Any,
    ) -> Any: ...

    async def teardown(self) -> None: ...


@runtime_checkable
class ReportFormatter(Protocol):
    """Protocol for report output plugins."""

    name: str
    file_extension: str

    async def format(self, report: Any, output_path: Any) -> Any: ...


PLUGIN_TYPES = {
    "attack_executor": AttackExecutor,
    "siem_connector": SIEMConnector,
    "llm_provider": LLMProvider,
    "report_formatter": ReportFormatter,
}
