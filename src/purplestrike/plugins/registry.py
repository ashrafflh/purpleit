from __future__ import annotations

from purplestrike.plugins.protocols import (
    AttackExecutor,
    LLMProvider,
    ReportFormatter,
    SIEMConnector,
)


class PluginRegistry:
    """Central registry for all PurpleStrike plugins."""

    def __init__(self) -> None:
        self._attack_executors: dict[str, AttackExecutor] = {}
        self._siem_connectors: dict[str, SIEMConnector] = {}
        self._llm_providers: dict[str, LLMProvider] = {}
        self._report_formatters: dict[str, ReportFormatter] = {}

    def register_attack_executor(self, executor: AttackExecutor) -> None:
        self._attack_executors[executor.name] = executor

    def register_siem_connector(self, connector: SIEMConnector) -> None:
        self._siem_connectors[connector.name] = connector

    def register_llm_provider(self, provider: LLMProvider) -> None:
        self._llm_providers[provider.name] = provider

    def register_report_formatter(self, formatter: ReportFormatter) -> None:
        self._report_formatters[formatter.name] = formatter

    def get_attack_executor(self, name: str) -> AttackExecutor | None:
        return self._attack_executors.get(name)

    def get_siem_connector(self, name: str) -> SIEMConnector | None:
        return self._siem_connectors.get(name)

    def get_llm_provider(self, name: str) -> LLMProvider | None:
        return self._llm_providers.get(name)

    def get_report_formatter(self, name: str) -> ReportFormatter | None:
        return self._report_formatters.get(name)

    def list_attack_executors(self) -> list[str]:
        return list(self._attack_executors.keys())

    def list_siem_connectors(self) -> list[str]:
        return list(self._siem_connectors.keys())

    def list_llm_providers(self) -> list[str]:
        return list(self._llm_providers.keys())

    def list_report_formatters(self) -> list[str]:
        return list(self._report_formatters.keys())

    def list_techniques_for_executor(self, executor_name: str) -> list[str]:
        executor = self.get_attack_executor(executor_name)
        if executor is None:
            return []
        return list(executor.supported_techniques)

    def find_executor_for_technique(self, technique_id: str) -> AttackExecutor | None:
        for executor in self._attack_executors.values():
            if technique_id in executor.supported_techniques:
                return executor
        return None


plugin_registry = PluginRegistry()
