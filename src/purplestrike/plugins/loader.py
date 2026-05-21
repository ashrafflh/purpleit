from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from purplestrike.plugins.registry import PluginRegistry, plugin_registry

logger = logging.getLogger(__name__)

BUILTIN_PLUGIN_DIRS = {
    "attack_executor": "purplestrike.plugins.attack_executors",
    "siem_connector": "purplestrike.plugins.siem_connectors",
    "llm_provider": "purplestrike.plugins.llm_providers",
    "report_formatter": "purplestrike.plugins.report_formatters",
}

USER_PLUGIN_BASE = Path.home() / ".purplestrike" / "plugins"

BUILTIN_EXECUTORS = ["custom_python"]
BUILTIN_SIEM_CONNECTORS = ["wazuh"]
BUILTIN_LLM_PROVIDERS = ["openai", "anthropic", "ollama", "vllm", "nvidia"]
BUILTIN_REPORT_FORMATTERS = ["json", "csv"]


class PluginLoader:
    """Discovers and loads plugins from built-in, user, and project-local paths."""

    def __init__(self, registry: PluginRegistry | None = None) -> None:
        self.registry = registry or plugin_registry

    async def load_all(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        await self._load_builtin_executors(config.get("attack_executors", {}))
        await self.load_siem_connectors(config)
        await self._load_builtin_llm_providers(config.get("llm_providers", {}))
        await self._load_builtin_report_formatters(config.get("report_formatters", {}))
        await self._load_user_plugins(config)

    async def load_siem_connectors(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        await self._load_builtin_siem_connectors(config.get("siem_connectors", {}))

    async def _load_builtin_executors(self, config: dict[str, Any]) -> None:
        for name in BUILTIN_EXECUTORS:
            try:
                module = importlib.import_module(
                    f"purplestrike.plugins.attack_executors.{name}"
                )
                cls = getattr(module, f"{self._to_class_name(name)}Executor", None)
                if cls is None:
                    logger.warning(f"No executor class found in {name}")
                    continue
                executor = cls()
                await executor.setup(config.get(name, {}))
                self.registry.register_attack_executor(executor)
                logger.info(f"Loaded attack executor: {name}")
            except Exception as e:
                logger.error(f"Failed to load attack executor '{name}': {e}")

    async def _load_builtin_siem_connectors(self, config: dict[str, Any]) -> None:
        for name in BUILTIN_SIEM_CONNECTORS:
            try:
                module = importlib.import_module(
                    f"purplestrike.plugins.siem_connectors.{name}"
                )
                cls = getattr(module, f"{self._to_class_name(name)}Connector", None)
                if cls is None:
                    logger.warning(f"No connector class found in {name}")
                    continue
                connector = cls()
                self.registry.register_siem_connector(connector)
                logger.info(f"Loaded SIEM connector: {name}")
            except Exception as e:
                logger.error(f"Failed to load SIEM connector '{name}': {e}")

    async def _load_builtin_llm_providers(self, config: dict[str, Any]) -> None:
        """Load LLM providers. Only logs individual failures if no provider was loaded."""
        errors: list[str] = []
        for name in BUILTIN_LLM_PROVIDERS:
            try:
                module = importlib.import_module(
                    f"purplestrike.plugins.llm_providers.{name}"
                )
                cls = getattr(module, f"{self._to_class_name(name)}Provider", None)
                if cls is None:
                    errors.append(f"No provider class found in {name}")
                    continue
                provider = cls()
                prov_logger = logging.getLogger(f"purplestrike.plugins.llm_providers.{name}")
                old_level = prov_logger.level
                prov_logger.setLevel(logging.ERROR)
                try:
                    await provider.setup(config.get(name, {}))
                finally:
                    prov_logger.setLevel(old_level)
                self.registry.register_llm_provider(provider)
            except Exception as e:
                errors.append(f"Failed to load LLM provider '{name}': {e}")

        loaded = self.registry.list_llm_providers()
        if not loaded:
            for err in errors:
                logger.error(err)
        else:
            for name in loaded:
                logger.info(f"Loaded LLM provider: {name}")

    async def _load_builtin_report_formatters(self, config: dict[str, Any]) -> None:
        for name in BUILTIN_REPORT_FORMATTERS:
            try:
                module = importlib.import_module(
                    f"purplestrike.plugins.report_formatters.{name}"
                )
                cls = getattr(module, f"{self._to_class_name(name)}Formatter", None)
                if cls is None:
                    logger.warning(f"No formatter class found in {name}")
                    continue
                formatter = cls()
                await formatter.setup(config.get(name, {}))
                self.registry.register_report_formatter(formatter)
                logger.info(f"Loaded report formatter: {name}")
            except Exception as e:
                logger.error(f"Failed to load report formatter '{name}': {e}")

    async def _load_user_plugins(self, config: dict[str, Any]) -> None:
        if not USER_PLUGIN_BASE.exists():
            return
        for plugin_type_dir in USER_PLUGIN_BASE.iterdir():
            if not plugin_type_dir.is_dir():
                continue
            logger.info(f"Scanning user plugins in {plugin_type_dir}")
    @staticmethod
    def _to_class_name(snake: str) -> str:
        return "".join(part.capitalize() for part in snake.split("_"))
