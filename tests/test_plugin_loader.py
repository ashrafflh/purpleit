from __future__ import annotations

import pytest

from purplestrike.plugins.loader import PluginLoader
from purplestrike.plugins.registry import PluginRegistry

pytestmark = pytest.mark.asyncio


async def test_llm_loader_only_loads_configured_provider() -> None:
    registry = PluginRegistry()
    loader = PluginLoader(registry)

    await loader._load_builtin_llm_providers({"deepseek": {"api_key": "test-key"}})

    assert registry.list_llm_providers() == ["deepseek"]

    provider = registry.get_llm_provider("deepseek")
    assert provider is not None
    await provider.teardown()
