from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class AnthropicProvider:
    name = "anthropic"
    model = "claude-3-5-sonnet-20241022"

    def __init__(self) -> None:
        self._api_key: str = ""
        self._model: str = "claude-3-5-sonnet-20241022"
        self._client: Any = None

    async def setup(self, config: dict[str, Any]) -> None:
        self._api_key = config.get("api_key") or os.getenv("PURPLESTRIKE_ANTHROPIC_API_KEY", "")
        self._model = config.get("model") or os.getenv("PURPLESTRIKE_ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

        if not self._api_key:
            logger.warning("Anthropic API key not configured. Set PURPLESTRIKE_ANTHROPIC_API_KEY.")

        try:
            from anthropic import AsyncAnthropic

            self._client = AsyncAnthropic(api_key=self._api_key)
            self.model = self._model
        except ImportError:
            logger.error("anthropic package not installed. Install with: pip install purplestrike[anthropic]")
            self._client = None

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        if self._client is None:
            raise RuntimeError("Anthropic client not initialized")

        system_msg = ""
        user_messages = []
        for m in messages:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                user_messages.append(m)

        for attempt in range(3):
            try:
                response = await self._client.messages.create(
                    model=self._model,
                    max_tokens=kwargs.get("max_tokens", 4096),
                    system=system_msg,
                    messages=user_messages,  # type: ignore[arg-type]
                )
                return response.content[0].text
            except Exception as e:
                wait = 2 ** (attempt + 1)
                logger.warning(f"Anthropic API call failed (attempt {attempt + 1}/3): {e}. Retrying in {wait}s...")
                import asyncio
                await asyncio.sleep(wait)

        raise RuntimeError("Anthropic API call failed after 3 attempts")

    async def complete_structured(self, messages: list[dict[str, str]], schema: type, **kwargs: Any) -> Any:
        raw = await self.complete(messages, **kwargs)
        data = json.loads(raw)
        return schema.model_validate(data)

    async def teardown(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None

    @property
    def supported_techniques(self) -> list[str]:
        return []
