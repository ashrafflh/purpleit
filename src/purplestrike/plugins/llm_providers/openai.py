from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class OpenaiProvider:
    name = "openai"
    model = "gpt-4o"

    def __init__(self) -> None:
        self._api_key: str = ""
        self._model: str = "gpt-4o"
        self._base_url: str | None = None
        self._temperature: float = 0.3
        self._max_tokens: int = 4096
        self._client: Any = None

    async def setup(self, config: dict[str, Any]) -> None:
        self._api_key = config.get("api_key") or os.getenv("PURPLESTRIKE_OPENAI_API_KEY", "")
        self._model = config.get("model") or os.getenv("PURPLESTRIKE_OPENAI_MODEL", "gpt-4o")
        self._base_url = config.get("base_url")
        self._temperature = float(config.get("temperature", 0.3))
        self._max_tokens = int(config.get("max_tokens", 4096))

        if not self._api_key:
            logger.warning("OpenAI API key not configured. Set PURPLESTRIKE_OPENAI_API_KEY.")

        try:
            from openai import AsyncOpenAI

            kwargs: dict[str, Any] = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = AsyncOpenAI(**kwargs)
            self.model = self._model
        except ImportError:
            logger.error("openai package not installed. Install with: pip install purplestrike[openai]")
            self._client = None

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        if self._client is None:
            raise RuntimeError("OpenAI client not initialized. Install openai package and set API key.")

        for attempt in range(3):
            try:
                response = await self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=kwargs.get("temperature", self._temperature),
                    max_tokens=kwargs.get("max_tokens", self._max_tokens),
                )
                content = response.choices[0].message.content
                return content or ""
            except Exception as e:
                wait = 2 ** (attempt + 1)
                logger.warning(f"OpenAI API call failed (attempt {attempt + 1}/3): {e}. Retrying in {wait}s...")
                import asyncio
                await asyncio.sleep(wait)

        raise RuntimeError("OpenAI API call failed after 3 attempts")

    async def complete_structured(
        self,
        messages: list[dict[str, str]],
        schema: type,
        **kwargs: Any,
    ) -> Any:
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
