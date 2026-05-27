from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class DeepseekProvider:
    name = "deepseek"
    model = "deepseek-chat"

    def __init__(self) -> None:
        self._api_key: str = ""
        self._base_url: str = "https://api.deepseek.com"
        self._model: str = "deepseek-chat"
        self._temperature: float = 0.3
        self._max_tokens: int = 4096
        self._thinking: str = "disabled"
        self._timeout: float = 180.0
        self._client: Any = None

    async def setup(self, config: dict[str, Any]) -> None:
        extra = config.get("extra", {})
        self._api_key = config.get("api_key") or os.getenv("PURPLESTRIKE_DEEPSEEK_API_KEY", "")
        self._base_url = config.get("base_url") or os.getenv(
            "PURPLESTRIKE_DEEPSEEK_BASE_URL", "https://api.deepseek.com"
        )
        self._model = config.get("model") or os.getenv(
            "PURPLESTRIKE_DEEPSEEK_MODEL", "deepseek-chat"
        )
        self._temperature = float(config.get("temperature", 0.3))
        self._max_tokens = int(config.get("max_tokens", 4096))
        self._thinking = str(extra.get("thinking", "disabled"))
        self._timeout = float(extra.get("timeout", 180.0))
        self.model = self._model

        if not self._api_key:
            logger.warning("DeepSeek API key not configured. Set PURPLESTRIKE_DEEPSEEK_API_KEY.")

        try:
            from openai import AsyncOpenAI

            self._client = AsyncOpenAI(
                api_key=self._api_key,
                base_url=self._base_url,
                timeout=self._timeout,
            )
        except ImportError:
            logger.error("openai package not installed. Install with: pip install purplestrike[deepseek]")
            self._client = None

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        if self._client is None:
            raise RuntimeError("DeepSeek client not initialized. Install openai package and set API key.")

        for attempt in range(3):
            try:
                request: dict[str, Any] = {
                    "model": self._model,
                    "messages": messages,
                    "temperature": kwargs.get("temperature", self._temperature),
                    "max_tokens": kwargs.get("max_tokens", self._max_tokens),
                }
                if self._thinking in {"enabled", "disabled"}:
                    request["extra_body"] = {"thinking": {"type": self._thinking}}

                response = await self._client.chat.completions.create(
                    **request,  # type: ignore[arg-type]
                )
                content = response.choices[0].message.content
                return content or ""
            except Exception as e:
                wait = 2 ** (attempt + 1)
                cause = getattr(e, "__cause__", None)
                detail = f"{e}"
                if cause is not None:
                    detail = f"{detail} ({type(cause).__name__}: {cause})"
                logger.warning(
                    f"DeepSeek API call failed (attempt {attempt + 1}/3): {detail}. "
                    f"Retrying in {wait}s..."
                )
                import asyncio

                await asyncio.sleep(wait)

        raise RuntimeError("DeepSeek API call failed after 3 attempts")

    async def complete_structured(
        self,
        messages: list[dict[str, str]],
        schema: type,
        **kwargs: Any,
    ) -> Any:
        raw = await self.complete(messages, **kwargs)
        json_str = raw
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0]
        data = json.loads(json_str.strip())
        return schema.model_validate(data)

    async def teardown(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None

    @property
    def supported_techniques(self) -> list[str]:
        return []
