from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class NvidiaProvider:
    name = "nvidia"
    model = "meta/llama-3.1-8b-instruct"

    def __init__(self) -> None:
        self._api_key: str = ""
        self._base_url: str = "https://integrate.api.nvidia.com/v1"
        self._model: str = "meta/llama-3.1-8b-instruct"
        self._client: Any = None

    async def setup(self, config: dict[str, Any]) -> None:
        self._api_key = config.get("api_key") or os.getenv("PURPLESTRIKE_NVIDIA_API_KEY", "")
        self._base_url = config.get("base_url") or os.getenv("PURPLESTRIKE_NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self._model = config.get("model") or os.getenv("PURPLESTRIKE_NVIDIA_MODEL", "meta/llama-3.1-8b-instruct")
        self.model = self._model

        if not self._api_key:
            logger.warning("NVIDIA API key not configured. Set PURPLESTRIKE_NVIDIA_API_KEY.")

        try:
            import httpx

            headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
            import ssl

            self._client = httpx.AsyncClient(
                base_url=self._base_url, timeout=120.0, headers=headers,
                verify=ssl.create_default_context(),
            )
        except ImportError:
            logger.error("httpx not installed. Required for NVIDIA provider.")
            self._client = None

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        if self._client is None:
            raise RuntimeError("NVIDIA client not initialized")

        payload: dict[str, Any] = {
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "temperature": kwargs.get("temperature", 0.3),
        }
        if self._model:
            payload["model"] = self._model

        for attempt in range(3):
            try:
                response = await self._client.post("/chat/completions", json=payload)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
            except Exception as e:
                wait = 2 ** (attempt + 1)
                logger.warning(f"NVIDIA API call failed (attempt {attempt + 1}/3): {e}. Retrying in {wait}s...")
                import asyncio
                await asyncio.sleep(wait)

        raise RuntimeError("NVIDIA API call failed after 3 attempts")

    async def complete_structured(self, messages: list[dict[str, str]], schema: type, **kwargs: Any) -> Any:
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
            await self._client.aclose()
            self._client = None

    @property
    def supported_techniques(self) -> list[str]:
        return []
