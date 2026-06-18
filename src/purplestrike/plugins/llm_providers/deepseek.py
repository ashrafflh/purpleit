from __future__ import annotations

import json
import os
from typing import Any

import httpx


class DeepseekProvider:
    name = "deepseek"
    model = "deepseek-chat"

    def __init__(self) -> None:
        self._api_key = ""
        self._model = "deepseek-chat"
        self._base_url = "https://api.deepseek.com"
        self._temperature = 0.3
        self._max_tokens = 4096
        self._timeout = 60.0
        self._client: httpx.AsyncClient | None = None

    async def setup(self, config: dict[str, Any]) -> None:
        extra = config.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}

        self._api_key = config.get("api_key") or os.getenv("PURPLESTRIKE_DEEPSEEK_API_KEY", "")
        self._model = (
            config.get("model")
            or os.getenv("PURPLESTRIKE_DEEPSEEK_MODEL", "")
            or "deepseek-chat"
        )
        self.model = self._model
        self._base_url = (
            config.get("base_url")
            or extra.get("base_url")
            or os.getenv("PURPLESTRIKE_DEEPSEEK_BASE_URL", "")
            or "https://api.deepseek.com"
        ).rstrip("/")
        self._temperature = float(config.get("temperature", 0.3))
        self._max_tokens = int(config.get("max_tokens", 4096))
        self._timeout = float(extra.get("timeout", 60.0))

        if not self._api_key:
            raise ValueError("DeepSeek API key not configured. Set PURPLESTRIKE_DEEPSEEK_API_KEY.")

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        if self._client is None:
            raise RuntimeError("DeepSeek client not initialized. Set PURPLESTRIKE_DEEPSEEK_API_KEY.")

        payload = {
            "model": kwargs.get("model", self._model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self._temperature),
            "max_tokens": kwargs.get("max_tokens", self._max_tokens),
        }

        response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""

    async def complete_structured(
        self,
        messages: list[dict[str, str]],
        schema: type,
        **kwargs: Any,
    ) -> Any:
        raw = await self.complete(messages, **kwargs)
        json_str = raw
        if "```json" in raw:
            json_str = raw.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in raw:
            json_str = raw.split("```", 1)[1].split("```", 1)[0]
        return schema.model_validate(json.loads(json_str.strip()))

    async def teardown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def supported_techniques(self) -> list[str]:
        return []
