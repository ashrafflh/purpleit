from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class OllamaProvider:
    name = "ollama"
    model = "llama3"

    def __init__(self) -> None:
        self._base_url: str = "http://localhost:11434"
        self._model: str = "llama3"
        self._client: Any = None

    async def setup(self, config: dict[str, Any]) -> None:
        self._base_url = config.get("base_url") or os.getenv("PURPLESTRIKE_OLLAMA_BASE_URL", "http://localhost:11434")
        self._model = config.get("model") or os.getenv("PURPLESTRIKE_OLLAMA_MODEL", "llama3")
        self.model = self._model

        try:
            import httpx

            self._client = httpx.AsyncClient(base_url=self._base_url, timeout=120.0)
        except ImportError:
            logger.error("httpx not installed. Required for Ollama provider.")
            self._client = None

    async def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        if self._client is None:
            raise RuntimeError("Ollama client not initialized")

        prompt = "\n".join(f"{m['role']}: {m['content']}" for m in messages)

        for attempt in range(3):
            try:
                response = await self._client.post(
                    "/api/generate",
                    json={"model": self._model, "prompt": prompt, "stream": False},
                )
                response.raise_for_status()
                data = response.json()
                return data.get("response", "")
            except Exception as e:
                wait = 2 ** (attempt + 1)
                logger.warning(f"Ollama call failed (attempt {attempt + 1}/3): {e}. Retrying in {wait}s...")
                import asyncio
                await asyncio.sleep(wait)

        raise RuntimeError("Ollama call failed after 3 attempts")

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
