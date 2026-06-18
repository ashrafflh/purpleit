from __future__ import annotations

from typing import Any

import pytest

from purplestrike.plugins.llm_providers.deepseek import DeepseekProvider

pytestmark = pytest.mark.asyncio


class FakeResponse:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"detection_status":"detected","confidence":0.9,'
                            '"matched_alerts":[],"reasoning":"ok"}'
                        )
                    }
                }
            ]
        }


class FakeClient:
    def __init__(self) -> None:
        self.path = ""
        self.payload: dict[str, Any] = {}
        self.closed = False

    async def post(self, path: str, json: dict[str, Any]) -> FakeResponse:
        self.path = path
        self.payload = json
        return FakeResponse()

    async def aclose(self) -> None:
        self.closed = True


async def test_deepseek_provider_posts_chat_completion_payload() -> None:
    provider = DeepseekProvider()
    fake_client = FakeClient()
    provider._client = fake_client
    provider._model = "deepseek-chat"

    result = await provider.complete([{"role": "user", "content": "hello"}])

    assert result.startswith('{"detection_status"')
    assert fake_client.path == "/chat/completions"
    assert fake_client.payload["model"] == "deepseek-chat"
    assert fake_client.payload["messages"] == [{"role": "user", "content": "hello"}]

    await provider.teardown()

    assert fake_client.closed is True
