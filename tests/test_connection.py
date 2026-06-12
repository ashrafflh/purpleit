from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from purplestrike.techniques import connection
from purplestrike.techniques.connection import TargetConnection, set_target_credentials


class FakeSession:
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        FakeSession.args = args
        FakeSession.kwargs = kwargs


@pytest.fixture(autouse=True)
def clear_target_credentials() -> Any:
    connection._target_credentials.clear()
    yield
    connection._target_credentials.clear()


@pytest.fixture
def fake_winrm(monkeypatch: pytest.MonkeyPatch) -> type[FakeSession]:
    FakeSession.args = ()
    FakeSession.kwargs = {}
    monkeypatch.setitem(
        __import__("sys").modules,
        "winrm",
        SimpleNamespace(Session=FakeSession),
    )
    return FakeSession


@pytest.mark.asyncio
async def test_winrm_defaults_to_ntlm_when_password_is_configured(
    fake_winrm: type[FakeSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PURPLESTRIKE_WINRM_TRANSPORT", raising=False)
    monkeypatch.delenv("WINRM_TRANSPORT", raising=False)
    set_target_credentials(
        domain="purple.local",
        username="seif.hassine",
        password="secret",
    )

    conn = TargetConnection("10.10.1.108")
    await conn._connect_winrm()

    assert fake_winrm.args == ("10.10.1.108",)
    assert fake_winrm.kwargs["auth"] == ("purple.local\\seif.hassine", "secret")
    assert fake_winrm.kwargs["transport"] == "ntlm"


@pytest.mark.asyncio
async def test_winrm_respects_explicit_transport(
    fake_winrm: type[FakeSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PURPLESTRIKE_WINRM_TRANSPORT", "kerberos")
    set_target_credentials(
        domain="purple.local",
        username="seif.hassine",
        password="secret",
    )

    conn = TargetConnection("10.10.1.108")
    await conn._connect_winrm()

    assert fake_winrm.kwargs["transport"] == "kerberos"


@pytest.mark.asyncio
async def test_winrm_uses_kerberos_without_password(
    fake_winrm: type[FakeSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PURPLESTRIKE_WINRM_TRANSPORT", raising=False)
    monkeypatch.delenv("WINRM_TRANSPORT", raising=False)
    set_target_credentials(domain="purple.local", username="seif.hassine", password="")

    conn = TargetConnection("10.10.1.108")
    await conn._connect_winrm()

    assert fake_winrm.kwargs["transport"] == "kerberos"
