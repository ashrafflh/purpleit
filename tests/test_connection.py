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


class FakeRunResult:
    def __init__(
        self,
        std_out: bytes = b"",
        std_err: bytes = b"",
        status_code: int = 0,
    ) -> None:
        self.std_out = std_out
        self.std_err = std_err
        self.status_code = status_code


class FlakyWinRMSession:
    def __init__(self) -> None:
        self.calls = 0

    def run_ps(self, script: str) -> FakeRunResult:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("ConnectTimeoutError: Max retries exceeded")
        return FakeRunResult(std_out=f"ran {script}".encode())


class FailingWinRMSession:
    def __init__(self) -> None:
        self.calls = 0

    def run_ps(self, script: str) -> FakeRunResult:
        self.calls += 1
        raise RuntimeError("Access denied")


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


@pytest.mark.asyncio
async def test_winrm_retries_transient_transport_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[int] = []

    async def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(connection.asyncio, "sleep", fake_sleep)
    session = FlakyWinRMSession()
    conn = TargetConnection("10.10.1.108")
    conn._winrm_conn = session

    result = await conn.run_ps("whoami", timeout=5)

    assert result.success
    assert result.stdout == "ran whoami"
    assert session.calls == 2
    assert sleeps == [2]


@pytest.mark.asyncio
async def test_winrm_does_not_retry_command_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[int] = []

    async def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(connection.asyncio, "sleep", fake_sleep)
    session = FailingWinRMSession()
    conn = TargetConnection("10.10.1.108")
    conn._winrm_conn = session

    result = await conn.run_ps("whoami", timeout=5)

    assert not result.success
    assert result.stderr == "Access denied"
    assert session.calls == 1
    assert sleeps == []
