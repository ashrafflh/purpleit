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
    assert "\nwhoami\n" in result.stdout
    assert "$ErrorActionPreference = 'Stop'" in result.stdout
    assert "exit $LASTEXITCODE" in result.stdout
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


@pytest.mark.asyncio
@pytest.mark.parametrize("username", [r"PURPLE\user", "user@purple.local", r".\localuser"])
async def test_winrm_preserves_qualified_usernames(fake_winrm, username) -> None:
    set_target_credentials(domain="purple.local", username=username, password="secret")
    await TargetConnection("10.10.1.107")._connect_winrm()
    assert fake_winrm.kwargs["auth"][0] == username


def test_configured_linux_ip_uses_ssh() -> None:
    connection.set_target_platforms({"10.10.1.200": "linux"})
    try:
        assert TargetConnection("10.10.1.200").os_type == "linux"
    finally:
        connection.set_target_platforms({})


def test_clixml_errors_are_readable_and_progress_is_omitted() -> None:
    result = connection.CommandResult("", '#< CLIXML\n<Objs>'
        '<Obj S="progress"><S>noise</S></Obj>'
        '<S S="Error">Access denied_x000D__x000A_</S></Objs>', 1)
    assert result.stderr == "Access denied\r\n"
    assert not result.success


def test_native_failure_without_stderr_preserves_output() -> None:
    result = connection.CommandResult("Task failed: 5", "", 5)
    assert result.stderr == "Task failed: 5"
    assert not result.success


@pytest.mark.asyncio
async def test_read_timeout_does_not_repeat_submitted_command() -> None:
    class ReadTimeoutSession:
        calls = 0

        def run_ps(self, script):
            self.calls += 1
            raise RuntimeError("HTTPConnectionPool: Read timed out")

    session = ReadTimeoutSession()
    conn = TargetConnection("host")
    conn._winrm_conn = session
    result = await conn.run_ps("New-Service example", timeout=5)
    assert not result.success
    assert session.calls == 1


class RecordingProtocol:
    def __init__(self):
        self.events = []

    def open_shell(self):
        self.events.append("open")
        return "owned-shell"

    def run_command(self, shell, command, args, skip_cmd_shell=False):
        assert skip_cmd_shell
        self.events.append("submit")
        return "owned-command"

    def get_command_output_raw(self, shell, command):
        return b"output", b"", 0, True

    def cleanup_command(self, shell, command):
        assert (shell, command) == ("owned-shell", "owned-command")
        self.events.append("terminate")

    def close_shell(self, shell):
        assert shell == "owned-shell"
        self.events.append("close")


def test_winrm_deadline_terminates_the_remote_command(monkeypatch):
    now = [0.0]
    protocol = RecordingProtocol()

    def pending(shell, command):
        now[0] = 2.0
        return b"partial", b"", -1, False

    protocol.get_command_output_raw = pending
    monkeypatch.setattr(connection.time, "monotonic", lambda: now[0])
    result = connection._run_ps_with_deadline(SimpleNamespace(protocol=protocol), "whoami", 1)
    assert result.status_code == 124
    assert result.std_out == b"partial"
    assert protocol.events == ["open", "submit", "terminate", "close"]


@pytest.mark.asyncio
async def test_winrm_does_not_resubmit_after_output_transport_failure():
    protocol = RecordingProtocol()

    def fail_receive(shell, command):
        raise RuntimeError("ConnectTimeoutError: Max retries exceeded")

    protocol.get_command_output_raw = fail_receive
    conn = TargetConnection("host")
    conn._winrm_conn = SimpleNamespace(protocol=protocol)
    result = await conn.run_ps("New-Service example", timeout=5)
    assert not result.success
    assert protocol.events == ["open", "submit", "terminate", "close"]


def test_winrm_closes_shell_even_if_termination_fails():
    protocol = RecordingProtocol()

    def fail_cleanup(shell, command):
        raise RuntimeError("Already closed")

    protocol.cleanup_command = fail_cleanup
    result = connection._run_ps_with_deadline(SimpleNamespace(protocol=protocol), "whoami", 5)
    assert result.status_code == 0
    assert protocol.events == ["open", "submit", "close"]


def test_large_powershell_scripts_are_streamed_over_stdin():
    protocol = RecordingProtocol()
    supplied = []

    def send_input(shell, command, data, end=False):
        supplied.append((connection.base64.b64decode(data).decode("utf-16-le"), end))

    protocol.send_command_input = send_input
    script = "Write-Output '" + "x" * 5000 + "'"
    result = connection._run_ps_with_deadline(SimpleNamespace(protocol=protocol), script, 5)
    assert result.status_code == 0
    assert supplied == [(script, True)]
