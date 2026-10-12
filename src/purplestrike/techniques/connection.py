from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import shlex
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from xml.etree import ElementTree

from purplestrike.models.config import ConnectionMethod, ConnectionSettings, PurpleStrikeConfig

logger = logging.getLogger(__name__)

_target_credentials: dict[str, str] = {}
_target_platforms: dict[str, str] = {}
_connection_settings: ConnectionSettings | None = None
_target_methods: dict[str, ConnectionMethod] = {}
_WINRM_MAX_ATTEMPTS = 3
_WINRM_TRANSIENT_MARKERS = (
    "connecttimeouterror",
    "connection to",
    "httpconnectionpool",
    "max retries exceeded",
    "read timed out",
    "timed out",
    "timeout",
    "temporarily unavailable",
)


def set_target_credentials(domain: str = "", username: str = "", password: str = "") -> None:
    """Set target credentials to be used by TargetConnection."""
    _target_credentials["TARGET_AD_DOMAIN"] = domain
    _target_credentials["TARGET_USERNAME"] = username
    _target_credentials["TARGET_PASSWORD"] = password


class ConnectionError(Exception):  # noqa: A001 - retain the public exception API
    pass


class _SubmittedCommandError(Exception):
    """The command may have run; retrying it could duplicate target changes."""


class CommandResult:
    __slots__ = ("exit_code", "stderr", "stdout", "success")

    def __init__(self, stdout: str, stderr: str, exit_code: int) -> None:
        self.stdout = stdout
        self.stderr = _decode_powershell_errors(stderr)
        if exit_code != 0 and not self.stderr.strip():
            self.stderr = stdout.strip() or f"Remote command failed with exit code {exit_code}"
        self.exit_code = exit_code
        self.success = exit_code == 0

    def __repr__(self) -> str:
        status = "OK" if self.success else f"FAIL({self.exit_code})"
        return f"CommandResult({status}, stdout={len(self.stdout)}c)"


def _get_credential(key: str, default: str = "") -> str:
    if _target_credentials.get(key):
        return _target_credentials[key]
    val = os.environ.get(f"PURPLESTRIKE_{key}", default)
    if not val:
        val = os.environ.get(key, default)
    return val


def _decode_powershell_errors(stderr: str) -> str:
    if not stderr.startswith("#< CLIXML"):
        return stderr
    try:
        root = ElementTree.fromstring(stderr.split("\n", 1)[1])
        errors = [
            element.text or "" for element in root.iter() if element.get("S", "").lower() == "error"
        ]
        return re.sub(r"_x([0-9A-Fa-f]{4})_", lambda m: chr(int(m[1], 16)), "".join(errors))
    except (ElementTree.ParseError, IndexError):
        return stderr


def _redact_target_password(text: str) -> str:
    for key in (
        "TARGET_PASSWORD",
        "WINRM_PASSWORD",
        "WINRM_NONADMIN_PASSWORD",
        "SSH_PASSWORD",
        "WMI_PASSWORD",
    ):
        password = _get_credential(key, "")
        if password:
            text = text.replace(password.replace("'", "''"), "[REDACTED]")
            text = text.replace(password, "[REDACTED]")
    return text


def set_connection_settings(
    settings: ConnectionSettings,
    methods: dict[str, ConnectionMethod] | None = None,
) -> None:
    global _connection_settings
    _connection_settings = settings.model_copy(deep=True)
    _target_methods.clear()
    _target_methods.update(methods or {})


def _powershell_script(script: str, cwd: str | None = None) -> str:
    prefix = (
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; "
        "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); "
        "$global:LASTEXITCODE = 0;\n"
    )
    if cwd:
        prefix += "Set-Location -LiteralPath '" + cwd.replace("'", "''") + "';\n"
    return (
        prefix + script + "\n$__purpleSuccess = $?; "
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
        "if (-not $__purpleSuccess) { exit 1 }"
    )


def _get_winrm_transport(password: str) -> str:
    transport = _get_credential("WINRM_TRANSPORT", "").strip()
    if transport:
        return transport
    return "ntlm" if password else "kerberos"


def _target_os(target: str) -> str:
    if target in _target_platforms:
        return _target_platforms[target]
    if any(
        indicator in target.lower() for indicator in ("linux", "lnx", "ubuntu", "centos", "rhel")
    ):
        return "linux"
    return "windows"


def set_target_platforms(platforms: dict[str, str]) -> None:
    """Use configured platforms, including targets addressed by IP."""
    _target_platforms.clear()
    _target_platforms.update(platforms)


def _is_transient_winrm_error(error: Exception) -> bool:
    if isinstance(error, _SubmittedCommandError):
        return False
    message = str(error).lower()
    # A read timeout occurs after submission; retrying can duplicate target changes.
    if "read timed out" in message or "readtimeout" in message:
        return False
    return any(marker in message for marker in _WINRM_TRANSIENT_MARKERS)


def _run_ps_with_deadline(
    session: Any,
    script: str,
    timeout: int,
    noprofile: bool = False,
) -> Any:
    """Bound WinRM receive polling and always terminate/close our own remote shell."""
    from winrm.exceptions import WinRMOperationTimeoutError

    protocol = session.protocol
    deadline = time.monotonic() + timeout
    shell_id = None
    command_id = None
    submitted = False
    original_operation_timeout = getattr(protocol, "operation_timeout_sec", None)
    if original_operation_timeout is not None:
        protocol.operation_timeout_sec = min(original_operation_timeout, max(1, timeout - 1))
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    try:
        shell_id = protocol.open_shell(noprofile=True) if noprofile else protocol.open_shell()
        if time.monotonic() >= deadline:
            return SimpleNamespace(
                std_out=b"", std_err=b"Remote shell creation timed out", status_code=124
            )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        script_input = None
        if len(encoded) > 7000:
            # WinRS can still impose cmd.exe's command-line limit. Stream large
            # scripts over stdin using a small encoded bootstrap instead.
            script_input = encoded.encode("ascii")
            bootstrap = (
                "$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("
                "[Console]::In.ReadToEnd())); Invoke-Expression $s"
            )
            encoded = base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")
        submitted = True
        command_id = protocol.run_command(
            shell_id,
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            skip_cmd_shell=True,
        )
        if script_input is not None:
            protocol.send_command_input(shell_id, command_id, script_input, end=True)
        receive = getattr(protocol, "get_command_output_raw", None)
        if receive is None:
            receive = protocol._raw_get_command_output
        while time.monotonic() < deadline:
            try:
                out, err, code, done = receive(shell_id, command_id)
                stdout.append(out)
                stderr.append(err)
                if done:
                    if time.monotonic() >= deadline:
                        return SimpleNamespace(
                            std_out=b"".join(stdout),
                            std_err=b"Command completed after its deadline",
                            status_code=124,
                        )
                    return SimpleNamespace(
                        std_out=b"".join(stdout), std_err=b"".join(stderr), status_code=code
                    )
            except WinRMOperationTimeoutError:
                continue
        return SimpleNamespace(
            std_out=b"".join(stdout),
            std_err=b"Remote command timed out; termination requested",
            status_code=124,
        )
    except Exception as error:
        if submitted:
            raise _SubmittedCommandError(str(error)) from error
        raise
    finally:
        if command_id is not None:
            try:
                protocol.cleanup_command(shell_id, command_id)
            except Exception as error:
                logger.warning("Failed to terminate WinRM command %s: %s", command_id, error)
        if shell_id is not None:
            try:
                protocol.close_shell(shell_id)
            except Exception as error:
                logger.warning("Failed to close WinRM shell %s: %s", shell_id, error)
        if original_operation_timeout is not None:
            protocol.operation_timeout_sec = original_operation_timeout


def command_error(result: CommandResult, default: str = "Remote command failed") -> str:
    return result.stderr or result.stdout or default


def is_transport_failure(result: CommandResult) -> bool:
    if result.success:
        return False
    message = command_error(result, "").lower()
    return any(marker in message for marker in _WINRM_TRANSIENT_MARKERS)


class TargetConnection:
    """Agentless execution with an explicit transport independent of the target OS."""

    def __init__(
        self,
        target: str,
        method: ConnectionMethod | str | None = None,
        settings: ConnectionSettings | None = None,
    ) -> None:
        self.target = target
        self._os_type = _target_os(target)
        self.settings = settings or _connection_settings or PurpleStrikeConfig.from_env().connection
        self.method = ConnectionMethod(
            method or _target_methods.get(target) or self.settings.method
        )
        if self.method == ConnectionMethod.AUTO:
            self.method = ConnectionMethod.WINRM if self.is_windows else ConnectionMethod.SSH
        if not self.is_windows and self.method != ConnectionMethod.SSH:
            raise ConnectionError(f"{self.method} requires a Windows target")
        self._ssh_conn: Any = None
        self._winrm_conn: Any = None
        self._wmi_conn: Any = None

    def _credentials(self) -> tuple[str, str, str]:
        prefix = self.method.value.upper()
        mode_username = _get_credential(f"{prefix}_USERNAME")
        username = mode_username or _get_credential(
            "TARGET_USERNAME",
            "Administrator" if self.is_windows else "attack_user",
        )
        password = _get_credential(f"{prefix}_PASSWORD")
        if not mode_username and not password:
            password = _get_credential("TARGET_PASSWORD")
        domain = _get_credential(f"{prefix}_DOMAIN") or _get_credential("TARGET_AD_DOMAIN")
        return username, password, domain

    def _qualified_username(self, username: str, domain: str) -> str:
        if self.is_windows and domain and "\\" not in username and "@" not in username:
            return f"{domain}\\{username}"
        return username

    @property
    def os_type(self) -> str:
        return self._os_type

    @property
    def is_windows(self) -> bool:
        return self._os_type == "windows"

    async def connect(self) -> None:
        if self.method == ConnectionMethod.SSH:
            await self._connect_ssh()
        elif self.method == ConnectionMethod.WMI:
            from purplestrike.techniques.wmi_connection import WmiConnection

            self._wmi_conn = WmiConnection(self.target, self._credentials(), self.settings)
            try:
                await asyncio.to_thread(self._wmi_conn.connect)
            except Exception as error:
                await self.disconnect()
                raise ConnectionError(_redact_target_password(str(error))) from None
        else:
            await self._connect_winrm()
            if self.method == ConnectionMethod.WINRM_NONADMIN:
                # Check the group SIDs, including deny-only Administrators membership.
                # Selecting this mode never silently turns an admin token into a user token.
                result = await self.run_ps(
                    "$id = [Security.Principal.WindowsIdentity]::GetCurrent(); "
                    "if (@($id.Groups | ForEach-Object { $_.Value }) -contains 'S-1-5-32-544') "
                    "{ throw 'winrm_nonadmin requires an account outside local Administrators' }; "
                    "Write-Output $id.Name",
                    timeout=self.settings.connect_timeout,
                )
                if not result.success:
                    await self.disconnect()
                    raise ConnectionError(command_error(result))

    async def _connect_ssh(self) -> None:
        try:
            import asyncssh

            username, password, domain = self._credentials()
            username = self._qualified_username(username, domain)

            kwargs: dict[str, Any] = {
                "host": self.target,
                "username": username,
                "port": self.settings.ssh_port,
                "connect_timeout": self.settings.connect_timeout,
                "login_timeout": self.settings.connect_timeout,
            }
            if self.settings.ssh_known_hosts:
                kwargs["known_hosts"] = (
                    None
                    if self.settings.ssh_known_hosts == "none"
                    else str(Path(self.settings.ssh_known_hosts).expanduser())
                )
            if self.settings.ssh_client_keys:
                kwargs["client_keys"] = [
                    str(Path(p).expanduser()) for p in self.settings.ssh_client_keys
                ]
            if password:
                kwargs["password"] = password

            self._ssh_conn = await asyncssh.connect(**kwargs)
            logger.info(f"SSH connected to {self.target}")
        except ImportError:
            raise ConnectionError(
                "asyncssh not installed. Install with: uv sync --extra ssh"
            ) from None
        except Exception as e:
            raise ConnectionError(
                _redact_target_password(
                    f"SSH connection to {self.target}:{self.settings.ssh_port} failed: "
                    f"{str(e) or type(e).__name__}"
                )
            ) from None

    async def _connect_winrm(self) -> None:
        try:
            import winrm

            username, password, domain = self._credentials()
            username = self._qualified_username(username, domain)

            transport = _get_winrm_transport(password)

            self._winrm_conn = winrm.Session(
                self.settings.winrm_endpoint.format(host=self.target) or self.target,
                auth=(username, password),
                transport=transport,
                server_cert_validation=self.settings.winrm_cert_validation,
                operation_timeout_sec=min(10, self.settings.connect_timeout),
                read_timeout_sec=max(11, self.settings.connect_timeout + 1),
            )
            logger.info(f"WinRM connected to {self.target}")
        except ImportError:
            raise ConnectionError("pywinrm not installed. Install with: uv sync") from None
        except Exception as e:
            raise ConnectionError(
                _redact_target_password(f"WinRM connection to {self.target} failed: {e}")
            ) from None

    async def run_command(
        self,
        command: str,
        timeout: int = 60,
        cwd: str | None = None,
    ) -> CommandResult:
        if self.is_windows:
            if cwd:
                command = "Set-Location -LiteralPath '" + cwd.replace("'", "''") + "';\n" + command
            return await self.run_ps(command, timeout)
        if self._ssh_conn is not None:
            return await self._run_ssh(command, timeout, cwd)
        if self._winrm_conn is not None:
            return await self._run_winrm(command, timeout)
        raise ConnectionError(f"Not connected to {self.target}")

    async def _run_ssh(
        self, command: str, timeout: int = 60, cwd: str | None = None
    ) -> CommandResult:
        if cwd:
            command = f"cd {shlex.quote(cwd)} && {command}"

        try:
            result = await asyncio.wait_for(
                self._ssh_conn.run(command),
                timeout=timeout,
            )
            return CommandResult(
                stdout=_redact_target_password(result.stdout or ""),
                stderr=_redact_target_password(result.stderr or ""),
                exit_code=result.exit_status if result.exit_status is not None else 1,
            )
        except TimeoutError:
            return CommandResult(stdout="", stderr="Command timed out", exit_code=124)

    async def _run_winrm(self, command: str, timeout: int = 60) -> CommandResult:
        return await self._run_winrm_with_retries(command, timeout)

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        if self._wmi_conn is not None:
            try:
                stdout, stderr, code = await asyncio.to_thread(
                    self._wmi_conn.run_ps,
                    _powershell_script(script),
                    timeout,
                )
                return CommandResult(
                    _redact_target_password(stdout), _redact_target_password(stderr), code
                )
            except Exception as error:
                return CommandResult("", _redact_target_password(str(error)), 1)
        if self._winrm_conn is not None:
            return await self._run_winrm_ps(script, timeout)
        if self._ssh_conn is not None:
            if self.is_windows:
                return await self._run_windows_ssh_ps(_powershell_script(script), timeout)
            escaped = script.replace("'", "'\\''")
            return await self._run_ssh(
                f"powershell -NoProfile -NonInteractive -Command '{escaped}'",
                timeout,
            )
        raise ConnectionError(f"Not connected to {self.target}")

    async def _run_windows_ssh_ps(self, script: str, timeout: int) -> CommandResult:
        # Stream the body through stdin; a small encoded bootstrap works with both
        # cmd.exe and PowerShell as sshd's default shell, including long/Unicode scripts.
        encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        bootstrap = (
            "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); "
            "$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("
            "[Console]::In.ReadToEnd())); & ([scriptblock]::Create($s))"
        )
        encoded = base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")
        process = await self._ssh_conn.create_process(
            f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}",
            encoding="utf-8",
        )
        try:
            process.stdin.write(encoded_script)
            process.stdin.write_eof()
            result = await asyncio.wait_for(process.wait(), timeout)
            return CommandResult(
                _redact_target_password(result.stdout or ""),
                _redact_target_password(result.stderr or ""),
                result.exit_status if result.exit_status is not None else 1,
            )
        except TimeoutError:
            process.kill()
            return CommandResult("", "SSH command timed out; termination requested", 124)
        finally:
            process.close()

    async def _run_winrm_ps(self, script: str, timeout: int = 60) -> CommandResult:
        return await self._run_winrm_with_retries(script, timeout)

    async def _run_winrm_with_retries(self, script: str, timeout: int) -> CommandResult:
        script = _powershell_script(script)
        last_error: Exception | None = None
        session = self._winrm_conn
        for attempt in range(1, _WINRM_MAX_ATTEMPTS + 1):
            try:
                if hasattr(session, "protocol"):
                    # The worker enforces its deadline and cleans up before returning.
                    # Cancelling only an asyncio future leaves pywinrm polling forever.
                    result = await asyncio.get_running_loop().run_in_executor(
                        None,
                        _run_ps_with_deadline,
                        session,
                        script,
                        timeout,
                        self.method == ConnectionMethod.WINRM_NONADMIN,
                    )
                else:
                    result = await asyncio.wait_for(
                        asyncio.get_running_loop().run_in_executor(
                            None, lambda: session.run_ps(script)
                        ),
                        timeout=timeout,
                    )
                return CommandResult(
                    stdout=_redact_target_password(
                        result.std_out.decode("utf-8", errors="replace") if result.std_out else ""
                    ),
                    stderr=_redact_target_password(
                        result.std_err.decode("utf-8", errors="replace") if result.std_err else ""
                    ),
                    exit_code=result.status_code if result.status_code is not None else 1,
                )
            except TimeoutError:
                # A timed-out remote command may still be running; do not execute it twice.
                return CommandResult(stdout="", stderr="Remote command timed out", exit_code=124)
            except Exception as e:
                last_error = e
                if attempt >= _WINRM_MAX_ATTEMPTS or not _is_transient_winrm_error(e):
                    break
                logger.warning(
                    "Transient WinRM error on %s attempt %s/%s: %s",
                    self.target,
                    attempt,
                    _WINRM_MAX_ATTEMPTS,
                    e,
                )
                await asyncio.sleep(2)
        return CommandResult(
            stdout="", stderr=_redact_target_password(str(last_error)), exit_code=1
        )

    async def upload(self, local_path: str, remote_path: str) -> None:
        if self._ssh_conn is not None:
            async with self._ssh_conn.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
        else:
            content = Path(local_path).read_bytes()
            b64 = base64.b64encode(content).decode()
            quoted_path = remote_path.replace("'", "''")
            script = (
                f"$bytes = [Convert]::FromBase64String('{b64}'); "
                f"[IO.File]::WriteAllBytes('{quoted_path}', $bytes)"
            )
            result = await self.run_ps(script)
            if not result.success:
                raise ConnectionError(f"Upload failed: {result.stderr}")

    async def download(self, remote_path: str, local_path: str) -> None:
        if self._ssh_conn is not None:
            async with self._ssh_conn.start_sftp_client() as sftp:
                await sftp.get(remote_path, local_path)
        else:
            quoted_path = remote_path.replace("'", "''")
            script = (
                f"$bytes = [IO.File]::ReadAllBytes('{quoted_path}'); "
                f"[Convert]::ToBase64String($bytes)"
            )
            result = await self.run_ps(script)
            if not result.success:
                raise ConnectionError(f"Download failed: {result.stderr}")
            data = base64.b64decode(result.stdout.strip(), validate=True)
            Path(local_path).write_bytes(data)

    async def disconnect(self) -> None:
        if self._wmi_conn is not None:
            await asyncio.to_thread(self._wmi_conn.disconnect)
            self._wmi_conn = None
        if self._ssh_conn is not None:
            self._ssh_conn.close()
            await self._ssh_conn.wait_closed()
            self._ssh_conn = None
        self._winrm_conn = None
        logger.info(f"Disconnected from {self.target}")


async def get_connection(target: str) -> TargetConnection:
    conn = TargetConnection(target)
    await conn.connect()
    return conn
