from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_target_credentials: dict[str, str] = {}


def set_target_credentials(
    domain: str = "", username: str = "", password: str = ""
) -> None:
    """Set target credentials to be used by TargetConnection."""
    _target_credentials["TARGET_AD_DOMAIN"] = domain
    _target_credentials["TARGET_USERNAME"] = username
    _target_credentials["TARGET_PASSWORD"] = password


class ConnectionError(Exception):
    pass


class CommandResult:
    __slots__ = ("stdout", "stderr", "exit_code", "success")

    def __init__(self, stdout: str, stderr: str, exit_code: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.success = exit_code == 0

    def __repr__(self) -> str:
        status = "OK" if self.success else f"FAIL({self.exit_code})"
        return f"CommandResult({status}, stdout={len(self.stdout)}c)"


def _get_credential(key: str, default: str = "") -> str:
    if key in _target_credentials and _target_credentials[key]:
        return _target_credentials[key]
    val = os.environ.get(f"PURPLESTRIKE_{key}", default)
    if not val:
        val = os.environ.get(key, default)
    return val


def _target_os(target: str) -> str:
    if any(indicator in target.lower() for indicator in ("linux", "lnx", "ubuntu", "centos", "rhel")):
        return "linux"
    return "windows"


class TargetConnection:
    """Manages remote connections to target systems via SSH or WinRM."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._os_type = _target_os(target)
        self._ssh_conn: Any = None
        self._winrm_conn: Any = None

    @property
    def os_type(self) -> str:
        return self._os_type

    @property
    def is_windows(self) -> bool:
        return self._os_type == "windows"

    async def connect(self) -> None:
        if self._os_type == "linux":
            await self._connect_ssh()
        else:
            await self._connect_winrm()

    async def _connect_ssh(self) -> None:
        try:
            import asyncssh

            username = _get_credential("TARGET_USERNAME", "attack_user")
            password = _get_credential("TARGET_PASSWORD", "")
            domain = _get_credential("TARGET_AD_DOMAIN", "")

            if domain and "\\" not in username and "@" not in username:
                username = f"{domain}\\{username}"

            kwargs: dict[str, Any] = {
                "host": self.target,
                "username": username,
                "known_hosts": None,
            }
            if password:
                kwargs["password"] = password

            self._ssh_conn = await asyncssh.connect(**kwargs)
            logger.info(f"SSH connected to {self.target}")
        except ImportError:
            raise ConnectionError(
                "asyncssh not installed. Install with: uv sync --extra ssh"
            )
        except Exception as e:
            raise ConnectionError(f"SSH connection to {self.target} failed: {e}")

    async def _connect_winrm(self) -> None:
        try:
            import winrm

            username = _get_credential("TARGET_USERNAME", "Administrator")
            password = _get_credential("TARGET_PASSWORD", "")
            domain = _get_credential("TARGET_AD_DOMAIN", "")

            if domain and "@" not in username:
                username = f"{username}@{domain}"

            transport = _get_credential("WINRM_TRANSPORT", "ntlm")

            self._winrm_conn = winrm.Session(
                self.target,
                auth=(username, password),
                transport=transport,
                server_cert_validation="ignore",
            )
            logger.info(f"WinRM connected to {self.target}")
        except ImportError:
            raise ConnectionError(
                "pywinrm not installed. Install with: uv sync"
            )
        except Exception as e:
            raise ConnectionError(f"WinRM connection to {self.target} failed: {e}")

    async def run_command(
        self,
        command: str,
        timeout: int = 60,
        cwd: str | None = None,
    ) -> CommandResult:
        if self._ssh_conn is not None:
            return await self._run_ssh(command, timeout, cwd)
        if self._winrm_conn is not None:
            return await self._run_winrm(command, timeout)
        raise ConnectionError(f"Not connected to {self.target}")

    async def _run_ssh(
        self, command: str, timeout: int = 60, cwd: str | None = None
    ) -> CommandResult:
        if cwd:
            command = f"cd {cwd} && {command}"

        try:
            result = await asyncio.wait_for(
                self._ssh_conn.run(command),
                timeout=timeout,
            )
            return CommandResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                exit_code=result.exit_status or 0,
            )
        except asyncio.TimeoutError:
            return CommandResult(stdout="", stderr="Command timed out", exit_code=124)

    async def _run_winrm(
        self, command: str, timeout: int = 60
    ) -> CommandResult:
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._winrm_conn.run_ps(command),
            )
            return CommandResult(
                stdout=result.std_out.decode("utf-8", errors="replace") if result.std_out else "",
                stderr=result.std_err.decode("utf-8", errors="replace") if result.std_err else "",
                exit_code=result.status_code or 0,
            )
        except Exception as e:
            return CommandResult(stdout="", stderr=str(e), exit_code=1)

    async def run_ps(self, script: str, timeout: int = 60) -> CommandResult:
        if self._winrm_conn is not None:
            return await self._run_winrm_ps(script, timeout)
        if self._ssh_conn is not None:
            escaped = script.replace("'", "'\\''")
            return await self._run_ssh(
                f"powershell -NoProfile -NonInteractive -Command '{escaped}'",
                timeout,
            )
        raise ConnectionError(f"Not connected to {self.target}")

    async def _run_winrm_ps(self, script: str, timeout: int = 60) -> CommandResult:
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._winrm_conn.run_ps(script),
            )
            return CommandResult(
                stdout=result.std_out.decode("utf-8", errors="replace") if result.std_out else "",
                stderr=result.std_err.decode("utf-8", errors="replace") if result.std_err else "",
                exit_code=result.status_code or 0,
            )
        except Exception as e:
            return CommandResult(stdout="", stderr=str(e), exit_code=1)

    async def upload(self, local_path: str, remote_path: str) -> None:
        if self._ssh_conn is not None:
            async with self._ssh_conn.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
        else:
            content = open(local_path, "rb").read()
            b64 = __import__("base64").b64encode(content).decode()
            script = (
                f"$bytes = [Convert]::FromBase64String('{b64}'); "
                f"[IO.File]::WriteAllBytes('{remote_path}', $bytes)"
            )
            result = await self.run_ps(script)
            if not result.success:
                raise ConnectionError(f"Upload failed: {result.stderr}")

    async def download(self, remote_path: str, local_path: str) -> None:
        if self._ssh_conn is not None:
            async with self._ssh_conn.start_sftp_client() as sftp:
                await sftp.get(remote_path, local_path)
        else:
            script = (
                f"$bytes = [IO.File]::ReadAllBytes('{remote_path}'); "
                f"[Convert]::ToBase64String($bytes)"
            )
            result = await self.run_ps(script)
            if result.success and result.stdout.strip():
                import base64

                data = base64.b64decode(result.stdout.strip())
                with open(local_path, "wb") as f:
                    f.write(data)

    async def disconnect(self) -> None:
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
