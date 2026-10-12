"""Native Windows WMI-over-DCOM execution with SMB staging; never uses WinRM.

The controller requires Windows PowerShell 5.1. Credentials and scripts travel to
the local worker over stdin, not process arguments. Each job owns a UUID directory.
"""

from __future__ import annotations

import base64
import json
import ntpath
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from uuid import uuid4

from purplestrike.models.config import ConnectionSettings


def _validate_paths(settings: ConnectionSettings) -> None:
    if not settings.wmi_share or any(c in settings.wmi_share for c in "/\\:"):
        raise ValueError("WMI_SHARE must be a share name, not a UNC path")
    relative = settings.wmi_share_path.replace("/", "\\")
    if ntpath.isabs(relative) or ":" in relative or ".." in relative.split("\\"):
        raise ValueError("WMI_SHARE_PATH must be relative to the share, without '..'")
    drive, tail = ntpath.splitdrive(settings.wmi_remote_path)
    if len(drive) != 2 or drive[1] != ":" or not tail.startswith("\\"):
        raise ValueError("WMI_REMOTE_PATH must be an absolute target drive path")
    if ".." in tail.split("\\") or any(c in settings.wmi_remote_path for c in '\r\n"'):
        raise ValueError("WMI_REMOTE_PATH contains unsupported characters")


# Executed ON THE TARGET through Win32_Process.Create. The technique runs in a
# child so explicit exit/native failure codes can be collected independently.
_REMOTE_WRAPPER = r"""
$ErrorActionPreference = 'Stop'
$dir = __DIRECTORY__
$result = @{exit_code=1; error=''; timed_out=$false}
$child = $null
try {
    $inputPath = (Join-Path $dir 'input.ps1').Replace("'", "''")
    $bootstrap = "Invoke-Expression ([IO.File]::ReadAllText('" + $inputPath + "'))"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    $args = '-NoProfile -NonInteractive -EncodedCommand ' + $encoded
    $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $child = Start-Process -FilePath $powershell `
        -ArgumentList $args -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $dir 'stdout.txt') `
        -RedirectStandardError (Join-Path $dir 'stderr.txt')
    # Retain the process handle before waiting so ExitCode remains available.
    $null = $child.Handle
    if (-not $child.WaitForExit(__TIMEOUT__)) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $child.Id /T /F | Out-Null
        $result.exit_code = 124
        $result.timed_out = $true
        $result.error = 'WMI command timed out; termination requested for owned process tree'
        if (-not $child.WaitForExit(5000)) { $result.error += '; process may still be running' }
    } else {
        $child.WaitForExit()
        $result.exit_code = $child.ExitCode
    }
} catch { $result.error = $_.ToString() }
finally {
    if ($null -ne $child) { $child.Dispose() }
    [IO.File]::WriteAllText((Join-Path $dir 'result.tmp'), ($result | ConvertTo-Json -Compress))
    [IO.File]::Move((Join-Path $dir 'result.tmp'), (Join-Path $dir 'result.json'))
}
"""


# Executed ON THE CONTROLLER. System.Management uses WMI/DCOM directly rather
# than the CIM cmdlets' WSMan default. SMB stages this job's script and results.
_WORKER = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$settings = $request.settings
$user = $request.credentials[0]
$domain = $request.credentials[2]
if ($domain -and -not $user.Contains('\') -and -not $user.Contains('@')) {
    $user = $domain + '\' + $user
}
$secure = ConvertTo-SecureString $request.credentials[1] -AsPlainText -Force
$credential = New-Object Management.Automation.PSCredential($user, $secure)
$processClass = $drive = $null
$owned = $false
$completed = $false
$submitted = $false
$response = @{}
$cleanupErrors = @()
try {
    Add-Type -AssemblyName System.Management
    $options = New-Object System.Management.ConnectionOptions
    $options.Username = $user
    $options.SecurePassword = $secure
    $options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
    $options.Authentication = [System.Management.AuthenticationLevel]::PacketPrivacy
    $options.Timeout = [TimeSpan]::FromSeconds($settings.connect_timeout)
    $namespace = '\\' + $request.target + '\root\cimv2'
    $scope = New-Object System.Management.ManagementScope($namespace, $options)
    $scope.Connect()
    $classPath = New-Object System.Management.ManagementPath('Win32_Process')
    $processClass = New-Object System.Management.ManagementClass($scope, $classPath, $null)
    $processClass.Get()
    $shareRoot = '\\' + $request.target + '\' + $settings.wmi_share
    $drive = New-PSDrive -Name PSTransport -PSProvider FileSystem `
        -Root $shareRoot -Credential $credential
    $base = Join-Path 'PSTransport:\' $settings.wmi_share_path
    $ownedPath = Join-Path $base $request.job
    $remoteDir = Join-Path $settings.wmi_remote_path $request.job
    New-Item -ItemType Directory -Path $ownedPath | Out-Null
    $owned = $true
    Set-Content -LiteralPath (Join-Path $ownedPath 'input.ps1') `
        -Value $request.script -Encoding UTF8
    if ($request.action -eq 'check') {
        $response = @{connected=$true}
        $completed = $true
    } else {
        $arguments = $processClass.GetMethodParameters('Create')
        $arguments.CommandLine = 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' +
            $request.wrapper
        $arguments.CurrentDirectory = $settings.wmi_remote_path
        $submitted = $true
        $started = $processClass.InvokeMethod('Create', $arguments, $null)
        if ($started.ReturnValue -ne 0) {
            $submitted = $false
            throw "WMI process creation failed: ReturnValue=$($started.ReturnValue)"
        }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $resultPath = Join-Path $ownedPath 'result.json'
        while (-not (Test-Path -LiteralPath $resultPath)) {
            if ($timer.Elapsed.TotalSeconds -gt ($request.timeout + 12)) {
                throw ("No completion record from WMI PID $($started.ProcessId); " +
                    "remote status unknown; inspect $remoteDir")
            }
            Start-Sleep -Milliseconds 250
        }
        $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -eq $result.exit_code) { throw 'WMI child exit code is unavailable' }
        $completed = $true
        $out = $err = ''
        foreach ($file in @('stdout.txt', 'stderr.txt')) {
            $path = Join-Path $ownedPath $file
            if (Test-Path -LiteralPath $path) {
                $value = [string](Get-Content -LiteralPath $path -Raw -Encoding UTF8)
                if ($file -eq 'stdout.txt') { $out = $value } else { $err = $value }
            } elseif (-not $result.error) { throw "Missing WMI output file: $file" }
        }
        $response = @{stdout=$out; stderr=($err + $result.error); exit_code=[int]$result.exit_code}
    }
} catch { $response = @{error=$_.ToString()} }
finally {
    if ($owned -and ($completed -or -not $submitted)) {
        foreach ($file in @('input.ps1','stdout.txt','stderr.txt','result.tmp','result.json')) {
            try {
                $path = Join-Path $ownedPath $file
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
            } catch { $cleanupErrors += $_.ToString() }
        }
        # No recursive deletion, even for this unique job directory.
        try { Remove-Item -LiteralPath $ownedPath -ErrorAction Stop }
        catch { $cleanupErrors += $_.ToString() }
    }
    if ($drive) { Remove-PSDrive -Name PSTransport -ErrorAction SilentlyContinue }
    if ($processClass) { $processClass.Dispose() }
}
if ($cleanupErrors.Count) {
    $response.error = 'Cleanup incomplete in ' + $remoteDir + ': ' + ($cleanupErrors -join '; ')
}
[Console]::Out.Write(($response | ConvertTo-Json -Compress -Depth 5))
"""


class WmiConnection:
    def __init__(
        self,
        target: str,
        credentials: tuple[str, str, str],
        settings: ConnectionSettings,
    ) -> None:
        self.target = target
        self.credentials = credentials
        self.settings = settings
        _validate_paths(settings)

    def _invoke(self, action: str, script: str = "", timeout: int = 60) -> dict[str, Any]:
        if sys.platform != "win32":
            raise RuntimeError(
                "WMI/DCOM mode requires a Windows controller with Windows PowerShell 5.1"
            )
        if not self.credentials[1]:
            raise ValueError("WMI/DCOM mode requires password credentials")
        job = "purplestrike_" + uuid4().hex
        remote_dir = ntpath.join(self.settings.wmi_remote_path, job)
        quoted_dir = "'" + remote_dir.replace("'", "''") + "'"
        wrapper = _REMOTE_WRAPPER.replace("__DIRECTORY__", quoted_dir).replace(
            "__TIMEOUT__",
            str(timeout * 1000),
        )
        request = {
            "action": action,
            "target": self.target,
            "credentials": self.credentials,
            "settings": self.settings.model_dump(mode="json"),
            "script": script,
            "timeout": timeout,
            "job": job,
            "wrapper": base64.b64encode(wrapper.encode("utf-16-le")).decode("ascii"),
        }
        budget = self.settings.connect_timeout * 3 + (timeout + 15 if action == "run" else 0)
        executable = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / (
            r"System32\WindowsPowerShell\v1.0\powershell.exe"
        )
        try:
            # A file invocation keeps WMI COM exceptions inside PowerShell's
            # try/catch reliably. Only static source goes on disk; credentials
            # and target scripts remain on stdin.
            with tempfile.TemporaryDirectory(prefix="purplestrike_wmi_") as folder:
                worker = Path(folder) / "worker.ps1"
                worker.write_text(_WORKER, encoding="utf-8-sig")
                result = subprocess.run(
                    [str(executable), "-NoProfile", "-NonInteractive", "-File", str(worker)],
                    input=json.dumps(request),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=budget,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(
                f"WMI/DCOM worker exceeded {budget}s. Remote execution status is unknown; "
                f"inspect owned directory {remote_dir}. The command was not resubmitted.",
            ) from error
        try:
            response = json.loads(result.stdout.lstrip("\ufeff"))
        except (ValueError, TypeError) as error:
            raise RuntimeError(
                f"WMI worker returned no valid result (exit {result.returncode}): "
                f"{result.stderr[-1500:] or 'no error output; check PowerShell/application policy'}"
            ) from error
        if response.get("error"):
            raise RuntimeError(response["error"])
        return response

    def connect(self) -> None:
        self._invoke("check")

    def run_ps(self, script: str, timeout: int) -> tuple[str, str, int]:
        result = self._invoke("run", script, timeout)
        return result["stdout"], result["stderr"], result["exit_code"]

    def disconnect(self) -> None:
        # Each worker closes its own authenticated connections.
        pass
