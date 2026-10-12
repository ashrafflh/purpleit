"""Explicit, benign connection validation; never runs an ATT&CK technique."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import uuid4

import typer
from rich.console import Console

from purplestrike.cli.config import DEFAULT_CONFIG_PATH
from purplestrike.models.config import ConnectionMethod, PurpleStrikeConfig
from purplestrike.techniques.connection import (
    TargetConnection,
    _redact_target_password,
    set_target_credentials,
    set_target_platforms,
)

app = typer.Typer(no_args_is_help=True)
console = Console()


async def check_connection(
    target: str, method: ConnectionMethod, config: PurpleStrikeConfig
) -> dict:
    """Check identity, Unicode/long input, exit codes, and an owned temporary artifact."""
    record = {"target": target, "method": method.value, "status": "failed", "checks": {}}
    conn = None
    try:
        conn = TargetConnection(target, method=method, settings=config.connection)
        record["method"] = conn.method.value
        await conn.connect()
        if conn.is_windows:
            identity = await conn.run_ps(
                "$id=[Security.Principal.WindowsIdentity]::GetCurrent(); "
                "$p=New-Object Security.Principal.WindowsPrincipal($id); "
                "[pscustomobject]@{identity=$id.Name; "
                "administrator=$p.IsInRole("
                "[Security.Principal.WindowsBuiltInRole]::Administrator); "
                "computer=$env:COMPUTERNAME} | ConvertTo-Json -Compress",
            )
        else:
            identity = await conn.run_command("id")
        if not identity.success:
            raise RuntimeError(identity.stderr or "Identity probe failed")
        # A pywinrm Session is lazy: identity execution proves the connection.
        record["checks"]["connect"] = True
        record["identity"] = (
            json.loads(identity.stdout) if conn.is_windows else identity.stdout.strip()
        )
        record["checks"]["identity"] = True
        marker = "PurpleStrike-connection-" + uuid4().hex
        if conn.is_windows:
            script = (
                "# " + "long input " * 1000 + "\n"
                "$path=Join-Path $env:TEMP '" + marker + ".txt'; "
                "try { [IO.File]::WriteAllText($path, '" + marker + "-Grüße'); "
                "[IO.File]::ReadAllText($path) } "
                "finally { if (Test-Path -LiteralPath $path) { [IO.File]::Delete($path) } }"
            )
            result = await conn.run_ps(script)
            record["checks"]["long_unicode_script_and_temp_cleanup"] = (
                result.success and marker + "-Grüße" in result.stdout
            )
            # A success response from process creation is insufficient: check the child status.
            failure = await conn.run_ps("Write-Output 'expected nonzero'; exit 7")
            record["checks"]["exit_code"] = failure.exit_code == 7
            native_failure = await conn.run_ps("cmd.exe /c exit 9")
            record["checks"]["native_exit_code"] = native_failure.exit_code == 9
            timeout = await conn.run_ps("Start-Sleep -Seconds 8", timeout=2)
            record["checks"]["timeout"] = timeout.exit_code == 124
            record["command_exit_codes"] = {
                "long_unicode": result.exit_code,
                "explicit": failure.exit_code,
                "native": native_failure.exit_code,
                "timeout": timeout.exit_code,
            }
        else:
            result = await conn.run_command("printf " + marker)
            record["checks"]["output"] = result.success and marker in result.stdout
            failure = await conn.run_command("exit 7")
            record["checks"]["exit_code"] = failure.exit_code == 7
        if not all(record["checks"].values()):
            failed = ", ".join(key for key, passed in record["checks"].items() if not passed)
            record["error"] = result.stderr or f"Failed checks: {failed}"
        else:
            record["status"] = "passed"
    except Exception as error:
        record["error"] = _redact_target_password(str(error) or type(error).__name__)
    finally:
        try:
            if conn is not None:
                await conn.disconnect()
        except Exception as error:
            record["status"] = "failed"
            record["cleanup_error"] = _redact_target_password(str(error))
    return record


@app.command("check")
def check(
    target: Annotated[
        str, typer.Option(help="Configured hostname/IP; defaults to configured hosts.")
    ] = "",
    method: Annotated[
        str, typer.Option(help="auto, all, winrm, winrm_nonadmin, ssh, or wmi.")
    ] = "auto",
    output: Annotated[
        Path | None, typer.Option(help="Write a sanitized JSON validation report.")
    ] = None,
) -> None:
    """Run harmless identity, output, exit-code, timeout, and temporary-file checks."""
    if method not in {m.value for m in ConnectionMethod} | {"all"}:
        raise typer.BadParameter("Unknown connection method")
    config = PurpleStrikeConfig.from_yaml_or_env(DEFAULT_CONFIG_PATH)
    set_target_credentials(config.target_ad_domain, config.target_username, config.target_password)
    hosts = {h.ip: h for g in config.target_groups.values() for h in g.hosts}
    set_target_platforms({a: str(h.os) for h in hosts.values() for a in (h.ip, h.hostname)})
    if target:
        selected = [h for h in hosts.values() if target in (h.ip, h.hostname)]
        if not selected:
            raise typer.BadParameter("Target must be a hostname/IP in configured target_groups")
    else:
        selected = list(hosts.values())
    if not selected:
        raise typer.BadParameter("No target hosts configured")

    async def run() -> list[dict]:
        results = []
        for host in selected:
            if method == "all":
                methods = (
                    [
                        ConnectionMethod.WINRM,
                        ConnectionMethod.WINRM_NONADMIN,
                        ConnectionMethod.SSH,
                        ConnectionMethod.WMI,
                    ]
                    if host.os == "windows"
                    else [ConnectionMethod.SSH]
                )
            else:
                configured = host.connection_method or config.connection.method
                methods = [ConnectionMethod(method) if method != "auto" else configured]
            for selected_method in methods:
                console.print(f"Checking {host.ip} via {selected_method.value}...")
                result = await check_connection(host.ip, selected_method, config)
                results.append(result)
                console.print(json.dumps(result, ensure_ascii=False))
        return results

    results = asyncio.run(run())
    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "kind": "connection_validation",
        "results": results,
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"Report: {output}")
    if any(result["status"] != "passed" for result in results):
        raise typer.Exit(1)
