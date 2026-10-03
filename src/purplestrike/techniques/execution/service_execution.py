from __future__ import annotations

import logging
import json
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection
from purplestrike.techniques.scripts import ps_quote

logger = logging.getLogger(__name__)
_created_services: set[tuple[str, str]] = set()
_artifacts: dict[tuple[str, str], str] = {}


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create and start a Windows service to execute a command."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        service_name = parameters.get("service_name", "PurpleStrikeSvc")
        command = parameters.get("command") or "whoami"
        filename = f"purplestrike_svc_{uuid4().hex}.txt"
        paths = f"$outPath = Join-Path $env:windir {ps_quote('Temp/' + filename)}; "
        # A real service acknowledges SCM startup before running the command.
        # Console programs used directly as ImagePath can be killed on error 1053.
        source = r'''
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;
public sealed class PurpleStrikeSimulationService : ServiceBase {
    public PurpleStrikeSimulationService() { ServiceName = SERVICE_NAME; }
    public static void Main() { ServiceBase.Run(new PurpleStrikeSimulationService()); }
    protected override void OnStart(string[] args) {
        ThreadPool.QueueUserWorkItem(delegate {
            string output = Path.Combine(Environment.GetEnvironmentVariable("windir"), "Temp", OUTPUT_NAME);
            int code = 1;
            try {
                var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec"),
                    "/d /s /c \"" + COMMAND + " 2>&1\"");
                start.UseShellExecute = false;
                start.CreateNoWindow = true;
                start.RedirectStandardOutput = true;
                using (var process = Process.Start(start)) {
                    string text = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    File.WriteAllText(output, text);
                    code = process.ExitCode;
                }
            } catch (Exception error) { File.WriteAllText(output, error.ToString()); }
            finally { File.WriteAllText(output + ".exit", code.ToString()); Stop(); }
        });
    }
}
'''.replace('SERVICE_NAME', json.dumps(service_name)).replace('OUTPUT_NAME', json.dumps(filename)).replace('COMMAND', json.dumps(command))
        _artifacts[(target, service_name)] = filename
        create_result = await conn.run_ps(
            "$ErrorActionPreference = 'Stop'; " +
            paths +
            "$exe = $outPath + '.exe'; "
            f"Add-Type -TypeDefinition {ps_quote(source)} "
            "-ReferencedAssemblies 'System.ServiceProcess.dll','System.dll' "
            "-OutputAssembly $exe -OutputType ConsoleApplication -ErrorAction Stop; "
            "$binPath = '\"' + $exe + '\"'; "
            f"New-Service -Name {ps_quote(service_name)} -BinaryPathName $binPath "
            "-StartupType Manual -ErrorAction Stop"
        )
        if not create_result.success:
            raise RuntimeError(command_error(create_result))
        _created_services.add((target, service_name))
        start_result = await conn.run_ps(f"sc.exe start {ps_quote(service_name)}")
        output_result = await conn.run_ps(
            paths +
            "for ($i=0; $i -lt 20 -and !(Test-Path -LiteralPath ($outPath + '.exit')); $i++) "
            "{ Start-Sleep -Milliseconds 500 }; "
            "if (!(Test-Path -LiteralPath ($outPath + '.exit'))) "
            "{ throw 'Service command did not produce a completion marker' }; "
            "Get-Content -LiteralPath $outPath -ErrorAction Stop; "
            "$code = [int](Get-Content -LiteralPath ($outPath + '.exit')); "
            "if ($code -ne 0) { throw \"Service command exited with code $code\" }"
        )
        combined_output = create_result.stdout + "\n" + start_result.stdout + "\n" + output_result.stdout
        # Require a fresh completion marker containing the actual command exit code.
        success = output_result.success
        return TechniqueResult(
            technique_id="T1569.002",
            success=success,
            output=combined_output[:4096],
            error=command_error(output_result)[:1024] if not success else None,
            execution_status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1569.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1569.002",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str, parameters: dict[str, Any] | None = None) -> None:
    """Reverse any changes made during execution."""
    conn: TargetConnection | None = None
    try:
        name = (parameters or {}).get("service_name", "PurpleStrikeSvc")
        if (target, name) not in _created_services and (target, name) not in _artifacts:
            return
        conn = await get_connection(target)
        if (target, name) in _created_services:
            await conn.run_ps(f"Stop-Service -Name {ps_quote(name)} -ErrorAction SilentlyContinue")
            deleted = await conn.run_ps(f"sc.exe delete {ps_quote(name)}")
            if not deleted.success:
                raise RuntimeError(command_error(deleted))
            _created_services.discard((target, name))
        filename = _artifacts.get((target, name))
        if filename:
            removed = await conn.run_ps(
                f"$outPath = Join-Path $env:windir {ps_quote('Temp/' + filename)}; "
                "foreach ($path in @($outPath, ($outPath + '.exit'), ($outPath + '.exe'))) { "
                "if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -ErrorAction Stop } }"
            )
            if not removed.success:
                raise RuntimeError(command_error(removed))
            _artifacts.pop((target, name), None)
    except Exception as e:
        logger.warning(f"T1569.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
