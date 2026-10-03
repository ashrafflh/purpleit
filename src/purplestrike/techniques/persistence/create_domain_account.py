from __future__ import annotations

import logging
import re
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.connection import TargetConnection, command_error, get_connection
from purplestrike.techniques.scripts import ldap_directory_entry, ps_quote

logger = logging.getLogger(__name__)
_created_accounts: set[tuple[str, str]] = set()


async def execute(target: str, parameters: dict[str, Any]) -> TechniqueResult:
    """Create a domain account for persistence."""
    conn: TargetConnection | None = None
    try:
        conn = await get_connection(target)
        username = parameters.get("username") or "purplestrike_domain"
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,20}", username):
            raise ValueError("Use a domain account name of 1-20 letters, digits, dots, dashes or underscores")
        # Bind with the configured identity: an NTLM WinRM token cannot make a second hop.
        create_cmd = (
            ldap_directory_entry("CN=Users") +
            f"$user = $de.Children.Add({ps_quote('CN=' + username)}, 'user'); "
            f"$user.Properties['sAMAccountName'].Value = {ps_quote(username)}; "
            "$user.CommitChanges(); 'Created disabled simulation account'"
        )
        result = await conn.run_ps(create_cmd)
        if result.success:
            _created_accounts.add((target, username))
            result = await conn.run_ps(
                ldap_directory_entry("CN=Users") +
                f"$user = $de.Children.Find({ps_quote('CN=' + username)}, 'user'); "
                "$user.Invoke('SetPassword', @('PurpleStrike1!')); "
                "$user.Properties['userAccountControl'].Value = 512; "
                "$user.CommitChanges(); 'Enabled simulation account'"
            )
        return TechniqueResult(
            technique_id="T1136.002",
            success=result.success,
            output=result.stdout[:4096],
            error=command_error(result)[:1024] if not result.success else None,
            execution_status=ExecutionStatus.SUCCESS if result.success else ExecutionStatus.FAILURE,
        )
    except Exception as e:
        logger.error(f"T1136.002 execution failed: {e}")
        return TechniqueResult(
            technique_id="T1136.002",
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
        username = (parameters or {}).get("username") or "purplestrike_domain"
        if (target, username) not in _created_accounts:
            return
        conn = await get_connection(target)
        result = await conn.run_ps(
            ldap_directory_entry("CN=Users") +
            f"$user = $de.Children.Find({ps_quote('CN=' + username)}, 'user'); "
            "$de.Children.Remove($user)"
        )
        if not result.success:
            raise RuntimeError(result.stderr or result.stdout)
        _created_accounts.discard((target, username))
    except Exception as e:
        logger.warning(f"T1136.002 cleanup failed: {e}")
    finally:
        if conn:
            await conn.disconnect()
