from unittest.mock import AsyncMock

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.persistence import create_domain_account, create_local_account
from purplestrike.techniques.privilege_escalation import windows_service
from purplestrike.techniques.execution import service_execution
from purplestrike.techniques.persistence import file_association
from purplestrike.techniques.privilege_escalation import bypass_uac
from purplestrike.techniques.shared import v19_controls


@pytest.mark.asyncio
@pytest.mark.parametrize("module", [windows_service, create_domain_account, create_local_account])
async def test_cleanup_does_not_remove_resources_it_did_not_create(monkeypatch, module):
    connect = AsyncMock()
    monkeypatch.setattr(module, "get_connection", connect)
    await module.cleanup("unrelated-host", {"service_name": "ExistingSvc", "username": "existing"})
    connect.assert_not_called()


@pytest.mark.asyncio
async def test_service_cleanup_only_removes_its_created_service(monkeypatch):
    conn = AsyncMock()
    conn.run_ps.return_value = CommandResult("ok", "", 0)
    monkeypatch.setattr(windows_service, "get_connection", AsyncMock(return_value=conn))
    params = {"service_name": "PurpleStrikeAuditSvc", "binary_path": "cmd.exe /c echo test"}
    await windows_service.execute("host", params)
    conn.run_ps.reset_mock()
    await windows_service.cleanup("host", params)
    conn.run_ps.assert_awaited_once_with("sc.exe delete 'PurpleStrikeAuditSvc'")


@pytest.mark.asyncio
async def test_domain_account_is_cleaned_up_when_enable_fails(monkeypatch):
    conn = AsyncMock()
    conn.run_ps.side_effect = [
        CommandResult("created", "", 0),
        CommandResult("", "Password policy rejected account activation", 1),
        CommandResult("", "", 0),
    ]
    monkeypatch.setattr(create_domain_account, "get_connection", AsyncMock(return_value=conn))
    monkeypatch.setattr(create_domain_account, "ldap_directory_entry", lambda container: "$de = $bound; ")
    params = {"username": "PurpleAudit"}
    result = await create_domain_account.execute("domain-host", params)
    assert not result.success
    assert ("domain-host", "PurpleAudit") in create_domain_account._created_accounts
    await create_domain_account.cleanup("domain-host", params)
    assert ("domain-host", "PurpleAudit") not in create_domain_account._created_accounts
    assert "Children.Remove($user)" in conn.run_ps.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("completed", [True, False])
async def test_service_requires_command_completion_not_scm_success(monkeypatch, completed):
    conn = AsyncMock()
    conn.run_ps.side_effect = [
        CommandResult("created", "", 0),
        CommandResult("SCM 1053", "", 1),
        CommandResult("", "" if completed else "Service command did not produce a completion marker",
                      0 if completed else 1),
    ]
    monkeypatch.setattr(service_execution, "get_connection", AsyncMock(return_value=conn))
    params = {"service_name": "AuditSvc", "command": "ver > NUL"}
    result = await service_execution.execute("service-host", params)
    assert result.success is completed
    conn.run_ps.side_effect = None
    conn.run_ps.return_value = CommandResult("", "", 0)
    await service_execution.cleanup("service-host", params)


@pytest.mark.asyncio
@pytest.mark.parametrize(("module", "marker"), [
    (file_association, "PurpleStrike-association-resources-owned"),
    (bypass_uac, "PurpleStrike-uac-resources-owned"),
])
@pytest.mark.parametrize("owned", [True, False])
async def test_partial_registry_setup_cleanup_requires_ownership(
    monkeypatch, module, marker, owned,
):
    conn = AsyncMock()
    conn.run_ps.return_value = CommandResult(marker if owned else "", "setup failed", 1)
    if module is bypass_uac:
        conn.run_ps.side_effect = [
            CommandResult("S-1-16-8192", "", 0),
            conn.run_ps.return_value,
        ]
    monkeypatch.setattr(module, "get_connection", AsyncMock(return_value=conn))
    host = f"partial-{module.__name__}-{owned}"
    result = await module.execute(host, {})
    assert not result.success
    conn.run_ps.reset_mock()
    conn.run_ps.side_effect = None
    conn.run_ps.return_value = CommandResult("", "", 0)
    await module.cleanup(host)
    assert conn.run_ps.await_count == int(owned)


@pytest.mark.asyncio
async def test_uac_does_not_claim_elevation_from_an_already_elevated_session(monkeypatch):
    conn = AsyncMock()
    conn.run_ps.return_value = CommandResult("Mandatory Label S-1-16-12288", "", 0)
    monkeypatch.setattr(bypass_uac, "get_connection", AsyncMock(return_value=conn))
    result = await bypass_uac.execute("elevated-host", {})
    assert not result.success
    assert result.execution_status == "skipped"
    assert "already high/system integrity" in result.error
    conn.run_ps.assert_awaited_once_with("whoami /groups")


@pytest.mark.asyncio
async def test_shared_artifact_cleanup_does_not_remove_other_scenarios(monkeypatch):
    conn = AsyncMock()
    conn.is_windows = True
    conn.run_ps.return_value = CommandResult("", "", 0)
    monkeypatch.setattr(v19_controls, "get_connection", AsyncMock(return_value=conn))
    await v19_controls.cleanup("host", {"_technique_id": "T1684.001"})
    script = conn.run_ps.call_args.args[0]
    assert "purplestrike_impersonation.txt" in script
    assert "purplestrike_social_engineering.txt" not in script
    assert "Remove-NetFirewallRule" not in script


@pytest.mark.asyncio
async def test_shared_probe_cleanup_makes_no_connection(monkeypatch):
    connect = AsyncMock()
    monkeypatch.setattr(v19_controls, "get_connection", connect)
    await v19_controls.cleanup("host", {"_technique_id": "T1685"})
    connect.assert_not_called()
