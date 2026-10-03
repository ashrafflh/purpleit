from unittest.mock import AsyncMock

import pytest

from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.persistence import create_domain_account, create_local_account
from purplestrike.techniques.privilege_escalation import windows_service
from purplestrike.techniques.execution import service_execution


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
