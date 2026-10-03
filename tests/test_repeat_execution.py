from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from purplestrike.models.techniques import TechniqueResult
from purplestrike.plugins.attack_executors.custom_python.executor import CustomPythonExecutor
from purplestrike.techniques.connection import CommandResult
from purplestrike.techniques.persistence import file_association


@pytest.mark.parametrize(("technique_id", "field", "extra"), [
    ("T1543.003", "service_name", {"binary_path": "cmd.exe /c echo test"}),
    ("T1569.002", "service_name", {}),
    ("T1053.005", "task_name", {}),
    ("T1053.005p", "task_name", {}),
    ("T1547.001", "value_name", {}),
    ("T1136.001", "username", {}),
    ("T1136.002", "username", {"domain": "lab.test"}),
])
async def test_replay_keeps_existing_resources_and_cleans_exact_run(monkeypatch, technique_id, field, extra):
    existing = "ExistingLabResource"
    resources = {existing}
    allocated = []

    async def execute(target, parameters):
        name = parameters[field]
        assert name not in resources
        if field == "username":
            assert len(name) <= 20
        resources.add(name)
        allocated.append(name)
        return TechniqueResult(technique_id=technique_id, success=True)

    async def cleanup(target, parameters):
        assert parameters[field] != existing
        resources.remove(parameters[field])

    module = SimpleNamespace(execute=execute, cleanup=cleanup)
    executor = CustomPythonExecutor()
    monkeypatch.setattr(executor, "_load_technique_module", lambda path: module)
    params = {field: existing, **extra}
    original = dict(params)
    # Defer cleanup to reproduce leftover objects from an earlier run.
    first = await executor.execute(technique_id, "host", params)
    second = await executor.execute(technique_id, "host", params)
    assert first.success and second.success
    assert len(resources) == 3
    assert params == original
    assert f"{field}={allocated[0]}" in first.artifacts
    await executor.cleanup(technique_id, "host", params)
    assert resources == {existing, allocated[1]}
    await executor.cleanup(technique_id, "host", params)
    await executor.cleanup(technique_id, "host", params)
    assert resources == {existing}


async def test_new_executor_does_not_reuse_names_or_claim_old_cleanup(monkeypatch):
    module = SimpleNamespace(
        execute=AsyncMock(return_value=TechniqueResult(technique_id="T1547.001", success=True)),
        cleanup=AsyncMock(),
    )
    first, restarted = CustomPythonExecutor(), CustomPythonExecutor()
    for executor in (first, restarted):
        monkeypatch.setattr(executor, "_load_technique_module", lambda path: module)
    await first.execute("T1547.001", "host", {})
    await restarted.cleanup("T1547.001", "host", {})
    module.cleanup.assert_not_awaited()
    await restarted.execute("T1547.001", "host", {})
    names = [call.kwargs["parameters"]["value_name"] for call in module.execute.await_args_list]
    assert len(set(names)) == 2


async def test_file_association_replays_have_disjoint_resources(monkeypatch):
    conn = AsyncMock()
    conn.run_ps.return_value = CommandResult("PurpleStrike-T1546.001", "", 0)
    monkeypatch.setattr(file_association, "get_connection", AsyncMock(return_value=conn))
    first = await file_association.execute("repeat-host", {"_run_id": "first"})
    second = await file_association.execute("repeat-host", {"_run_id": "second"})
    assert first.success and second.success
    assert set(first.artifacts).isdisjoint(second.artifacts)
    await file_association.cleanup("repeat-host", {"_run_id": "first"})
    script = conn.run_ps.call_args.args[0]
    assert first.artifacts[-1] in script
    assert second.artifacts[-1] not in script
    await file_association.cleanup("repeat-host", {"_run_id": "second"})
