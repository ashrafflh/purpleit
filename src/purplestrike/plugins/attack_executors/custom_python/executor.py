from __future__ import annotations

import inspect
import logging
import time
from typing import Any
from uuid import uuid4

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.registry import technique_registry

logger = logging.getLogger(__name__)


class CustomPythonExecutor:
    """Executes attack techniques using custom Python modules via remote connections."""

    name = "custom_python"

    def __init__(self) -> None:
        self._connections: dict[str, Any] = {}
        self._runs: dict[tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]] = {}

    @property
    def supported_techniques(self) -> list[str]:
        return technique_registry.get_technique_ids()

    async def setup(self, config: dict[str, Any]) -> None:
        pass

    async def execute(
        self,
        technique_id: str,
        target: str,
        parameters: dict[str, Any],
    ) -> TechniqueResult:
        technique = technique_registry.get_technique(technique_id)
        if technique is None:
            return TechniqueResult(
                technique_id=technique_id,
                success=False,
                error=f"Technique {technique_id} not found in registry",
                execution_status=ExecutionStatus.FAILURE,
            )

        requested_parameters = dict(parameters)
        parameters = {
            **{p.name: p.default for p in technique.parameters if p.default is not None},
            **{key: value for key, value in parameters.items() if value is not None},
        }
        # Shared executors need an authoritative scenario identity. Keep it
        # reserved so a plan cannot make one ATT&CK ID execute another ID's
        # behavior while retaining the original report attribution.
        parameters["_technique_id"] = technique_id
        missing = [p.name for p in technique.parameters
                   if p.required and parameters.get(p.name) in (None, "")]
        if missing:
            return TechniqueResult(
                technique_id=technique_id, success=False,
                error=f"Missing required parameters: {', '.join(missing)}",
                execution_status=ExecutionStatus.FAILURE,
            )
        module_path = technique.module
        if not module_path:
            return TechniqueResult(
                technique_id=technique_id,
                success=False,
                error=f"No module path defined for technique {technique_id}",
                execution_status=ExecutionStatus.FAILURE,
            )

        start = time.monotonic()
        try:
            module = self._load_technique_module(module_path)
            if module is None:
                return TechniqueResult(
                    technique_id=technique_id,
                    success=False,
                    error=f"Could not load module: {module_path}",
                    execution_status=ExecutionStatus.FAILURE,
                )

            if hasattr(module, "execute"):
                # Scope names here, not just when generating default plans: saved
                # and agent-generated plans must be safe to run repeatedly too.
                run_id = uuid4().hex
                parameters["_run_id"] = run_id
                resources = {}
                for name in ("service_name", "task_name", "value_name"):
                    if name in parameters:
                        parameters[name] = f"{str(parameters[name])[:80]}_{run_id[:16]}"
                        resources[name] = parameters[name]
                if technique_id in {"T1136.001", "T1136.002"}:
                    # Windows SAM account names are limited to 20 characters.
                    parameters["username"] = f"{str(parameters['username'])[:9]}_{run_id[:10]}"
                    resources["username"] = parameters["username"]
                self._runs.setdefault((target, technique_id), []).append(
                    (requested_parameters, dict(parameters))
                )
                result = await module.execute(target=target, parameters=parameters)
                if isinstance(result, TechniqueResult):
                    result.execution_time_seconds = time.monotonic() - start
                    result.artifacts.extend(f"{key}={value}" for key, value in resources.items())
                    return result
                return TechniqueResult(
                    technique_id=technique_id,
                    success=True,
                    output=str(result),
                    execution_time_seconds=time.monotonic() - start,
                )
            else:
                return TechniqueResult(
                    technique_id=technique_id,
                    success=False,
                    error=f"Module {module_path} has no 'execute' function",
                    execution_status=ExecutionStatus.FAILURE,
                    execution_time_seconds=time.monotonic() - start,
                )

        except Exception as e:
            logger.error(f"Technique execution failed: {e}")
            return TechniqueResult(
                technique_id=technique_id,
                success=False,
                error=str(e),
                execution_status=ExecutionStatus.FAILURE,
                execution_time_seconds=time.monotonic() - start,
            )

    async def cleanup(
        self,
        technique_id: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        technique = technique_registry.get_technique(technique_id)
        if technique and technique.module:
            try:
                runs = self._runs.get((target, technique_id), [])
                # Clean the oldest matching execution, using the exact allocated
                # names. Never infer ownership from a plan's unsuffixed name.
                run = next((r for r in runs if parameters is None or r[0] == parameters), None)
                if run is None:
                    return
                module = self._load_technique_module(technique.module)
                if module and hasattr(module, "cleanup"):
                    cleanup_params = inspect.signature(module.cleanup).parameters
                    if "parameters" in cleanup_params:
                        cleanup_parameters = dict(run[1])
                        cleanup_parameters["_technique_id"] = technique_id
                        await module.cleanup(target=target, parameters=cleanup_parameters)
                    else:
                        await module.cleanup(target=target)
                    runs.remove(run)
                    if not runs:
                        self._runs.pop((target, technique_id), None)
            except Exception as e:
                logger.warning(f"Cleanup failed for {technique_id} on {target}: {e}")

    async def teardown(self) -> None:
        self._connections.clear()

    def _load_technique_module(self, module_path: str) -> Any:
        try:
            parts = module_path.split(".")
            package = "purplestrike.techniques." + ".".join(parts[:-1])
            module_name = parts[-1]
            import importlib

            full_module = f"{package}.{module_name}"
            return importlib.import_module(full_module)
        except ImportError as e:
            logger.error(f"Failed to import technique module {module_path}: {e}")
            return None
