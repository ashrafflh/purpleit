from __future__ import annotations

import logging
import inspect
import time
from typing import Any

from purplestrike.models.techniques import ExecutionStatus, TechniqueResult
from purplestrike.techniques.registry import technique_registry

logger = logging.getLogger(__name__)


class CustomPythonExecutor:
    """Executes attack techniques using custom Python modules via remote connections."""

    name = "custom_python"

    def __init__(self) -> None:
        self._connections: dict[str, Any] = {}

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

        parameters = {
            **{p.name: p.default for p in technique.parameters if p.default is not None},
            **{key: value for key, value in parameters.items() if value is not None},
        }
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
                result = await module.execute(target=target, parameters=parameters)
                if isinstance(result, TechniqueResult):
                    result.execution_time_seconds = time.monotonic() - start
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
                module = self._load_technique_module(technique.module)
                if module and hasattr(module, "cleanup"):
                    cleanup_params = inspect.signature(module.cleanup).parameters
                    if "parameters" in cleanup_params:
                        await module.cleanup(target=target, parameters=parameters)
                    else:
                        await module.cleanup(target=target)
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
