"""Replay saved feedback against the real LLM without executing any technique.

Only MCP initialization/tools-list and LLM completion calls are made. The saved
report does not include the unexecuted plan parameters, so they are reconstructed
from current technique defaults. This is a diagnostic replay, not an exact replay
of an unrecorded original prompt.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from jsonschema import validate

from purplestrike.core.execution_graph import ExecutionDecision, ExecutionGraph, ExecutionState
from purplestrike.core.orchestrator import Orchestrator
from purplestrike.core.plan import AttackPlan, AttackPlanStep
from purplestrike.mcp.client import MCPToolClient
from purplestrike.models.config import PurpleStrikeConfig
from purplestrike.models.report import SimulationReport
from purplestrike.plugins.loader import PluginLoader
from purplestrike.plugins.registry import PluginRegistry


async def replay(args: argparse.Namespace) -> None:
    load_dotenv(Path(".env"))
    config = PurpleStrikeConfig.from_yaml_or_env(args.config)
    report = SimulationReport.model_validate_json(args.report.read_text(encoding="utf-8"))
    if config.llm.provider.value != report.llm_provider:
        raise ValueError("Current provider differs from the saved run")
    matches = re.findall(
        r"Plan generated:.*techniques=(\[.*\])", args.log.read_text(encoding="utf-8")
    )
    if not matches or not report.results:
        raise ValueError("A generated plan and recorded feedback are required")
    technique_ids = ast.literal_eval(matches[-1])
    plugins = PluginRegistry()
    await PluginLoader(plugins)._load_builtin_llm_providers(
        {
            config.llm.provider.value: config.llm.model_dump(mode="json"),
        }
    )
    provider = plugins.get_llm_provider(config.llm.provider.value)
    if provider is None:
        raise RuntimeError("Configured LLM provider could not be initialized")
    samples: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {
        "provider": report.llm_provider,
        "model": getattr(provider, "model", config.llm.model),
        "source_report": args.report.name,
        "techniques_executed": 0,
        "limitation": "Unexecuted plan parameters reconstructed from current defaults; "
        "original AI response and full prompt were not saved.",
        "samples": samples,
    }
    try:
        async with MCPToolClient(config) as client:
            orchestrator = Orchestrator(config)
            orchestrator._mcp = client
            orchestrator._technique_registry = client.registry
            steps = []
            for position, tid in enumerate(technique_ids, 1):
                technique = client.registry.get_technique(tid)
                if technique is None:
                    raise ValueError(f"No current MCP mapping for {tid}")
                recorded = next((r for r in report.results if r.plan_step == position), None)
                steps.append(
                    AttackPlanStep(
                        order=position,
                        technique_id=tid,
                        technique_name=technique.name,
                        parameters=recorded.parameters
                        if recorded
                        else orchestrator._default_parameters_for_technique(
                            technique, report.target_group
                        ),
                        expected_detection_rules=[m.rule_id for m in technique.detection_mappings],
                        risk_level=technique.risk_level,
                    )
                )
            plan = AttackPlan(name=report.plan_name, target_group=report.target_group, steps=steps)
            latest = report.results[-1]
            graph = ExecutionGraph(
                orchestrator,
                plan,
                plugins,
                None,
                latest.target,
                "agent",
                False,
            )
            results = [r.model_copy(deep=True) for r in report.results]
            results[-1].decision = {}  # The rejected decision was not part of its own prompt.
            state: ExecutionState = {
                "current": latest.plan_step - 1,
                "pending": [i - 1 for i in report.metadata["pending_steps"]],
                "parameters": latest.parameters,
                "attempts": {int(k): v for k, v in report.metadata["attempts"].items()},
                "results": results,
                "environment": report.metadata["environment"],
                "status": "running",
                "reason": "",
                "uncertain": False,
            }
            for number in range(1, args.samples + 1):
                sample: dict[str, Any] = {"number": number}
                try:
                    decision = await graph._ask(state)
                    sample["decision"] = graph._redact(decision.model_dump(mode="json"))
                    validate(
                        decision.model_dump(mode="json"), ExecutionDecision.model_json_schema()
                    )
                    sample["schema_accepts"] = True
                    try:
                        transition = graph._transition(state, decision)
                        sample["runtime_accepts"] = True
                        sample["next_plan_position"] = (
                            transition.get("current", state["current"]) + 1
                        )
                    except Exception as exc:
                        sample["runtime_accepts"] = False
                        sample["runtime_error"] = graph._redact(str(exc))
                except Exception as exc:
                    sample["request_error"] = graph._redact(str(exc))
                samples.append(sample)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
                print(json.dumps(sample), flush=True)
    finally:
        await provider.teardown()
    print(f"Evidence saved: {args.output}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument(
        "--config", type=Path, default=Path.home() / ".purplestrike" / "config.yaml"
    )
    parser.add_argument("--samples", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--output", type=Path, required=True)
    asyncio.run(replay(parser.parse_args()))


if __name__ == "__main__":
    main()
