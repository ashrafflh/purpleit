# PurpleStrike — Product Requirements Document

**Version:** 1.0  
**Date:** 2026-05-02  
**Status:** Draft  
**Author:** PurpleStrike Team  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Product Vision & Goals](#3-product-vision--goals)
4. [User Personas](#4-user-personas)
5. [System Architecture](#5-system-architecture)
6. [Core Components — Detailed Design](#6-core-components--detailed-design)
7. [Plugin System](#7-plugin-system)
8. [MITRE ATT&CK Coverage — MVP Scope](#8-mitre-attck-coverage--mvp-scope)
9. [SIEM Integration — Wazuh Connector](#9-siem-integration--wazuh-connector)
10. [Detection Validation Engine](#10-detection-validation-engine)
11. [Financial Risk Quantification Model](#11-financial-risk-quantification-model)
12. [Remediation & Detection Engineering Guidance](#12-remediation--detection-engineering-guidance)
13. [CLI Interface Design](#13-cli-interface-design)
14. [Reporting — JSON/CSV Export](#14-reporting--jsoncsv-export)
15. [Security & Credential Management](#15-security--credential-management)
16. [Safety Controls](#16-safety-controls)
17. [Data Model & Storage](#17-data-model--storage)
18. [Error Handling & Resilience](#18-error-handling--resilience)
19. [Development Roadmap](#19-development-roadmap)
20. [Success Metrics & KPIs](#20-success-metrics--kpis)
21. [Appendix A — MITRE Technique Inventory (MVP)](#21-appendix-a--mitre-technique-inventory-mvp)
22. [Appendix B — JSON Report Schema](#22-appendix-b--json-report-schema)
23. [Appendix C — CSV Report Schema](#23-appendix-c--csv-report-schema)
24. [Appendix D — Wazuh API Endpoints Used](#24-appendix-d--wazuh-api-endpoints-used)
25. [Appendix E — Financial Risk Model Details](#25-appendix-e--financial-risk-model-details)

---

## 1. Executive Summary

**PurpleStrike** is an AI-driven Breach and Attack Simulation (BAS) platform that autonomously executes MITRE ATT&CK techniques against on-premises enterprise environments and validates whether the deployed SIEM (starting with Wazuh) detects them. It combines an autonomous AI agent with pre-built attack playbooks, maps execution results against SIEM alerts using a hybrid rule-based + AI-powered correlation engine, and outputs financial risk quantification for undetected gaps along with actionable remediation guidance.

**Key Differentiators:**
- AI agent that autonomously chains multi-stage attack paths (not just isolated atomic tests)
- Hybrid detection validation: deterministic rule mapping + LLM-powered alert correlation
- Financial risk quantification for detection gaps (FAIR-inspired), not just pass/fail
- SIEM-specific remediation guidance (Wazuh custom rules + decoders) alongside generic recommendations
- Plugin-based architecture: extensible to any SIEM, any attack framework, any LLM provider

---

## 2. Problem Statement

Security teams invest heavily in SIEM deployment and rule authoring, yet they lack a continuous, objective mechanism to answer the question:

> **"If an attacker executed technique X right now, would our SIEM alert us?"**

Current approaches fail in the following ways:

| Problem | Impact |
|---|---|
| **Manual red team exercises** are expensive, infrequent, and non-repeatable | Detection gaps persist for months between engagements |
| **Atomic Red Team** tests are isolated — no multi-stage attack chain simulation | Misses detection gaps that only appear in correlated, multi-step attacks |
| **Existing BAS tools** (Pentera, AttackIQ) are commercial, black-box, and SIEM-agnostic in their validation | Teams cannot validate their specific SIEM rules, only generic coverage |
| **No financial quantification** of detection gaps | CISOs cannot prioritize remediation investments or communicate risk to the board |
| **No remediation guidance** tied to specific SIEM configuration | Security engineers must independently figure out how to close each gap |

PurpleStrike solves these by providing an open, agent-driven, SIEM-validation-focused attack simulation platform with financial risk quantification and actionable remediation.

---

## 3. Product Vision & Goals

### Vision

> Make detection validation as continuous, automated, and measurable as vulnerability scanning.

### Goals

| # | Goal | Success Criteria |
|---|---|---|
| G1 | Execute realistic multi-stage attack chains based on MITRE ATT&CK | Agent completes full kill-chain scenarios (5+ chained techniques) against test targets |
| G2 | Validate SIEM detection per technique and per campaign | Achieve >95% accuracy in detection validation vs. manual analyst review |
| G3 | Quantify financial risk of detection gaps | Produce dollar-value risk estimates that CISOs can use in risk registers |
| G4 | Provide actionable remediation guidance | For each undetected technique, output SIEM-specific rule/decoder configurations |
| G5 | Support extensible SIEM and attack plugin ecosystem | Third party can write a new SIEM connector in <4 hours by implementing the plugin interface |
| G6 | Operate safely in production-adjacent environments | Zero unintended damage to production systems during simulation runs |

### Non-Goals (MVP)

- Cloud-native attack simulation (AWS/Azure/GCP)
- Web UI / dashboard
- Multi-user / team collaboration
- Real-time streaming of attack execution
- Automated remediation deployment (guidance only)
- Scheduled/recurring execution
- CI/CD pipeline integration

---

## 4. User Personas

### Primary: Security Engineer (Detection Engineer)

- **Name:** Sarah
- **Role:** Detection Engineer on the SOC team
- **Pain:** Writes Wazuh rules all day but has no way to verify they actually fire against real attack patterns
- **Use Case:** Runs PurpleStrike weekly to validate new rules, gets JSON output showing which techniques are detected and which are gaps, then writes new rules for gaps
- **Success Metric:** Can validate 50+ techniques in a single 30-minute simulation run

### Secondary: CISO / Security Manager

- **Name:** Marcus
- **Role:** CISO responsible for security budget and risk reporting
- **Pain:** Needs to justify detection engineering headcount and tool investment to the board
- **Use Case:** Reviews PurpleStrike risk quantification reports to understand financial exposure of detection gaps, prioritizes investment
- **Success Metric:** Can cite dollar-value risk figures in board presentations

### Tertiary: Red Team Operator

- **Name:** Alex
- **Role:** Red team operator who wants to test detection coverage before/after engagements
- **Use Case:** Uses PurpleStrike agent mode to simulate multi-stage attack chains and validates whether the blue team's SIEM catches each step
- **Success Metric:** Can define custom attack scenarios via playbooks and validate end-to-end

---

## 5. System Architecture

### 5.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PurpleStrike CLI                         │
│                   (Entry point / Operator UI)                    │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Orchestrator Core                          │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────────┐  │
│  │  Agent Loop   │  │  Playbook     │  │  Execution Strategy  │  │
│  │  (AI-driven)  │  │  Runner       │  │  (Plan Approval)     │  │
│  └───────┬───────┘  └───────┬───────┘  └──────────┬──────────┘  │
│          │                  │                      │             │
│          ▼                  ▼                      ▼             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Technique Execution Engine                  │    │
│  │   (Dispatches technique modules, manages state)         │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │                                      │
│          ┌────────────────┼────────────────┐                    │
│          ▼                ▼                ▼                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐           │
│  │  Custom      │ │  Atomic Red  │ │  Caldera /   │           │
│  │  Python      │ │  Team        │ │  Sliver /    │           │
│  │  Modules     │ │  Atomics     │ │  Mythic      │           │
│  └──────────────┘ └──────────────┘ └──────────────┘           │
│                     Attack Plugin Layer                         │
└──────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Target Interaction Layer                      │
│  ┌──────────────────┐    ┌──────────────────────────────────┐   │
│  │  Remote Execution │    │  Agent-Based Execution           │   │
│  │  (SSH, WinRM,    │    │  (Lightweight implant on target   │   │
│  │   WMI, PS Remoting│    │   receives C2 commands)           │   │
│  └──────────────────┘    └──────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                   Detection Validation Engine                    │
│  ┌─────────────────────┐  ┌──────────────────────────────────┐  │
│  │  Rule-Based Mapper   │  │  AI Alert Correlator             │  │
│  │  (MITRE technique →  │  │  (LLM analyzes SIEM alerts to    │  │
│  │   SIEM rule mapping) │  │   correlate with attack steps)   │  │
│  └──────────┬──────────┘  └──────────────┬───────────────────┘  │
│             └──────────┬─────────────────┘                      │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │             SIEM Connector Plugin (Wazuh)                │    │
│  │   - Query alerts via Wazuh API                          │    │
│  │   - Retrieve rule/decoder definitions                   │    │
│  │   - Map alerts to MITRE techniques                      │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Reporting & Risk Engine                       │
│  ┌──────────────────┐  ┌────────────────────┐                  │
│  │  Risk Quantifier │  │  Remediation Engine │                  │
│  │  (FAIR-inspired  │  │  (SIEM-specific +   │                  │
│  │   $ risk model)  │  │   generic guidance) │                  │
│  └────────┬─────────┘  └─────────┬──────────┘                  │
│           └────────┬─────────────┘                              │
│                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │             Report Generator (JSON / CSV)               │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Component Responsibilities

| Component | Responsibility |
|---|---|
| **CLI** | Parse commands, load config, display progress, output results |
| **Orchestrator Core** | Coordinate agent loop, playbook runner, and execution strategy |
| **Agent Loop** | Use LLM to plan multi-stage attack chains, select techniques, adapt based on results |
| **Playbook Runner** | Execute pre-defined attack scenarios sequentially |
| **Execution Strategy** | Enforce safety controls (plan approval), manage execution flow |
| **Technique Execution Engine** | Dispatch technique modules to appropriate attack plugin, track execution state |
| **Attack Plugin Layer** | Execute techniques via custom Python, Atomic Red Team, Caldera, or C2 frameworks |
| **Target Interaction Layer** | Communicate with targets via remote protocols or deployed implants |
| **Detection Validation Engine** | Check SIEM for alerts after each step and after full campaign |
| **Rule-Based Mapper** | Match MITRE technique IDs to specific SIEM detection rules |
| **AI Alert Correlator** | Use LLM to analyze ambiguous/unmapped SIEM alerts against attack context |
| **SIEM Connector** | Interface with Wazuh API to query alerts and retrieve rule definitions |
| **Risk Quantifier** | Calculate financial risk for undetected techniques |
| **Remediation Engine** | Generate SIEM-specific rule configurations and generic detection guidance |
| **Report Generator** | Produce JSON and CSV output with results, risk scores, and remediation |

### 5.3 Data Flow

```
1. Operator runs: purplestrike run --mode agent --target-group production_win
2. CLI loads config → Orchestrator initializes Agent Loop with target context
3. Agent Loop queries LLM → generates attack plan (ordered technique list with parameters)
4. Execution Strategy presents plan to operator → operator approves
5. For each technique in plan:
   a. Technique Execution Engine dispatches to Attack Plugin
   b. Attack Plugin executes against target via Remote or Agent channel
   c. Execution result logged (success/failure/output)
   d. Detection Validation Engine queries SIEM (Wazuh API) for alerts
   e. Rule-Based Mapper checks expected rule firings
   f. AI Alert Correlator analyzes unmapped alerts against attack context
   g. Per-step detection result recorded (detected / partially detected / not detected)
6. After all steps complete:
   a. Post-campaign detection correlation check
   b. Risk Quantifier calculates financial exposure per undetected technique
   c. Remediation Engine generates guidance per gap
   d. Report Generator outputs JSON + CSV files
```

---

## 6. Core Components — Detailed Design

### 6.1 Agent Loop

The Agent Loop is the AI-driven brain of PurpleStrike. It uses an LLM to plan, execute, and adapt attack chains.

**Design:**

```
┌──────────────────────────────────────────┐
│              Agent Loop                   │
│                                          │
│  ┌─────────────────────────────────┐     │
│  │  Context Builder                │     │
│  │  - Target OS, services, domain  │     │
│  │  - Available techniques (plugins)│    │
│  │  - Previous step results        │     │
│  │  - MITRE ATT&CK knowledge base  │     │
│  └──────────────┬──────────────────┘     │
│                 ▼                        │
│  ┌─────────────────────────────────┐     │
│  │  LLM Planner                    │     │
│  │  - Selects next technique(s)    │     │
│  │  - Chains techniques logically  │     │
│  │  - Adapts based on step results │     │
│  │  - Considers detection evasion  │     │
│  └──────────────┬──────────────────┘     │
│                 ▼                        │
│  ┌─────────────────────────────────┐     │
│  │  Plan Formatter                 │     │
│  │  - Structured attack plan       │     │
│  │  - Each step: technique ID,     │     │
│  │    target, parameters,          │     │
│  │    expected detection rules     │     │
│  └─────────────────────────────────┘     │
└──────────────────────────────────────────┘
```

**Agent Prompt Architecture:**

The LLM planner receives a structured system prompt containing:
1. **Role definition:** "You are an adversary emulation planner. Your job is to select and chain MITRE ATT&CK techniques to simulate a realistic attack against the specified target environment."
2. **Target context:** OS, domain, services, known credentials, network layout
3. **Available techniques:** List of technique IDs with descriptions, supported parameters, and prerequisites
4. **Execution history:** Results from previously executed steps (success/failure, output, detection status)
5. **Constraints:** Safety boundaries (no data destruction, no real exfiltration, no impact on availability)

**Plan Output Format:**

```json
{
  "name": "Credential Harvesting via Kerberoasting",
  "description": "Enumerate SPNs, request service tickets, extract and crack offline",
  "steps": [
    {
      "order": 1,
      "technique_id": "T1018",
      "technique_name": "Remote System Discovery",
      "target": "dc01.corp.local",
      "parameters": {
        "method": "ldap_query",
        "query": "(servicePrincipalName=*)"
      },
      "expected_detection_rules": ["wazuh_rule_100001", "wazuh_rule_100002"]
    },
    {
      "order": 2,
      "technique_id": "T1558.001",
      "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
      "target": "dc01.corp.local",
      "parameters": {
        "method": "rubeus",
        "output_format": "hashcat"
      },
      "expected_detection_rules": ["wazuh_rule_100050"]
    }
  ]
}
```

**Adaptive Behavior:**
- If a step fails, the agent can select an alternative technique (e.g., if Kerberoasting fails, try AS-REP Roasting)
- If a step succeeds but produces unexpected output, the agent can adjust the next step's parameters
- The agent respects a configurable max-steps limit to prevent runaway execution

**LLM Provider Interface:**

```python
class LLMProvider(Protocol):
    async def complete(self, messages: list[Message], **kwargs) -> str: ...
    async def complete_structured(self, messages: list[Message], schema: type[BaseModel], **kwargs) -> BaseModel: ...
```

Supported providers:
- `OpenAIProvider` — GPT-4o, GPT-4-turbo
- `AnthropicProvider` — Claude 3.5 Sonnet, Claude 3 Opus
- `OllamaProvider` — Local models via Ollama API
- `vLLMProvider` — Local models via vLLM server

Provider selection via environment variable `PURPLESTRIKE_LLM_PROVIDER` or config file.

### 6.2 Playbook Runner

Executes pre-defined attack scenarios without AI planning. Playbooks are YAML files defining a fixed sequence of techniques.

**Playbook Schema:**

```yaml
name: "AD Credential Harvesting"
description: "Simulate credential theft in Active Directory environments"
author: "PurpleStrike Team"
mitre_attack_version: "14.1"
target_os: ["windows"]

steps:
  - order: 1
    technique_id: "T1087.001"
    technique_name: "Account Discovery: Local Account"
    executor: "custom_python"
    module: "recon.local_account_discovery"
    parameters:
      method: "net_user"
    expected_detection_rules:
      - "wazuh_rule_100001"
    timeout_seconds: 30

  - order: 2
    technique_id: "T1018"
    technique_name: "Remote System Discovery"
    executor: "atomic_red_team"
    atomic_test_guid: "4ea5eb37-6a45-4f10-8e42-2453e8857894"
    timeout_seconds: 60

  - order: 3
    technique_id: "T1558.001"
    technique_name: "Steal or Forge Kerberos Tickets: Kerberoasting"
    executor: "custom_python"
    module: "credential_access.kerberoast"
    parameters:
      tool: "rubeus"
    expected_detection_rules:
      - "wazuh_rule_100050"
    timeout_seconds: 120
```

**Playbook Discovery:** Playbooks are loaded from:
1. `~/.purplestrike/playbooks/` (user-defined)
2. `./playbooks/` (project-local)
3. Built-in playbooks shipped with PurpleStrike

### 6.3 Execution Strategy

Manages the flow from plan creation to execution with safety controls.

**Flow:**

```
Plan Created → Display to Operator → Operator Approves/Rejects/Modifies
                                              │
                                    ┌─────────┴──────────┐
                                    │  Approved           │  Rejected
                                    ▼                     ▼
                              Execute all steps     Abort or re-plan
                              sequentially          with feedback
```

**Approval Interface (CLI):**

When a plan is generated, the CLI displays:
- Full attack plan with technique names, targets, and parameters
- Risk assessment per step (high/medium/low impact)
- Estimated total execution time
- Prompt: `Approve this plan? [y/n/e(edit)]`

**Operator Edit Mode:**
- Type `e` to open the plan in `$EDITOR`
- Modify technique parameters, remove steps, reorder steps
- Save and confirm to execute the modified plan

---

## 7. Plugin System

### 7.1 Plugin Architecture Overview

PurpleStrike uses a plugin-based architecture with four plugin types:

| Plugin Type | Purpose | Interface |
|---|---|---|
| **Attack Executor** | Execute attack techniques via a specific framework | `AttackExecutor` |
| **SIEM Connector** | Query alerts, rules, and decoders from a SIEM | `SIEMConnector` |
| **LLM Provider** | Provide LLM completion for agent reasoning | `LLMProvider` |
| **Report Formatter** | Generate output in a specific format | `ReportFormatter` |

### 7.2 Plugin Discovery & Loading

```
~/.purplestrike/plugins/
├── attack_executors/
│   ├── custom_python/
│   ├── atomic_red_team/
│   ├── caldera/
│   └── sliver/
├── siem_connectors/
│   ├── wazuh/
│   └── (future: splunk/, elastic/, qradar/)
├── llm_providers/
│   ├── openai/
│   ├── anthropic/
│   ├── ollama/
│   └── vllm/
└── report_formatters/
    ├── json/
    └── csv/
```

**Loading Order:**
1. Built-in plugins (shipped with PurpleStrike package)
2. User plugins from `~/.purplestrike/plugins/`
3. Project-local plugins from `./plugins/`

Later plugins override earlier ones with the same name.

### 7.3 Attack Executor Plugin Interface

```python
from typing import Protocol, Any
from dataclasses import dataclass

@dataclass
class TechniqueResult:
    technique_id: str
    success: bool
    output: str
    error: str | None
    artifacts: list[str]  # file paths to captured artifacts
    execution_time_seconds: float

class AttackExecutor(Protocol):
    name: str
    supported_techniques: list[str]  # MITRE technique IDs

    async def setup(self, config: dict) -> None:
        """Initialize the executor with configuration."""
        ...

    async def execute(self, technique_id: str, target: str, parameters: dict) -> TechniqueResult:
        """Execute a single technique against a target."""
        ...

    async def cleanup(self, technique_id: str, target: str) -> None:
        """Clean up artifacts left by a technique execution."""
        ...

    async def teardown(self) -> None:
        """Shutdown the executor and release resources."""
        ...
```

### 7.4 SIEM Connector Plugin Interface

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

@dataclass
class SIEMAlert:
    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_description: str
    severity: str
    source: str
    mitre_technique_ids: list[str]  # if the SIEM rule maps to MITRE
    raw_log: dict

@dataclass
class SIEMRule:
    rule_id: str
    description: str
    severity: str
    mitre_technique_ids: list[str]
    rule_logic: str  # the rule query/logic as string

class SIEMConnector(Protocol):
    name: str

    async def setup(self, config: dict) -> None: ...

    async def query_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        rule_ids: list[str] | None = None,
        source: str | None = None,
    ) -> list[SIEMAlert]:
        """Query alerts from the SIEM within a time window."""
        ...

    async def get_rule(self, rule_id: str) -> SIEMRule | None:
        """Retrieve a specific rule definition."""
        ...

    async def get_rules_for_technique(self, technique_id: str) -> list[SIEMRule]:
        """Get all rules mapped to a MITRE technique."""
        ...

    async def teardown(self) -> None: ...
```

### 7.5 LLM Provider Plugin Interface

```python
from typing import Protocol
from pydantic import BaseModel

class Message(BaseModel):
    role: str  # "system" | "user" | "assistant"
    content: str

class LLMProvider(Protocol):
    name: str
    model: str

    async def setup(self, config: dict) -> None: ...

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Generate a free-text completion."""
        ...

    async def complete_structured(
        self,
        messages: list[Message],
        schema: type[BaseModel],
        **kwargs,
    ) -> BaseModel:
        """Generate a structured completion conforming to a Pydantic schema."""
        ...

    async def teardown(self) -> None: ...
```

### 7.6 Report Formatter Plugin Interface

```python
from typing import Protocol
from pathlib import Path

class SimulationReport(BaseModel):
    # Full report data model (see Appendix B)
    ...

class ReportFormatter(Protocol):
    name: str
    file_extension: str

    async def format(self, report: SimulationReport, output_path: Path) -> Path:
        """Write the formatted report to output_path and return the path."""
        ...
```

---

## 8. MITRE ATT&CK Coverage — MVP Scope

### 8.1 Built-in Tactics

The original MVP covered five tactics. The current built-in catalog also covers
the Stealth and Defense Impairment techniques introduced with ATT&CK v19:

| Tactic | ID | # Techniques (MVP) | Priority |
|---|---|---|---|
| Initial Access | TA0001 | 8 | High |
| Execution | TA0002 | 10 | High |
| Persistence | TA0003 | 8 | High |
| Privilege Escalation | TA0004 | 8 | High |
| Credential Access | TA0006 | 8 | High |
| Stealth | TA0005 | 4 | Medium |
| Defense Impairment | TA0112 | 15 | High |
| **Total** | | **61 scenarios / 60 unique ATT&CK IDs** | |

### 8.2 Technique Selection Criteria

Techniques are selected for the MVP based on:
1. **Prevalence in real incidents** — techniques most commonly observed in APT campaigns targeting on-prem AD environments
2. **Detection testability** — the technique produces observable artifacts that a SIEM could reasonably detect
3. **Execution safety** — the technique can be simulated without causing denial of service, data corruption, or persistent system changes that cannot be automatically cleaned up
4. **Wazuh coverage** — Wazuh has existing or potential detection rules for the technique

### 8.3 Progressive Expansion Plan

| Version | Additional Tactics | New Techniques | Cumulative |
|---|---|---|---|
| v0.1 | Initial Access, Execution, Persistence, PrivEsc, Credential Access | 42 | 42 |
| Current | + ATT&CK v19 Stealth and Defense Impairment | 19 | 61 |
| v0.2 | + Lateral Movement | ~10 | ~71 |
| v0.3 | + Collection, Exfiltration, C2 | ~20 | ~87 |
| v0.4 | + Discovery, Impact | ~15 | ~102 |
| v1.0 | Full MITRE ATT&CK coverage for on-prem | ~30 | ~132 |

---

## 9. SIEM Integration — Wazuh Connector

### 9.1 Wazuh API Integration

PurpleStrike integrates with Wazuh exclusively through the Wazuh Management API for the MVP.

**Connection Configuration:**

```env
PURPLESTRIKE_WAZUH_API_URL=https://wazuh-manager:55000
PURPLESTRIKE_WAZUH_API_USER=purplestrike
PURPLESTRIKE_WAZUH_API_PASSWORD=<password>
PURPLESTRIKE_WAZUH_API_TIMEOUT=30
```

**Key API Endpoints Used:**

| Endpoint | Purpose | Frequency |
|---|---|---|
| `GET /alerts` | Query alerts within time window | After each attack step + post-campaign |
| `GET /rules` | Retrieve rule definitions and MITRE mappings | Before simulation (once) |
| `GET /rules/{rule_id}` | Get specific rule logic | During detection validation |
| `GET /decoders` | Retrieve decoder definitions | Before simulation (once) |
| `GET /cluster/status` | Verify Wazuh cluster health | Before simulation (once) |

*(See Appendix D for full endpoint specifications.)*

### 9.2 Alert Query Strategy

**Per-Step Check (immediately after technique execution):**

```
1. Record pre-execution timestamp T0
2. Execute attack technique
3. Record post-execution timestamp T1
4. Wait configurable delay (default: 30s) for SIEM processing pipeline
5. Query Wazuh API: GET /alerts?time_from={T0}&time_to={T1+delay}
6. Filter alerts by:
   - Rule IDs mapped to the executed technique (rule-based check)
   - Source agent matching the target host
7. If no mapped rules fired → AI Alert Correlator analyzes all alerts in window
8. Record per-step detection result
```

**Post-Campaign Check (after all steps complete):**

```
1. Record full campaign time window [T_campaign_start, T_campaign_end]
2. Query Wazuh API for ALL alerts in campaign window
3. Cross-reference with full technique list from the plan
4. Identify:
   - Techniques detected by individual step checks
   - Techniques only detected in aggregate (campaign-level correlation)
   - Techniques not detected at all
5. Record final campaign detection result
```

### 9.3 MITRE Technique → Wazuh Rule Mapping

PurpleStrike maintains a mapping table between MITRE techniques and Wazuh rules. This mapping is:

1. **Pre-loaded** with known Wazuh rule-to-MITRE mappings (Wazuh rules include `mitre.id` fields)
2. **Queried at runtime** from the Wazuh API (rules endpoint returns MITRE metadata)
3. **User-extensible** via a mapping override file: `~/.purplestrike/wazuh_rule_mapping.yaml`

**Mapping Format:**

```yaml
T1558.001:
  technique_name: "Steal or Forge Kerberos Tickets: Kerberoasting"
  wazuh_rules:
    - rule_id: "100050"
      confidence: high
      description: "Detects Kerberos service ticket requests for SPN accounts"
    - rule_id: "100051"
      confidence: medium
      description: "Detects suspicious Kerberos traffic patterns"
  custom_rules:
    - rule_id: "custom_100200"
      confidence: high
      description: "Custom rule for Kerberoasting detection"
```

---

## 10. Detection Validation Engine

### 10.1 Hybrid Validation Pipeline

```
                    ┌────────────────────────┐
                    │   SIEM Alerts Retrieved │
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │  Rule-Based Mapper      │
                    │  Check if expected      │
                    │  Wazuh rules fired      │
                    └───────────┬────────────┘
                                │
                   ┌────────────┼─────────────┐
                   │                          │
            Mapped rules found         No mapped rules found
                   │                          │
                   ▼                          ▼
           ┌───────────┐          ┌────────────────────┐
           │  DETECTED │          │  AI Alert Correlator│
           │           │          │  LLM analyzes all   │
           └───────────┘          │  alerts in window   │
                                  └──────────┬─────────┘
                                             │
                              ┌──────────────┼──────────────┐
                              │              │              │
                        LLM finds        LLM finds      No relevant
                        strong match    partial match   alerts found
                              │              │              │
                              ▼              ▼              ▼
                        ┌──────────┐  ┌──────────┐  ┌──────────────┐
                        │ DETECTED │  │ PARTIAL  │  │ NOT DETECTED │
                        └──────────┘  └──────────┘  └──────────────┘
```

### 10.2 Detection Result Classification

| Result | Meaning | Risk Impact |
|---|---|---|
| **DETECTED** | Expected SIEM rule(s) fired OR AI correlator found strong alert match | No gap — SIEM working as expected |
| **PARTIALLY DETECTED** | Some expected rules fired, but key attack indicators were missed; OR AI correlator found only partial coverage | Medium gap — SIEM detects some but not all indicators |
| **NOT DETECTED** | No expected rules fired AND AI correlator found no relevant alerts | Full gap — SIEM is blind to this technique |
| **UNKNOWN** | SIEM query failed, timeout, or insufficient data to determine | Cannot validate — needs manual review |

### 10.3 AI Alert Correlator

When rule-based mapping fails (no mapped rules fired), the AI Alert Correlator uses an LLM to analyze raw SIEM alerts against the attack context.

**Correlator Prompt Architecture:**

```
System: You are a detection validation analyst. You must determine whether
any of the following SIEM alerts indicate detection of the executed attack
technique. Be conservative — only flag as "detected" if the alert clearly
relates to the attack indicators.

Attack Context:
- Technique: T1558.001 - Kerberoasting
- Target: dc01.corp.local
- Execution time: 2026-05-02T14:30:00Z to 2026-05-02T14:30:45Z
- Key indicators: RC4 encryption in Kerberos TGS, service ticket requests for SPN accounts

SIEM Alerts in Time Window:
[... list of alert objects ...]

Respond with:
- detection_status: "detected" | "partially_detected" | "not_detected"
- confidence: 0.0-1.0
- matched_alerts: list of alert_ids that correlate
- reasoning: brief explanation
```

**Cost Control:** The AI Alert Correlator is only invoked when rule-based mapping returns no results. This minimizes LLM API calls and cost.

---

## 11. Financial Risk Quantification Model

PurpleStrike uses a FAIR-inspired (Factor Analysis of Information Risk) model to translate detection gaps into dollar-value risk estimates.

### 11.1 Model Overview

```
Risk ($) = Loss Event Frequency × Loss Magnitude

Where:
  Loss Event Frequency = Threat Event Frequency × Vulnerability (detection gap probability)
  Loss Magnitude = Primary Loss + Secondary Loss
```

### 11.2 Detection Gap → Vulnerability Mapping

A detection gap directly increases the **Vulnerability** factor — the probability that an attack succeeds undetected.

| Detection Result | Vulnerability Score | Meaning |
|---|---|---|
| DETECTED | 0.05 | SIEM would likely catch it; attacker has ~5% chance of going unnoticed |
| PARTIALLY DETECTED | 0.40 | Some detection; attacker has ~40% chance of evading |
| NOT DETECTED | 0.90 | SIEM is blind; attacker has ~90% chance of going unnoticed |
| UNKNOWN | 0.50 | Cannot determine; assume 50/50 |

### 11.3 Threat Event Frequency

Derived from industry threat intelligence, mapped per MITRE technique:

| Technique Category | Annual Threat Event Frequency | Source |
|---|---|---|
| Common (e.g., T1059.001 PowerShell) | 52/year (weekly) | Verizon DBIR, MITRE evaluations |
| Moderate (e.g., T1558.001 Kerberoasting) | 12/year (monthly) | Industry threat reports |
| Rare (e.g., T1190 Exploit Public-Facing App) | 4/year (quarterly) | APT campaign data |

These defaults are configurable via `~/.purplestrike/risk_parameters.yaml`.

### 11.4 Loss Magnitude

Per-technique loss estimates based on industry data:

| Loss Type | Low | Moderate | High |
|---|---|---|---|
| Primary Loss (incident response cost) | $15K | $50K | $150K |
| Secondary Loss (business impact, data breach) | $50K | $500K | $5M |
| **Total Loss Magnitude** | **$65K** | **$550K** | **$5.15M** |

Technique-specific loss magnitude is derived from:
1. **Technique severity** — techniques leading to credential theft or domain admin have higher loss magnitude
2. **Asset value** — configurable per target group (e.g., domain controllers = high, workstations = moderate)
3. **Industry vertical** — configurable multiplier (healthcare/finance = higher)

### 11.5 Risk Calculation Example

```
Technique: T1558.001 Kerberoasting
Detection Result: NOT DETECTED
Vulnerability Score: 0.90
Threat Event Frequency: 12/year
Loss Magnitude: $550,000 (moderate — credential access on DC)

Risk = 12 × 0.90 × $550,000 = $5,940,000/year Annualized Loss Expectancy (ALE)
```

This means: given that Kerberoasting is not detected, the organization faces an estimated $5.94M annualized risk from this gap alone.

### 11.6 Risk Aggregation

The total organizational risk from detection gaps is the sum of individual ALEs:

```
Total ALE = Σ (Threat Event Frequency_i × Vulnerability_i × Loss Magnitude_i)
           for all techniques where detection_result ≠ "DETECTED"
```

**Caveat:** This is a simplified model. Techniques are not fully independent (an attacker chaining techniques increases cumulative risk). Future versions may add correlation factors.

*(See Appendix E for the full parameter tables and calculation methodology.)*

---

## 12. Remediation & Detection Engineering Guidance

### 12.1 Remediation Output Structure

For each technique where `detection_result` is not "DETECTED", PurpleStrike generates:

1. **Wazuh-specific remediation** — concrete custom rule and decoder XML configurations
2. **Generic detection guidance** — SIEM-agnostic recommendations based on MITRE detection data sources

### 12.2 Wazuh-Specific Remediation Format

```xml
<!-- Suggested Wazuh Custom Rule for T1558.001 Kerberoasting -->
<group name="purplestrike_remediation,">
  <rule id="100200" level="10">
    <if_sid>100050</if_sid>
    <field name="win.system.eventID">4769</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>Kerberoasting detected: RC4-encrypted TGS ticket requested for SPN account</description>
    <mitre>
      <id>T1558.001</id>
    </mitre>
  </rule>
</group>
```

Each remediation includes:
- **Rule XML** — ready to paste into Wazuh custom rules file
- **Decoder XML** (if needed) — for log parsing
- **Log source requirements** — what log channels must be forwarded to Wazuh (e.g., Windows Security Event Log, Sysmon)
- **Testing instructions** — how to verify the rule fires after deployment

### 12.3 Generic Detection Guidance Format

```
Technique: T1558.001 - Kerberoasting
Data Sources:
  - Windows Security Event Log (Event ID 4769)
  - Sysmon Event ID 1 (process creation of Rubeus/Invoke-Kerberoast)
  - Network traffic analysis (Kerberos TGS requests with RC4 encryption)
Detection Logic:
  - Monitor for Event 4769 where TicketEncryptionType = 0x17 (RC4)
    and ServiceName matches an SPN account pattern
  - Alert on high volume of TGS requests from a single source in short time
  - Monitor for known Kerberoasting tool process names (Rubeus.exe, Invoke-Kerberoast)
False Positive Considerations:
  - Legitimate service ticket requests use RC4 for older services
  - Correlate with account sensitivity (gMSA, high-privilege SPN accounts)
References:
  - MITRE ATT&CK: https://attack.mitre.org/techniques/T1558/001/
  - Wazuh Ruleset: https://github.com/wazuh/wazuh-ruleset
```

### 12.4 Remediation Confidence Levels

| Level | Meaning |
|---|---|
| **High** | PurpleStrike has a tested, verified Wazuh rule for this technique |
| **Medium** | PurpleStrike has a suggested rule based on MITRE data sources but it has not been tested against this exact environment |
| **Low** | Only generic guidance is available; the technique may require custom log sources not yet forwarded to Wazuh |

---

## 13. CLI Interface Design

### 13.1 Command Structure

```
purplestrike <command> [options]

Commands:
  run          Execute an attack simulation
  plan         Generate an attack plan without executing (dry-run)
  playbooks    List/manage available playbooks
  techniques   List available MITRE techniques and their support status
  siem         SIEM connector management (test connection, list rules)
  config       Manage PurpleStrike configuration
  version      Show version information
```

### 13.2 `run` Command

```
purplestrike run [OPTIONS]

Options:
  --mode <mode>            Execution mode: "agent" | "playbook"   [default: agent]
  --playbook <path>        Path to playbook YAML (required if --mode=playbook)
  --target-group <name>    Target group name from config            [required]
  --tactics <tactics>      Comma-separated MITRE tactic IDs to target
                           [default: TA0001,TA0002,TA0003,TA0004,TA0006]
  --techniques <ids>       Comma-separated specific technique IDs to execute
  --max-steps <n>          Maximum number of attack steps            [default: 20]
  --detection-check-delay  Seconds to wait before querying SIEM     [default: 30]
  --output-dir <path>      Directory for output reports              [default: ./results]
  --format <fmt>           Report format: "json" | "csv" | "both"  [default: both]
  --llm-provider <name>    LLM provider: "openai" | "anthropic" | "ollama" | "vllm"
                           [default: from config or PURPLESTRIKE_LLM_PROVIDER]
  --skip-cleanup           Do not clean up attack artifacts after execution
  --dry-run                Generate plan only, do not execute
```

### 13.3 `plan` Command

```
purplestrike plan [OPTIONS]

Options:
  --mode <mode>            "agent" | "playbook"                     [default: agent]
  --playbook <path>        Path to playbook YAML
  --target-group <name>    Target group name from config            [required]
  --tactics <tactics>      Comma-separated MITRE tactic IDs
  --output <path>          Save plan to file (YAML format)
```

### 13.4 `playbooks` Command

```
purplestrike playbooks list              # List all available playbooks
purplestrike playbooks show <name>       # Show playbook details
purplestrike playbooks validate <path>   # Validate a playbook YAML file
```

### 13.5 `techniques` Command

```
purplestrike techniques list             # List all supported techniques
purplestrike techniques list --tactic TA0002  # Filter by tactic
purplestrike techniques show T1558.001   # Show technique details and detection mapping
```

### 13.6 `siem` Command

```
purplestrike siem test                   # Test SIEM connectivity
purplestrike siem rules                  # List SIEM rules with MITRE mappings
purplestrike siem rules --technique T1558.001  # Rules for specific technique
```

### 13.7 `config` Command

```
purplestrike config init                 # Initialize config file with wizard
purplestrike config show                 # Display current configuration
purplestrike config set <key> <value>    # Set a configuration value
purplestrike config validate             # Validate configuration
```

### 13.8 CLI Output — Execution Progress

During execution, the CLI displays real-time progress:

```
purplestrike run --mode agent --target-group production_win

[*] PurpleStrike v0.1.0 — AI-Driven Breach & Attack Simulation
[*] Target group: production_win (3 hosts: dc01, ws01, ws02)
[*] LLM Provider: openai (gpt-4o)
[*] SIEM Connector: wazuh (wazuh-manager:55000)

[*] Generating attack plan...
[*] Plan: "Credential Harvesting via AD Exploitation" (5 steps)

  #  Technique                          Target          Risk
  1  T1018 Remote System Discovery      dc01.corp.local LOW
  2  T1087.001 Local Account Discovery  ws01.corp.local LOW
  3  T1558.001 Kerberoasting            dc01.corp.local MED
  4  T1110.001 Password Brute Force     dc01.corp.local MED
  5  T1552.001 Credentials in Files     ws02.corp.local LOW

  Estimated time: ~8 minutes

Approve this plan? [y/n/e(edit)]: y

[*] Executing step 1/5: T1018 Remote System Discovery...
    [✓] Executed successfully (12.3s)
    [✓] DETECTED by Wazuh rule 100001

[*] Executing step 2/5: T1087.001 Local Account Discovery...
    [✓] Executed successfully (8.1s)
    [✗] NOT DETECTED — no matching SIEM alerts

[*] Executing step 3/5: T1558.001 Kerberoasting...
    [✓] Executed successfully (24.7s)
    [~] PARTIALLY DETECTED — rule 100050 fired but missed RC4 indicator

[*] Executing step 4/5: T1110.001 Password Brute Force...
    [✓] Executed successfully (45.2s)
    [✓] DETECTED by Wazuh rule 100075

[*] Executing step 5/5: T1552.001 Credentials in Files...
    [✓] Executed successfully (6.4s)
    [✗] NOT DETECTED — no matching SIEM alerts

[*] Post-campaign detection correlation...

══════════════════════════════════════════════════════
  SIMULATION RESULTS
══════════════════════════════════════════════════════
  Techniques Executed:  5
  Detected:             2 (40%)
  Partially Detected:   1 (20%)
  Not Detected:         2 (40%)

  Total Annualized Risk: $8,420,000

  Reports saved to:
    ./results/sim_20260502_143000.json
    ./results/sim_20260502_143000.csv

  Run 'purplestrike siem rules --technique T1087.001' to view
  detection recommendations for gaps.
══════════════════════════════════════════════════════
```

---

## 14. Reporting — JSON/CSV Export

### 14.1 JSON Report Structure

*(See Appendix B for the full JSON schema.)*

```json
{
  "simulation_id": "sim_20260502_143000",
  "timestamp": "2026-05-02T14:30:00Z",
  "mode": "agent",
  "target_group": "production_win",
  "llm_provider": "openai",
  "siem_connector": "wazuh",
  "plan": {
    "name": "Credential Harvesting via AD Exploitation",
    "total_steps": 5
  },
  "results": [
    {
      "step": 1,
      "technique_id": "T1018",
      "technique_name": "Remote System Discovery",
      "tactic": "TA0001",
      "target": "dc01.corp.local",
      "execution_status": "success",
      "execution_time_seconds": 12.3,
      "detection_result": "detected",
      "detection_confidence": 1.0,
      "matched_rules": ["100001"],
      "matched_alerts": [
        {
          "alert_id": "1704215",
          "timestamp": "2026-05-02T14:30:15Z",
          "rule_id": "100001",
          "description": "Remote system discovery detected"
        }
      ],
      "risk": {
        "vulnerability_score": 0.05,
        "annualized_loss_expectancy": 0
      }
    }
  ],
  "summary": {
    "total_techniques": 5,
    "detected": 2,
    "partially_detected": 1,
    "not_detected": 2,
    "detection_rate": 0.4,
    "total_annualized_risk": 8420000
  },
  "remediation": [
    {
      "technique_id": "T1087.001",
      "current_detection": "not_detected",
      "wazuh_remediation": {
        "confidence": "high",
        "rule_xml": "<group name=\"purplestrike_remediation,\"><rule id=\"100201\" ...>",
        "decoder_xml": null,
        "log_sources_required": ["Windows Security Event Log"],
        "testing_instructions": "Run: purplestrike run --techniques T1087.001 ..."
      },
      "generic_guidance": {
        "data_sources": ["Windows Security Event Log (Event ID 4798, 4799)"],
        "detection_logic": "Monitor for user enumeration commands...",
        "false_positive_considerations": "Legitimate admin tools may trigger...",
        "references": ["https://attack.mitre.org/techniques/T1087/001/"]
      }
    }
  ]
}
```

### 14.2 CSV Report Structure

*(See Appendix C for the full CSV schema.)*

Two CSV files are generated:

**File 1: `sim_<id>_results.csv`** — One row per technique execution

| Column | Type | Description |
|---|---|---|
| step | int | Step order in attack chain |
| technique_id | string | MITRE technique ID |
| technique_name | string | MITRE technique name |
| tactic | string | MITRE tactic ID |
| target | string | Target hostname |
| execution_status | string | success / failure / timeout |
| execution_time_seconds | float | Wall-clock execution time |
| detection_result | string | detected / partially_detected / not_detected / unknown |
| detection_confidence | float | 0.0–1.0 |
| matched_rule_ids | string | Semicolon-separated Wazuh rule IDs |
| vulnerability_score | float | Risk model vulnerability score |
| annualized_loss_expectancy | float | Dollar-value ALE |
| risk_level | string | critical / high / medium / low |

**File 2: `sim_<id>_remediation.csv`** — One row per detection gap with remediation

| Column | Type | Description |
|---|---|---|
| technique_id | string | MITRE technique ID |
| technique_name | string | MITRE technique name |
| detection_result | string | partially_detected / not_detected |
| remediation_confidence | string | high / medium / low |
| suggested_rule_ids | string | Semicolon-separated suggested Wazuh rule IDs |
| log_sources_required | string | Semicolon-separated required log sources |
| generic_detection_logic | string | Brief detection logic description |

---

## 15. Security & Credential Management

### 15.1 Credential Storage

All credentials are managed via environment variables. No credentials are stored in config files, databases, or any persistent storage within PurpleStrike.

**Required Environment Variables:**

```env
# Target system credentials
PURPLESTRIKE_TARGET_AD_DOMAIN=corp.local
PURPLESTRIKE_TARGET_USERNAME=attack_user
PURPLESTRIKE_TARGET_PASSWORD=<password>

# Wazuh SIEM credentials
PURPLESTRIKE_WAZUH_API_URL=https://wazuh-manager:55000
PURPLESTRIKE_WAZUH_API_USER=purplestrike
PURPLESTRIKE_WAZUH_API_PASSWORD=<password>

# LLM API credentials
PURPLESTRIKE_OPENAI_API_KEY=<key>
PURPLESTRIKE_ANTHROPIC_API_KEY=<key>
# Ollama/vLLM typically don't need API keys

# Optional: C2 framework credentials
PURPLESTRIKE_SLIVER_OPERATOR_TOKEN=<token>
PURPLESTRIKE_CALDERA_API_KEY=<key>
```

### 15.2 Credential Handling Rules

1. **Never log credentials** — all log output redacts sensitive values
2. **Never include credentials in reports** — JSON/CSV output contains no credential material
3. **Never persist credentials to disk** — environment variables only, loaded at runtime
4. **Never transmit credentials over unencrypted channels** — enforce HTTPS for Wazuh API, SSH for target communication
5. **Optional .env file support** — load from `.env` file in working directory for convenience, but `.env` must be in `.gitignore`

### 15.3 Runtime Security

- All network communication uses TLS (Wazuh API, LLM APIs)
- Target connections use encrypted protocols (SSH, WinRM over HTTPS)
- Implant communication channels use mutual TLS (mTLS)
- No credential material is included in technique execution output captured for reports

---

## 16. Safety Controls

### 16.1 Plan-Once-Approval Model

The operator approves the full attack plan before any execution begins. Once approved:

1. All steps execute sequentially without further prompts
2. The operator can interrupt at any time with `Ctrl+C` (graceful shutdown + cleanup)
3. No step can execute outside the approved plan

### 16.2 Built-In Safety Constraints

The AI agent is hard-constrained (prompt-level + code-level enforcement) to never:

| Constraint | Implementation |
|---|---|
| **No data exfiltration** | Techniques that access/copy data simulate the action but write to a local temp directory, not to external destinations |
| **No data destruction** | Techniques that delete/modify data are simulated with no-op or dry-run variants |
| **No denial of service** | Brute-force techniques are rate-limited; no flooding or resource exhaustion |
| **No persistence after run** | All implanted artifacts, scheduled tasks, registry modifications are cleaned up post-execution |
| **No lateral movement to unapproved targets** | Agent can only target hosts in the configured target group |

### 16.3 Cleanup System

After each technique execution (and after the full campaign):

```
1. Technique executor calls cleanup() for the executed module
2. Orchestrator runs a post-campaign cleanup sweep:
   - Remove deployed implants
   - Remove scheduled tasks / cron jobs / registry entries
   - Remove temporary files on targets
   - Remove created user accounts (if any)
3. Cleanup results are logged and included in the report
4. If cleanup fails, the report flags it as a WARNING requiring manual review
```

### 16.4 Emergency Stop

- `Ctrl+C` triggers graceful shutdown: stop current step, run cleanup, generate partial report
- Double `Ctrl+C` within 3 seconds triggers immediate abort without cleanup (for emergencies)
- SIGTERM behaves like single `Ctrl+C`
- SIGKILL is caught at orchestrator level for best-effort cleanup

---

## 17. Data Model & Storage

### 17.1 SQLite Schema

PurpleStrike uses SQLite to store simulation runs and results. Each simulation is a self-contained record.

```sql
CREATE TABLE simulations (
    id TEXT PRIMARY KEY,              -- sim_20260502_143000
    timestamp TEXT NOT NULL,          -- ISO 8601
    mode TEXT NOT NULL,               -- 'agent' | 'playbook'
    target_group TEXT NOT NULL,
    llm_provider TEXT NOT NULL,
    siem_connector TEXT NOT NULL,
    plan_name TEXT,
    status TEXT NOT NULL,             -- 'completed' | 'partial' | 'aborted' | 'failed'
    total_techniques INTEGER,
    detected INTEGER,
    partially_detected INTEGER,
    not_detected INTEGER,
    total_ale REAL,                   -- Annualized Loss Expectancy
    report_path_json TEXT,
    report_path_csv TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE simulation_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    simulation_id TEXT NOT NULL REFERENCES simulations(id),
    step_order INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    target TEXT NOT NULL,
    execution_status TEXT NOT NULL,   -- 'success' | 'failure' | 'timeout'
    execution_time_seconds REAL,
    detection_result TEXT NOT NULL,   -- 'detected' | 'partially_detected' | 'not_detected' | 'unknown'
    detection_confidence REAL,
    matched_rule_ids TEXT,            -- JSON array of strings
    vulnerability_score REAL,
    ale REAL,
    result_detail TEXT,               -- JSON blob with full step result
    created_at TEXT NOT NULL
);

CREATE TABLE remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    simulation_id TEXT NOT NULL REFERENCES simulations(id),
    technique_id TEXT NOT NULL,
    detection_result TEXT NOT NULL,
    wazuh_remediation_confidence TEXT,
    wazuh_rule_xml TEXT,
    wazuh_decoder_xml TEXT,
    log_sources_required TEXT,        -- JSON array
    generic_guidance TEXT,            -- JSON blob
    created_at TEXT NOT NULL
);
```

### 17.2 Database Location

Default: `~/.purplestrike/purplestrike.db`

Configurable via: `PURPLESTRIKE_DB_PATH` environment variable or config file.

---

## 18. Error Handling & Resilience

### 18.1 Error Categories

| Category | Example | Handling |
|---|---|---|
| **Technique execution failure** | Target unreachable, command times out | Log failure, mark step as failed, continue to next step |
| **SIEM query failure** | Wazuh API returns 500, connection timeout | Mark detection as UNKNOWN, retry once, then skip and log warning |
| **LLM API failure** | Rate limit, timeout, invalid response | Retry with exponential backoff (3 attempts), fallback to simpler plan |
| **Cleanup failure** | Cannot remove implant, file locked | Log WARNING, include in report, flag for manual review |
| **Target crash** | Target becomes unresponsive during attack | Halt execution, attempt cleanup, generate partial report |
| **Config error** | Missing env var, invalid target group | Fail fast with clear error message before execution begins |

### 18.2 Retry Policy

- **LLM calls:** 3 retries with exponential backoff (2s, 4s, 8s)
- **SIEM API calls:** 2 retries with linear backoff (5s, 10s)
- **Target connections:** 1 retry per step, then mark as failed

### 18.3 Partial Results

If a simulation is interrupted or fails midway:
- All completed steps are preserved in the database
- A partial report is generated with completed steps only
- The report metadata includes `status: "partial"` and `last_completed_step: N`
- Incomplete steps are listed with `execution_status: "skipped"`

---

## 19. Development Roadmap

### Phase 1: Foundation (v0.1.0) — 12 weeks

**Goal:** MVP with agent mode, 5 MITRE tactics, Wazuh integration, JSON/CSV reporting

| Week | Deliverable |
|---|---|
| 1–2 | Project scaffolding: CLI framework (Typer), config system, SQLite schema, plugin loader |
| 3–4 | Core engine: Orchestrator, Agent Loop (LLM integration), Plan approval flow |
| 5–6 | Attack execution: Custom Python executor, 61 scenarios (7 tactics), Remote execution (SSH/WinRM) |
| 7–8 | Detection validation: Wazuh connector, Rule-based mapper, AI Alert Correlator |
| 9–10 | Reporting: Risk quantification engine, Remediation engine, JSON/CSV formatters |
| 11 | Playbook runner, built-in playbooks, Agent-based execution (implant) |
| 12 | Integration testing, documentation, v0.1.0 release |

### Phase 2: Expansion (v0.2.0) — 8 weeks

**Goal:** Add Lateral Movement, Atomic Red Team integration, and enhanced remediation

| Week | Deliverable |
|---|---|
| 1–3 | ~10 Lateral Movement techniques and the Atomic Red Team executor plugin |
| 4–5 | Enhanced AI Alert Correlator (multi-alert correlation, attack chain reconstruction) |
| 6–7 | Remediation lab: auto-deploy suggested Wazuh rules to test instance and re-run validation |
| 8 | Integration testing, v0.2.0 release |

### Phase 3: Advanced (v0.3.0) — 8 weeks

**Goal:** Collection, Exfiltration, C2 tactics; Caldera + Sliver/Mythic integration; scheduled runs

| Week | Deliverable |
|---|---|
| 1–3 | ~20 additional techniques, Caldera executor plugin, Sliver C2 executor plugin |
| 4–5 | Scheduled/recurring execution (cron-style), email notification on completion |
| 6–7 | Regression detection: compare results across runs, alert on previously-detected techniques now missed |
| 8 | Integration testing, v0.3.0 release |

### Phase 4: Full Coverage (v1.0.0) — 8 weeks

**Goal:** Full MITRE ATT&CK on-prem coverage, multi-SIEM support, CI/CD integration

| Week | Deliverable |
|---|---|
| 1–3 | Remaining techniques (Discovery, Impact), Splunk + Elastic SIEM connectors |
| 4–5 | CI/CD integration (GitHub Actions, GitLab CI), Docker container packaging |
| 6–7 | Web dashboard (optional), API server mode, multi-user support |
| 8 | Full regression test suite, security audit, v1.0.0 release |

---

## 20. Success Metrics & KPIs

### 20.1 Product Metrics

| Metric | Target (v0.1) | Target (v1.0) |
|---|---|---|
| MITRE techniques supported | 61 scenarios (7 tactics) | 132 (broader on-prem scope) |
| Detection validation accuracy | ≥90% vs. manual analyst | ≥95% |
| SIEM connectors | 1 (Wazuh) | 4+ (Wazuh, Splunk, Elastic, QRadar) |
| Attack executor plugins | 1 (Custom Python) | 4 (Custom, ART, Caldera, Sliver) |
| Time to run full 61-scenario simulation | <30 minutes | <15 minutes (parallel execution) |
| Time to add new SIEM connector | N/A | <4 hours (plugin interface) |

### 20.2 Quality Metrics

| Metric | Target |
|---|---|
| Test coverage (unit + integration) | ≥80% |
| Zero unintended production impact | 100% |
| Cleanup success rate | ≥95% |
| False positive detection validation rate | <5% |
| CLI command documentation coverage | 100% |

### 20.3 Adoption Metrics

| Metric | Target (6 months post-v1.0) |
|---|---|
| GitHub stars | 1,000+ |
| Active contributors | 10+ |
| Community-contributed plugins | 5+ |
| Organizations using in production | 20+ |

---

## 21. Appendix A — MITRE Technique Inventory (MVP)

### Initial Access (TA0001) — 8 Techniques

| Technique ID | Name | Executor | Detection Feasibility |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Custom Python | High |
| T1133 | External Remote Services | Custom Python | High |
| T1078 | Valid Accounts | Custom Python | High |
| T1078.001 | Valid Accounts: Default Accounts | Custom Python | High |
| T1078.002 | Valid Accounts: Domain Accounts | Custom Python | High |
| T1078.003 | Valid Accounts: Local Accounts | Custom Python | High |
| T1566.001 | Phishing: Spearphishing Attachment | Custom Python | Medium |
| T1566.002 | Phishing: Spearphishing Link | Custom Python | Medium |

### Execution (TA0002) — 10 Techniques

| Technique ID | Name | Executor | Detection Feasibility |
|---|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Custom Python | High |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Custom Python | High |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Custom Python | High |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | Custom Python | Medium |
| T1047 | Windows Management Instrumentation | Custom Python | High |
| T1569.001 | System Services: Launch Agent | Custom Python | Medium |
| T1569.002 | System Services: Service Execution | Custom Python | High |
| T1204.001 | User Execution: Malicious Link | Custom Python | Medium |
| T1204.002 | User Execution: Malicious File | Custom Python | Medium |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Custom Python | High |

### Persistence (TA0003) — 8 Techniques

| Technique ID | Name | Executor | Detection Feasibility |
|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Custom Python | High |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Custom Python | High |
| T1547.004 | Boot or Logon Autostart Execution: Winlogon Helper DLL | Custom Python | Medium |
| T1546.001 | Event Triggered Execution: Change Default File Association | Custom Python | Medium |
| T1546.003 | Event Triggered Execution: Windows Management Instrumentation | Custom Python | Medium |
| T1546.008 | Event Triggered Execution: Accessibility Features | Custom Python | High |
| T1136.001 | Create Account: Local Account | Custom Python | High |
| T1136.002 | Create Account: Domain Account | Custom Python | High |

### Privilege Escalation (TA0004) — 8 Techniques

| Technique ID | Name | Executor | Detection Feasibility |
|---|---|---|---|
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | Custom Python | Medium |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Custom Python | High |
| T1068 | Exploitation for Privilege Escalation | Custom Python | Medium |
| T1543.003 | Create or Modify System Process: Windows Service | Custom Python | High |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Custom Python | High |
| T1134.002 | Access Token Manipulation: Create Process with Token | Custom Python | High |
| T1484.001 | Domain Policy Modification: Group Policy Modification | Custom Python | High |
| T1055.001 | Process Injection: Dynamic-link Library Injection | Custom Python | Medium |

### Credential Access (TA0006) — 8 Techniques

| Technique ID | Name | Executor | Detection Feasibility |
|---|---|---|---|
| T1558.001 | Steal or Forge Kerberos Tickets: Kerberoasting | Custom Python | High |
| T1558.002 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Custom Python | High |
| T1110.001 | Brute Force: Password Guessing | Custom Python | High |
| T1110.003 | Brute Force: Password Spraying | Custom Python | High |
| T1552.001 | Unsecured Credentials: Credentials in Files | Custom Python | High |
| T1552.002 | Unsecured Credentials: Credentials in Registry | Custom Python | High |
| T1003.001 | OS Credential Dumping: LSASS Memory | Custom Python | High |
| T1003.002 | OS Credential Dumping: Security Account Manager | Custom Python | High |

---

## 22. Appendix B — JSON Report Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PurpleStrike Simulation Report",
  "type": "object",
  "required": ["simulation_id", "timestamp", "mode", "target_group", "results", "summary", "remediation"],
  "properties": {
    "simulation_id": { "type": "string", "pattern": "^sim_\\d{8}_\\d{6}$" },
    "timestamp": { "type": "string", "format": "date-time" },
    "mode": { "type": "string", "enum": ["agent", "playbook"] },
    "target_group": { "type": "string" },
    "llm_provider": { "type": "string" },
    "siem_connector": { "type": "string" },
    "status": { "type": "string", "enum": ["completed", "partial", "aborted", "failed"] },
    "plan": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "total_steps": { "type": "integer" }
      }
    },
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["step", "technique_id", "technique_name", "tactic", "target", "execution_status", "detection_result", "risk"],
        "properties": {
          "step": { "type": "integer" },
          "technique_id": { "type": "string" },
          "technique_name": { "type": "string" },
          "tactic": { "type": "string" },
          "target": { "type": "string" },
          "execution_status": { "type": "string", "enum": ["success", "failure", "timeout", "skipped"] },
          "execution_time_seconds": { "type": "number" },
          "detection_result": { "type": "string", "enum": ["detected", "partially_detected", "not_detected", "unknown"] },
          "detection_confidence": { "type": "number", "minimum": 0, "maximum": 1 },
          "matched_rules": { "type": "array", "items": { "type": "string" } },
          "matched_alerts": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "alert_id": { "type": "string" },
                "timestamp": { "type": "string", "format": "date-time" },
                "rule_id": { "type": "string" },
                "description": { "type": "string" }
              }
            }
          },
          "ai_correlation_reasoning": { "type": ["string", "null"] },
          "risk": {
            "type": "object",
            "properties": {
              "vulnerability_score": { "type": "number", "minimum": 0, "maximum": 1 },
              "threat_event_frequency": { "type": "number" },
              "loss_magnitude": { "type": "number" },
              "annualized_loss_expectancy": { "type": "number" }
            }
          }
        }
      }
    },
    "summary": {
      "type": "object",
      "required": ["total_techniques", "detected", "partially_detected", "not_detected", "detection_rate", "total_annualized_risk"],
      "properties": {
        "total_techniques": { "type": "integer" },
        "detected": { "type": "integer" },
        "partially_detected": { "type": "integer" },
        "not_detected": { "type": "integer" },
        "unknown": { "type": "integer" },
        "detection_rate": { "type": "number", "minimum": 0, "maximum": 1 },
        "total_annualized_risk": { "type": "number" },
        "risk_by_tactic": {
          "type": "object",
          "additionalProperties": { "type": "number" }
        }
      }
    },
    "remediation": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["technique_id", "current_detection"],
        "properties": {
          "technique_id": { "type": "string" },
          "current_detection": { "type": "string" },
          "wazuh_remediation": {
            "type": "object",
            "properties": {
              "confidence": { "type": "string", "enum": ["high", "medium", "low"] },
              "rule_xml": { "type": "string" },
              "decoder_xml": { "type": ["string", "null"] },
              "log_sources_required": { "type": "array", "items": { "type": "string" } },
              "testing_instructions": { "type": "string" }
            }
          },
          "generic_guidance": {
            "type": "object",
            "properties": {
              "data_sources": { "type": "array", "items": { "type": "string" } },
              "detection_logic": { "type": "string" },
              "false_positive_considerations": { "type": "string" },
              "references": { "type": "array", "items": { "type": "string" } }
            }
          }
        }
      }
    },
    "metadata": {
      "type": "object",
      "properties": {
        "purplestrike_version": { "type": "string" },
        "mitre_attack_version": { "type": "string" },
        "execution_duration_seconds": { "type": "number" },
        "cleanup_status": { "type": "string", "enum": ["success", "partial", "failed"] },
        "cleanup_warnings": { "type": "array", "items": { "type": "string" } }
      }
    }
  }
}
```

---

## 23. Appendix C — CSV Report Schema

### File 1: `sim_<id>_results.csv`

```csv
step,technique_id,technique_name,tactic,target,execution_status,execution_time_seconds,detection_result,detection_confidence,matched_rule_ids,vulnerability_score,threat_event_frequency,loss_magnitude,annualized_loss_expectancy,risk_level
1,T1018,Remote System Discovery,TA0001,dc01.corp.local,success,12.3,detected,1.0,100001,0.05,52,50000,130000,low
2,T1087.001,Local Account Discovery,TA0002,ws01.corp.local,success,8.1,not_detected,0.0,,0.90,12,550000,5940000,high
```

### File 2: `sim_<id>_remediation.csv`

```csv
technique_id,technique_name,detection_result,remediation_confidence,suggested_rule_ids,log_sources_required,generic_detection_logic
T1087.001,Local Account Discovery,not_detected,high,100201,"Windows Security Event Log;Sysmon","Monitor for user enumeration commands (net user, net localgroup) via Event 4798/4799 and Sysmon EID 1"
```

---

## 24. Appendix D — Wazuh API Endpoints Used

| Endpoint | Method | Purpose | Parameters |
|---|---|---|---|
| `GET /alerts` | GET | Query alerts in time window | `time_from`, `time_to`, `rule.id`, `agent.id`, `limit`, `offset` |
| `GET /rules` | GET | List all rules with MITRE mappings | `limit`, `offset` |
| `GET /rules/{rule_id}` | GET | Get specific rule definition | — |
| `GET /decoders` | GET | List decoder definitions | `limit`, `offset` |
| `GET /decoders/{decoder_name}` | GET | Get specific decoder | — |
| `GET /cluster/status` | GET | Check Wazuh cluster health | — |
| `GET /manager/status` | GET | Check manager daemon status | — |
| `GET /agents` | GET | List enrolled agents (verify target coverage) | `limit`, `offset` |

**Authentication:** Wazuh API uses basic auth (username:password) with JWT token generation. PurpleStrike authenticates once at startup and refreshes the token as needed.

**Rate Limiting:** Wazuh API has built-in rate limiting. PurpleStrike respects rate limit headers and implements backoff.

---

## 25. Appendix E — Financial Risk Model Details

### E.1 Vulnerability Score Derivation

| Detection Result | Vulnerability Score | Rationale |
|---|---|---|
| DETECTED | 0.05 | Residual 5% for evasion, alert fatigue, or misconfiguration |
| PARTIALLY DETECTED | 0.40 | Attacker may evade partial coverage with technique variation |
| NOT DETECTED | 0.90 | Attacker has near-certain chance of going undetected |
| UNKNOWN | 0.50 | Cannot determine; assume 50/50 |

### E.2 Threat Event Frequency Defaults

| Technique ID | Technique Name | Annual Frequency | Source Rationale |
|---|---|---|---|
| T1190 | Exploit Public-Facing App | 4 | Quarterly based on external-facing exploit campaigns |
| T1078 | Valid Accounts | 52 | Weekly — credential compromise is pervasive |
| T1566 | Phishing | 52 | Weekly — phishing is the #1 initial access vector |
| T1059.001 | PowerShell | 52 | Weekly — most common execution method |
| T1059.003 | CMD | 52 | Weekly — ubiquitous |
| T1047 | WMI | 26 | Bi-weekly — common for lateral movement |
| T1053.005 | Scheduled Task | 26 | Bi-weekly — common persistence mechanism |
| T1547.001 | Registry Run Keys | 12 | Monthly — common persistence |
| T1548.002 | Bypass UAC | 12 | Monthly — common priv esc |
| T1068 | Exploit for Priv Esc | 4 | Quarterly — less frequent but high impact |
| T1558.001 | Kerberoasting | 12 | Monthly — common in AD attacks |
| T1558.002 | AS-REP Roasting | 8 | Bi-monthly |
| T1110.001 | Password Guessing | 26 | Bi-weekly |
| T1110.003 | Password Spraying | 12 | Monthly |
| T1003.001 | LSASS Memory | 12 | Monthly — common credential theft |
| T1003.002 | SAM Database | 8 | Bi-monthly |
| T1552.001 | Credentials in Files | 12 | Monthly |
| T1552.002 | Credentials in Registry | 8 | Bi-monthly |
| T1136.001 | Create Local Account | 8 | Bi-monthly |
| T1136.002 | Create Domain Account | 4 | Quarterly |
| T1055.001 | Dynamic-link Library Injection | 8 | Bi-monthly |
| T1134.001 | Token Impersonation | 12 | Monthly |
| T1134.002 | Create Process with Token | 8 | Bi-monthly |
| T1484.001 | Group Policy Modification | 4 | Quarterly |

*All frequencies are configurable via `~/.purplestrike/risk_parameters.yaml`*

### E.3 Loss Magnitude Defaults

| Technique Category | Primary Loss | Secondary Loss (Low) | Secondary Loss (Moderate) | Secondary Loss (High) | Default Total |
|---|---|---|---|---|---|
| Initial Access | $15K | $50K | $200K | $1M | $215K |
| Execution | $10K | $25K | $100K | $500K | $110K |
| Persistence | $15K | $50K | $200K | $1M | $215K |
| Privilege Escalation | $25K | $100K | $500K | $2M | $525K |
| Credential Access | $50K | $200K | $500K | $5M | $550K |

*Secondary loss is selected based on asset value (configurable per target group).*

### E.4 Asset Value Multipliers

| Asset Type | Multiplier | Example |
|---|---|---|
| Domain Controller | 3.0x | dc01.corp.local |
| Critical Server (DB, App) | 2.0x | sql01.corp.local |
| Standard Server | 1.5x | file01.corp.local |
| Workstation | 1.0x | ws01.corp.local |

### E.5 Industry Multipliers

| Industry | Multiplier |
|---|---|
| Healthcare | 1.5x |
| Financial Services | 2.0x |
| Government | 1.5x |
| Technology | 1.2x |
| Retail | 1.0x |
| Other | 1.0x |

---

*End of PRD — PurpleStrike v1.0*
