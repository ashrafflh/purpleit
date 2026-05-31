<p align="center">
<h1 align="center">PurpleStrike</h1>
<p align="center"><strong>AI-Driven Breach & Attack Simulation for SIEM Detection Validation</strong></p>
</p>

---

## What is PurpleStrike?

PurpleStrike is an open-source, AI-driven Breach and Attack Simulation (BAS) platform that autonomously executes MITRE ATT&CK techniques against on-premises enterprise environments and validates whether your SIEM detects them. It answers the question:

> **"If an attacker executed technique X right now, would our SIEM alert us?"**

## Key Features

- **Autonomous AI Agent** — Plans and chains multi-stage attack paths using LLM reasoning (OpenAI, DeepSeek, Anthropic, Ollama, vLLM)
- **Pre-built Playbooks** — Run defined attack scenarios without AI planning
- **Hybrid Detection Validation** — Deterministic rule mapping + LLM-powered alert correlation for accurate detection checks
- **Financial Risk Quantification** — FAIR-inspired model translates detection gaps into dollar-value Annualized Loss Expectancy (ALE)
- **Actionable Remediation** — SIEM-specific Wazuh custom rule/decoder XML + generic detection guidance per gap
- **Plugin Architecture** — Extensible to any SIEM, any attack framework, any LLM provider
- **Safety Controls** — Plan-once-approval model, built-in safety constraints, automatic cleanup

## Supported Environments

- **Target:** On-premises enterprise (Active Directory, Windows, Linux)
- **SIEM:** Wazuh (v0.1), extensible to Splunk, Elastic, QRadar via plugin
- **Attack Libraries:** Custom Python modules, Atomic Red Team, Caldera, Sliver/Mythic (C2)

---

## Installation

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- A Wazuh manager with API access
- Target test environment (**NOT production**)
- LLM API key (OpenAI or Anthropic) or local Ollama instance

### Install from Source (Development)

```bash
# Clone the repository
git clone https://github.com/your-org/purplestrike.git
cd purplestrike

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

# Create virtual environment and install dependencies
uv sync

# Install with dev dependencies (linting, testing, type-checking)
uv sync --extra dev

# Install optional LLM providers
uv sync --extra openai        # OpenAI GPT-4o
uv sync --extra deepseek      # DeepSeek API
uv sync --extra anthropic     # Anthropic Claude
uv sync --extra ollama        # Ollama (local)
uv sync --extra all           # All optional dependencies

# Verify installation
uv run purplestrike version
```

### Install via pip

```bash
pip install purplestrike

# With optional providers
pip install purplestrike[openai]
pip install purplestrike[anthropic]
pip install purplestrike[all]
```

### Configure

```bash
# Interactive configuration wizard
purplestrike config init
```

Set environment variables (or use `.env` — copy from `.env.example`):

```env
# Target credentials
PURPLESTRIKE_TARGET_AD_DOMAIN=corp.local
PURPLESTRIKE_TARGET_USERNAME=attack_user
PURPLESTRIKE_TARGET_PASSWORD=<password>

# Wazuh SIEM
PURPLESTRIKE_WAZUH_API_URL=https://wazuh-manager:55000
PURPLESTRIKE_WAZUH_API_USER=admin
PURPLESTRIKE_WAZUH_API_PASSWORD=<password>
PURPLESTRIKE_WAZUH_API_TIMEOUT=30
# PurpleStrike logs into the Wazuh Dashboard and obtains a Wazuh API JWT from it
PURPLESTRIKE_WAZUH_DASHBOARD_URL=https://wazuh-dashboard
PURPLESTRIKE_WAZUH_DASHBOARD_API_ID=default

# LLM Provider (openai | deepseek | anthropic | ollama | vllm | nvidia)
PURPLESTRIKE_LLM_PROVIDER=openai
PURPLESTRIKE_OPENAI_API_KEY=<key>
PURPLESTRIKE_OPENAI_MODEL=gpt-4o
PURPLESTRIKE_DEEPSEEK_API_KEY=<key>
PURPLESTRIKE_DEEPSEEK_MODEL=deepseek-chat
```

Validate your configuration:

```bash
purplestrike config validate
purplestrike config show
```

---

## WinRM Setup (Kerberos-less, IP-based, NTLM)

This guide documents a working WinRM configuration for Windows 10/11 targets using:

- WinRM over HTTP (5985)
- NTLM authentication (Negotiate)
- IP-based targeting (no DNS required)
- TrustedHosts (required for NTLM over IP)
- No Kerberos, no CredSSP, no domain required

---

### Target Machine Setup (Windows 10/11)

Run all commands in **elevated PowerShell** on the target.

#### 1. Enable WinRM

```powershell
Enable-PSRemoting -Force
```

Or:

```powershell
winrm quickconfig -q
```

#### 2. Verify WinRM listener

```powershell
winrm enumerate winrm/config/listener
```

Expected output:

```
Transport = HTTP
Port = 5985
Address = *
```

If missing, re-run `winrm quickconfig`.

#### 3. Enable NTLM authentication

```powershell
winrm set winrm/config/service/auth '@{Kerberos="false"; Basic="false"; Negotiate="true"; CredSSP="false"}'
```

#### 4. Allow local account remote access (IMPORTANT for workgroup setups)

```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

#### 5. Ensure user is in Administrators group

```powershell
net localgroup administrators <username> /add
```

#### 6. Restart WinRM

```powershell
Restart-Service WinRM
```

---

### Client Machine Setup

Run in **elevated PowerShell** on the PurpleStrike client machine.

#### 1. Configure TrustedHosts (required for IP-based connections)

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.1.107" -Force
```

Verify:

```powershell
Get-Item WSMan:\localhost\Client\TrustedHosts
```

(Optional) Allow all hosts (lab only):

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

---

### Connectivity Tests

#### 1. Test WinRM service

```powershell
Test-WSMan 10.10.1.107
```

Expected: WSMan identity response.

#### 2. Test TCP connectivity

```powershell
Test-NetConnection 10.10.1.107 -Port 5985
```

Expected: `TcpTestSucceeded : True`

---

### Remote PowerShell Usage

Start interactive session:

```powershell
Enter-PSSession -ComputerName 10.10.1.107 -Authentication Negotiate -Credential Administrator
```

Run remote command:

```powershell
Invoke-Command -ComputerName 10.10.1.107 -Authentication Negotiate -Credential Administrator -ScriptBlock {
    whoami
}
```

---

### Python (pywinrm) Usage

```python
import winrm

session = winrm.Session(
    "10.10.1.107",
    auth=("Administrator", "password"),
    transport="ntlm",
)

result = session.run_ps("whoami")
print(result.status_code)
print(result.std_out.decode())
```

---

### Common Issues & Fixes

| Issue | Fix |
|---|---|
| **"Access is denied"** | Run on target: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f`. Ensure user is in Administrators group. |
| **WinRM connection fails** | Check `winrm quickconfig` on target and `Test-NetConnection <ip> -Port 5985` from client. |
| **TrustedHosts error** | Run on client: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<target-ip>" -Force` |

---

## Quick Start

```bash
# AI agent mode — agent plans and chains attacks
purplestrike run --mode agent --target-group production_win

# Playbook mode — run a pre-defined scenario
purplestrike run --mode playbook --playbook ad_credential_harvesting \
    --target-group production_win

# Dry-run — generate plan only, no execution
purplestrike plan --mode agent --target-group production_win

# Check what your SIEM covers
purplestrike siem rules --technique T1558.001
```

---

## CLI Reference

### Top-level Commands

| Command | Description |
|---|---|
| `purplestrike version` | Show version information |
| `purplestrike run` | Execute an attack simulation |
| `purplestrike plan` | Generate an attack plan without executing (dry-run) |
| `purplestrike config` | Manage configuration (init, show, set-value, validate) |
| `purplestrike techniques` | List and inspect MITRE ATT&CK techniques |
| `purplestrike siem` | SIEM connector management (test, rules) |
| `purplestrike playbooks` | List, show, and validate attack playbooks |

### `purplestrike run`

Execute an attack simulation against a target group.

```bash
purplestrike run \
    --target-group production_win \   # (required) target group from config
    --mode agent \                    # agent | playbook
    --playbook ad_credential_harvesting \  # playbook name (for playbook mode)
    --tactics TA0001,TA0002 \         # filter by MITRE tactic IDs
    --techniques T1558.001,T1059.001 \# filter by technique IDs
    --max-steps 20 \                  # max attack steps
    --detection-check-delay 30 \      # seconds to wait before querying SIEM
    --output-dir ./results \          # report output directory
    --format both \                   # json | csv | both
    --llm-provider openai \           # override LLM provider
    --skip-cleanup \                  # skip cleanup after execution
    --dry-run                         # generate plan only, no execution
```

### `purplestrike plan`

Generate an attack plan without executing it.

```bash
purplestrike plan \
    --target-group production_win \   # (required) target group from config
    --mode agent \                    # agent | playbook
    --playbook path/to/playbook.yaml\ # path to playbook YAML
    --tactics TA0001,TA0002 \         # filter by MITRE tactic IDs
    --output plan.yaml                # save plan to YAML file
```

### `purplestrike techniques`

List and inspect the 42 supported MITRE ATT&CK techniques.

```bash
# List all techniques
purplestrike techniques list

# Filter by tactic
purplestrike techniques list --tactic TA0006

# Show technique details, parameters, and detection mappings
purplestrike techniques show T1558.001
```

### `purplestrike siem`

Manage SIEM connectivity and inspect rules.

```bash
# Test SIEM connectivity
purplestrike siem test

# List all SIEM rules with MITRE mappings
purplestrike siem rules

# List rules for a specific technique
purplestrike siem rules --technique T1543.003
```

### `purplestrike config`

Manage PurpleStrike configuration.

```bash
# Interactive configuration wizard
purplestrike config init

# Display current configuration
purplestrike config show

# Set a configuration value (dot-notation)
purplestrike config set-value siem.api_url https://wazuh:55000
purplestrike config set-value siem.api_user admin
purplestrike config set-value siem.api_password
purplestrike config set-value siem.dashboard_url https://wazuh-dashboard

# Validate configuration
purplestrike config validate
```

### `purplestrike playbooks`

List, inspect, and validate attack playbooks.

```bash
# List available playbooks
purplestrike playbooks list

# Show playbook details and steps
purplestrike playbooks show ad_credential_harvesting

# Validate a playbook YAML file
purplestrike playbooks validate path/to/playbook.yaml
```

---

## How It Works

```
┌──────────────┐    ┌────────────────┐    ┌─────────────────┐
│ AI Agent /   │───▶│ Attack Plugin  │───▶│ Target Systems  │
│ Playbook     │    │ (Custom/ART/   │    │ (AD, Win, Linux)│
│ Runner       │    │  Caldera/C2)   │    │                 │
└──────────────┘    └────────────────┘    └────────┬────────┘
                                                   │
                                                   ▼
                         ┌────────────────────────────────────────┐
                         │      Detection Validation Engine      │
                         │  ┌──────────────┐ ┌───────────────┐   │
                         │  │ Rule-Based   │ │ AI Alert      │   │
                         │  │ Mapper       │ │ Correlator    │   │
                         │  └──────────────┘ └───────────────┘   │
                         │       SIEM Connector (Wazuh)          │
                         └──────────────────┬─────────────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────────┐
                         │  Risk Quantifier + Remediation Engine  │
                         │       JSON / CSV Report Output         │
                         └────────────────────────────────────────┘
```

1. **Plan** — AI agent or playbook generates an attack plan (technique chain)
2. **Approve** — Operator reviews and approves the plan before execution
3. **Execute** — Attack techniques are executed against target systems
4. **Validate** — After each step + after full campaign, query Wazuh for alerts
5. **Quantify** — Calculate financial risk (ALE) for undetected techniques
6. **Remediate** — Generate Wazuh custom rules + generic detection guidance for gaps
7. **Report** — Output JSON + CSV with full results, risk scores, and remediation

---

## MITRE ATT&CK Coverage

| Version | Tactics | Techniques |
|---|---|---|
| v0.1 (MVP) | Initial Access, Execution, Persistence, Privilege Escalation, Credential Access | 42 |
| v0.2 | + Defense Evasion, Lateral Movement | ~67 |
| v0.3 | + Collection, Exfiltration, C2 | ~87 |
| v1.0 | Full on-prem coverage | ~132 |

### Technique Breakdown (v0.1 — 42 Techniques)

| Tactic | ID | Techniques |
|---|---|---|
| Initial Access (TA0001) | T1190, T1133, T1078.001–003, T1566.001–002 | 8 |
| Execution (TA0002) | T1059.001–005, T1047, T1569.001–002, T1204.001–002, T1053.005 | 11 |
| Persistence (TA0003) | T1053.005p, T1547.001, T1547.004, T1546.001, T1546.003, T1546.008, T1136.001–002 | 8 |
| Privilege Escalation (TA0004) | T1548.001–002, T1068, T1543.003, T1134.001–002, T1484.001, T1055.001 | 7 |
| Credential Access (TA0006) | T1558.001–002, T1110.001–003, T1552.001–002, T1003.001–002 | 8 |

---

## Architecture

PurpleStrike uses a **plugin-based modular architecture** with four plugin types:

| Plugin | Purpose | Built-in Implementations |
|---|---|---|
| **Attack Executor** | Execute techniques on target systems | Custom Python (SSH/WinRM) |
| **SIEM Connector** | Query alerts and rules from SIEM | Wazuh |
| **LLM Provider** | Power agent reasoning and alert correlation | OpenAI, DeepSeek, Anthropic, Ollama, vLLM |
| **Report Formatter** | Generate output reports | JSON, CSV |

All plugin types follow Python `Protocol` interfaces (runtime-checkable) and are loaded by the `PluginLoader` from built-in packages or user plugin directories (`~/.purplestrike/plugins/`).

---

## Project Structure

```
purplestrike/
├── src/purplestrike/
│   ├── __init__.py              # Package version
│   ├── cli/                     # CLI commands (Typer + Rich)
│   │   ├── app.py               # Top-level CLI app & command registration
│   │   ├── config.py            # config init / show / set-value / validate
│   │   ├── plan.py              # plan — dry-run attack plan generation
│   │   ├── run.py               # run — execute simulation
│   │   ├── techniques.py        # techniques list / show
│   │   ├── siem.py              # siem test / rules
│   │   └── playbooks.py         # playbooks list / show / validate
│   ├── core/                    # Core orchestration & AI agent
│   │   ├── orchestrator.py      # Top-level simulation coordinator
│   │   ├── agent_loop.py        # LLM-driven attack plan generation
│   │   └── plan.py              # AttackPlan & AttackPlanStep models
│   ├── models/                  # Pydantic data models
│   │   ├── config.py            # PurpleStrikeConfig, TargetGroup, RiskParameters
│   │   ├── techniques.py        # Technique, DetectionMapping, TechniqueParameter
│   │   ├── simulation.py        # Simulation, SimulationStep, DetectionResult, RiskResult
│   │   ├── remediation.py       # RemediationEntry, WazuhRemediation, GenericGuidance
│   │   └── report.py            # SimulationReport, SimulationSummary
│   ├── techniques/              # MITRE ATT&CK technique definitions
│   │   ├── registry.py          # TechniqueRegistry with lazy auto-loading
│   │   ├── initial_access/      # 8 techniques (T1190, T1133, T1078.x, T1566.x)
│   │   ├── execution/           # 11 techniques (T1059.x, T1047, T1569.x, T1204.x)
│   │   ├── persistence/         # 8 techniques (T1053.005p, T1547.x, T1546.x, T1136.x)
│   │   ├── privilege_escalation/# 7 techniques (T1548.x, T1068, T1543.003, T1134.x, T1055.001)
│   │   └── credential_access/   # 8 techniques (T1558.x, T1110.x, T1552.x, T1003.x)
│   ├── validation/              # Detection validation engine
│   │   └── engine.py            # Hybrid rule-based mapper + AI alert correlator
│   ├── risk/                    # Financial risk quantification
│   │   └── quantifier.py        # FAIR-inspired ALE calculation
│   ├── remediation/             # Remediation & guidance engine
│   │   └── engine.py            # Wazuh XML rule DB + generic guidance fallback
│   ├── reporting/               # Report storage
│   │   └── store.py             # SQLite simulation store
│   └── plugins/                 # Plugin system
│       ├── protocols.py         # AttackExecutor, SIEMConnector, LLMProvider, ReportFormatter
│       ├── registry.py          # PluginRegistry singleton
│       ├── loader.py            # Builtin + user plugin discovery & loading
│       ├── attack_executors/
│       │   └── custom_python/   # Dynamic module loading executor
│       ├── siem_connectors/
│       │   └── wazuh/           # Wazuh API client (auth, alerts, rules)
│       ├── llm_providers/
│       │   ├── openai_provider.py   # OpenAI with retry logic
│       │   ├── anthropic_provider.py# Anthropic with retry logic
│       │   ├── ollama_provider.py   # Ollama local inference
│       │   └── vllm_provider.py     # vLLM local inference
│       └── report_formatters/
│           ├── json_fmt.py          # JSON report output
│           └── csv_fmt.py           # CSV report output
├── tests/                       # Test suite
├── playbooks/                   # Built-in attack playbooks (YAML)
├── pyproject.toml               # Project config (hatchling, deps, ruff, mypy, pytest)
├── .env.example                 # Environment variable template
├── PRD.md                       # Full Product Requirements Document
├── README.md                    # This file
└── TODO.md                      # Development task tracker
```

---

## Code Documentation

### Core Modules

#### Orchestrator (`core/orchestrator.py`)

The `Orchestrator` is the top-level coordinator for every simulation run. It:

- Generates attack plans via AI agent or playbook parsing
- Displays the plan for operator approval (plan-once-approval safety model)
- Executes each plan step via the configured attack executor
- Validates detection after each step (with configurable delay for SIEM ingestion)
- Calculates financial risk (ALE) for undetected techniques
- Generates remediation guidance (Wazuh rules + generic)
- Outputs reports (JSON + CSV) to the configured directory

```python
from purplestrike.core.orchestrator import Orchestrator
from purplestrike.models.config import PurpleStrikeConfig

config = PurpleStrikeConfig()
orchestrator = Orchestrator(config=config)
report = await orchestrator.execute(
    mode="agent",
    target_group_name="production_win",
    tactics=["TA0006"],
    technique_ids=["T1558.001"],
)
```

#### Agent Loop (`core/agent_loop.py`)

The `AgentLoop` uses an LLM provider to generate realistic, chained attack plans. It:

- Builds a prompt with available techniques, target context, and safety constraints
- Parses the LLM's JSON response into an `AttackPlan`
- Filters out unsafe techniques (`safe_to_execute=True` only)
- Falls back to default technique selection if the LLM fails

#### Detection Validation Engine (`validation/engine.py`)

Hybrid detection validation with two layers:

1. **Rule-Based Mapper** — Checks if expected SIEM rule IDs appear in alerts (exact match)
2. **AI Alert Correlator** — Uses LLM to analyze alert semantics when rule-based matching fails

Returns `DetectionResult` with status (`detected` / `partially_detected` / `not_detected` / `unknown`), confidence score, matched rules, and AI reasoning.

#### Risk Quantifier (`risk/quantifier.py`)

FAIR-inspired financial risk model:

- **Threat Event Frequency (TEF)** — How often the technique occurs per year (per-technique defaults, configurable)
- **Detection Vulnerability Score** — 0.05 (detected) / 0.5 (partial) / 0.95 (not detected)
- **Loss Magnitude** — Per-tactic dollar impact (e.g., Credential Access = $550k)
- **ALE** = TEF x Vulnerability Score x Loss Magnitude

#### Remediation Engine (`remediation/engine.py`)

For every undetected technique, generates:

- **Wazuh-specific remediation** — Custom Wazuh rule XML (with MITRE tag), log source requirements, and testing instructions. Built-in database covers 6 key techniques (T1558.001, T1558.002, T1003.001, T1003.002, T1110.001, T1110.003)
- **Generic guidance** — Data sources, detection logic, false positive considerations, and MITRE references for all 42 techniques

#### Simulation Store (`reporting/store.py`)

SQLite-backed persistent storage for simulation results. Schema includes:

- `simulations` — Run metadata, detection summary, total ALE
- `simulation_steps` — Per-step execution and detection results
- `remediations` — Generated remediation entries per simulation

### Plugin System

All plugins implement `Protocol` interfaces defined in `plugins/protocols.py`:

| Protocol | Methods |
|---|---|
| `AttackExecutor` | `setup()`, `execute()`, `cleanup()`, `teardown()` |
| `SIEMConnector` | `setup()`, `query_alerts()`, `get_rule()`, `get_rules_for_technique()`, `teardown()` |
| `LLMProvider` | `setup()`, `complete()`, `complete_structured()`, `teardown()` |
| `ReportFormatter` | `setup()`, `format()`, `teardown()` |

The `PluginLoader` discovers and loads:
- **Built-in plugins** — From `purplestrike.plugins.*` packages
- **User plugins** — From `~/.purplestrike/plugins/` directory

Naming convention: snake_case module name → PascalCase class name + suffix (e.g., `custom_python` → `CustomPythonExecutor`)

### Technique Registry

The `TechniqueRegistry` uses lazy auto-loading (`_ensure_loaded()`) to avoid circular imports at module level. Techniques are defined as `TechniqueDefinition` instances in per-tactic modules and registered on first access.

```python
from purplestrike.techniques.registry import technique_registry

# List all 42 techniques
all_techniques = technique_registry.list_techniques()

# Get a specific technique
t = technique_registry.get_technique("T1558.001")
print(t.name, t.detection_mappings, t.parameters)
```

### Data Models

All data models use Pydantic v2 with strict validation:

| Module | Key Models |
|---|---|
| `models/config.py` | `PurpleStrikeConfig`, `TargetGroup`, `TargetHost`, `SIEMConfig`, `LLMConfig`, `RiskParameters` |
| `models/techniques.py` | `Technique`, `DetectionMapping`, `TechniqueParameter`, `TacticID` |
| `models/simulation.py` | `Simulation`, `SimulationStep`, `DetectionResult`, `RiskResult`, `SIEMAlert`, `SIEMRule` |
| `models/remediation.py` | `RemediationEntry`, `WazuhRemediation`, `GenericGuidance`, `RemediationConfidence` |
| `models/report.py` | `SimulationReport`, `SimulationSummary` |

---

## Development

### Setup

```bash
# Clone and enter the project
git clone https://github.com/your-org/purplestrike.git
cd purplestrike

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

# Install all dependencies (including dev)
uv sync --extra dev

# Verify
uv run purplestrike version
```

### Linting & Formatting

```bash
# Run ruff linter
uv run ruff check src/

# Auto-fix safe issues
uv run ruff check --fix src/

# Run ruff formatter
uv run ruff format src/

# Line length: 100 (configured in pyproject.toml)
# Rule set: E, F, I, N, W, UP, B, A, SIM, RUF
```

### Type Checking

```bash
# Run mypy (strict mode)
uv run mypy src/

# Config: python_version = "3.11", strict = true
# Ignored: pywinrm.*, asyncssh.*, ollama.*
```

### Testing

```bash
# Run all tests
uv run pytest

# With coverage (minimum 80%)
uv run pytest --cov

# Verbose with short tracebacks
uv run pytest -v --tb=short

# Config: asyncio_mode = "auto", testpaths = ["tests"]
```

### Dependency Management

```bash
# Add a core dependency
uv add <package>

# Add an optional dependency group
uv add --optional <group> <package>

# Add a dev dependency
uv add --dev <package>

# Current optional groups:
#   openai, anthropic, ollama, ssh, winrm, all, dev
```

### Project Configuration

All tool configuration lives in `pyproject.toml`:

| Tool | Settings |
|---|---|
| **Build** | hatchling, `packages = ["src/purplestrike"]` |
| **Ruff** | target py311, line-length 100, strict rule set |
| **Mypy** | strict mode, py311, warn_return_any |
| **Pytest** | asyncio auto mode, 80% coverage minimum |

---

## Safety

- **Plan approval required** — No execution without operator approval
- **No data exfiltration** — Data access is simulated, not real
- **No data destruction** — Destructive techniques are dry-run only
- **No denial of service** — Brute-force is rate-limited
- **Automatic cleanup** — All artifacts, scheduled tasks, and implants are removed post-run
- **Emergency stop** — `Ctrl+C` for graceful shutdown, double-tap for immediate abort

---

## Documentation

- [PRD.md](./PRD.md) — Full Product Requirements Document (architecture, data models, APIs, risk model)
- [TODO.md](./TODO.md) — Development task tracker

## Contributing

Contributions are welcome. Plugin development is the primary extension point — see the plugin interfaces in [PRD.md](./PRD.md) to get started.

## License

MIT

## Disclaimer

PurpleStrike is intended **exclusively for authorized security testing**. Only use it against environments you own or have explicit written permission to test. Unauthorized use is illegal. The authors assume no liability for misuse.
