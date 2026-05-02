<p align="center">
  <h1 align="center">PurpleStrike</h1>
  <p align="center"><strong>AI-Driven Breach & Attack Simulation for SIEM Detection Validation</strong></p>
</p>

---

## What is PurpleStrike?

PurpleStrike is an open-source, AI-driven Breach and Attack Simulation (BAS) platform that autonomously executes MITRE ATT&CK techniques against on-premises enterprise environments and validates whether your SIEM detects them. It answers the question:

> **"If an attacker executed technique X right now, would our SIEM alert us?"**

## Key Features

- **Autonomous AI Agent** — Plans and chains multi-stage attack paths using LLM reasoning (OpenAI, Anthropic, Ollama, vLLM)
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

## Quick Start

### Prerequisites

- Python 3.11+
- A Wazuh manager with API access
- Target test environment (NOT production)
- LLM API key (OpenAI or Anthropic) or local Ollama instance

### Install

```bash
pip install purplestrike
```

### Configure

```bash
purplestrike config init
```

Set environment variables (or use `.env`):

```env
# Target credentials
PURPLESTRIKE_TARGET_AD_DOMAIN=corp.local
PURPLESTRIKE_TARGET_USERNAME=attack_user
PURPLESTRIKE_TARGET_PASSWORD=<password>

# Wazuh SIEM
PURPLESTRIKE_WAZUH_API_URL=https://wazuh-manager:55000
PURPLESTRIKE_WAZUH_API_USER=purplestrike
PURPLESTRIKE_WAZUH_API_PASSWORD=<password>

# LLM Provider
PURPLESTRIKE_LLM_PROVIDER=openai
PURPLESTRIKE_OPENAI_API_KEY=<key>
```

### Run

```bash
# AI agent mode — agent plans and chains attacks
purplestrike run --mode agent --target-group production_win

# Playbook mode — run a pre-defined scenario
purplestrike run --mode playbook --playbook ad_credential_harvesting --target-group production_win

# Dry-run — generate plan only, no execution
purplestrike plan --mode agent --target-group production_win

# Check what your SIEM covers
purplestrike siem rules --technique T1558.001
```

## How It Works

```
┌──────────────┐     ┌────────────────┐     ┌─────────────────┐
│  AI Agent /  │────▶│  Attack Plugin │────▶│  Target Systems │
│  Playbook    │     │  (Custom/ART/  │     │  (AD, Win, Linux│
│  Runner      │     │   Caldera/C2)  │     │                 │
└──────────────┘     └────────────────┘     └────────┬────────┘
                                                      │
                                                      ▼
                     ┌────────────────────────────────────────┐
                     │       Detection Validation Engine      │
                     │  ┌──────────────┐  ┌───────────────┐  │
                     │  │ Rule-Based   │  │ AI Alert      │  │
                     │  │ Mapper       │  │ Correlator    │  │
                     │  └──────────────┘  └───────────────┘  │
                     │         SIEM Connector (Wazuh)         │
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

## MITRE ATT&CK Coverage

| Version | Tactics | Techniques |
|---|---|---|
| v0.1 (MVP) | Initial Access, Execution, Persistence, Privilege Escalation, Credential Access | 42 |
| v0.2 | + Defense Evasion, Lateral Movement | ~67 |
| v0.3 | + Collection, Exfiltration, C2 | ~87 |
| v1.0 | Full on-prem coverage | ~132 |

## Architecture

PurpleStrike uses a **plugin-based modular architecture** with four plugin types:

| Plugin | Purpose |
|---|---|
| **Attack Executor** | Execute techniques via Custom Python, Atomic Red Team, Caldera, or C2 |
| **SIEM Connector** | Query alerts and rules from Wazuh (extensible to any SIEM) |
| **LLM Provider** | Power agent reasoning via OpenAI, Anthropic, Ollama, or vLLM |
| **Report Formatter** | Generate JSON, CSV, or custom output formats |

See [PRD.md](./PRD.md) for full architecture details, plugin interfaces, and design specifications.

## Safety

- **Plan approval required** — No execution without operator approval
- **No data exfiltration** — Data access is simulated, not real
- **No data destruction** — Destructive techniques are dry-run only
- **No denial of service** — Brute-force is rate-limited
- **Automatic cleanup** — All artifacts, scheduled tasks, and implants are removed post-run
- **Emergency stop** — `Ctrl+C` for graceful shutdown, double-tap for immediate abort

## Project Structure

```
purplestrike/
├── src/
│   └── purplestrike/
│       ├── cli/                  # CLI commands (Typer)
│       ├── core/                 # Orchestrator, Agent Loop, Playbook Runner
│       ├── engine/               # Technique Execution Engine
│       ├── validation/           # Detection Validation Engine
│       ├── risk/                 # Financial Risk Quantification
│       ├── remediation/          # Remediation & Guidance Engine
│       ├── reporting/            # JSON/CSV Report Generator
│       ├── plugins/              # Built-in plugins
│       │   ├── attack_executors/ # Custom Python, ART, Caldera, Sliver
│       │   ├── siem_connectors/  # Wazuh connector
│       │   ├── llm_providers/    # OpenAI, Anthropic, Ollama, vLLM
│       │   └── report_formatters/# JSON, CSV formatters
│       └── models/               # Pydantic data models
├── playbooks/                    # Built-in attack playbooks
├── tests/
├── PRD.md
├── README.md
└── TODO.md
```

## Documentation

- [PRD.md](./PRD.md) — Full Product Requirements Document (architecture, data models, APIs, risk model)
- [TODO.md](./TODO.md) — Development task tracker

## Contributing

Contributions are welcome. Plugin development is the primary extension point — see the plugin interfaces in [PRD.md §7](./PRD.md) to get started.

## License

TBD

## Disclaimer

PurpleStrike is intended **exclusively for authorized security testing**. Only use it against environments you own or have explicit written permission to test. Unauthorized use is illegal. The authors assume no liability for misuse.
