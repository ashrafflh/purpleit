# PurpleStrike — Development TODO

Comprehensive task list derived from [PRD.md](./PRD.md). Tasks are organized by phase and component.

---

## Legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete

---

## Phase 1: Foundation (v0.1.0) — MVP

### 1.1 Project Scaffolding & Infrastructure

- [ ] Initialize Python project with `pyproject.toml` (setuptools/hatchling)
- [ ] Set up project directory structure (`src/purplestrike/` layout)
- [ ] Configure `ruff` linter and `mypy` type checker
- [ ] Set up `pytest` with `pytest-asyncio` for async test support
- [ ] Set up `pre-commit` hooks (ruff, mypy, pytest)
- [ ] Create `.env.example` with all required environment variables
- [ ] Create `.gitignore` (`.env`, `__pycache__/`, `*.db`, `results/`, etc.)
- [ ] Set up CI pipeline (GitHub Actions) — lint, typecheck, test

### 1.2 CLI Framework

- [ ] Implement CLI entry point using `typer` with rich console output
- [ ] Implement `purplestrike version` command
- [ ] Implement `purplestrike config init` — interactive config wizard
- [ ] Implement `purplestrike config show` — display current config
- [ ] Implement `purplestrike config set <key> <value>` — set config values
- [ ] Implement `purplestrike config validate` — validate configuration
- [ ] Add config file loading (`~/.purplestrike/config.yaml`)
- [ ] Add environment variable loading (`.env` support via `python-dotenv`)
- [ ] Add rich progress display during simulation execution (step status, detection results)

### 1.3 Configuration System

- [ ] Define `PurpleStrikeConfig` Pydantic model (target groups, SIEM, LLM, risk params)
- [ ] Implement target group configuration (hosts, OS, credentials ref, asset type)
- [ ] Implement SIEM connector configuration (Wazuh API URL, credentials ref)
- [ ] Implement LLM provider configuration (provider name, model, API key ref, base URL)
- [ ] Implement risk parameter defaults (threat frequencies, loss magnitudes, asset multipliers)
- [ ] Support config overrides from CLI flags
- [ ] Validate all required env vars at startup before execution

### 1.4 Plugin System

- [ ] Define `AttackExecutor` protocol (setup, execute, cleanup, teardown)
- [ ] Define `SIEMConnector` protocol (setup, query_alerts, get_rule, get_rules_for_technique, teardown)
- [ ] Define `LLMProvider` protocol (setup, complete, complete_structured, teardown)
- [ ] Define `ReportFormatter` protocol (format)
- [ ] Implement plugin discovery and loading (built-in + `~/.purplestrike/plugins/` + `./plugins/`)
- [ ] Implement plugin registry (name → plugin class mapping)
- [ ] Implement plugin configuration injection (each plugin receives its config section)
- [ ] Write unit tests for plugin loader

### 1.5 Core Orchestrator

- [ ] Implement `Orchestrator` class — top-level coordinator
- [ ] Implement execution flow: init → plan → approve → execute → validate → report
- [ ] Implement step-by-step sequential execution with state tracking
- [ ] Implement graceful shutdown on `Ctrl+C` (SIGINT handler)
- [ ] Implement emergency stop on double `Ctrl+C` (immediate abort)
- [ ] Implement SIGTERM handler for graceful shutdown
- [ ] Implement post-simulation cleanup orchestration (call each executor's cleanup)
- [ ] Implement partial result generation on abort/failure

### 1.6 Agent Loop (AI-Driven Planning)

- [ ] Implement `AgentLoop` class with context builder
- [ ] Design and implement system prompt template for adversary emulation planner
- [ ] Implement target context serialization (OS, domain, services, credentials, network)
- [ ] Implement available techniques list serialization for LLM context
- [ ] Implement execution history tracking and serialization for LLM context
- [ ] Implement plan generation via LLM (`complete_structured` with Plan Pydantic schema)
- [ ] Implement adaptive re-planning (on step failure, query LLM for alternative technique)
- [ ] Implement max-steps limit enforcement
- [ ] Implement safety constraint injection into LLM prompts (no destruction, no exfil, no DoS)

### 1.7 LLM Provider Plugins

- [ ] Implement `OpenAIProvider` (GPT-4o, GPT-4-turbo) with `complete` and `complete_structured`
- [ ] Implement `AnthropicProvider` (Claude 3.5 Sonnet, Claude 3 Opus)
- [ ] Implement `OllamaProvider` (local models via Ollama API)
- [ ] Implement `vLLMProvider` (local models via vLLM server)
- [ ] Implement retry logic with exponential backoff (3 attempts: 2s, 4s, 8s)
- [ ] Implement provider selection logic (env var `PURPLESTRIKE_LLM_PROVIDER` or config)
- [ ] Write unit tests with mocked LLM responses for each provider

### 1.8 Playbook Runner

- [ ] Implement `PlaybookRunner` class
- [ ] Define and validate playbook YAML schema (Pydantic model: steps, technique_id, executor, parameters)
- [ ] Implement playbook loading from `~/.purplestrike/playbooks/`, `./playbooks/`, built-in
- [ ] Implement `purplestrike playbooks list` command
- [ ] Implement `purplestrike playbooks show <name>` command
- [ ] Implement `purplestrike playbooks validate <path>` command
- [ ] Create 3-5 built-in playbooks for common AD attack scenarios
- [ ] Write unit tests for playbook loading and validation

### 1.9 Execution Strategy (Plan Approval)

- [ ] Implement plan display formatter (technique list, targets, risk level, estimated time)
- [ ] Implement approval prompt (`[y/n/e(edit)]`)
- [ ] Implement edit mode — open plan YAML in `$EDITOR`, save, re-validate, confirm
- [ ] Implement plan validation (check technique IDs exist, targets are in group, parameters are valid)
- [ ] Implement `--dry-run` flag support (generate + display plan, no execution)

### 1.10 Technique Execution Engine

- [ ] Implement `TechniqueExecutionEngine` — dispatches technique to appropriate `AttackExecutor` plugin
- [ ] Implement technique registry — map technique IDs to available executors
- [ ] Implement per-step timeout enforcement
- [ ] Implement step result capture (success/failure/output/artifacts/execution_time)
- [ ] Implement step state tracking (pending → running → completed/failed/timeout)
- [ ] Implement `purplestrike techniques list` command (with `--tactic` filter)
- [ ] Implement `purplestrike techniques show <id>` command (details + detection mapping)

### 1.11 Custom Python Attack Executor Plugin

- [ ] Implement `CustomPythonExecutor` plugin class
- [ ] Design technique module structure (each technique = Python module with `execute`, `cleanup` functions)
- [ ] Implement remote execution via SSH (Linux targets) using `asyncssh`
- [ ] Implement remote execution via WinRM/PowerShell Remoting (Windows targets) using `pywinrm`
- [ ] Implement WMI remote execution (Windows targets)
- [ ] Implement agent-based execution (deploy lightweight implant, receive commands)
- [ ] Design implant communication protocol (mTLS, command queue)
- [ ] Build implant binary (Python-based, compiled with Nuitka or similar)

### 1.12 Built-in Attack Technique Modules (61 scenarios)

#### Initial Access (TA0001) — 8 techniques

- [ ] T1190 — Exploit Public-Facing Application
- [ ] T1133 — External Remote Services
- [ ] T1078 — Valid Accounts
- [ ] T1078.001 — Valid Accounts: Default Accounts
- [ ] T1078.002 — Valid Accounts: Domain Accounts
- [ ] T1078.003 — Valid Accounts: Local Accounts
- [ ] T1566.001 — Phishing: Spearphishing Attachment (simulated)
- [ ] T1566.002 — Phishing: Spearphishing Link (simulated)

#### Execution (TA0002) — 10 techniques

- [ ] T1059.001 — PowerShell
- [ ] T1059.003 — Windows Command Shell
- [ ] T1059.004 — Unix Shell
- [ ] T1059.005 — Visual Basic
- [ ] T1047 — Windows Management Instrumentation
- [ ] T1569.001 — Launch Agent
- [ ] T1569.002 — Service Execution
- [ ] T1204.001 — User Execution: Malicious Link (simulated)
- [ ] T1204.002 — User Execution: Malicious File (simulated)
- [ ] T1053.005 — Scheduled Task

#### Persistence (TA0003) — 8 techniques

- [ ] T1053.005 — Scheduled Task/Job: Scheduled Task
- [ ] T1547.001 — Registry Run Keys
- [ ] T1547.004 — Winlogon Helper DLL
- [ ] T1546.001 — Change Default File Association
- [ ] T1546.003 — WMI Event Subscription
- [ ] T1546.008 — Accessibility Features
- [ ] T1136.001 — Create Account: Local Account
- [ ] T1136.002 — Create Account: Domain Account

#### Privilege Escalation (TA0004) — 8 techniques

- [ ] T1548.001 — Setuid and Setgid
- [ ] T1548.002 — Bypass User Account Control
- [ ] T1068 — Exploitation for Privilege Escalation
- [ ] T1543.003 — Create or Modify System Process: Windows Service
- [ ] T1134.001 — Token Impersonation/Theft
- [ ] T1134.002 — Create Process with Token
- [ ] T1484.001 — Group Policy Modification
- [ ] T1055.001 — Process Injection: Dynamic-link Library Injection

#### Credential Access (TA0006) — 8 techniques

- [ ] T1558.001 — Kerberoasting
- [ ] T1558.002 — AS-REP Roasting
- [ ] T1110.001 — Password Guessing
- [ ] T1110.003 — Password Spraying
- [ ] T1552.001 — Credentials in Files
- [ ] T1552.002 — Credentials in Registry
- [ ] T1003.001 — LSASS Memory
- [ ] T1003.002 — Security Account Manager

#### Stealth (TA0005) — 4 techniques

- [x] T1027.018 — Obfuscated Files or Information: Invisible Unicode
- [x] T1684 — Social Engineering
- [x] T1684.001 — Social Engineering: Impersonation
- [x] T1684.002 — Social Engineering: Email Spoofing

#### Defense Impairment (TA0112) — 15 techniques

- [x] T1685 and T1685.001–006 — Disable or Modify Tools
- [x] T1686 and T1686.001–003 — Disable or Modify System Firewall
- [x] T1687 — Exploitation for Defense Impairment
- [x] T1688 — Safe Mode Boot
- [x] T1689 — Downgrade Attack
- [x] T1690 — Prevent Command History Logging

### 1.13 Wazuh SIEM Connector Plugin

- [ ] Implement `WazuhConnector` plugin class
- [ ] Implement Wazuh API authentication (basic auth → JWT token)
- [ ] Implement JWT token refresh logic
- [ ] Implement `query_alerts` — `GET /alerts` with time window, rule ID, agent ID filters
- [ ] Implement `get_rule` — `GET /rules/{rule_id}`
- [ ] Implement `get_rules_for_technique` — `GET /rules` filtered by MITRE technique ID
- [ ] Implement `GET /decoders` — retrieve decoder definitions
- [ ] Implement `GET /cluster/status` — verify Wazuh cluster health
- [ ] Implement `GET /agents` — list enrolled agents for target coverage verification
- [ ] Implement `GET /manager/status` — verify manager daemon is running
- [ ] Implement Wazuh API rate limit handling and backoff
- [ ] Implement `purplestrike siem test` — connectivity check command
- [ ] Implement `purplestrike siem rules` — list rules with MITRE mappings command
- [ ] Write integration tests against Wazuh API (mocked + live test suite)

### 1.14 Detection Validation Engine

- [ ] Implement `DetectionValidationEngine` class
- [ ] Implement per-step detection check flow (execute → wait delay → query SIEM → classify)
- [ ] Implement configurable detection check delay (default 30s)
- [ ] Implement `RuleBasedMapper` — match technique IDs to Wazuh rule IDs
- [ ] Implement MITRE → Wazuh rule mapping table (pre-loaded from Wazuh API `mitre.id` fields)
- [ ] Implement user-extensible mapping override file (`~/.purplestrike/wazuh_rule_mapping.yaml`)
- [ ] Implement `AIAlertCorrelator` — LLM-based alert correlation for unmapped results
- [ ] Implement correlator prompt template (conservative: only flag clear matches)
- [ ] Implement detection result classification: DETECTED / PARTIALLY_DETECTED / NOT_DETECTED / UNKNOWN
- [ ] Implement post-campaign detection correlation check (full window query)
- [ ] Write unit tests with mocked SIEM responses for each detection outcome
- [ ] Write integration tests for end-to-end validation flow

### 1.15 Financial Risk Quantification

- [ ] Implement `RiskQuantifier` class
- [ ] Implement vulnerability score derivation from detection result (0.05/0.40/0.90/0.50)
- [ ] Implement threat event frequency lookup (default table + user overrides from `risk_parameters.yaml`)
- [ ] Implement loss magnitude calculation (primary + secondary loss by technique category)
- [ ] Implement asset value multiplier application (DC=3x, critical=2x, standard=1.5x, workstation=1x)
- [ ] Implement industry multiplier application (configurable)
- [ ] Implement ALE calculation per technique: `TEF × Vulnerability × LossMagnitude`
- [ ] Implement total ALE aggregation across all undetected techniques
- [ ] Implement risk level classification (critical/high/medium/low thresholds)
- [ ] Implement risk-by-tactic breakdown
- [ ] Write unit tests verifying ALE calculations against known examples

### 1.16 Remediation Engine

- [ ] Implement `RemediationEngine` class
- [ ] Build remediation database — per-technique Wazuh custom rule XML
- [ ] Build remediation database — per-technique Wazuh decoder XML (where needed)
- [ ] Build remediation database — per-technique log source requirements
- [ ] Build remediation database — per-technique generic detection guidance (data sources, logic, FP considerations)
- [ ] Implement remediation confidence classification (high/medium/low)
- [ ] Implement Wazuh-specific remediation formatter (copy-paste-ready XML blocks)
- [ ] Implement generic guidance formatter
- [ ] Implement testing instructions generator per remediation
- [ ] Write unit tests for remediation output formatting

### 1.17 Report Generator (JSON/CSV)

- [ ] Define `SimulationReport` Pydantic model (full report data structure)
- [ ] Implement `JSONFormatter` plugin — write full JSON report
- [ ] Validate JSON report against JSON Schema (Appendix B of PRD)
- [ ] Implement `CSVFormatter` plugin — write `sim_<id>_results.csv`
- [ ] Implement `CSVFormatter` plugin — write `sim_<id>_remediation.csv`
- [ ] Implement `--output-dir` handling (create dir if not exists, write files)
- [ ] Implement `--format` flag (json / csv / both)
- [ ] Write unit tests for report output (schema validation, field completeness)

### 1.18 SQLite Storage

- [ ] Implement SQLite database initialization (schema creation)
- [ ] Implement `simulations` table CRUD
- [ ] Implement `simulation_steps` table CRUD
- [ ] Implement `remediations` table CRUD
- [ ] Implement database path configuration (`PURPLESTRIKE_DB_PATH` or default `~/.purplestrike/purplestrike.db`)
- [ ] Write unit tests for database operations

### 1.19 `purplestrike run` Command Integration

- [ ] Wire CLI `run` command to Orchestrator
- [ ] Implement `--mode agent` flow (agent loop → plan → approve → execute → validate → report)
- [ ] Implement `--mode playbook` flow (playbook load → approve → execute → validate → report)
- [ ] Implement `--target-group` loading from config
- [ ] Implement `--tactics` and `--techniques` filtering
- [ ] Implement `--max-steps` enforcement
- [ ] Implement `--skip-cleanup` flag
- [ ] Implement `--llm-provider` override
- [ ] Implement real-time CLI progress output (step status, detection results, summary)

### 1.20 `purplestrike plan` Command

- [ ] Implement `plan` command — generate plan without execution
- [ ] Implement `--output` flag to save plan as YAML
- [ ] Display plan in CLI with technique details, targets, risk assessment

### 1.21 End-to-End Integration & Testing

- [ ] Set up test AD lab environment (Windows Server DC + workstations + Linux)
- [ ] Set up Wazuh manager in test lab with agents enrolled on all targets
- [ ] Write end-to-end test: agent mode full simulation against lab
- [ ] Write end-to-end test: playbook mode full simulation against lab
- [ ] Write end-to-end test: detection validation accuracy (known rules fire correctly)
- [ ] Write end-to-end test: risk quantification (ALE values match manual calculation)
- [ ] Write end-to-end test: remediation output (Wazuh rules are valid XML)
- [ ] Write end-to-end test: cleanup verification (no artifacts remain on targets)
- [ ] Write end-to-end test: graceful shutdown and partial report generation
- [ ] Write end-to-end test: SIEM connection failure handling

### 1.22 Documentation & Release

- [ ] Write CLI usage documentation (all commands, all flags)
- [ ] Write plugin development guide (how to write a new SIEM connector, attack executor, LLM provider)
- [ ] Write deployment guide (prerequisites, config, first run)
- [ ] Write safety guidelines documentation
- [ ] Tag v0.1.0 release

---

## Phase 2: Expansion (v0.2.0)

### 2.1 Additional Attack Techniques

- [x] Implement ATT&CK v19 Stealth (TA0005) and Defense Impairment (TA0112) additions
- [ ] Add an authorized pre-compromise workflow for T1682 and T1683/T1683.001–002
- [ ] Implement ~10 Lateral Movement techniques (TA0008)
- [ ] Implement technique modules for new techniques

### 2.2 Atomic Red Team Integration

- [ ] Implement `AtomicRedTeamExecutor` plugin
- [ ] Implement Atomic Red Team test catalog download and caching
- [ ] Implement atomic test GUID → technique ID mapping
- [ ] Implement atomic test execution (PowerShell, Command Prompt, Bash)
- [ ] Implement input argument handling for atomic tests
- [ ] Write integration tests for ART executor

### 2.3 Enhanced AI Alert Correlator

- [ ] Implement multi-alert correlation (chain of alerts indicating multi-step attack)
- [ ] Implement attack chain reconstruction from SIEM alerts
- [ ] Implement confidence calibration (compare AI correlator results vs. manual analyst on historical runs)

### 2.4 Remediation Lab (Auto-Deploy & Re-Validate)

- [ ] Implement auto-deploy of suggested Wazuh custom rules to a test Wazuh instance
- [ ] Implement re-run validation after rule deployment
- [ ] Implement before/after comparison report

### 2.5 Release

- [ ] Integration testing for all new techniques
- [ ] Tag v0.2.0 release

---

## Phase 3: Advanced (v0.3.0)

### 3.1 Additional Attack Techniques

- [ ] Implement ~10 Collection techniques (TA0009)
- [ ] Implement ~5 Exfiltration techniques (TA0010)
- [ ] Implement ~5 Command and Control techniques (TA0011)

### 3.2 Caldera Integration

- [ ] Implement `CalderaExecutor` plugin
- [ ] Implement Caldera API client (ability import, adversary profile, agent deployment)
- [ ] Implement technique mapping between Caldera abilities and MITRE IDs
- [ ] Write integration tests

### 3.3 Sliver/Mythic C2 Integration

- [ ] Implement `SliverExecutor` plugin
- [ ] Implement Sliver API client (session management, command execution)
- [ ] Implement `MythicExecutor` plugin
- [ ] Implement Mythic API client (callback creation, task submission)
- [ ] Write integration tests

### 3.4 Scheduled Execution

- [ ] Implement cron-style scheduling for recurring simulation runs
- [ ] Implement email notification on simulation completion
- [ ] Implement configurable notification templates

### 3.5 Regression Detection

- [ ] Implement cross-run result comparison
- [ ] Implement regression detection (previously-detected technique now missed)
- [ ] Implement regression alerting (email/notification on regression)

### 3.6 Release

- [ ] Integration testing for all new components
- [ ] Tag v0.3.0 release

---

## Phase 4: Full Coverage (v1.0.0)

### 4.1 Complete MITRE ATT&CK On-Prem Coverage

- [ ] Implement ~10 Discovery techniques (TA0007)
- [ ] Implement ~5 Impact techniques (TA0040)
- [ ] Implement remaining techniques for full on-prem coverage (~132 total)

### 4.2 Multi-SIEM Support

- [ ] Implement `SplunkConnector` plugin (Splunk REST API, SPL queries)
- [ ] Implement `ElasticConnector` plugin (Elasticsearch API, KQL/EQL queries)
- [ ] Implement `QRadarConnector` plugin (QRadar API, AQL queries)
- [ ] Implement SIEM-agnostic remediation fallback (generic guidance only when no SIEM-specific connector)
- [ ] Write integration tests for each SIEM connector

### 4.3 CI/CD Integration

- [ ] Implement GitHub Actions workflow template
- [ ] Implement GitLab CI pipeline template
- [ ] Implement exit code conventions (0 = all detected, 1 = gaps found, 2 = execution error)
- [ ] Document CI/CD integration guide

### 4.4 Containerization

- [ ] Create Dockerfile for PurpleStrike CLI
- [ ] Create Docker Compose stack (PurpleStrike + Wazuh + test targets)
- [ ] Publish container image to GitHub Container Registry

### 4.5 Optional: Web Dashboard

- [ ] Implement FastAPI server mode
- [ ] Implement REST API for simulation management
- [ ] Implement React/Vue web dashboard
- [ ] Implement MITRE ATT&CK heatmap visualization
- [ ] Implement detection trend charts
- [ ] Implement remediation tracking

### 4.6 Security Audit & Release

- [ ] Conduct security audit of credential handling
- [ ] Conduct security audit of implant communication
- [ ] Conduct penetration test of PurpleStrike itself
- [ ] Full regression test suite across all techniques and SIEM connectors
- [ ] Tag v1.0.0 release

---

## Cross-Cutting Tasks (All Phases)

### Testing

- [ ] Achieve ≥80% test coverage for v0.1
- [ ] Achieve ≥85% test coverage for v1.0
- [ ] Maintain <5% false positive rate in detection validation
- [ ] Verify 100% cleanup success rate (or flag warnings)

### Performance

- [ ] Profile and optimize Wazuh API query performance
- [ ] Implement parallel technique execution where safe (v0.2+)
- [ ] Target: full 61-scenario simulation in <30 minutes
- [ ] Target: full 61-scenario simulation in <15 minutes (v1.0 with parallel execution)

### Documentation

- [ ] Keep PRD.md updated as design evolves
- [ ] Keep TODO.md updated as tasks are completed
- [ ] Maintain CHANGELOG.md from v0.1 onward
- [ ] Write contributing guidelines (CONTRIBUTING.md)

### Community

- [ ] Set up GitHub Issues templates (bug report, feature request, plugin proposal)
- [ ] Set up GitHub Discussions for community support
- [ ] Write plugin development tutorial
- [ ] Target: 1,000+ GitHub stars within 6 months of v1.0
- [ ] Target: 5+ community-contributed plugins within 6 months of v1.0
