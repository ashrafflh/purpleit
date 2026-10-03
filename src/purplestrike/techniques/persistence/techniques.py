from purplestrike.models.techniques import (
    DetectionMapping,
    TacticID,
    Technique,
    TechniqueParameter,
)

PERSISTENCE_TECHNIQUES = [
    Technique(
        technique_id="T1053.005p",
        mitre_technique_id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task (Persistence)",
        tactic=TacticID.PERSISTENCE,
        description="Creates a scheduled task for persistence",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.scheduled_task",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100200",
                confidence="high",
                description="Detects scheduled task creation for persistence",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="task_name",
                description="Scheduled task name prefix; execution adds a unique suffix",
                type="string",
                required=True,
                default="PurpleStrikeTask",
            ),
            TechniqueParameter(
                name="command",
                description="Command to schedule",
                type="string",
                required=True,
                default="cmd.exe",
            ),
        ],
    ),
    Technique(
        technique_id="T1547.001",
        name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        tactic=TacticID.PERSISTENCE,
        description="Adds a registry run key for persistence",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.registry_run_keys",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100201",
                confidence="high",
                description="Detects registry run key modification",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="key_path",
                description="Registry key path",
                type="string",
                required=True,
                default="HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            TechniqueParameter(
                name="value_name",
                description="Registry value name prefix; each execution adds a unique suffix",
                default="PurpleStrike",
            ),
            TechniqueParameter(
                name="value",
                description="Registry value to set",
                type="string",
                required=True,
                default="cmd.exe /c echo PurpleStrike",
            ),
        ],
    ),
    Technique(
        technique_id="T1547.004",
        name="Boot or Logon Autostart Execution: Winlogon Helper DLL",
        tactic=TacticID.PERSISTENCE,
        description="Modifies Winlogon helper DLL for persistence",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.winlogon_helper",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100202",
                confidence="medium",
                description="Detects Winlogon registry modification",
            ),
        ],
    ),
    Technique(
        technique_id="T1546.001",
        name="Event Triggered Execution: Change Default File Association",
        tactic=TacticID.PERSISTENCE,
        description="Creates and invokes an isolated per-user file association",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.file_association",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100203",
                confidence="medium",
                description="Detects file association changes",
            ),
        ],
    ),
    Technique(
        technique_id="T1546.003",
        name="Event Triggered Execution: WMI Event Subscription",
        tactic=TacticID.PERSISTENCE,
        description="Creates a WMI event subscription for persistence",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.wmi_event_subscription",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100204",
                confidence="high",
                description="Detects WMI event subscription creation",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="event_query",
                description="WMI event query",
                type="string",
                required=True,
                default="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'notepad.exe'",
            ),
            TechniqueParameter(
                name="command",
                description="Benign command to execute on the process-start trigger",
                type="string",
                required=True,
                default=(
                    "cmd.exe /d /c echo PurpleStrike-T1546.003>"
                    "C:\\Windows\\Temp\\purplestrike_wmi_subscription.txt"
                ),
            ),
        ],
    ),
    Technique(
        technique_id="T1546.008",
        name="Event Triggered Execution: Accessibility Features",
        tactic=TacticID.PERSISTENCE,
        description="Uses a temporary IFEO debugger for an accessibility feature",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.accessibility_features",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100205",
                confidence="high",
                description="Detects accessibility feature IFEO hijacking",
            ),
        ],
    ),
    Technique(
        technique_id="T1136.001",
        name="Create Account: Local Account",
        tactic=TacticID.PERSISTENCE,
        description="Creates a local account for persistence",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="persistence.create_local_account",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100206", confidence="high", description="Detects local account creation"
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="username",
                description="Account username prefix; execution shortens it and adds a unique suffix",
                type="string",
                required=True,
                default="purplestrike_local",
            ),
        ],
    ),
    Technique(
        technique_id="T1136.002",
        name="Create Account: Domain Account",
        tactic=TacticID.PERSISTENCE,
        description="Creates a domain account for persistence",
        target_os=["windows"],
        executor="custom_python",
        module="persistence.create_domain_account",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100207", confidence="high", description="Detects domain account creation"
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="username",
                description="Domain username prefix; execution shortens it and adds a unique suffix",
                type="string",
                required=True,
                default="purplestrike_domain",
            ),
            TechniqueParameter(
                name="domain", description="Target domain", type="string", required=True
            ),
        ],
    ),
]
