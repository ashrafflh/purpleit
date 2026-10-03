from purplestrike.models.techniques import (
    DetectionMapping,
    TacticID,
    Technique,
    TechniqueParameter,
)

EXECUTION_TECHNIQUES = [
    Technique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic=TacticID.EXECUTION,
        description="Executes commands via PowerShell",
        target_os=["windows"],
        executor="custom_python",
        module="execution.powershell",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100100",
                confidence="high",
                description="Detects suspicious PowerShell execution",
            ),
            DetectionMapping(
                rule_id="91815",
                confidence="medium",
                description="Wazuh detects process discovery executed through PowerShell",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="command",
                description="PowerShell command to execute",
                type="string",
                required=True,
                default="Write-Output 'PurpleStrike PowerShell simulation'",
            ),
            TechniqueParameter(
                name="encoded", description="Use encoded command", type="boolean", default=False
            ),
        ],
    ),
    Technique(
        technique_id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        tactic=TacticID.EXECUTION,
        description="Executes commands via cmd.exe",
        target_os=["windows"],
        executor="custom_python",
        module="execution.cmd_shell",
        risk_level="low",
        detection_mappings=[
            DetectionMapping(
                rule_id="100101",
                confidence="high",
                description="Detects suspicious cmd.exe execution",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="command",
                description="Command to execute",
                type="string",
                required=True,
                default="echo PurpleStrike cmd simulation",
            ),
        ],
    ),
    Technique(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic=TacticID.EXECUTION,
        description="Executes commands through a Unix shell (Bash on the built-in Linux runner)",
        target_os=["linux"],
        executor="custom_python",
        module="execution.bash",
        risk_level="low",
        detection_mappings=[
            DetectionMapping(
                rule_id="100102",
                confidence="high",
                description="Detects suspicious Unix shell execution",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="command",
                description="Unix shell command to execute",
                type="string",
                required=True,
                default="echo PurpleStrike shell simulation",
            ),
        ],
    ),
    Technique(
        technique_id="T1059.005",
        name="Command and Scripting Interpreter: Visual Basic",
        tactic=TacticID.EXECUTION,
        description="Executes commands via Visual Basic",
        target_os=["windows"],
        executor="custom_python",
        module="execution.visual_basic",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100103",
                confidence="medium",
                description="Detects VBScript or VBA execution",
            ),
        ],
    ),
    Technique(
        technique_id="T1047",
        name="Windows Management Instrumentation",
        tactic=TacticID.EXECUTION,
        description="Uses WMI for remote command execution",
        target_os=["windows"],
        executor="custom_python",
        module="execution.wmi",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100104", confidence="high", description="Detects WMI remote execution"
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="command",
                description="WMI command to execute",
                type="string",
                required=True,
                default="whoami",
            ),
        ],
    ),
    Technique(
        technique_id="T1569.003",
        name="System Services: Systemctl",
        tactic=TacticID.EXECUTION,
        description="Executes a benign command through a temporary systemd service on Linux",
        target_os=["linux"],
        executor="custom_python",
        module="execution.launch_agent",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100105",
                confidence="medium",
                description="Detects suspicious systemd unit creation and systemctl execution",
            ),
        ],
    ),
    Technique(
        technique_id="T1569.002",
        name="System Services: Service Execution",
        tactic=TacticID.EXECUTION,
        description="Executes commands via Windows services",
        target_os=["windows"],
        executor="custom_python",
        module="execution.service_execution",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100106",
                confidence="high",
                description="Detects suspicious service creation or modification",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="service_name",
                description="Service name to create/modify",
                type="string",
                required=True,
                default="PurpleStrikeSvc",
            ),
            TechniqueParameter(
                name="command",
                description="Command the service will execute",
                type="string",
                required=True,
                default="whoami",
            ),
        ],
    ),
    Technique(
        technique_id="T1204.001",
        name="User Execution: Malicious Link",
        tactic=TacticID.EXECUTION,
        description="Opens a reserved-domain URL through the registered Windows protocol handler",
        target_os=["windows"],
        executor="custom_python",
        module="execution.malicious_link",
        risk_level="low",
        safe_to_execute=True,
        detection_mappings=[
            DetectionMapping(
                rule_id="100107",
                confidence="low",
                description="Detects suspicious browser or URL activity",
            ),
        ],
    ),
    Technique(
        technique_id="T1204.002",
        name="User Execution: Malicious File",
        tactic=TacticID.EXECUTION,
        description="Creates and launches a benign script-shaped file and verifies execution",
        target_os=["windows"],
        executor="custom_python",
        module="execution.malicious_file",
        risk_level="low",
        safe_to_execute=True,
        detection_mappings=[
            DetectionMapping(
                rule_id="100108",
                confidence="medium",
                description="Detects suspicious file execution",
            ),
        ],
    ),
    Technique(
        technique_id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic=TacticID.EXECUTION,
        description="Creates a scheduled task for execution",
        target_os=["windows"],
        executor="custom_python",
        module="execution.scheduled_task",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100109", confidence="high", description="Detects scheduled task creation"
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="task_name",
                description="Scheduled task name",
                type="string",
                required=True,
                default="PurpleStrikeTask",
            ),
            TechniqueParameter(
                name="command",
                description="Command to schedule",
                type="string",
                required=True,
                default="whoami",
            ),
        ],
    ),
]
