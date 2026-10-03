from purplestrike.models.techniques import (
    DetectionMapping,
    TacticID,
    Technique,
    TechniqueParameter,
)

PRIV_ESC_TECHNIQUES = [
    Technique(
        technique_id="T1548.001",
        name="Abuse Elevation Control Mechanism: Setuid and Setgid",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Executes an allowlisted setuid utility to generate boundary telemetry",
        target_os=["linux"],
        executor="custom_python",
        module="privilege_escalation.setuid_setgid",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100300",
                confidence="medium",
                description="Detects suspicious setuid binary execution",
            ),
        ],
    ),
    Technique(
        technique_id="T1548.002",
        name="Abuse Elevation Control Mechanism: Bypass User Account Control",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Bypasses Windows UAC for privilege escalation",
        target_os=["windows"],
        executor="custom_python",
        module="privilege_escalation.bypass_uac",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100301", confidence="high", description="Detects UAC bypass attempts"
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="method", description="UAC bypass method", type="string", default="fodhelper"
            ),
        ],
    ),
    Technique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Enumerates prerequisites for a separately supplied escalation exploit",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="privilege_escalation.exploit_priv_esc",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100302",
                confidence="medium",
                description="Detects privilege escalation exploitation",
            ),
        ],
    ),
    Technique(
        technique_id="T1543.003",
        name="Create or Modify System Process: Windows Service",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Creates or modifies a Windows service for privilege escalation",
        target_os=["windows"],
        executor="custom_python",
        module="privilege_escalation.windows_service",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100303",
                confidence="high",
                description="Detects suspicious service creation/modification",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="service_name",
                description="Service name prefix; execution adds a unique suffix",
                type="string",
                required=True,
                default="PurpleStrikePrivEscSvc",
            ),
            TechniqueParameter(
                name="binary_path",
                description="Service binary path",
                type="string",
                required=True,
                default="C:\\Windows\\System32\\cmd.exe /c echo PurpleStrike",
            ),
        ],
    ),
    Technique(
        technique_id="T1134.001",
        name="Access Token Manipulation: Token Impersonation/Theft",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Enumerates processes and token prerequisites; does not steal a token",
        target_os=["windows"],
        executor="custom_python",
        module="privilege_escalation.token_impersonation",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100304",
                confidence="high",
                description="Detects token impersonation activity",
            ),
        ],
    ),
    Technique(
        technique_id="T1134.002",
        name="Access Token Manipulation: Create Process with Token",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Enumerates token privileges; does not create a process with another token",
        target_os=["windows"],
        executor="custom_python",
        module="privilege_escalation.create_process_with_token",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100305",
                confidence="high",
                description="Detects process creation with elevated token",
            ),
        ],
    ),
    Technique(
        technique_id="T1484.001",
        name="Domain Policy Modification: Group Policy Modification",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Enumerates Group Policy objects; does not modify a GPO",
        target_os=["windows"],
        executor="custom_python",
        module="privilege_escalation.gpo_modification",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100306", confidence="high", description="Detects Group Policy modification"
            ),
        ],
    ),
    Technique(
        technique_id="T1055.001",
        name="Process Injection: Dynamic-link Library Injection",
        tactic=TacticID.PRIVILEGE_ESCALATION,
        description="Enumerates an injection target; does not write remote process memory",
        target_os=["windows"],
        executor="custom_python",
        module="privilege_escalation.dll_injection",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100307", confidence="high", description="Detects DLL injection activity"
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="target_process",
                description="Target process name or PID",
                type="string",
                required=True,
                default="explorer",
            ),
            TechniqueParameter(
                name="dll_path",
                description="DLL to inject",
                type="string",
                required=True,
                default="C:\\Windows\\System32\\kernel32.dll",
            ),
        ],
    ),
]
