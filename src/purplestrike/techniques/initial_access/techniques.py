from purplestrike.models.techniques import (
    DetectionMapping,
    TacticID,
    Technique,
    TechniqueParameter,
)

INITIAL_ACCESS_TECHNIQUES = [
    Technique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=TacticID.INITIAL_ACCESS,
        description="Sends a bounded exploit canary to a configured lab web application",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="initial_access.exploit_public_app",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100001",
                confidence="medium",
                description="Detects exploitation attempts against public-facing services",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="target_port",
                description="Target port to exploit",
                type="integer",
                required=True,
                default=80,
            ),
            TechniqueParameter(
                name="exploit_module",
                description="Exploit module to use",
                type="string",
                required=True,
                default="generic_probe",
            ),
            TechniqueParameter(
                name="request_path",
                description="Bounded HTTP exploit-canary path",
                type="string",
                default="/purplestrike/%2e%2e/%2e%2e/etc/passwd?canary=T1190",
            ),
        ],
    ),
    Technique(
        technique_id="T1133",
        name="External Remote Services",
        tactic=TacticID.INITIAL_ACCESS,
        description="Exercises the configured remote service and records session evidence",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="initial_access.external_remote_services",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100002",
                confidence="medium",
                description="Detects suspicious remote service logins",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="service_type",
                description=(
                    "Expected external service context "
                    "(auto, vpn, rdp, citrix, ssh, winrm)"
                ),
                type="string",
                required=True,
                default="auto",
            ),
        ],
    ),
    Technique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic=TacticID.INITIAL_ACCESS,
        description="Uses valid credentials to gain initial access to systems",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="initial_access.valid_accounts",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100003",
                confidence="high",
                description="Detects authentication with valid credentials from unusual sources",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="account_type",
                description="Account type (domain, local, default)",
                type="string",
                default="domain",
            ),
        ],
    ),
    Technique(
        technique_id="T1078.001",
        name="Valid Accounts: Default Accounts",
        tactic=TacticID.INITIAL_ACCESS,
        description="Enumerates predefined accounts and their enabled state",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="initial_access.default_accounts",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100004", confidence="high", description="Detects use of default accounts"
            ),
        ],
    ),
    Technique(
        technique_id="T1078.002",
        name="Valid Accounts: Domain Accounts",
        tactic=TacticID.INITIAL_ACCESS,
        description="Enumerates domain accounts using the configured directory identity",
        target_os=["windows"],
        executor="custom_python",
        module="initial_access.domain_accounts",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100005",
                confidence="high",
                description="Detects domain account authentication anomalies",
            ),
        ],
    ),
    Technique(
        technique_id="T1078.003",
        name="Valid Accounts: Local Accounts",
        tactic=TacticID.INITIAL_ACCESS,
        description="Enumerates local accounts and their enabled state",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="initial_access.local_accounts",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100006",
                confidence="high",
                description="Detects local account authentication anomalies",
            ),
        ],
    ),
    Technique(
        technique_id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic=TacticID.INITIAL_ACCESS,
        description="Stages a benign attachment marker; no email transport is included",
        target_os=["windows"],
        executor="custom_python",
        module="initial_access.phishing_attachment",
        risk_level="medium",
        safe_to_execute=True,
        detection_mappings=[
            DetectionMapping(
                rule_id="100007",
                confidence="low",
                description="Detects phishing-related file artifacts",
            ),
        ],
    ),
    Technique(
        technique_id="T1566.002",
        name="Phishing: Spearphishing Link",
        tactic=TacticID.INITIAL_ACCESS,
        description="Stages a benign URL marker; no email transport is included",
        target_os=["windows"],
        executor="custom_python",
        module="initial_access.phishing_link",
        risk_level="medium",
        safe_to_execute=True,
        detection_mappings=[
            DetectionMapping(
                rule_id="100008",
                confidence="low",
                description="Detects phishing-related URL artifacts",
            ),
        ],
    ),
]
