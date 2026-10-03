from purplestrike.models.techniques import (
    DetectionMapping,
    TacticID,
    Technique,
    TechniqueParameter,
)

CREDENTIAL_ACCESS_TECHNIQUES = [
    Technique(
        technique_id="T1558.003",
        name="Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Requests Kerberos service tickets for eligible user SPNs",
        target_os=["windows"],
        executor="custom_python",
        module="credential_access.kerberoasting",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100400",
                confidence="high",
                description=("Detects Kerberoasting — RC4 TGS ticket requests for SPN accounts"),
            ),
            DetectionMapping(
                rule_id="100401",
                confidence="medium",
                description="Detects suspicious Kerberos TGS request patterns",
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="tool",
                description="Tool to use (rubeus, invoke_kerberoast, powerview)",
                type="string",
                default="rubeus",
            ),
            TechniqueParameter(
                name="output_format",
                description="Hash output format (hashcat, john)",
                type="string",
                default="hashcat",
            ),
        ],
    ),
    Technique(
        technique_id="T1558.004",
        name="Steal or Forge Kerberos Tickets: AS-REP Roasting",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Enumerates accounts that do not require Kerberos preauthentication",
        target_os=["windows"],
        executor="custom_python",
        module="credential_access.asrep_roasting",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100402",
                confidence="high",
                description=(
                    "Detects AS-REP Roasting — AS-REQ without pre-auth for vulnerable accounts"
                ),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="tool",
                description="Tool to use (rubeus, getnpusers)",
                type="string",
                default="rubeus",
            ),
        ],
    ),
    Technique(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Attempts targeted password guessing against an account (rate-limited)",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="credential_access.password_guessing",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100403",
                confidence="high",
                description=("Detects password guessing — multiple authentication failures"),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="target_account",
                description="Account to target",
                type="string",
                required=True,
                default="Administrator",
            ),
            TechniqueParameter(
                name="password_list",
                description="Comma-separated candidate passwords (bounded by max_attempts)",
                type="string",
                default="PurpleStrikeInvalid123!",
            ),
            TechniqueParameter(
                name="max_attempts",
                description="Maximum attempts before stopping",
                type="integer",
                default=5,
            ),
        ],
    ),
    Technique(
        technique_id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Attempts a single password against many accounts (rate-limited)",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="credential_access.password_spraying",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100404",
                confidence="high",
                description=("Detects password spraying — same password across multiple accounts"),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="password",
                description="Password to spray",
                type="string",
                required=True,
                default="PurpleStrikeInvalid123!",
            ),
            TechniqueParameter(
                name="account_list",
                description="Comma-separated account names",
                type="string",
                required=True,
                default="Administrator",
            ),
            TechniqueParameter(
                name="delay_seconds",
                description="Delay between attempts",
                type="integer",
                default=10,
            ),
        ],
    ),
    Technique(
        technique_id="T1552.001",
        name="Unsecured Credentials: Credentials in Files",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Searches for credentials stored in files on the target system",
        target_os=["windows", "linux"],
        executor="custom_python",
        module="credential_access.credentials_in_files",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100405",
                confidence="high",
                description=("Detects credential file searches — suspicious file access patterns"),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="search_paths",
                description="Directories to search",
                type="string",
                default="C:\\Users;C:\\Temp",
            ),
            TechniqueParameter(
                name="file_patterns",
                description="File patterns to search for",
                type="string",
                default="*.txt;*.xml;*.config;*.ini",
            ),
        ],
    ),
    Technique(
        technique_id="T1552.002",
        name="Unsecured Credentials: Credentials in Registry",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Searches for credentials stored in the Windows Registry",
        target_os=["windows"],
        executor="custom_python",
        module="credential_access.credentials_in_registry",
        risk_level="medium",
        detection_mappings=[
            DetectionMapping(
                rule_id="100406",
                confidence="high",
                description=("Detects registry credential searches — suspicious registry access"),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="registry_paths",
                description="Registry paths to search",
                type="string",
                default="HKLM\\SOFTWARE;HKCU\\SOFTWARE",
            ),
        ],
    ),
    Technique(
        technique_id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Opens an LSASS read handle without reading or retaining credential material",
        target_os=["windows"],
        executor="custom_python",
        module="credential_access.lsass_dump",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100407",
                confidence="high",
                description=(
                    "Detects LSASS memory access — procdump, comsvcs, or direct memory read"
                ),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="method",
                description="Safe emulation method",
                type="string",
                default="handle_open",
            ),
        ],
    ),
    Technique(
        technique_id="T1003.002",
        name="OS Credential Dumping: Security Account Manager",
        tactic=TacticID.CREDENTIAL_ACCESS,
        description="Saves and removes a temporary SAM hive without extracting hashes",
        target_os=["windows"],
        executor="custom_python",
        module="credential_access.sam_dump",
        risk_level="high",
        detection_mappings=[
            DetectionMapping(
                rule_id="100408",
                confidence="high",
                description=("Detects SAM database access — registry hive read or shadow copy"),
            ),
        ],
        parameters=[
            TechniqueParameter(
                name="method",
                description="Dump method (registry, shadow_copy, mimikatz)",
                type="string",
                default="registry",
            ),
        ],
    ),
]
