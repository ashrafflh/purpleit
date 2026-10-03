from __future__ import annotations

from dataclasses import dataclass

from purplestrike.models.techniques import ATTACK_VERSION, EmulationMode, Technique


@dataclass(frozen=True)
class AttackCatalogEntry:
    official_name: str
    version: str
    tactics: tuple[str, ...]
    detection_strategy_id: str
    analytic_ids: tuple[str, ...]
    log_sources: tuple[str, ...]


@dataclass(frozen=True)
class EmulationProfile:
    mode: EmulationMode
    procedure: str
    success_criteria: tuple[str, ...]
    limitation: str = ""


# Generated and reviewed against the official Enterprise ATT&CK v19.2 STIX bundle.
# Keep the ATT&CK object version separate from the overall ATT&CK release version.
ATTACK_CATALOG: dict[str, AttackCatalogEntry] = {
    "T1003.001": AttackCatalogEntry(
        "LSASS Memory",
        "1.5",
        ("credential-access",),
        "DET0363",
        ("AN1030",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1003.002": AttackCatalogEntry(
        "Security Account Manager",
        "1.1",
        ("credential-access",),
        "DET0085",
        ("AN0235",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1047": AttackCatalogEntry(
        "Windows Management Instrumentation",
        "1.6",
        ("execution",),
        "DET0364",
        ("AN1031",),
        ("WinEventLog:Sysmon", "WinEventLog:WMI"),
    ),
    "T1053.005": AttackCatalogEntry(
        "Scheduled Task",
        "1.8",
        ("execution", "persistence", "privilege-escalation"),
        "DET0441",
        ("AN1221",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1055.001": AttackCatalogEntry(
        "Dynamic-link Library Injection",
        "2.0",
        ("stealth", "privilege-escalation"),
        "DET0389",
        ("AN1095",),
        ("WinEventLog:Sysmon",),
    ),
    "T1059.001": AttackCatalogEntry(
        "PowerShell",
        "1.5",
        ("execution",),
        "DET0455",
        ("AN1252",),
        ("WinEventLog:PowerShell", "WinEventLog:Sysmon"),
    ),
    "T1059.003": AttackCatalogEntry(
        "Windows Command Shell",
        "1.5",
        ("execution",),
        "DET0202",
        ("AN0578",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1059.004": AttackCatalogEntry(
        "Unix Shell",
        "1.4",
        ("execution",),
        "DET0384",
        ("AN1081", "AN1082", "AN1083", "AN1084"),
        ("auditd:SYSCALL", "linux:osquery", "linux:syslog"),
    ),
    "T1059.005": AttackCatalogEntry(
        "Visual Basic",
        "1.5",
        ("execution",),
        "DET0076",
        ("AN0209", "AN0210", "AN0211"),
        ("WinEventLog:Sysmon",),
    ),
    "T1068": AttackCatalogEntry(
        "Exploitation for Privilege Escalation",
        "1.6",
        ("privilege-escalation",),
        "DET0514",
        ("AN1419", "AN1420", "AN1421", "AN1422"),
        ("auditd:SYSCALL", "WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1078": AttackCatalogEntry(
        "Valid Accounts",
        "3.0",
        ("stealth", "persistence", "privilege-escalation", "initial-access"),
        "DET0560",
        ("AN1543", "AN1544", "AN1545", "AN1546", "AN1547"),
        ("WinEventLog:Security", "WinEventLog:Sysmon", "linux:auth"),
    ),
    "T1078.001": AttackCatalogEntry(
        "Default Accounts",
        "2.0",
        ("stealth", "persistence", "privilege-escalation", "initial-access"),
        "DET0465",
        ("AN1283", "AN1284", "AN1285", "AN1286", "AN1287"),
        ("WinEventLog:Security", "auditd:USER_LOGIN"),
    ),
    "T1078.002": AttackCatalogEntry(
        "Domain Accounts",
        "2.0",
        ("stealth", "persistence", "privilege-escalation", "initial-access"),
        "DET0210",
        ("AN0590", "AN0591", "AN0592", "AN0593"),
        ("WinEventLog:Security", "WinEventLog:Sysmon", "linux:syslog"),
    ),
    "T1078.003": AttackCatalogEntry(
        "Local Accounts",
        "2.0",
        ("stealth", "persistence", "privilege-escalation", "initial-access"),
        "DET0407",
        ("AN1137", "AN1138", "AN1139"),
        ("WinEventLog:Security", "linux:auth", "auditd:USER_LOGIN"),
    ),
    "T1110.001": AttackCatalogEntry(
        "Password Guessing",
        "1.7",
        ("credential-access",),
        "DET0551",
        ("AN1521", "AN1522", "AN1523", "AN1524", "AN1525", "AN1526"),
        ("WinEventLog:Security", "linux:syslog"),
    ),
    "T1110.003": AttackCatalogEntry(
        "Password Spraying",
        "1.8",
        ("credential-access",),
        "DET0487",
        ("AN1336", "AN1337", "AN1338", "AN1339", "AN1340", "AN1341", "AN1342", "AN1343"),
        ("WinEventLog:Security", "linux:syslog"),
    ),
    "T1133": AttackCatalogEntry(
        "External Remote Services",
        "2.5",
        ("persistence", "initial-access"),
        "DET0354",
        ("AN1004", "AN1005", "AN1006", "AN1007"),
        ("WinEventLog:Security", "WinEventLog:Sysmon", "auditd:SYSCALL", "NSM:Flow"),
    ),
    "T1134.001": AttackCatalogEntry(
        "Token Impersonation/Theft",
        "2.0",
        ("stealth", "privilege-escalation"),
        "DET0482",
        ("AN1324",),
        ("ETW:Token", "WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1134.002": AttackCatalogEntry(
        "Create Process with Token",
        "2.0",
        ("stealth", "privilege-escalation"),
        "DET0456",
        ("AN1253",),
        ("ETW:ProcThread", "WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1136.001": AttackCatalogEntry(
        "Local Account",
        "1.5",
        ("persistence",),
        "DET0447",
        ("AN1235", "AN1236", "AN1237", "AN1238", "AN1239", "AN1240"),
        ("WinEventLog:Security", "WinEventLog:Sysmon", "auditd:SYSCALL"),
    ),
    "T1136.002": AttackCatalogEntry(
        "Domain Account",
        "1.1",
        ("persistence",),
        "DET0003",
        ("AN0006", "AN0007", "AN0008"),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1190": AttackCatalogEntry(
        "Exploit Public-Facing Application",
        "2.8",
        ("initial-access",),
        "DET0080",
        ("AN0219", "AN0220", "AN0221", "AN0222", "AN0223", "AN0224", "AN0225"),
        ("ApplicationLog:WebServer", "ApplicationLog:IIS", "NSM:Flow"),
    ),
    "T1204.001": AttackCatalogEntry(
        "Malicious Link",
        "1.2",
        ("execution",),
        "DET0066",
        ("AN0178", "AN0179", "AN0180"),
        ("WinEventLog:Security", "WinEventLog:Sysmon", "NSM:Flow"),
    ),
    "T1204.002": AttackCatalogEntry(
        "Malicious File",
        "1.6",
        ("execution",),
        "DET0294",
        ("AN0819", "AN0820", "AN0821"),
        ("WinEventLog:Sysmon",),
    ),
    "T1484.001": AttackCatalogEntry(
        "Group Policy Modification",
        "2.0",
        ("defense-impairment", "privilege-escalation"),
        "DET0305",
        ("AN0854",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1543.003": AttackCatalogEntry(
        "Windows Service",
        "1.6",
        ("persistence", "privilege-escalation"),
        "DET0552",
        ("AN1527",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1546.001": AttackCatalogEntry(
        "Change Default File Association",
        "1.1",
        ("privilege-escalation", "persistence"),
        "DET0061",
        ("AN0170",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1546.003": AttackCatalogEntry(
        "Windows Management Instrumentation Event Subscription",
        "1.5",
        ("privilege-escalation", "persistence"),
        "DET0086",
        ("AN0236",),
        ("WinEventLog:Sysmon", "WinEventLog:WMI"),
    ),
    "T1546.008": AttackCatalogEntry(
        "Accessibility Features",
        "1.2",
        ("privilege-escalation", "persistence"),
        "DET0033",
        ("AN0094",),
        ("WinEventLog:Sysmon",),
    ),
    "T1547.001": AttackCatalogEntry(
        "Registry Run Keys / Startup Folder",
        "2.1",
        ("persistence", "privilege-escalation"),
        "DET0365",
        ("AN1032",),
        ("WinEventLog:Microsoft-Windows-Shell-Core", "WinEventLog:Sysmon"),
    ),
    "T1547.004": AttackCatalogEntry(
        "Winlogon Helper DLL",
        "1.3",
        ("persistence", "privilege-escalation"),
        "DET0404",
        ("AN1133",),
        ("Autoruns:RegistryScan", "WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1548.001": AttackCatalogEntry(
        "Setuid and Setgid",
        "2.0",
        ("privilege-escalation",),
        "DET0110",
        ("AN0307", "AN0308"),
        ("auditd:SYSCALL",),
    ),
    "T1548.002": AttackCatalogEntry(
        "Bypass User Account Control",
        "3.0",
        ("privilege-escalation",),
        "DET0388",
        ("AN1094",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1552.001": AttackCatalogEntry(
        "Credentials In Files",
        "1.3",
        ("credential-access",),
        "DET0307",
        ("AN0856", "AN0857", "AN0858", "AN0859", "AN0860"),
        ("WinEventLog:Security", "WinEventLog:Sysmon", "auditd:EXECVE", "auditd:SYSCALL"),
    ),
    "T1552.002": AttackCatalogEntry(
        "Credentials in Registry",
        "1.2",
        ("credential-access",),
        "DET0250",
        ("AN0694",),
        ("EDR:hunting", "WinEventLog:Sysmon"),
    ),
    "T1558.003": AttackCatalogEntry(
        "Kerberoasting",
        "1.3",
        ("credential-access",),
        "DET0157",
        ("AN0444",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1558.004": AttackCatalogEntry(
        "AS-REP Roasting",
        "1.2",
        ("credential-access",),
        "DET0113",
        ("AN0316",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1566.001": AttackCatalogEntry(
        "Spearphishing Attachment",
        "2.2",
        ("initial-access",),
        "DET0236",
        ("AN0655", "AN0656", "AN0657"),
        ("Application:Mail", "m365:unified", "WinEventLog:Sysmon"),
    ),
    "T1566.002": AttackCatalogEntry(
        "Spearphishing Link",
        "2.8",
        ("initial-access",),
        "DET0107",
        ("AN0298", "AN0299", "AN0300", "AN0301"),
        ("Application:Mail", "m365:unified", "NSM:Flow", "WinEventLog:Sysmon"),
    ),
    "T1569.002": AttackCatalogEntry(
        "Service Execution",
        "1.3",
        ("execution",),
        "DET0421",
        ("AN1185",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1569.003": AttackCatalogEntry(
        "Systemctl",
        "1.0",
        ("execution",),
        "DET0073",
        ("AN0200",),
        ("auditd:CONFIG_CHANGE", "auditd:EXECVE", "auditd:SYSCALL"),
    ),
    "T1027.018": AttackCatalogEntry(
        "Invisible Unicode",
        "1.0",
        ("stealth",),
        "DET0920",
        ("AN2063", "AN2064", "AN2065"),
        (
            "WinEventLog:Sysmon",
            "WinEventLog:Security",
            "WinEventLog:PowerShell",
            "auditd:SYSCALL",
            "auditd:EXECVE",
            "macos:unifiedlog",
        ),
    ),
    "T1684": AttackCatalogEntry(
        "Social Engineering",
        "1.0",
        ("stealth",),
        "DET0899",
        ("AN2033", "AN2034", "AN2035", "AN2036", "AN2037"),
        (
            "m365:unified",
            "m365:exchange",
            "m365:teams",
            "saas:okta",
            "saas:slack",
            "saas:zoom",
            "WinEventLog:Sysmon",
            "WinEventLog:Security",
            "auditd:EXECVE",
            "auditd:PATH",
            "NSM:Connections",
        ),
    ),
    "T1684.001": AttackCatalogEntry(
        "Impersonation",
        "1.0",
        ("stealth",),
        "DET0286",
        ("AN0792", "AN0793", "AN0794", "AN0795", "AN0796"),
        (
            "WinEventLog:Security",
            "m365:unified",
            "Application:Mail",
            "auditd:SYSCALL",
            "macos:unifiedlog",
            "gcp:workspaceaudit",
        ),
    ),
    "T1684.002": AttackCatalogEntry(
        "Email Spoofing",
        "1.0",
        ("stealth",),
        "DET0431",
        ("AN1202", "AN1203", "AN1204", "AN1205"),
        ("m365:messagetrace", "linux:syslog", "macos:unifiedlog", "saas:email"),
    ),
    "T1685": AttackCatalogEntry(
        "Disable or Modify Tools",
        "1.0",
        ("defense-impairment",),
        "DET0497",
        ("AN1369", "AN1370", "AN1371", "AN1372", "AN1373", "AN1374", "AN2044"),
        (
            "WinEventLog:System",
            "WinEventLog:Sysmon",
            "auditd:SYSCALL",
            "auditd:CONFIG_CHANGE",
            "AWS:CloudTrail",
            "kubernetes:audit",
            "networkdevice:config",
            "networkdevice:syslog",
            "esxi:shell",
            "esxi:hostd",
        ),
    ),
    "T1685.001": AttackCatalogEntry(
        "Disable or Modify Windows Event Log",
        "1.0",
        ("defense-impairment",),
        "DET0187",
        ("AN0535",),
        ("WinEventLog:System", "WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1685.002": AttackCatalogEntry(
        "Disable or Modify Cloud Log",
        "1.0",
        ("defense-impairment",),
        "DET0289",
        ("AN0801", "AN0802", "AN0803", "AN0804"),
        ("AWS:CloudTrail", "gcp:config", "azure:policy", "m365:unified", "saas:audit"),
    ),
    "T1685.003": AttackCatalogEntry(
        "Modify or Spoof Tool UI",
        "1.0",
        ("defense-impairment",),
        "DET0311",
        ("AN0868", "AN0869", "AN0870"),
        ("WinEventLog:System", "WinEventLog:Sysmon", "auditd:SYSCALL", "linux:syslog"),
    ),
    "T1685.004": AttackCatalogEntry(
        "Disable or Modify Linux Audit System Log",
        "1.0",
        ("defense-impairment",),
        "DET0062",
        ("AN0171",),
        ("auditd:EXECVE", "auditd:SYSCALL", "auditd:FILE", "linux:syslog"),
    ),
    "T1685.005": AttackCatalogEntry(
        "Clear Windows Event Logs",
        "1.0",
        ("defense-impairment",),
        "DET0532",
        ("AN1472",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1685.006": AttackCatalogEntry(
        "Clear Linux or Mac System Logs",
        "1.0",
        ("defense-impairment",),
        "DET0520",
        ("AN1438", "AN1439"),
        ("auditd:SYSCALL", "macos:unifiedlog", "fs:fsusage"),
    ),
    "T1686": AttackCatalogEntry(
        "Disable or Modify System Firewall",
        "1.0",
        ("defense-impairment",),
        "DET0145",
        ("AN0406", "AN0407", "AN0408", "AN0409", "AN0410"),
        (
            "WinEventLog:Security",
            "WinEventLog:Sysmon",
            "auditd:SYSCALL",
            "linux:osquery",
            "macos:unifiedlog",
            "esxi:hostd",
            "networkdevice:cli",
        ),
    ),
    "T1686.001": AttackCatalogEntry(
        "Cloud Firewall",
        "1.0",
        ("defense-impairment",),
        "DET0424",
        ("AN1188",),
        ("AWS:CloudTrail",),
    ),
    "T1686.002": AttackCatalogEntry(
        "Network Device Firewall",
        "1.0",
        ("defense-impairment",),
        "DET0306",
        ("AN0855",),
        ("networkdevice:Firewall", "NSM:Flow"),
    ),
    "T1686.003": AttackCatalogEntry(
        "Windows Host Firewall",
        "1.0",
        ("defense-impairment",),
        "DET0901",
        ("AN2043",),
        ("WinEventLog:Sysmon", "WinEventLog:Security", "WinEventLog:System"),
    ),
    "T1687": AttackCatalogEntry(
        "Exploitation for Defense Impairment",
        "1.0",
        ("defense-impairment",),
        "DET0900",
        ("AN2038", "AN2039", "AN2040", "AN2041", "AN2042"),
        (
            "WinEventLog:System",
            "WinEventLog:Sysmon",
            "auditd:EXECVE",
            "auditd:DAEMON",
            "macos:unifiedlog",
            "AWS:CloudTrail",
            "saas:okta",
            "m365:unified",
        ),
    ),
    "T1688": AttackCatalogEntry(
        "Safe Mode Boot",
        "1.0",
        ("defense-impairment",),
        "DET0116",
        ("AN0323",),
        ("WinEventLog:Security", "WinEventLog:Sysmon"),
    ),
    "T1689": AttackCatalogEntry(
        "Downgrade Attack",
        "1.0",
        ("defense-impairment",),
        "DET0350",
        ("AN0995", "AN0996", "AN0997"),
        ("WinEventLog:Sysmon", "WinEventLog:Security", "auditd:SYSCALL", "linux:syslog"),
    ),
    "T1690": AttackCatalogEntry(
        "Prevent Command History Logging",
        "1.0",
        ("defense-impairment",),
        "DET0563",
        ("AN1555", "AN1556", "AN1557", "AN1558", "AN1559"),
        (
            "auditd:SYSCALL",
            "linux:osquery",
            "macos:unifiedlog",
            "WinEventLog:PowerShell",
            "WinEventLog:Sysmon",
            "esxi:shell",
            "networkdevice:cli",
        ),
    ),
}


def _profile(
    mode: EmulationMode,
    procedure: str,
    success: str,
    limitation: str = "",
) -> EmulationProfile:
    return EmulationProfile(mode, procedure, (success,), limitation)


# These describe what the built-in executor actually does, rather than what the
# technique could do in an unconstrained intrusion. Every registered technique
# must have an entry; tests enforce this inventory.
EMULATION_PROFILES: dict[str, EmulationProfile] = {
    "T1190": _profile(
        EmulationMode.TELEMETRY,
        "Send a bounded HTTP canary request to the configured lab application.",
        "The request reaches the configured endpoint and returns an HTTP response.",
        "A canary exploit attempt does not prove code execution in the application.",
    ),
    "T1133": _profile(
        EmulationMode.TELEMETRY,
        "Establish the configured SSH or WinRM session and execute an identity check.",
        "The remote service authenticates the test identity and runs the check.",
        "The runner cannot prove that the service is exposed beyond the lab boundary.",
    ),
    "T1078": _profile(
        EmulationMode.PROCEDURE,
        "Authenticate with the configured valid account and run an identity/authorization check.",
        "The authenticated session reports the expected identity.",
    ),
    "T1078.001": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate predefined accounts and their enabled state.",
        "The target returns the default-account inventory.",
        "Enumeration is not authentication with a default credential.",
    ),
    "T1078.002": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate domain accounts through the configured directory identity.",
        "The directory query completes.",
        "Directory enumeration is not a new domain-account authentication event.",
    ),
    "T1078.003": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate local accounts and their enabled state.",
        "The local account query completes.",
        "Account enumeration is not local-account authentication.",
    ),
    "T1566.001": _profile(
        EmulationMode.ARTIFACT,
        "Create a benign attachment-shaped marker on the endpoint.",
        "The marker is created and its metadata is returned.",
        "No email is delivered, so this cannot validate spearphishing coverage.",
    ),
    "T1566.002": _profile(
        EmulationMode.ARTIFACT,
        "Create a benign Internet Shortcut marker on the endpoint.",
        "The marker is created and its metadata is returned.",
        "No email or message is delivered, so this cannot validate spearphishing coverage.",
    ),
    "T1059.001": _profile(
        EmulationMode.PROCEDURE,
        "Run a benign PowerShell command.",
        "PowerShell returns the command output.",
    ),
    "T1059.003": _profile(
        EmulationMode.PROCEDURE,
        "Run a benign command through cmd.exe.",
        "cmd.exe returns the command output.",
    ),
    "T1059.004": _profile(
        EmulationMode.PROCEDURE,
        "Run a benign command through a Unix shell.",
        "The shell returns the command output.",
    ),
    "T1059.005": _profile(
        EmulationMode.PROCEDURE,
        "Create and execute a benign VBScript.",
        "cscript creates the expected output marker.",
    ),
    "T1047": _profile(
        EmulationMode.PROCEDURE,
        "Create a process through WMI/CIM.",
        "The WMI-created process writes the expected output.",
    ),
    "T1569.003": _profile(
        EmulationMode.PROCEDURE,
        "Create, enable, and start a temporary systemd service.",
        "systemctl starts the unit and the unit writes its marker.",
    ),
    "T1569.002": _profile(
        EmulationMode.PROCEDURE,
        "Create and start a temporary Windows service.",
        "SCM starts the service and its command exits successfully.",
    ),
    "T1204.001": _profile(
        EmulationMode.PROCEDURE,
        "Open a benign URL through the registered protocol handler.",
        "The protocol-handler process is launched successfully.",
    ),
    "T1204.002": _profile(
        EmulationMode.PROCEDURE,
        "Create and launch a benign script-shaped file.",
        "The launched file writes the expected output marker.",
    ),
    "T1053.005": _profile(
        EmulationMode.PROCEDURE,
        "Register and start a temporary scheduled task.",
        "The task reports exit code zero and writes command output.",
    ),
    "T1053.005p": _profile(
        EmulationMode.PROCEDURE,
        "Register a temporary at-logon scheduled task.",
        "The persistent task exists with the expected trigger and action.",
    ),
    "T1547.001": _profile(
        EmulationMode.PROCEDURE,
        "Create a per-user Run key with a benign marker command.",
        "The exact Run value can be read back.",
    ),
    "T1547.004": _profile(
        EmulationMode.PROCEDURE,
        "Temporarily modify the Winlogon helper value after backing it up.",
        "The modified value can be read back and the backup is retained.",
    ),
    "T1546.001": _profile(
        EmulationMode.PROCEDURE,
        "Register and invoke an isolated test file association.",
        "Opening the test extension invokes its handler and writes a marker.",
    ),
    "T1546.003": _profile(
        EmulationMode.PROCEDURE,
        "Create a temporary permanent WMI event subscription.",
        "The filter, consumer, and binding are present.",
    ),
    "T1546.008": _profile(
        EmulationMode.PROCEDURE,
        "Temporarily configure an accessibility-feature execution hijack.",
        "Launching the feature invokes the benign marker command.",
    ),
    "T1136.001": _profile(
        EmulationMode.PROCEDURE,
        "Create a temporary local account.",
        "The account exists and can be queried.",
    ),
    "T1136.002": _profile(
        EmulationMode.PROCEDURE,
        "Create a temporary domain account.",
        "The directory account exists and is enabled.",
    ),
    "T1548.001": _profile(
        EmulationMode.TELEMETRY,
        "Execute a harmless setuid/setgid binary and capture its real/effective identity.",
        "The selected binary executes and identity evidence is returned.",
        "The harness does not launch a privileged shell or modify a privileged binary.",
    ),
    "T1548.002": _profile(
        EmulationMode.PROCEDURE,
        "Configure and trigger the fodhelper UAC bypass with a benign marker payload.",
        "The marker records a high-integrity child token.",
    ),
    "T1068": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate platform and configuration prerequisites for an exploit.",
        "The prerequisite inventory completes.",
        "No vulnerability is exploited and no elevated token is created.",
    ),
    "T1543.003": _profile(
        EmulationMode.PROCEDURE,
        "Create a temporary Windows service.",
        "The service exists with the requested image path.",
    ),
    "T1134.001": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate processes, token groups, and available token privileges.",
        "Token inventory commands complete.",
        "No token is duplicated, stolen, or impersonated.",
    ),
    "T1134.002": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate the current token and privileges.",
        "Token inventory commands complete.",
        "No process is created with a duplicated or stolen token.",
    ),
    "T1484.001": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate Group Policy objects through the configured directory identity.",
        "The GPO inventory completes.",
        "No GPO or SYSVOL policy content is modified.",
    ),
    "T1055.001": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate candidate target processes and loaded modules.",
        "The requested target process can be queried.",
        "No remote memory is allocated or written and no remote thread is created.",
    ),
    "T1558.003": _profile(
        EmulationMode.PROCEDURE,
        "Request service tickets for eligible user SPNs.",
        "At least one Kerberos service ticket request succeeds.",
    ),
    "T1558.004": _profile(
        EmulationMode.PREREQUISITE,
        "Enumerate accounts configured without Kerberos preauthentication.",
        "The directory query completes.",
        "No unauthenticated AS-REQ is sent and no AS-REP material is collected.",
    ),
    "T1110.001": _profile(
        EmulationMode.PROCEDURE,
        "Submit a bounded set of invalid passwords for one account.",
        "The configured authentication attempts are submitted.",
    ),
    "T1110.003": _profile(
        EmulationMode.PROCEDURE,
        "Submit one controlled password across multiple test accounts.",
        "The configured authentication attempts are submitted.",
    ),
    "T1552.001": _profile(
        EmulationMode.PROCEDURE,
        "Search bounded paths and read matching credential-like file content.",
        "The bounded file search completes.",
    ),
    "T1552.002": _profile(
        EmulationMode.PROCEDURE,
        "Enumerate bounded registry paths for credential-like values.",
        "The bounded registry search completes.",
    ),
    "T1003.001": _profile(
        EmulationMode.TELEMETRY,
        "Open LSASS with read/query access and immediately close the handle.",
        "The LSASS process handle is opened with the requested access mask.",
        "No LSASS bytes or credentials are read and no dump is retained.",
    ),
    "T1003.002": _profile(
        EmulationMode.PROCEDURE,
        "Save a temporary SAM hive and delete it without extracting hashes.",
        "A non-empty SAM hive is created and removed.",
    ),
    "T1027.018": _profile(
        EmulationMode.PROCEDURE,
        "Create and execute a benign script whose filename contains U+2063 Invisible Separator.",
        "The script executes and reports the invisible code point and artifact path.",
    ),
    "T1684": _profile(
        EmulationMode.ARTIFACT,
        "Create a clearly labelled social-engineering lure artifact without delivering it.",
        "The lure artifact is created and its metadata is returned.",
        "No user is contacted and no social interaction occurs.",
    ),
    "T1684.001": _profile(
        EmulationMode.ARTIFACT,
        "Create a clearly labelled help-desk impersonation message artifact.",
        "The impersonation artifact is created and its metadata is returned.",
        "No user or external service receives the message.",
    ),
    "T1684.002": _profile(
        EmulationMode.ARTIFACT,
        "Create an RFC 822 message with intentionally mismatched sender headers.",
        "The message artifact is created and its metadata is returned.",
        "The message is not transmitted, so mail-gateway spoofing controls are not assessed.",
    ),
    "T1685": _profile(
        EmulationMode.PREREQUISITE,
        "Inventory security and logging services without changing their state.",
        "The control inventory completes.",
        "No security tool is stopped, disabled, or modified.",
    ),
    "T1685.001": _profile(
        EmulationMode.PREREQUISITE,
        "Read the Windows Event Log service and Security-channel configuration.",
        "The service and channel configuration can be queried.",
        "The Event Log service and channels are not changed.",
    ),
    "T1685.002": _profile(
        EmulationMode.PREREQUISITE,
        "Check for installed cloud logging administration tools.",
        "The local prerequisite check completes.",
        "No cloud account is authenticated and no cloud log is changed.",
    ),
    "T1685.003": _profile(
        EmulationMode.ARTIFACT,
        "Create a labelled HTML artifact resembling a false security-status interface.",
        "The simulated interface artifact is created.",
        "No real security product interface or process state is modified.",
    ),
    "T1685.004": _profile(
        EmulationMode.PREREQUISITE,
        "Query auditd status and configuration availability.",
        "The audit subsystem prerequisite query completes.",
        "auditd is not stopped and its configuration is not modified.",
    ),
    "T1685.005": _profile(
        EmulationMode.PREREQUISITE,
        "Read the Windows Security event-log configuration.",
        "The Security channel configuration can be queried.",
        "No production event log is cleared.",
    ),
    "T1685.006": _profile(
        EmulationMode.TELEMETRY,
        "Create and truncate an isolated PurpleStrike log file.",
        "The dedicated log is empty after truncation.",
        "No operating-system or security log is modified.",
    ),
    "T1686": _profile(
        EmulationMode.PREREQUISITE,
        "Inventory host firewall configuration.",
        "The firewall configuration query completes.",
        "The parent scenario does not change firewall policy; use T1686.003 on Windows.",
    ),
    "T1686.001": _profile(
        EmulationMode.PREREQUISITE,
        "Check for installed cloud firewall administration tools.",
        "The local prerequisite check completes.",
        "No cloud account is authenticated and no cloud firewall is modified.",
    ),
    "T1686.002": _profile(
        EmulationMode.PREREQUISITE,
        "Inventory local routing information needed to target a network firewall test.",
        "The routing prerequisite query completes.",
        "No network device is authenticated and no firewall rule is modified.",
    ),
    "T1686.003": _profile(
        EmulationMode.PROCEDURE,
        "Create and verify a temporary outbound Windows Firewall rule for TEST-NET-1.",
        "The enabled rule exists with the expected display name and is removed during cleanup.",
    ),
    "T1687": _profile(
        EmulationMode.PREREQUISITE,
        "Inventory security controls that could be targets of a lab exploit.",
        "The security-control inventory completes.",
        "No vulnerability is exploited and no control is impaired.",
    ),
    "T1688": _profile(
        EmulationMode.PREREQUISITE,
        "Read the active Windows boot configuration.",
        "The boot configuration query completes.",
        "Safe mode is not configured and the endpoint is not rebooted.",
    ),
    "T1689": _profile(
        EmulationMode.PREREQUISITE,
        "Inventory installed legacy interpreters and runtime versions.",
        "The runtime inventory completes.",
        "No component, protocol, or security policy is downgraded.",
    ),
    "T1690": _profile(
        EmulationMode.PROCEDURE,
        "Disable history persistence inside a disposable PowerShell or Bash process.",
        "The child shell confirms that history saving is disabled for its session.",
        "The change is process-scoped and does not alter persistent shell configuration.",
    ),
}


def attack_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def apply_catalog_metadata(technique: Technique) -> None:
    profile = EMULATION_PROFILES.get(technique.technique_id)
    if profile is None:
        raise ValueError(f"Missing emulation profile for {technique.technique_id}")

    attack_id = technique.detection_technique_id
    entry = ATTACK_CATALOG.get(attack_id)
    if entry is None:
        raise ValueError(f"Missing ATT&CK {ATTACK_VERSION} metadata for {attack_id}")

    technique.attack_version = ATTACK_VERSION
    technique.attack_technique_version = entry.version
    technique.attack_url = attack_url(attack_id)
    technique.attack_tactics = list(entry.tactics)
    technique.official_name = entry.official_name
    technique.detection_strategy_id = entry.detection_strategy_id
    technique.analytic_ids = list(entry.analytic_ids)
    technique.required_log_sources = list(entry.log_sources)
    technique.emulation_mode = profile.mode
    technique.procedure = profile.procedure
    technique.success_criteria = list(profile.success_criteria)
    technique.validation_notes = profile.limitation
