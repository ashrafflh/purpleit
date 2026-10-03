from purplestrike.models.techniques import TacticID, Technique


def _defense_impairment(
    technique_id: str,
    name: str,
    description: str,
    target_os: list[str],
    risk_level: str = "low",
) -> Technique:
    return Technique(
        technique_id=technique_id,
        name=name,
        tactic=TacticID.DEFENSE_IMPAIRMENT,
        description=description,
        target_os=target_os,
        executor="custom_python",
        module="shared.v19_controls",
        risk_level=risk_level,
    )


DEFENSE_IMPAIRMENT_TECHNIQUES = [
    _defense_impairment(
        "T1685",
        "Disable or Modify Tools",
        "Inventories security and logging services without changing their state.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1685.001",
        "Disable or Modify Tools: Disable or Modify Windows Event Log",
        "Queries the Windows Event Log service and Security channel without modifying them.",
        ["windows"],
    ),
    _defense_impairment(
        "T1685.002",
        "Disable or Modify Tools: Disable or Modify Cloud Log",
        "Checks for cloud logging administration tools without changing cloud logging.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1685.003",
        "Disable or Modify Tools: Modify or Spoof Tool UI",
        "Creates a clearly labelled simulated security-status interface artifact.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1685.004",
        "Disable or Modify Tools: Disable or Modify Linux Audit System Log",
        "Queries auditd status without stopping it or changing its configuration.",
        ["linux"],
    ),
    _defense_impairment(
        "T1685.005",
        "Disable or Modify Tools: Clear Windows Event Logs",
        "Queries the Security event log without clearing production telemetry.",
        ["windows"],
    ),
    _defense_impairment(
        "T1685.006",
        "Disable or Modify Tools: Clear Linux or Mac System Logs",
        "Truncates a dedicated PurpleStrike log rather than an operating-system log.",
        ["linux"],
    ),
    _defense_impairment(
        "T1686",
        "Disable or Modify System Firewall",
        "Inventories host firewall configuration without changing policy.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1686.001",
        "Disable or Modify System Firewall: Cloud Firewall",
        "Checks for cloud firewall administration tools without changing cloud policy.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1686.002",
        "Disable or Modify System Firewall: Network Device Firewall",
        "Inventories routing prerequisites without changing a network firewall.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1686.003",
        "Disable or Modify System Firewall: Windows Host Firewall",
        "Creates, verifies, and removes a narrowly scoped temporary Windows Firewall rule.",
        ["windows"],
        "medium",
    ),
    _defense_impairment(
        "T1687",
        "Exploitation for Defense Impairment",
        "Inventories security controls without exploiting a vulnerability.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1688",
        "Safe Mode Boot",
        "Reads the active Windows boot configuration without changing the boot mode.",
        ["windows"],
    ),
    _defense_impairment(
        "T1689",
        "Downgrade Attack",
        "Inventories legacy runtimes without installing or selecting a downgraded component.",
        ["windows", "linux"],
    ),
    _defense_impairment(
        "T1690",
        "Prevent Command History Logging",
        "Disables command-history persistence only inside a disposable child shell process.",
        ["windows", "linux"],
    ),
]
