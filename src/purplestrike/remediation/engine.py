from __future__ import annotations

import logging

from purplestrike.models.remediation import (
    GenericGuidance,
    RemediationConfidence,
    RemediationEntry,
    WazuhRemediation,
)
from purplestrike.models.simulation import DetectionStatus, SimulationStep

logger = logging.getLogger(__name__)

REMEDIATION_DB: dict[str, dict] = {
    "T1558.001": {
        "wazuh": WazuhRemediation(
            confidence=RemediationConfidence.HIGH,
            rule_xml=(
                '<group name="purplestrike_remediation,">\n'
                '  <rule id="100400" level="10">\n'
                '    <if_sid>100050</if_sid>\n'
                '    <field name="win.system.eventID">4769</field>\n'
                '    <field name="win.eventdata.ticketEncryptionType">0x17</field>\n'
                '    <description>Kerberoasting detected: RC4-encrypted TGS ticket requested for SPN account</description>\n'
                '    <mitre><id>T1558.001</id></mitre>\n'
                '  </rule>\n'
                '</group>'
            ),
            log_sources_required=["Windows Security Event Log"],
            testing_instructions="Run: purplestrike run --techniques T1558.001 --target-group <group>",
        ),
        "generic": GenericGuidance(
            data_sources=["Windows Security Event Log (Event ID 4769)", "Sysmon Event ID 1"],
            detection_logic="Monitor for Event 4769 where TicketEncryptionType = 0x17 (RC4) and ServiceName matches an SPN account pattern",
            false_positive_considerations="Legitimate service ticket requests may use RC4 for older services; correlate with account sensitivity",
            references=["https://attack.mitre.org/techniques/T1558/001/"],
        ),
    },
    "T1558.002": {
        "wazuh": WazuhRemediation(
            confidence=RemediationConfidence.HIGH,
            rule_xml=(
                '<group name="purplestrike_remediation,">\n'
                '  <rule id="100402" level="10">\n'
                '    <field name="win.system.eventID">4768</field>\n'
                '    <field name="win.eventdata.preAuthType">0</field>\n'
                '    <description>AS-REP Roasting detected: AS-REQ without pre-auth for vulnerable account</description>\n'
                '    <mitre><id>T1558.002</id></mitre>\n'
                '  </rule>\n'
                '</group>'
            ),
            log_sources_required=["Windows Security Event Log"],
            testing_instructions="Run: purplestrike run --techniques T1558.002 --target-group <group>",
        ),
        "generic": GenericGuidance(
            data_sources=["Windows Security Event Log (Event ID 4768)"],
            detection_logic="Monitor for Event 4768 where pre-authentication is not required (preAuthType = 0)",
            false_positive_considerations="Some service accounts legitimately have pre-auth disabled; audit DONT_REQ_PREAUTH attribute",
            references=["https://attack.mitre.org/techniques/T1558/002/"],
        ),
    },
    "T1003.001": {
        "wazuh": WazuhRemediation(
            confidence=RemediationConfidence.HIGH,
            rule_xml=(
                '<group name="purplestrike_remediation,">\n'
                '  <rule id="100407" level="12">\n'
                '    <field name="win.system.eventID">4663</field>\n'
                '    <field name="win.eventdata.objectName">\\Device\\LSASS</field>\n'
                '    <description>LSASS memory access detected</description>\n'
                '    <mitre><id>T1003.001</id></mitre>\n'
                '  </rule>\n'
                '</group>'
            ),
            log_sources_required=["Windows Security Event Log", "Sysmon Event ID 10"],
            testing_instructions="Run: purplestrike run --techniques T1003.001 --target-group <group>",
        ),
        "generic": GenericGuidance(
            data_sources=["Windows Security Event Log (Event ID 4663)", "Sysmon Event ID 10 (Process Access)"],
            detection_logic="Monitor for process access to LSASS memory, especially from procdump, comsvcs.dll, or unknown processes",
            false_positive_considerations="Security tools (EDR, AV) may legitimately access LSASS; whitelist known security binaries",
            references=["https://attack.mitre.org/techniques/T1003/001/"],
        ),
    },
    "T1003.002": {
        "wazuh": WazuhRemediation(
            confidence=RemediationConfidence.HIGH,
            rule_xml=(
                '<group name="purplestrike_remediation,">\n'
                '  <rule id="100408" level="12">\n'
                '    <field name="win.system.eventID">4656</field>\n'
                '    <field name="win.eventdata.objectType">SAM_DOMAIN</field>\n'
                '    <description>SAM database access detected</description>\n'
                '    <mitre><id>T1003.002</id></mitre>\n'
                '  </rule>\n'
                '</group>'
            ),
            log_sources_required=["Windows Security Event Log"],
            testing_instructions="Run: purplestrike run --techniques T1003.002 --target-group <group>",
        ),
        "generic": GenericGuidance(
            data_sources=["Windows Security Event Log (Event ID 4656, 4663)", "Sysmon Event ID 1"],
            detection_logic="Monitor for SAM registry hive access, volume shadow copy creation, and reg.exe SAM save commands",
            false_positive_considerations="Backup operations may legitimately access SAM; correlate with backup service accounts",
            references=["https://attack.mitre.org/techniques/T1003/002/"],
        ),
    },
    "T1110.001": {
        "wazuh": WazuhRemediation(
            confidence=RemediationConfidence.HIGH,
            rule_xml=(
                '<group name="purplestrike_remediation,">\n'
                '  <rule id="100403" level="10">\n'
                '    <field name="win.system.eventID">4625</field>\n'
                '    <description>Multiple authentication failures detected — possible password guessing</description>\n'
                '    <mitre><id>T1110.001</id></mitre>\n'
                '  </rule>\n'
                '</group>'
            ),
            log_sources_required=["Windows Security Event Log"],
            testing_instructions="Run: purplestrike run --techniques T1110.001 --target-group <group>",
        ),
        "generic": GenericGuidance(
            data_sources=["Windows Security Event Log (Event ID 4625)", "Wazuh authentication rules"],
            detection_logic="Monitor for high volume of Event 4625 (logon failure) from same source within short time window",
            false_positive_considerations="Users typing wrong passwords, service account misconfigurations; set appropriate thresholds",
            references=["https://attack.mitre.org/techniques/T1110/001/"],
        ),
    },
    "T1110.003": {
        "wazuh": WazuhRemediation(
            confidence=RemediationConfidence.HIGH,
            rule_xml=(
                '<group name="purplestrike_remediation,">\n'
                '  <rule id="100404" level="10">\n'
                '    <field name="win.system.eventID">4625</field>\n'
                '    <description>Password spraying detected: same password across multiple accounts</description>\n'
                '    <mitre><id>T1110.003</id></mitre>\n'
                '  </rule>\n'
                '</group>'
            ),
            log_sources_required=["Windows Security Event Log"],
            testing_instructions="Run: purplestrike run --techniques T1110.003 --target-group <group>",
        ),
        "generic": GenericGuidance(
            data_sources=["Windows Security Event Log (Event ID 4625)", "Authentication logs"],
            detection_logic="Monitor for same failed password attempt across multiple distinct accounts within a time window",
            false_positive_considerations="Common passwords may trigger false positives; correlate with source IP reputation",
            references=["https://attack.mitre.org/techniques/T1110/003/"],
        ),
    },
}


class RemediationEngine:
    """Generates SIEM-specific and generic remediation guidance for detection gaps."""

    def generate_remediation(self, steps: list[SimulationStep]) -> list[RemediationEntry]:
        entries: list[RemediationEntry] = []
        for step in steps:
            if step.detection_status in (DetectionStatus.DETECTED,):
                continue

            entry = self._generate_entry(step)
            if entry:
                entries.append(entry)

        return entries

    def _generate_entry(self, step: SimulationStep) -> RemediationEntry | None:
        db_entry = REMEDIATION_DB.get(step.technique_id)

        if db_entry:
            return RemediationEntry(
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                current_detection=step.detection_status.value,
                wazuh_remediation=db_entry.get("wazuh"),
                generic_guidance=db_entry.get("generic"),
            )

        return RemediationEntry(
            technique_id=step.technique_id,
            technique_name=step.technique_name,
            current_detection=step.detection_status.value,
            wazuh_remediation=WazuhRemediation(
                confidence=RemediationConfidence.LOW,
                rule_xml="",
                log_sources_required=["Windows Security Event Log", "Sysmon"],
                testing_instructions=f"Run: purplestrike run --techniques {step.technique_id} --target-group <group>",
            ),
            generic_guidance=self._generate_generic_guidance(step.technique_id),
        )

    def _generate_generic_guidance(self, technique_id: str) -> GenericGuidance:
        from purplestrike.techniques.registry import technique_registry

        technique = technique_registry.get_technique(technique_id)
        if technique:
            return GenericGuidance(
                data_sources=["Windows Security Event Log", "Sysmon"],
                detection_logic=f"Monitor for activity related to {technique.name} ({technique_id})",
                false_positive_considerations="Review common legitimate use cases before deploying detection rules",
                references=[f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"],
            )

        return GenericGuidance(
            data_sources=["Windows Security Event Log"],
            detection_logic=f"Monitor for indicators of {technique_id}",
            references=[f"https://attack.mitre.org/techniques/{technique_id}/"],
        )
