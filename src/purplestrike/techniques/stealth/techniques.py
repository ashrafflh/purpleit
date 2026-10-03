from purplestrike.models.techniques import TacticID, Technique


def _stealth(
    technique_id: str,
    name: str,
    description: str,
    target_os: list[str],
) -> Technique:
    return Technique(
        technique_id=technique_id,
        name=name,
        tactic=TacticID.STEALTH,
        description=description,
        target_os=target_os,
        executor="custom_python",
        module="shared.v19_controls",
        risk_level="low",
    )


STEALTH_TECHNIQUES = [
    _stealth(
        "T1027.018",
        "Obfuscated Files or Information: Invisible Unicode",
        "Creates and executes a benign script whose filename contains invisible Unicode.",
        ["windows", "linux"],
    ),
    _stealth(
        "T1684",
        "Social Engineering",
        "Creates a clearly labelled social-engineering lure artifact without delivering it.",
        ["windows", "linux"],
    ),
    _stealth(
        "T1684.001",
        "Social Engineering: Impersonation",
        "Creates a clearly labelled impersonation message artifact without contacting a user.",
        ["windows", "linux"],
    ),
    _stealth(
        "T1684.002",
        "Social Engineering: Email Spoofing",
        "Creates an RFC 822 message with mismatched sender headers but does not transmit it.",
        ["windows", "linux"],
    ),
]
