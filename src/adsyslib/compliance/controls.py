
# NIST 800-53 control subset relevant to DevOps/infrastructure audits
NIST_800_53: dict[str, str] = {
    "AC-2":  "Account Management",
    "AC-3":  "Access Enforcement",
    "AC-6":  "Least Privilege",
    "AC-17": "Remote Access",
    "AU-2":  "Event Logging",
    "AU-9":  "Protection of Audit Information",
    "CM-2":  "Baseline Configuration",
    "CM-3":  "Configuration Change Control",
    "CM-6":  "Configuration Settings",
    "CM-7":  "Least Functionality",
    "IA-2":  "Identification and Authentication",
    "IA-5":  "Authenticator Management",
    "IA-8":  "Identification and Authentication (Non-Org Users)",
    "SC-8":  "Transmission Confidentiality and Integrity",
    "SC-28": "Protection of Information at Rest",
    "SI-2":  "Flaw Remediation",
    "SI-3":  "Malicious Code Protection",
}

# Maps compliance framework → relevant NIST 800-53 control IDs
FRAMEWORK_CONTROLS: dict[str, list[str]] = {
    "fedramp": [
        "AC-2", "AC-3", "AC-6", "AC-17",
        "AU-2", "AU-9",
        "CM-2", "CM-3", "CM-6", "CM-7",
        "IA-2", "IA-5",
        "SC-8", "SC-28",
        "SI-2", "SI-3",
    ],
    "hipaa": [
        "AC-2", "AC-3", "AC-6",
        "AU-2",
        "IA-2", "IA-5",
        "SC-8", "SC-28",
    ],
    "sox": [
        "AC-2", "AC-3", "AC-6",
        "AU-2", "AU-9",
        "CM-3",
        "IA-2",
    ],
    "glba": [
        "AC-2", "AC-3",
        "AU-2",
        "IA-2",
        "SC-8", "SC-28",
    ],
}


def control_title(control_id: str) -> str:
    return NIST_800_53.get(control_id, control_id)


def get_controls_for_frameworks(frameworks: list[str]) -> list[str]:
    """Return deduplicated control IDs for the given frameworks, preserving order."""
    seen: set = set()
    result: list[str] = []
    for fw in frameworks:
        for ctrl_id in FRAMEWORK_CONTROLS.get(fw.lower(), []):
            if ctrl_id not in seen:
                seen.add(ctrl_id)
                result.append(ctrl_id)
    return result
