"""
MITRE ATT&CK technique mapping for detected anomalies.
"""

from typing import List, Dict, Any, Optional


# Comprehensive MITRE ATT&CK technique mapping
MITRE_TECHNIQUES = {
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Use of web protocols like HTTP/HTTPS for command and control",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Data exfiltration using alternative protocols instead of standard channels",
    },
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
        "tactic": "Exfiltration",
        "description": "Data exfiltration over non-C2 protocols",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries exploit vulnerabilities in public-facing applications",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated authentication attempts to obtain valid credentials",
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Systematic attempts to guess passwords",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Delivery of phishing emails with malicious links or attachments",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "User clicks on a malicious link or attachment",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Execution through scripting interpreters like bash, python, etc",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Data exfiltration through command and control channels",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using non-standard ports",
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "description": "Protocol tunneling like DNS tunneling for command and control",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries use valid accounts to maintain access and avoid detection",
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Gathering data from cloud storage services",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Exfiltration of data through web services and cloud platforms",
    },
    "T1567.001": {
        "name": "Exfiltration to Code Repository",
        "tactic": "Exfiltration",
        "description": "Exfiltration of sensitive data to code repositories",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Persistence",
        "description": "Using external remote services for command and control",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Transfer of tools and files for command execution",
    },
}


def map_anomalies_to_mitre(anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich anomalies with MITRE ATT&CK technique information.

    Args:
        anomalies: List of detected anomalies from rule engine

    Returns:
        List of anomalies with MITRE mapping information enriched
    """
    enriched = []

    for anomaly in anomalies:
        technique_id = anomaly.get("mitre_technique")
        if technique_id and technique_id in MITRE_TECHNIQUES:
            technique = MITRE_TECHNIQUES[technique_id]
            anomaly["mitre_details"] = {
                "id": technique_id,
                "name": technique["name"],
                "tactic": technique["tactic"],
                "description": technique["description"],
            }
        enriched.append(anomaly)

    return enriched


def get_mitre_summary(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of MITRE tactics from detected anomalies.

    Args:
        anomalies: List of detected anomalies (enriched with MITRE data)

    Returns:
        Summary dict with tactics and technique counts
    """
    tactics = {}
    techniques = {}

    for anomaly in anomalies:
        mitre_details = anomaly.get("mitre_details")
        if mitre_details:
            tactic = mitre_details.get("tactic")
            technique_id = mitre_details.get("id")
            technique_name = mitre_details.get("name")

            # Count tactics
            if tactic:
                tactics[tactic] = tactics.get(tactic, 0) + 1

            # Track techniques
            if technique_id:
                techniques[technique_id] = {
                    "name": technique_name,
                    "tactic": tactic,
                    "occurrences": techniques.get(technique_id, {}).get("occurrences", 0) + 1,
                }

    # Return as a flat list matching frontend MitreMapping[] interface
    technique_list = []
    for tid, info in techniques.items():
        technique_list.append({
            "technique_id": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "count": info["occurrences"],
        })

    return technique_list


def get_all_techniques() -> Dict[str, Any]:
    """
    Get all available MITRE ATT&CK techniques.

    Returns:
        Dictionary of all MITRE techniques
    """
    return MITRE_TECHNIQUES


def get_technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a specific MITRE technique by ID.

    Args:
        technique_id: MITRE technique ID (e.g., 'T1071')

    Returns:
        Technique details or None if not found
    """
    return MITRE_TECHNIQUES.get(technique_id)
