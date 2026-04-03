# mitre_d3fend_map.py — MITRE D3FEND Framework Mapping
# Maps detected threat types to MITRE D3FEND defensive techniques and countermeasures

MITRE_D3FEND_MAP = {
    "brute_force": {
        "defend_id": "D3-PSA",
        "defend_name": "Password Security Authentication",
        "tactic": "Harden",
        "technique": "Password Policy Enforcement",
        "description": "Implement strong password policies and multi-factor authentication to prevent brute force attacks",
        "attack_techniques": ["T1110.001", "T1110.003"],
        "digital_artifacts": ["user-account", "authentication-token", "password"],
        "countermeasures": [
            "Implement account lockout policies",
            "Enforce password complexity requirements",
            "Deploy multi-factor authentication (MFA)",
            "Implement rate limiting on authentication endpoints",
            "Use CAPTCHA for repeated failed attempts"
        ],
        "implementation_examples": [
            "Active Directory password policy configuration",
            "PAM password quality control modules",
            "OAuth 2.0 with MFA integration",
            "Fail2ban IP blocking",
            "Web application firewall (WAF) rules"
        ],
        "effectiveness": "HIGH",
        "implementation_cost": "MEDIUM",
        "maintenance_required": "LOW"
    },

    "port_scan": {
        "defend_id": "D3-NDS",
        "defend_name": "Network Discovery Suppression",
        "tactic": "Detect",
        "technique": "Port Scan Detection",
        "description": "Detect and respond to network reconnaissance activities through monitoring and filtering",
        "attack_techniques": ["T1046"],
        "digital_artifacts": ["network-traffic", "network-session", "ip-packet"],
        "countermeasures": [
            "Deploy network intrusion detection systems (NIDS)",
            "Implement port knocking techniques",
            "Use network segmentation to limit scan visibility",
            "Deploy honeypots to distract scanners",
            "Implement connection rate limiting"
        ],
        "implementation_examples": [
            "Snort/Suricata IDS rules for port scan detection",
            "Zeek network monitoring scripts",
            "Cisco ASA/NGFW scan detection",
            "Uncomplicated Firewall (UFW) rate limiting",
            "Docker container network isolation"
        ],
        "effectiveness": "MEDIUM",
        "implementation_cost": "MEDIUM",
        "maintenance_required": "MEDIUM"
    },

    "lateral_movement": {
        "defend_id": "D3-AML",
        "defend_name": "Authentication Movement Limitation",
        "tactic": "Isolate",
        "technique": "Network Segmentation",
        "description": "Limit lateral movement by implementing network segmentation and access controls",
        "attack_techniques": ["T1021.001", "T1021.004"],
        "digital_artifacts": ["network-session", "authentication-token", "user-account"],
        "countermeasures": [
            "Implement network microsegmentation",
            "Deploy just-in-time (JIT) access",
            "Use privileged access management (PAM)",
            "Implement jump hosts/bastion servers",
            "Deploy endpoint detection and response (EDR)"
        ],
        "implementation_examples": [
            "VMware NSX microsegmentation",
            "CyberArk privileged access management",
            "AWS Security Groups and NACLs",
            "Palo Alto Cortex XDR",
            "HashiCorp Vault for secrets management"
        ],
        "effectiveness": "HIGH",
        "implementation_cost": "HIGH",
        "maintenance_required": "HIGH"
    },

    "privilege_escalation": {
        "defend_id": "D3-EAP",
        "defend_name": "Elevation Attack Prevention",
        "tactic": "Harden",
        "technique": "Privilege Escalation Prevention",
        "description": "Prevent privilege escalation through proper access controls and monitoring",
        "attack_techniques": ["T1548.003"],
        "digital_artifacts": ["user-account", "process", "system-call"],
        "countermeasures": [
            "Implement principle of least privilege (PoLP)",
            "Deploy sudo logging and monitoring",
            "Use application control whitelisting",
            "Implement kernel-level protection mechanisms",
            "Deploy file integrity monitoring"
        ],
        "implementation_examples": [
            "Linux sudoers configuration with logging",
            "Windows User Account Control (UAC)",
            "AppLocker application whitelisting",
            "SELinux/AppArmor mandatory access control",
            "OSSEC file integrity monitoring"
        ],
        "effectiveness": "HIGH",
        "implementation_cost": "MEDIUM",
        "maintenance_required": "MEDIUM"
    }
}


def get_d3fend_info(threat_type: str) -> dict:
    """
    Return the full MITRE D3FEND entry for a given threat type.
    threat_type: one of brute_force | port_scan | lateral_movement | privilege_escalation
    """
    entry = MITRE_D3FEND_MAP.get(threat_type)
    if not entry:
        return {
            "defend_id": "D3-UNKNOWN",
            "defend_name": "Unknown Defense",
            "tactic": "Unknown",
            "technique": "Unknown Technique",
            "description": f"No D3FEND mapping found for threat type: {threat_type}",
            "attack_techniques": [],
            "digital_artifacts": [],
            "countermeasures": [],
            "implementation_examples": [],
            "effectiveness": "LOW",
            "implementation_cost": "UNKNOWN",
            "maintenance_required": "UNKNOWN"
        }
    return entry


def get_d3fend_countermeasures(threat_type: str) -> list:
    """Return defensive countermeasures for a threat type."""
    info = get_d3fend_info(threat_type)
    return info.get("countermeasures", [])


def get_d3fend_implementations(threat_type: str) -> list:
    """Return implementation examples for defensive techniques."""
    info = get_d3fend_info(threat_type)
    return info.get("implementation_examples", [])


def get_all_d3fend_mappings() -> list:
    """Return all D3FEND mappings as a list for API consumption."""
    result = []
    for threat_type, data in MITRE_D3FEND_MAP.items():
        result.append({
            "threat_type": threat_type,
            **data
        })
    return result


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    print("=== MITRE D3FEND Defensive Mappings ===\n")
    for t in MITRE_D3FEND_MAP:
        info = get_d3fend_info(t)
        print(f"[{info['defend_id']}] {info['defend_name']}")
        print(f"  Tactic: {info['tactic']} - {info['technique']}")
        print(f"  Effectiveness: {info['effectiveness']}")
        print(f"  Countermeasures: {len(info['countermeasures'])} available")
        print()
