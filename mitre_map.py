# mitre_map.py — MITRE ATT&CK Framework Mapping
# Maps detected threat types to official MITRE ATT&CK techniques

MITRE_MAP = {
    "brute_force": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "description":    (
            "Adversaries use brute force techniques to gain access to accounts "
            "by systematically trying many passwords until the correct one is found. "
            "Detected via repeated EventID 4625 (Windows) or SSH Failed password entries."
        ),
        "url":            "https://attack.mitre.org/techniques/T1110/",
        "subtechniques": {
            "T1110.001": "Password Guessing",
            "T1110.003": "Password Spraying",
        },
        "severity":  "HIGH",
        "ioc_fields": ["src_ip", "target_user", "failure_count", "time_window"],
        "response":  "block_ip,force_password_reset,notify_admin",
    },

    "port_scan": {
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "description":    (
            "Adversaries probe the network to enumerate open ports and running services. "
            "Detected via netflow logs showing one source IP hitting many destination ports "
            "within a short time window."
        ),
        "url":            "https://attack.mitre.org/techniques/T1046/",
        "subtechniques": {},
        "severity":  "MEDIUM",
        "ioc_fields": ["src_ip", "dest_ip", "ports_scanned", "time_window"],
        "response":  "block_ip,notify_admin",
    },

    "lateral_movement": {
        "technique_id":   "T1021",
        "technique_name": "Remote Services",
        "tactic":         "Lateral Movement",
        "tactic_id":      "TA0008",
        "description":    (
            "Adversaries use valid credentials to move laterally across systems via SSH. "
            "Detected by the same user account authenticating to multiple distinct hosts "
            "in a short time window (SSH hopping chain)."
        ),
        "url":            "https://attack.mitre.org/techniques/T1021/",
        "subtechniques": {
            "T1021.004": "SSH",
        },
        "severity":  "HIGH",
        "ioc_fields": ["user", "src_ip", "dest_ips", "hop_count", "time_window"],
        "response":  "isolate_host,notify_admin,force_password_reset",
    },

    "privilege_escalation": {
        "technique_id":   "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic":         "Privilege Escalation",
        "tactic_id":      "TA0004",
        "description":    (
            "Adversaries abuse sudo or similar mechanisms to gain elevated privileges. "
            "Detected via sudo auth failure logs followed by a successful sudo session "
            "opened for root — indicating repeated attempts until success."
        ),
        "url":            "https://attack.mitre.org/techniques/T1548/",
        "subtechniques": {
            "T1548.003": "Sudo and Sudo Caching",
        },
        "severity":  "CRITICAL",
        "ioc_fields": ["user", "src_ip", "sudo_failures", "sudo_success"],
        "response":  "isolate_host,notify_admin,force_password_reset,block_ip",
    },
}


def get_mitre_info(threat_type: str) -> dict:
    """
    Return the full MITRE entry for a given threat type.
    threat_type: one of brute_force | port_scan | lateral_movement | privilege_escalation
    """
    entry = MITRE_MAP.get(threat_type)
    if not entry:
        return {
            "technique_id":   "UNKNOWN",
            "technique_name": "Unknown Technique",
            "tactic":         "Unknown",
            "severity":       "LOW",
            "description":    f"No MITRE mapping found for threat type: {threat_type}",
            "url":            "https://attack.mitre.org/",
            "response":       "notify_admin",
        }
    return entry


def format_mitre_badge(threat_type: str) -> dict:
    """
    Return a compact badge dict for frontend display.
    """
    info = get_mitre_info(threat_type)
    return {
        "id":      info["technique_id"],
        "name":    info["technique_name"],
        "tactic":  info["tactic"],
        "severity": info["severity"],
        "url":     info.get("url", ""),
    }


def get_all_mappings() -> list:
    """Return all MITRE mappings as a list for API consumption."""
    result = []
    for threat_type, data in MITRE_MAP.items():
        result.append({
            "threat_type": threat_type,
            **data
        })
    return result


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    print("=== MITRE ATT&CK Mappings ===\n")
    for t in MITRE_MAP:
        info = get_mitre_info(t)
        print(f"[{info['technique_id']}] {info['technique_name']}")
        print(f"  Tactic   : {info['tactic']} ({info.get('tactic_id','')})")
        print(f"  Severity : {info['severity']}")
        print(f"  Response : {info['response']}")
        print()
