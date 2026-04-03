# mitre_engage_map.py — MITRE Engage Framework Mapping
# Maps detected threat types to MITRE Engage adversary engagement strategies and techniques

MITRE_ENGAGE_MAP = {
    "brute_force": {
        "engage_id": "ENG-ATD-001",
        "engage_name": "Attack Technique Deception",
        "strategy": "Deny",
        "technique": "Credential Decoy",
        "description": "Deploy deceptive credentials to detect and analyze brute force attempts while wasting adversary resources",
        "attack_techniques": ["T1110.001", "T1110.003"],
        "engagement_goals": [
            "Detect brute force attempts early",
            "Collect adversary TTPs and tools",
            "Waste attacker time and resources",
            "Gather intelligence on attack patterns"
        ],
        "deception_tactics": [
            "Deploy honeytoken accounts with weak credentials",
            "Create fake login portals with credential harvesting",
            "Place decoy password files in common locations",
            "Implement fake authentication services"
        ],
        "implementation_examples": [
            "Canary tokens for honey accounts",
            "Custom honeyport services",
            "Decoy SSH servers with logging",
            "Fake web application login pages"
        ],
        "success_metrics": [
            "Number of decoy account access attempts",
            "Time spent by attacker on decoys",
            "Unique attack patterns observed",
            "Tool and technique attribution"
        ],
        "risk_level": "LOW",
        "resource_requirements": "LOW"
    },

    "port_scan": {
        "engage_id": "ENG-NDD-001",
        "engage_name": "Network Discovery Deception",
        "strategy": "Detect",
        "technique": "Service Emulation",
        "description": "Deploy deceptive network services to detect reconnaissance and gather intelligence about scanning tools",
        "attack_techniques": ["T1046"],
        "engagement_goals": [
            "Detect network reconnaissance activities",
            "Identify scanning tools and methodologies",
            "Create realistic attack surface for analysis",
            "Collect attacker IP addresses and patterns"
        ],
        "deception_tactics": [
            "Deploy honeypot services on multiple ports",
            "Create fake network infrastructure",
            "Emulate vulnerable services for analysis",
            "Implement network traffic decoys"
        ],
        "implementation_examples": [
            "Docker honeypot containers",
            "Honeyd service emulation",
            "Cowrie SSH honeypot",
            "Dionaea malware capture honeypot"
        ],
        "success_metrics": [
            "Number of scan attempts detected",
            "Unique scanning tools identified",
            "Geographic source analysis",
            "Attack pattern classification"
        ],
        "risk_level": "LOW",
        "resource_requirements": "MEDIUM"
    },

    "lateral_movement": {
        "engage_id": "ENG-LMD-001",
        "engage_name": "Lateral Movement Deception",
        "strategy": "Disrupt",
        "technique": "Network Path Decoys",
        "description": "Create deceptive network paths and credentials to detect lateral movement attempts and collect intelligence",
        "attack_techniques": ["T1021.001", "T1021.004"],
        "engagement_goals": [
            "Detect lateral movement attempts early",
            "Identify stolen credentials in use",
            "Map attacker movement patterns",
            "Collect tools used for pivoting"
        ],
        "deception_tactics": [
            "Deploy decoy credentials on systems",
            "Create fake network shares and services",
            "Implement honeytokens in authentication systems",
            "Place decoy files with tracking capabilities"
        ],
        "implementation_examples": [
            "Active Directory honeytokens",
            "Fake SMB shares with monitoring",
            "Decoy SSH keys and certificates",
            "Honeypot database servers"
        ],
        "success_metrics": [
            "Lateral movement attempts detected",
            "Stolen credentials identified",
            "Attacker path mapping success",
            "Tool and technique attribution"
        ],
        "risk_level": "MEDIUM",
        "resource_requirements": "HIGH"
    },

    "privilege_escalation": {
        "engage_id": "ENG-PED-001",
        "engage_name": "Privilege Escalation Deception",
        "strategy": "Detect",
        "technique": "Elevation Decoys",
        "description": "Deploy deceptive privilege escalation opportunities to detect attempts and collect adversary techniques",
        "attack_techniques": ["T1548.003"],
        "engagement_goals": [
            "Detect privilege escalation attempts",
            "Identify escalation techniques and tools",
            "Collect malware samples and scripts",
            "Analyze attacker methodology"
        ],
        "deception_tactics": [
            "Deploy decoy sudo configurations",
            "Create fake privileged accounts",
            "Place vulnerable binaries with monitoring",
            "Implement fake configuration files"
        ],
        "implementation_examples": [
            "Decoy sudoers entries with logging",
            "Fake service configurations",
            "Honeytoken system binaries",
            "Decoy cron job entries"
        ],
        "success_metrics": [
            "Privilege escalation attempts detected",
            "Unique escalation techniques observed",
            "Malware samples collected",
            "Attacker methodology analysis"
        ],
        "risk_level": "MEDIUM",
        "resource_requirements": "MEDIUM"
    }
}


def get_engage_info(threat_type: str) -> dict:
    """
    Return the full MITRE Engage entry for a given threat type.
    threat_type: one of brute_force | port_scan | lateral_movement | privilege_escalation
    """
    entry = MITRE_ENGAGE_MAP.get(threat_type)
    if not entry:
        return {
            "engage_id": "ENG-UNKNOWN",
            "engage_name": "Unknown Engagement",
            "strategy": "Unknown",
            "technique": "Unknown Technique",
            "description": f"No Engage mapping found for threat type: {threat_type}",
            "attack_techniques": [],
            "engagement_goals": [],
            "deception_tactics": [],
            "implementation_examples": [],
            "success_metrics": [],
            "risk_level": "UNKNOWN",
            "resource_requirements": "UNKNOWN"
        }
    return entry


def get_engage_deception_tactics(threat_type: str) -> list:
    """Return deception tactics for a threat type."""
    info = get_engage_info(threat_type)
    return info.get("deception_tactics", [])


def get_engage_success_metrics(threat_type: str) -> list:
    """Return success metrics for engagement techniques."""
    info = get_engage_info(threat_type)
    return info.get("success_metrics", [])


def get_all_engage_mappings() -> list:
    """Return all Engage mappings as a list for API consumption."""
    result = []
    for threat_type, data in MITRE_ENGAGE_MAP.items():
        result.append({
            "threat_type": threat_type,
            **data
        })
    return result


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    print("=== MITRE Engage Adversary Engagement Mappings ===\n")
    for t in MITRE_ENGAGE_MAP:
        info = get_engage_info(t)
        print(f"[{info['engage_id']}] {info['engage_name']}")
        print(f"  Strategy: {info['strategy']} - {info['technique']}")
        print(f"  Risk Level: {info['risk_level']}")
        print(f"  Engagement Goals: {len(info['engagement_goals'])} objectives")
        print()
