# mitre_car_map.py — MITRE CAR (Cyber Analytics Repository) Framework Mapping
# Maps detected threat types to MITRE CAR analytics and detection methods

MITRE_CAR_MAP = {
    "brute_force": {
        "analytics_id": "CAR-2023-01-001",
        "analytics_name": "Brute Force Attack Detection",
        "hypothesis": "An adversary is attempting to gain access to accounts by systematically trying many passwords until the correct one is found",
        "information_domain": "host",
        "attack_techniques": ["T1110.001", "T1110.003"],
        "attack_tactics": ["Credential Access"],
        "pseudocode": """
# Detect brute force attacks
# Look for multiple failed login attempts from same source within time window
failed_logins = filter logs where status = "failure"
group_by_source = group failed_logins by src_ip, user
for each group in group_by_source:
    if count(group.events) >= BRUTE_FORCE_THRESHOLD and 
       time_window(group.events) <= TIME_WINDOW_SECONDS:
        generate_alert("brute_force", group.src_ip, group.user)
""",
        "unit_test": "Generate 5+ failed login events from same IP within 5 minutes",
        "data_sources": ["authentication_logs", "windows_event_logs", "ssh_logs"],
        "implementation": ["splunk", "eql", "python"],
        "confidence": "HIGH",
        "difficulty": "LOW"
    },

    "port_scan": {
        "analytics_id": "CAR-2023-02-001", 
        "analytics_name": "Network Service Scanning",
        "hypothesis": "An adversary is probing the network to enumerate open ports and running services to identify attack surface",
        "information_domain": "network",
        "attack_techniques": ["T1046"],
        "attack_tactics": ["Discovery"],
        "pseudocode": """
# Detect port scanning activity
# Look for connections to multiple distinct ports from same source
network_events = filter logs where source = "netflow"
group_by_source = group network_events by src_ip, dest_ip
for each group in group_by_source:
    unique_ports = count(distinct group.events.port)
    if unique_ports >= PORT_SCAN_THRESHOLD and 
       time_window(group.events) <= TIME_WINDOW_SECONDS:
        generate_alert("port_scan", group.src_ip, group.dest_ip)
""",
        "unit_test": "Generate connections to 5+ different ports from same IP within 2 minutes",
        "data_sources": ["netflow", "firewall_logs", "zeek_conn"],
        "implementation": ["zeek", "splunk", "eql"],
        "confidence": "MEDIUM",
        "difficulty": "LOW"
    },

    "lateral_movement": {
        "analytics_id": "CAR-2023-03-001",
        "analytics_name": "Lateral Movement Detection via SSH",
        "hypothesis": "An adversary is using valid credentials to move laterally across systems via SSH or other remote services",
        "information_domain": "host",
        "attack_techniques": ["T1021.001", "T1021.004"],
        "attack_tactics": ["Lateral Movement"],
        "pseudocode": """
# Detect lateral movement
# Look for same user authenticating to multiple distinct hosts
successful_logins = filter logs where status = "success" and source in ["ssh", "windows"]
group_by_user = group successful_logins by user, src_ip
for each group in group_by_user:
    unique_dest_hosts = count(distinct group.events.dest_ip)
    if unique_dest_hosts >= LATERAL_HOP_THRESHOLD and 
       time_window(group.events) <= TIME_WINDOW_SECONDS:
        generate_alert("lateral_movement", group.user, group.src_ip)
""",
        "unit_test": "Generate successful logins for same user from 3+ different hosts within 10 minutes",
        "data_sources": ["ssh_logs", "windows_event_logs", "authentication_logs"],
        "implementation": ["splunk", "eql", "python"],
        "confidence": "HIGH", 
        "difficulty": "MEDIUM"
    },

    "privilege_escalation": {
        "analytics_id": "CAR-2023-04-001",
        "analytics_name": "Privilege Escalation via Sudo Abuse",
        "hypothesis": "An adversary is abusing sudo or similar mechanisms to gain elevated privileges on a compromised host",
        "information_domain": "host",
        "attack_techniques": ["T1548.003"],
        "attack_tactics": ["Privilege Escalation"],
        "pseudocode": """
# Detect privilege escalation
# Look for sudo failures followed by successful sudo session
sudo_events = filter logs where source = "sudo"
group_by_user = group sudo_events by user, src_ip
for each group in group_by_user:
    failures = filter group.events where status = "failure"
    successes = filter group.events where status = "success"
    if count(failures) >= 1 and count(successes) >= 1 and
       time_between(first(failures), first(successes)) <= TIME_WINDOW_SECONDS:
        generate_alert("privilege_escalation", group.user, group.src_ip)
""",
        "unit_test": "Generate sudo failures followed by successful sudo for root access",
        "data_sources": ["sudo_logs", "auth_logs", "audit_logs"],
        "implementation": ["splunk", "eql", "python"],
        "confidence": "CRITICAL",
        "difficulty": "MEDIUM"
    }
}


def get_car_info(threat_type: str) -> dict:
    """
    Return the full MITRE CAR entry for a given threat type.
    threat_type: one of brute_force | port_scan | lateral_movement | privilege_escalation
    """
    entry = MITRE_CAR_MAP.get(threat_type)
    if not entry:
        return {
            "analytics_id": "CAR-UNKNOWN",
            "analytics_name": "Unknown Analytic",
            "hypothesis": f"No CAR mapping found for threat type: {threat_type}",
            "information_domain": "unknown",
            "attack_techniques": [],
            "attack_tactics": [],
            "pseudocode": "# No analytic available",
            "unit_test": "No test available",
            "data_sources": [],
            "implementation": [],
            "confidence": "LOW",
            "difficulty": "UNKNOWN"
        }
    return entry


def get_car_detection_methods(threat_type: str) -> list:
    """Return available detection implementations for a threat type."""
    info = get_car_info(threat_type)
    return info.get("implementation", [])


def get_car_data_sources(threat_type: str) -> list:
    """Return required data sources for CAR analytic detection."""
    info = get_car_info(threat_type)
    return info.get("data_sources", [])


def get_all_car_mappings() -> list:
    """Return all CAR mappings as a list for API consumption."""
    result = []
    for threat_type, data in MITRE_CAR_MAP.items():
        result.append({
            "threat_type": threat_type,
            **data
        })
    return result


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    print("=== MITRE CAR Analytics Mappings ===\n")
    for t in MITRE_CAR_MAP:
        info = get_car_info(t)
        print(f"[{info['analytics_id']}] {info['analytics_name']}")
        print(f"  Hypothesis: {info['hypothesis'][:80]}...")
        print(f"  Domain: {info['information_domain']}")
        print(f"  Confidence: {info['confidence']}")
        print(f"  Data Sources: {', '.join(info['data_sources'])}")
        print()
