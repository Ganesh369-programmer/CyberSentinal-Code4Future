# soar.py — SOAR-like Automated Response Workflows
# Defines response playbooks for each threat type.
# Actions are simulated (no real firewall/AD integration) but structured
# exactly as they would be in a production SOAR platform.

import datetime
import json
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "data", "soar_actions.log")


# ── Action Definitions ────────────────────────────────────────────────────────

def _action(name: str, description: str, simulated_cmd: str, risk: str = "LOW") -> dict:
    """Helper to build a consistent action dict."""
    return {
        "action":       name,
        "description":  description,
        "command":      simulated_cmd,
        "risk":         risk,
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
        "status":       "SIMULATED",
    }


def action_block_ip(ip: str) -> dict:
    return _action(
        name="BLOCK_IP",
        description=f"Block all inbound/outbound traffic from {ip} at perimeter firewall.",
        simulated_cmd=f"iptables -I INPUT -s {ip} -j DROP && iptables -I OUTPUT -d {ip} -j DROP",
        risk="LOW",
    )


def action_notify_admin(ip: str, threat_type: str, severity: str) -> dict:
    return _action(
        name="NOTIFY_ADMIN",
        description=f"Send alert email/Slack to SOC team: {threat_type} detected from {ip} [{severity}].",
        simulated_cmd=f'curl -X POST $SLACK_WEBHOOK -d \'{{"text":"[{severity}] {threat_type} from {ip}"}}\'',
        risk="NONE",
    )


def action_isolate_host(dest_ip: str) -> dict:
    return _action(
        name="ISOLATE_HOST",
        description=f"Quarantine host {dest_ip} — cut network access, preserve forensic state.",
        simulated_cmd=f"ansible {dest_ip} -m command -a 'ip link set eth0 down'",
        risk="HIGH",
    )


def action_force_password_reset(user: str) -> dict:
    return _action(
        name="FORCE_PASSWORD_RESET",
        description=f"Force immediate password reset for account '{user}' across all systems.",
        simulated_cmd=f"net user {user} /logonpasswordchg:yes  # Windows\npasswd --expire {user}  # Linux",
        risk="MEDIUM",
    )


def action_kill_session(user: str, dest_ip: str) -> dict:
    return _action(
        name="KILL_SESSION",
        description=f"Terminate all active sessions for '{user}' on {dest_ip}.",
        simulated_cmd=f"pkill -u {user} -9  # on {dest_ip} via SSH",
        risk="MEDIUM",
    )


def action_capture_forensics(ip: str) -> dict:
    return _action(
        name="CAPTURE_FORENSICS",
        description=f"Collect memory dump, process list, and network connections from host targeted by {ip}.",
        simulated_cmd=f"volatility -f /proc/kcore --profile=LinuxX64 pslist > /forensics/{ip}_pslist.txt",
        risk="LOW",
    )


# ── Playbooks ─────────────────────────────────────────────────────────────────

PLAYBOOKS = {
    "brute_force": {
        "name":        "Brute Force Response",
        "description": "Automated response for repeated authentication failures from a single source IP.",
        "steps": lambda ip, user, dest_ip: [
            action_block_ip(ip),
            action_notify_admin(ip, "BRUTE_FORCE", "HIGH"),
            action_force_password_reset(user),
            action_capture_forensics(ip),
        ],
    },
    "port_scan": {
        "name":        "Network Scan Response",
        "description": "Automated response for reconnaissance / port scanning activity.",
        "steps": lambda ip, user, dest_ip: [
            action_block_ip(ip),
            action_notify_admin(ip, "PORT_SCAN", "MEDIUM"),
        ],
    },
    "lateral_movement": {
        "name":        "Lateral Movement Response",
        "description": "Automated response for SSH hopping / lateral movement across internal hosts.",
        "steps": lambda ip, user, dest_ip: [
            action_notify_admin(ip, "LATERAL_MOVEMENT", "HIGH"),
            action_kill_session(user, dest_ip),
            action_isolate_host(dest_ip),
            action_force_password_reset(user),
            action_capture_forensics(ip),
        ],
    },
    "privilege_escalation": {
        "name":        "Privilege Escalation Response",
        "description": "Automated response for sudo abuse / unauthorized root access.",
        "steps": lambda ip, user, dest_ip: [
            action_notify_admin(ip, "PRIVILEGE_ESCALATION", "CRITICAL"),
            action_kill_session(user, dest_ip),
            action_isolate_host(dest_ip),
            action_force_password_reset(user),
            action_block_ip(ip),
            action_capture_forensics(ip),
        ],
    },
}


def get_response_playbook(threat_type: str, ip: str = "UNKNOWN",
                           user: str = "UNKNOWN", dest_ip: str = "UNKNOWN") -> dict:
    """
    Return the full response playbook for a given threat type.

    Args:
        threat_type : one of brute_force | port_scan | lateral_movement | privilege_escalation
        ip          : source / attacker IP address
        user        : targeted or compromised username
        dest_ip     : destination host IP

    Returns:
        dict with playbook name, description, and list of action steps
    """
    playbook_def = PLAYBOOKS.get(threat_type)
    if not playbook_def:
        return {
            "name":        "Generic Response",
            "description": f"No specific playbook for: {threat_type}",
            "threat_type": threat_type,
            "steps": [
                action_notify_admin(ip, threat_type.upper(), "UNKNOWN"),
            ],
        }

    steps = playbook_def["steps"](ip, user, dest_ip)

    result = {
        "name":        playbook_def["name"],
        "description": playbook_def["description"],
        "threat_type": threat_type,
        "src_ip":      ip,
        "user":        user,
        "dest_ip":     dest_ip,
        "step_count":  len(steps),
        "steps":       steps,
        "executed_at": datetime.datetime.utcnow().isoformat() + "Z",
    }

    # Persist to log file (simulated audit trail)
    _log_playbook_execution(result)
    return result


def _log_playbook_execution(playbook: dict):
    """Append playbook execution to audit log."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps({
                "playbook":    playbook["name"],
                "threat_type": playbook["threat_type"],
                "src_ip":      playbook["src_ip"],
                "user":        playbook["user"],
                "executed_at": playbook["executed_at"],
            }) + "\n")
    except Exception:
        pass  # Never crash the main flow due to logging


def get_all_playbook_names() -> list:
    """Return available playbook names for API listing."""
    return [
        {"threat_type": k, "name": v["name"], "description": v["description"]}
        for k, v in PLAYBOOKS.items()
    ]


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    test_cases = [
        ("brute_force",        "185.220.101.47", "admin",    "10.0.0.5"),
        ("port_scan",          "91.121.23.66",   "UNKNOWN",  "10.0.0.5"),
        ("lateral_movement",   "172.16.5.10",    "mlee",     "10.0.0.20"),
        ("privilege_escalation","172.16.5.10",   "mlee",     "10.0.0.5"),
    ]

    for threat, ip, user, dest in test_cases:
        pb = get_response_playbook(threat, ip, user, dest)
        print(f"\n=== {pb['name']} ===")
        print(f"  Threat : {threat}")
        print(f"  Source : {ip} → {dest}")
        for i, step in enumerate(pb["steps"], 1):
            print(f"  Step {i}: [{step['action']}] {step['description'][:70]}")
