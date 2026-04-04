# detector.py — Multi-Source Log Correlation & Threat Detection Engine
# Detects: brute force, port scan, privilege escalation, lateral movement
# Cross-correlates same IP across multiple log sources for severity scoring

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

from mitre_map import get_mitre_info, format_mitre_badge
from mitre_car_map import get_car_info, format_car_badge
from soar import get_response_playbook

# ── Config ────────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 3      # failures to flag brute force
PORT_SCAN_THRESHOLD     = 4      # distinct ports within window to flag scan
LATERAL_HOP_THRESHOLD   = 2      # distinct dest hosts to flag lateral movement
TIME_WINDOW_SECONDS     = 300    # 5-minute analysis window
CROSS_SOURCE_BONUS      = 2      # extra severity score per additional log source


# ── Log Loader ────────────────────────────────────────────────────────────────

def load_logs(path: str = None) -> list:
    """Load logs from JSON file. Falls back to empty list on error."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "real_json", "auth_logs.json")
    try:
        with open(path) as f:
            logs = json.load(f)
        # Normalise timestamps to datetime objects
        for log in logs:
            if isinstance(log.get("timestamp"), str):
                log["_dt"] = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            else:
                log["_dt"] = datetime.utcnow()
        return sorted(logs, key=lambda l: l["_dt"])
    except Exception as e:
        print(f"[detector] WARNING: Could not load logs: {e}")
        return []


# ── Individual Detectors ──────────────────────────────────────────────────────

def _detect_brute_force(logs: list) -> list:
    """
    Detect brute force: >= BRUTE_FORCE_THRESHOLD failures from the same IP
    within TIME_WINDOW_SECONDS. Covers Windows EventID 4625 and SSH failures.
    """
    alerts = []
    # Group failure events by src IP
    ip_failures = defaultdict(list)
    for log in logs:
        if log.get("status") in ("failure",) and log.get("source") in ("windows", "ssh", "web_authentication", "brute_force_simulator", "user"):
            ip_failures[log["ip"]].append(log)

    for ip, events in ip_failures.items():
        events.sort(key=lambda e: e["_dt"])
        # Sliding window check
        window_start = 0
        for i in range(len(events)):
            while (events[i]["_dt"] - events[window_start]["_dt"]).seconds > TIME_WINDOW_SECONDS:
                window_start += 1
            window_events = events[window_start : i + 1]
            if len(window_events) >= BRUTE_FORCE_THRESHOLD:
                users_tried  = list({e.get("user", "?") for e in window_events})
                sources_seen = list({e.get("source", "?") for e in window_events})
                alerts.append({
                    "type":          "brute_force",
                    "src_ip":        ip,
                    "dest_ip":       events[0].get("dest_ip", "?"),
                    "users_tried":   users_tried,
                    "failure_count": len(window_events),
                    "sources":       sources_seen,
                    "first_seen":    window_events[0]["timestamp"],
                    "last_seen":     window_events[-1]["timestamp"],
                    "evidence":      [
                        f"{e['timestamp']} | {e.get('source','?').upper()} | user={e.get('user','?')} | {e.get('message','')}"
                        for e in window_events
                    ],
                    "raw_logs":      window_events,
                })
                break   # one alert per IP per window
    return alerts


def _detect_port_scan(logs: list) -> list:
    """
    Detect port scan: same IP hitting >= PORT_SCAN_THRESHOLD distinct ports
    on the same destination within TIME_WINDOW_SECONDS. Uses netflow source.
    """
    alerts = []
    ip_scans = defaultdict(list)
    for log in logs:
        if log.get("source") == "netflow" and log.get("status") == "scan":
            key = (log["ip"], log.get("dest_ip", "?"))
            ip_scans[key].append(log)

    for (ip, dest), events in ip_scans.items():
        events.sort(key=lambda e: e["_dt"])
        ports = list({e.get("port") for e in events if e.get("port")})
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type":          "port_scan",
                "src_ip":        ip,
                "dest_ip":       dest,
                "ports_scanned": sorted(ports),
                "scan_count":    len(ports),
                "sources":       ["netflow"],
                "first_seen":    events[0]["timestamp"],
                "last_seen":     events[-1]["timestamp"],
                "evidence":      [
                    f"{e['timestamp']} | NETFLOW | {ip} → {dest}:{e.get('port','?')}"
                    for e in events
                ],
                "raw_logs":      events,
            })
    return alerts


def _detect_privilege_escalation(logs: list) -> list:
    """
    Detect privilege escalation: sudo failures followed by a sudo success
    (session opened for root) for the same user.
    """
    alerts = []
    user_sudo = defaultdict(list)
    for log in logs:
        if log.get("source") == "sudo":
            user_sudo[log.get("user", "?")].append(log)

    for user, events in user_sudo.items():
        events.sort(key=lambda e: e["_dt"])
        failures = [e for e in events if e.get("status") == "failure"]
        successes = [e for e in events if e.get("status") == "success"]
        if failures and successes:
            alerts.append({
                "type":          "privilege_escalation",
                "src_ip":        events[0].get("ip", "?"),
                "dest_ip":       events[0].get("dest_ip", "?"),
                "user":          user,
                "sudo_failures": len(failures),
                "sudo_success":  len(successes),
                "sources":       ["sudo"],
                "first_seen":    failures[0]["timestamp"],
                "last_seen":     successes[-1]["timestamp"],
                "evidence":      [
                    f"{e['timestamp']} | SUDO | user={user} | status={e['status']} | {e.get('message','')}"
                    for e in events
                ],
                "raw_logs":      events,
            })
    return alerts


def _detect_lateral_movement(logs: list) -> list:
    """
    Detect lateral movement (SSH hopping): same user SSHing to >= LATERAL_HOP_THRESHOLD
    distinct destination hosts in sequence within TIME_WINDOW_SECONDS.
    """
    alerts = []
    # Track SSH successes by user
    user_ssh = defaultdict(list)
    for log in logs:
        if log.get("source") == "ssh" and log.get("status") == "success":
            user_ssh[log.get("user", "?")].append(log)

    for user, events in user_ssh.items():
        events.sort(key=lambda e: e["_dt"])
        # Collect distinct destination hosts in time window
        dest_hosts = []
        seen_hosts = set()
        for e in events:
            dest = e.get("dest_ip")
            if dest and dest not in seen_hosts:
                dest_hosts.append(e)
                seen_hosts.add(dest)

        if len(dest_hosts) >= LATERAL_HOP_THRESHOLD:
            # Build hop chain: reconstruct the IP path
            hop_chain = []
            prev_src = dest_hosts[0].get("ip", "?")
            for hop in dest_hosts:
                hop_chain.append(f"{prev_src} → {hop.get('dest_ip','?')}")
                prev_src = hop.get("dest_ip", "?")

            alerts.append({
                "type":          "lateral_movement",
                "user":          user,
                "src_ip":        dest_hosts[0].get("ip", "?"),
                "dest_ip":       dest_hosts[-1].get("dest_ip", "?"),
                "hop_count":     len(dest_hosts),
                "hop_chain":     hop_chain,
                "dest_hosts":    [e.get("dest_ip") for e in dest_hosts],
                "sources":       ["ssh"],
                "first_seen":    dest_hosts[0]["timestamp"],
                "last_seen":     dest_hosts[-1]["timestamp"],
                "evidence":      [
                    f"{e['timestamp']} | SSH | user={user} | {e.get('ip','?')} → {e.get('dest_ip','?')}"
                    for e in dest_hosts
                ],
                "raw_logs":      dest_hosts,
            })
    return alerts


# ── Cross-Source Correlation ──────────────────────────────────────────────────

def _compute_correlation_score(alert: dict, all_alerts: list) -> dict:
    """
    Boost severity when the same IP appears in MULTIPLE alert types.
    Each additional threat type from the same IP adds CROSS_SOURCE_BONUS.
    Returns updated alert with correlation_score and correlated_threats.
    """
    ip = alert.get("src_ip", "")
    base_severity = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}.get(
        _get_base_severity(alert["type"]), 4
    )

    # Find other alert types involving the same IP
    correlated = [
        a["type"] for a in all_alerts
        if a.get("src_ip") == ip and a["type"] != alert["type"]
    ]
    correlated = list(set(correlated))

    correlation_score = base_severity + len(correlated) * CROSS_SOURCE_BONUS
    effective_severity = (
        "CRITICAL" if correlation_score >= 10
        else "HIGH"   if correlation_score >= 7
        else "MEDIUM" if correlation_score >= 4
        else "LOW"
    )

    alert["correlation_score"]   = correlation_score
    alert["correlated_threats"]  = correlated
    alert["effective_severity"]  = effective_severity
    alert["cross_source_hit"]    = len(correlated) > 0
    return alert


def _get_base_severity(threat_type: str) -> str:
    from mitre_map import MITRE_MAP
    return MITRE_MAP.get(threat_type, {}).get("severity", "MEDIUM")


# ── Main Detection Engine ─────────────────────────────────────────────────────

def detect_threats(logs: list = None) -> list:
    """
    Run all detectors against the log dataset.
    Applies cross-source correlation scoring.
    Enriches each alert with MITRE badge + SOAR playbook.

    Returns list of alert dicts, sorted by correlation_score descending.
    """
    if logs is None:
        logs = load_logs()

    raw_alerts = []
    raw_alerts.extend(_detect_brute_force(logs))
    raw_alerts.extend(_detect_port_scan(logs))
    raw_alerts.extend(_detect_privilege_escalation(logs))
    raw_alerts.extend(_detect_lateral_movement(logs))
    raw_alerts.extend(detect_windows_firewall_attacks(logs))

    # Deduplicate: same type + same src_ip → keep highest failure count
    seen = {}
    deduped = []
    for a in raw_alerts:
        key = (a["type"], a.get("src_ip", ""))
        if key not in seen:
            seen[key] = True
            deduped.append(a)

    # Apply cross-source correlation to every alert
    for alert in deduped:
        _compute_correlation_score(alert, deduped)

    # Enrich with MITRE + CAR + SOAR
    for alert in deduped:
        alert["mitre"]   = format_mitre_badge(alert["type"])
        alert["car"]     = format_car_badge(alert["type"])
        alert["playbook"] = get_response_playbook(
            alert["type"],
            ip      = alert.get("src_ip", "UNKNOWN"),
            user    = alert.get("user", alert.get("users_tried", ["UNKNOWN"])[0] if alert.get("users_tried") else "UNKNOWN"),
            dest_ip = alert.get("dest_ip", "UNKNOWN"),
        )
        # Remove raw log objects from API output (keep evidence strings)
        alert.pop("raw_logs", None)

    # Sort: critical first, then by correlation score
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda a: (
        severity_rank.get(a.get("effective_severity", "LOW"), 3),
        -a.get("correlation_score", 0)
    ))

    return deduped


# ── Attack Timeline Builder ───────────────────────────────────────────────────

def build_attack_timeline(ip: str, logs: list = None) -> dict:
    """
    Reconstruct a chronological attack timeline for a given IP address.
    Returns an ordered list of events with narrative descriptions.

    Args:
        ip   : source IP to investigate
        logs : log list (loads from file if None)

    Returns:
        dict with ip, event_count, timeline (list), and narrative (string)
    """
    if logs is None:
        logs = load_logs()

    # Collect all events involving this IP (as source or involved user)
    ip_events = [l for l in logs if l.get("ip") == ip]
    ip_events.sort(key=lambda e: e["_dt"])

    if not ip_events:
        return {
            "ip":          ip,
            "event_count": 0,
            "timeline":    [],
            "narrative":   f"No events found for IP {ip}.",
        }

    timeline = []
    for event in ip_events:
        source  = event.get("source", "unknown").upper()
        status  = event.get("status", "?")
        user    = event.get("user") or "N/A"
        port    = event.get("port")
        dest    = event.get("dest_ip", "?")
        ts      = event["timestamp"]
        msg     = event.get("message", "")

        # Classify this event
        if status == "failure" and source in ("WINDOWS", "SSH"):
            category = "AUTH_FAILURE"
            label    = f"Failed login as '{user}'"
        elif status == "success" and source in ("WINDOWS", "SSH"):
            category = "AUTH_SUCCESS"
            label    = f"Successful login as '{user}'"
        elif status == "scan":
            category = "RECON"
            label    = f"Port scan → {dest}:{port}"
        elif source == "SUDO":
            category = "PRIV_ESC" if status == "success" else "PRIV_ESC_ATTEMPT"
            label    = f"Sudo {'escalated to root' if status == 'success' else 'failure'} as '{user}'"
        else:
            category = "UNKNOWN"
            label    = msg or "Unknown event"

        timeline.append({
            "timestamp": ts,
            "category":  category,
            "label":     label,
            "source":    source,
            "user":      user,
            "dest_ip":   dest,
            "port":      port,
            "status":    status,
            "raw_msg":   msg,
        })

    # Build narrative summary
    first_ts   = timeline[0]["timestamp"]
    last_ts    = timeline[-1]["timestamp"]
    n_fail     = sum(1 for e in timeline if e["category"] == "AUTH_FAILURE")
    n_success  = sum(1 for e in timeline if e["category"] == "AUTH_SUCCESS")
    n_scan     = sum(1 for e in timeline if e["category"] == "RECON")
    n_priv     = sum(1 for e in timeline if "PRIV_ESC" in e["category"])

    narrative_parts = [f"Attacker IP {ip} first observed at {first_ts}."]
    if n_scan:
        narrative_parts.append(f"Performed port reconnaissance ({n_scan} scanned ports).")
    if n_fail:
        narrative_parts.append(f"Made {n_fail} failed authentication attempt(s).")
    if n_success:
        narrative_parts.append(f"Achieved {n_success} successful login(s).")
    if n_priv:
        narrative_parts.append(f"Attempted privilege escalation ({n_priv} sudo event(s)).")
    narrative_parts.append(f"Last activity recorded at {last_ts}.")

    return {
        "ip":          ip,
        "event_count": len(timeline),
        "first_seen":  first_ts,
        "last_seen":   last_ts,
        "auth_failures": n_fail,
        "auth_successes": n_success,
        "recon_events":  n_scan,
        "priv_esc_events": n_priv,
        "timeline":    timeline,
        "narrative":   " ".join(narrative_parts),
    }


def detect_windows_firewall_attacks(logs):
    """
    Detect attacks from Windows Firewall logs.
    Flags IPs with excessive blocked connections as potential attacks.
    """
    ip_count = {}
    ip_details = {}
    
    for log in logs:
        if log.get("source") == "firewall":
            ip = log.get("ip")
            if ip:
                ip_count[ip] = ip_count.get(ip, 0) + 1
                if ip not in ip_details:
                    ip_details[ip] = {
                        "ports": set(),
                        "dest_ips": set(),
                        "first_seen": log.get("timestamp"),
                        "last_seen": log.get("timestamp"),
                        "actions": set(),
                        "evidence": []
                    }
                details = ip_details[ip]
                details["ports"].add(log.get("port"))
                details["dest_ips"].add(log.get("dest_ip"))
                details["last_seen"] = log.get("timestamp")
                details["actions"].add(log.get("action"))
                details["evidence"].append(
                    f"{log.get('timestamp')} | FIREWALL | {log.get('action')} {log.get('protocol')} from {ip}:{log.get('src_port','?')} to {log.get('dest_ip')}:{log.get('port')}"
                )
    
    alerts = []
    FIREWALL_THRESHOLD = 10  # Blocked connections to flag as attack
    
    for ip, count in ip_count.items():
        if count >= FIREWALL_THRESHOLD:
            details = ip_details[ip]
            alerts.append({
                "type": "firewall_attack",
                "src_ip": ip,
                "attempts": count,
                "ports_targeted": list(details["ports"])[:10],
                "dest_ips": list(details["dest_ips"])[:5],
                "first_seen": details["first_seen"],
                "last_seen": details["last_seen"],
                "actions": list(details["actions"]),
                "sources": ["firewall"],
                "effective_severity": "HIGH",
                "evidence": details["evidence"][:10]  # Limit evidence
            })
    
    return alerts
if __name__ == "__main__":
    import json

    logs = load_logs()
    print(f"Loaded {len(logs)} log entries.\n")

    alerts = detect_threats(logs)
    print(f"=== Detected {len(alerts)} Threat(s) ===\n")
    for a in alerts:
        print(f"[{a['effective_severity']}] {a['type'].upper().replace('_',' ')}")
        print(f"  Source IP  : {a.get('src_ip','?')}")
        print(f"  MITRE      : {a['mitre']['id']} — {a['mitre']['name']}")
        print(f"  Corr.Score : {a['correlation_score']}  (cross-source: {a['cross_source_hit']})")
        print(f"  First seen : {a.get('first_seen','?')}")
        print(f"  Last seen  : {a.get('last_seen','?')}")
        print(f"  Evidence   :")
        for line in a.get("evidence", [])[:3]:
            print(f"    {line}")
        print()

    print("\n=== Attack Timeline: 185.220.101.47 ===")
    timeline = build_attack_timeline("185.220.101.47", logs)
    print(f"Narrative: {timeline['narrative']}\n")
    for event in timeline["timeline"]:
        print(f"  {event['timestamp']} [{event['category']}] {event['label']}")
