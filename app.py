# app.py — Flask API Server — CyberSentinel SOC Co-Pilot
# All routes the frontend calls via fetch()

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import os
import threading
import time
from datetime import datetime

from detector import detect_threats, build_attack_timeline, load_logs, detect_windows_firewall_attacks
from windows_firewall_monitor import monitor, get_firewall_stats, read_all_logs
from mitre_map import get_all_mappings, get_mitre_info
from mitre_car_map import get_all_car_mappings, get_car_info
from mitre_d3fend_map import get_all_d3fend_mappings, get_d3fend_info
from mitre_engage_map import get_all_engage_mappings, get_engage_info
from mitre_framework_analyzer import MITREFrameworkAnalyzer
from soar import get_response_playbook, get_all_playbook_names
from Brute_force.brute_force_attack import brute_force_instance
from llm import llm_bp 
app = Flask(__name__, template_folder='templates')
CORS(app)   # Allow frontend on different port during dev

# Register LLM chatbot blueprint
app.register_blueprint(llm_bp)

# Firewall log storage
_FIREWALL_LOGS = []

def handle_firewall_log(log):
    """Callback for new firewall log entries"""
    global _FIREWALL_LOGS, _LOGS
    _FIREWALL_LOGS.append(log)
    _LOGS.append(log)  # Add to main logs for unified analysis
    print(f"[Firewall] {log['action']} from {log['ip']} to port {log['port']}")

def start_firewall_monitor():
    """Start Windows Firewall log monitoring in background thread"""
    def run_monitor():
        # First load existing logs
        existing = read_all_logs()
        global _FIREWALL_LOGS, _LOGS
        _FIREWALL_LOGS.extend(existing)
        _LOGS.extend(existing)
        print(f"[Firewall] Loaded {len(existing)} existing firewall logs")
        
        # Start real-time monitoring
        monitor(handle_firewall_log)
    
    thread = threading.Thread(target=run_monitor, daemon=True)
    thread.start()
    print("[Firewall] Real-time monitoring thread started")
_LOGS = []

def get_logs():
    """Get all logs including real-time firewall updates"""
    global _LOGS
    if not _LOGS:
        # Initial load: auth logs + firewall logs
        auth_logs = load_logs()
        firewall_logs = read_all_logs()
        _LOGS = auth_logs + firewall_logs
    return _LOGS

def append_auth_log(log_entry):
    """Append authentication log to the real_json/auth_logs.json file and update cache"""
    global _LOGS
    logs_path = os.path.join(os.path.dirname(__file__), "real_json", "auth_logs.json")
    
    try:
        # Load existing auth logs
        with open(logs_path, 'r') as f:
            logs = json.load(f)
        
        # Generate new ID
        new_id = max([log.get('id', 0) for log in logs], default=0) + 1
        log_entry['id'] = new_id
        
        # Add timestamp in required format
        if 'timestamp' in log_entry:
            dt = datetime.fromisoformat(log_entry['timestamp'].replace('Z', '+00:00'))
            log_entry['timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Append to logs
        logs.append(log_entry)
        
        # Save back to file
        with open(logs_path, 'w') as f:
            json.dump(logs, f, indent=2)
        
        # Update cache
        _LOGS.append(log_entry)
        
        print(f"[app] Auth log stored: ID {new_id}, User: {log_entry.get('user')}, Status: {log_entry.get('status')}")
        return True
    except Exception as e:
        print(f"[app] ERROR: Could not append auth log: {e}")
        return False
    return True


# ── Page Route ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("mitre_dashboard.html")


@app.route("/login")
def login():
    return render_template("frontend/login.html")


@app.route("/brute-force")
def brute_force_dashboard():
    return render_template("Brute_force/brute_force_dashboard.html")


@app.route("/chatbot")
def chatbot_page():
    return render_template("chatbot.html")


@app.route("/firewall-logs")
def firewall_logs_page():
    return render_template("firewall_logs.html")


# ── POST /api/auth/log ───────────────────────────────────────────────────────────
# Receive and store authentication logs from login.html
@app.route("/api/auth/log", methods=["POST"])
def api_auth_log():
    body = request.get_json(force=True)
    
    if not body:
        return jsonify({"error": "No log data provided"}), 400
    
    # Validate required fields
    required_fields = ["timestamp", "source", "user", "ip", "status", "message"]
    missing_fields = [field for field in required_fields if field not in body]
    
    if missing_fields:
        return jsonify({"error": f"Missing required fields: {missing_fields}"}), 400
    
    # Append to logs
    success = append_auth_log(body)
    
    if success:
        return jsonify({
            "status": "success", 
            "message": "Authentication log recorded",
            "log_id": body.get('id')
        }), 200
    else:
        return jsonify({"error": "Failed to store authentication log"}), 500


# ── GET /api/auth/logs ───────────────────────────────────────────────────────────
# Returns only web authentication logs from real_json/auth_logs.json
@app.route("/api/auth/logs", methods=["GET"])
def api_auth_logs():
    auth_logs_path = os.path.join(os.path.dirname(__file__), "real_json", "auth_logs.json")
    
    try:
        with open(auth_logs_path, 'r') as f:
            auth_logs = json.load(f)
        
        # Sort by timestamp descending (newest first)
        auth_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify({"count": len(auth_logs), "logs": auth_logs})
    except Exception as e:
        print(f"[app] ERROR: Could not load auth logs: {e}")
        return jsonify({"count": 0, "logs": []})


# ── GET /api/logs ─────────────────────────────────────────────────────────────
# Returns all log entries (minus internal _dt field)
@app.route("/api/logs", methods=["GET"])
def api_logs():
    logs = get_logs()
    source  = request.args.get("source")   # ?source=ssh
    status  = request.args.get("status")   # ?status=failure
    ip      = request.args.get("ip")       # ?ip=185.220.101.47

    filtered = logs
    if source:
        filtered = [l for l in filtered if l.get("source") == source]
    if status:
        filtered = [l for l in filtered if l.get("status") == status]
    if ip:
        filtered = [l for l in filtered if l.get("ip") == ip]

    # Strip internal _dt objects before JSON serialisation
    clean = [{k: v for k, v in l.items() if k != "_dt"} for l in filtered]
    return jsonify({"count": len(clean), "logs": clean})


# ── GET /api/alerts ───────────────────────────────────────────────────────────
# Runs the full detection engine and returns all alerts
@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    logs   = get_logs()
    alerts = detect_threats(logs)
    return jsonify({
        "count":  len(alerts),
        "alerts": alerts,
    })


# ── POST /api/query ───────────────────────────────────────────────────────────
# Natural language query — simple keyword router
# In full project: delegates to ollama_client.py ask_llama()
@app.route("/api/query", methods=["POST"])
def api_query():
    body    = request.get_json(force=True)
    query   = body.get("query", "").strip()

    if not query:
        return jsonify({"error": "query field is required"}), 400

    logs   = get_logs()
    alerts = detect_threats(logs)

    lower = query.lower()
    result = {}

    if any(k in lower for k in ["failed", "failure", "brute"]):
        failures = [l for l in logs if l.get("status") == "failure"]
        result = {
            "answer": f"Found {len(failures)} failed login events in the log database.",
            "data":   [{k: v for k, v in l.items() if k != "_dt"} for l in failures],
            "type":   "log_filter",
        }

    elif any(k in lower for k in ["suspicious", "threat", "attack", "alert"]):
        result = {
            "answer": f"Detected {len(alerts)} active threats: " +
                      ", ".join(a["type"].replace("_", " ") for a in alerts),
            "data":   alerts,
            "type":   "threat_list",
        }

    elif any(k in lower for k in ["timeline", "history", "reconstruct"]):
        # Try to extract IP from query
        import re
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", query)
        if ip_match:
            ip = ip_match.group(1)
        else:
            # Default to top threat IP
            ip = alerts[0]["src_ip"] if alerts else "UNKNOWN"
        tl = build_attack_timeline(ip, logs)
        result = {
            "answer": tl["narrative"],
            "data":   tl,
            "type":   "timeline",
        }

    elif any(k in lower for k in ["summarize", "summary", "overview", "report"]):
        sources = list({l.get("source") for l in logs})
        result = {
            "answer": (
                f"Log database contains {len(logs)} events across {len(sources)} sources "
                f"({', '.join(sources)}). "
                f"Detected {len(alerts)} threats. "
                f"Top threat: {alerts[0]['type'].replace('_',' ')} from {alerts[0]['src_ip']}."
                if alerts else f"No threats detected across {len(logs)} log events."
            ),
            "data":  {"log_count": len(logs), "alert_count": len(alerts), "sources": sources},
            "type":  "summary",
        }

    elif any(k in lower for k in ["mitre", "framework", "technique"]):
        result = {
            "answer": "Fetching MITRE ATT&CK mappings for all detected threat types.",
            "data":   get_all_mappings(),
            "type":   "mitre_list",
        }

    else:
        result = {
            "answer": (
                "I can help you with: failed logins, suspicious activity, attack timelines, "
                "log summaries, MITRE mappings, and SOAR playbooks. "
                "Try: 'Show failed logins', 'Any suspicious activity?', "
                "'Reconstruct timeline for 185.220.101.47', or 'Summarize logs'."
            ),
            "data":   None,
            "type":   "help",
        }

    result["query"] = query
    return jsonify(result)


# ── POST /api/investigate ─────────────────────────────────────────────────────
# Full investigation report for a given IP address
@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    body = request.get_json(force=True)
    ip   = body.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "ip field is required"}), 400

    logs        = get_logs()
    timeline    = build_attack_timeline(ip, logs)
    all_alerts  = detect_threats(logs)
    ip_alerts   = [a for a in all_alerts if a.get("src_ip") == ip]

    report = {
        "ip":          ip,
        "summary":     timeline["narrative"],
        "timeline":    timeline,
        "alerts":      ip_alerts,
        "mitre":       [get_mitre_info(a["type"]) for a in ip_alerts],
        "playbooks":   [
            get_response_playbook(a["type"], ip=ip,
                user=a.get("user", a.get("users_tried", ["?"])[0] if a.get("users_tried") else "?"),
                dest_ip=a.get("dest_ip", "?"))
            for a in ip_alerts
        ],
        "risk_score":  max((a.get("correlation_score", 0) for a in ip_alerts), default=0),
    }

    return jsonify(report)


# ── POST /api/block-ip ────────────────────────────────────────────────────────
# Simulated IP block — returns the SOAR block action
@app.route("/api/block-ip", methods=["POST"])
def api_block_ip():
    body = request.get_json(force=True)
    ip   = body.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "ip field is required"}), 400

    # In production: call firewall API here
    action = {
        "action":    "BLOCK_IP",
        "ip":        ip,
        "status":    "SIMULATED",
        "command":   f"iptables -I INPUT -s {ip} -j DROP",
        "message":   f"IP {ip} has been flagged for blocking. (Simulated — no real firewall call made.)",
    }
    return jsonify(action)


# ── GET /api/memory ───────────────────────────────────────────────────────────
# Returns investigation memory (past findings per IP)
@app.route("/api/memory", methods=["GET"])
def api_memory():
    memory_file = os.path.join(os.path.dirname(__file__), "data", "memory.json")
    if not os.path.exists(memory_file):
        return jsonify({"memory": {}})
    with open(memory_file) as f:
        memory = json.load(f)
    return jsonify({"memory": memory})


# ── GET /api/mitre ────────────────────────────────────────────────────────────
@app.route("/api/mitre", methods=["GET"])
def api_mitre():
    return jsonify({"mappings": get_all_mappings()})


# ── GET /api/mitre/car ─────────────────────────────────────────────────────────
@app.route("/api/mitre/car", methods=["GET"])
def api_mitre_car():
    return jsonify({"mappings": get_all_car_mappings()})


# ── GET /api/mitre/d3fend ───────────────────────────────────────────────────────
@app.route("/api/mitre/d3fend", methods=["GET"])
def api_mitre_d3fend():
    return jsonify({"mappings": get_all_d3fend_mappings()})


# ── GET /api/mitre/engage ───────────────────────────────────────────────────────
@app.route("/api/mitre/engage", methods=["GET"])
def api_mitre_engage():
    return jsonify({"mappings": get_all_engage_mappings()})


# ── GET /api/mitre/analyze/<threat_type> ───────────────────────────────────────────
@app.route("/api/mitre/analyze/<threat_type>", methods=["GET"])
def api_mitre_analyze(threat_type):
    analyzer = MITREFrameworkAnalyzer()
    analysis = analyzer.analyze_threat_across_frameworks(threat_type)
    return jsonify(analysis)


# ── POST /api/mitre/compare ───────────────────────────────────────────────────────
@app.route("/api/mitre/compare", methods=["POST"])
def api_mitre_compare():
    body = request.get_json(force=True)
    threat_types = body.get("threat_types", [])
    
    if not threat_types:
        return jsonify({"error": "threat_types array is required"}), 400
    
    analyzer = MITREFrameworkAnalyzer()
    comparison = analyzer.compare_threats_across_frameworks(threat_types)
    return jsonify(comparison)


# ── GET /api/mitre/summary ───────────────────────────────────────────────────────
@app.route("/api/mitre/summary", methods=["GET"])
def api_mitre_summary():
    analyzer = MITREFrameworkAnalyzer()
    summary = analyzer.get_framework_summary()
    return jsonify(summary)


# ── GET /api/playbooks ────────────────────────────────────────────────────────
@app.route("/api/playbooks", methods=["GET"])
def api_playbooks():
    return jsonify({"playbooks": get_all_playbook_names()})


# ── GET /api/timeline/<ip> ────────────────────────────────────────────────────
@app.route("/api/timeline/<path:ip>", methods=["GET"])
def api_timeline(ip):
    logs     = get_logs()
    timeline = build_attack_timeline(ip, logs)
    return jsonify(timeline)


# ── Brute Force API Endpoints ─────────────────────────────────────────────────────

@app.route("/api/brute-force/start", methods=["POST"])
def api_brute_force_start():
    """Start a brute force attack"""
    body = request.get_json(force=True)
    
    if not body:
        return jsonify({"success": False, "message": "No configuration provided"}), 400
    
    # Validate required fields
    required_fields = ["target_ip", "target_username", "password_method", "max_attempts"]
    missing_fields = [field for field in required_fields if field not in body]
    
    if missing_fields:
        return jsonify({
            "success": False, 
            "message": f"Missing required fields: {missing_fields}"
        }), 400
    
    # Start the attack
    success, message = brute_force_instance.start_attack(
        target_ip=body["target_ip"],
        target_username=body["target_username"],
        password_method=body["password_method"],
        max_attempts=body["max_attempts"]
    )
    
    return jsonify({
        "success": success,
        "message": message
    })


@app.route("/api/brute-force/stop", methods=["POST"])
def api_brute_force_stop():
    """Stop the current brute force attack"""
    success, message = brute_force_instance.stop_attack()
    
    return jsonify({
        "success": success,
        "message": message
    })


@app.route("/api/brute-force/status", methods=["GET"])
def api_brute_force_status():
    """Get the current status of the brute force attack"""
    return jsonify(brute_force_instance.get_stats())


# ── GET /api/firewall/stats ───────────────────────────────────────────────────
@app.route("/api/firewall/stats", methods=["GET"])
def api_firewall_stats():
    """Get Windows Firewall log statistics"""
    stats = get_firewall_stats()
    firewall_alerts = detect_windows_firewall_attacks(get_logs())
    return jsonify({
        "stats": stats,
        "alerts": firewall_alerts,
        "monitoring_active": True
    })


# ── GET /api/stats ────────────────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Get overall system statistics"""
    logs = get_logs()
    alerts = detect_threats(logs)
    firewall_stats = get_firewall_stats()
    
    # Count by source
    sources = {}
    for log in logs:
        src = log.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1
    
    # Count by status
    statuses = {}
    for log in logs:
        status = log.get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1
    
    # Severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in alerts:
        sev = alert.get("effective_severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return jsonify({
        "logs": {
            "total": len(logs),
            "by_source": sources,
            "by_status": statuses
        },
        "alerts": {
            "total": len(alerts),
            "by_severity": severity_counts
        },
        "firewall": {
            "monitoring_active": True,
            "firewall_entries": firewall_stats.get("total_entries", 0),
            "blocked": firewall_stats.get("blocked", 0)
        },
        "timestamp": datetime.now().isoformat()
    })


# ── Health check ──────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def api_health():
    logs = get_logs()
    return jsonify({
        "status":    "ok",
        "log_count": len(logs),
        "version":   "1.0.0",
    })


# ── Boot ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== CyberSentinel SOC Co-Pilot API ===")
    print(f"Loaded {len(get_logs())} log entries")
    
    # Start Windows Firewall monitoring
    start_firewall_monitor()
    
    app.run(host="0.0.0.0", port=5000, debug=True)
