# app.py — Flask API Server — CyberSentinel SOC Co-Pilot
# All routes the frontend calls via fetch()

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import os

from detector import detect_threats, build_attack_timeline, load_logs
from mitre_map import get_all_mappings, get_mitre_info
from mitre_car_map import get_all_car_mappings, get_car_info
from mitre_d3fend_map import get_all_d3fend_mappings, get_d3fend_info
from mitre_engage_map import get_all_engage_mappings, get_engage_info
from mitre_framework_analyzer import MITREFrameworkAnalyzer
from soar import get_response_playbook, get_all_playbook_names

app = Flask(__name__)
CORS(app)   # Allow frontend on different port during dev

# ── Cached log data (loaded once at startup) ──────────────────────────────────
_LOGS = []

def get_logs():
    global _LOGS
    if not _LOGS:
        _LOGS = load_logs()
    return _LOGS


# ── Page Route ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("mitre_dashboard.html")


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
    print(f"Loaded {len(get_logs())} log entries from data/logs.json")
    app.run(host="0.0.0.0", port=5000, debug=True)
