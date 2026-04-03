# app.py — Flask API Server — CyberSentinel SOC Co-Pilot
# All routes the frontend calls via fetch()

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import os
from datetime import datetime

from detector import detect_threats, build_attack_timeline, load_logs
from mitre_map import get_all_mappings, get_mitre_info
from mitre_car_map import get_all_car_mappings, get_car_info
from mitre_d3fend_map import get_all_d3fend_mappings, get_d3fend_info
from mitre_engage_map import get_all_engage_mappings, get_engage_info
from mitre_framework_analyzer import MITREFrameworkAnalyzer
from soar import get_response_playbook, get_all_playbook_names
from log_mitre_mapper import log_mitre_mapper
from nvdia_ai.ai_chat_interface import ai_chat_bp

app = Flask(__name__, template_folder='templates')
CORS(app)   # Allow frontend on different port during dev

# ── Cached log data (loaded once at startup) ──────────────────────────────────
_LOGS = []

def get_logs():
    global _LOGS
    if not _LOGS:
        # Load logs from auth_logs.json for MITRE mapping
        logs_path = os.path.join(os.path.dirname(__file__), "real_json", "auth_logs.json")
        try:
            with open(logs_path, 'r') as f:
                _LOGS = json.load(f)
            print(f"[app] Loaded {len(_LOGS)} log entries from auth_logs.json")
        except Exception as e:
            print(f"[app] WARNING: Could not load auth_logs.json: {e}")
            _LOGS = []
    return _LOGS

def get_system_logs():
    """Get system logs for main dashboard (from data/logs.json)"""
    return load_logs()

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

# Register AI chat blueprint
app.register_blueprint(ai_chat_bp, url_prefix='/ai')

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


@app.route("/mitre-mapping")
def mitre_mapping_dashboard():
    return render_template("mitre_mapping_dashboard.html")


@app.route("/ai-chat")
def ai_chat_dashboard():
    return render_template("ai_chat.html")


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


# ── GET /api/mitre-mappings ───────────────────────────────────────────────────
@app.route("/api/mitre-mappings", methods=["GET"])
def api_mitre_mappings():
    """Get MITRE framework mappings for current security logs"""
    logs = get_logs()
    mapper = log_mitre_mapper
    
    # Get all mappings for the logs
    mappings_summary = mapper.get_technique_summary(logs)
    
    # Get detailed technique information
    attack_techniques = {}
    car_analytics = {}
    d3fend_defenses = {}
    engage_techniques = {}
    
    for threat_type in mappings_summary['framework_coverage']['attack']:
        attack_info = get_mitre_info(threat_type)
        if attack_info:
            attack_techniques[threat_type] = attack_info
    
    for threat_type in mappings_summary['framework_coverage']['car']:
        car_info = get_car_info(threat_type)
        if car_info:
            car_analytics[threat_type] = car_info
    
    for threat_type in mappings_summary['framework_coverage']['d3fend']:
        d3fend_info = get_d3fend_info(threat_type)
        if d3fend_info:
            d3fend_defenses[threat_type] = d3fend_info
    
    for threat_type in mappings_summary['framework_coverage']['engage']:
        engage_info = get_engage_info(threat_type)
        if engage_info:
            engage_techniques[threat_type] = engage_info
    
    return jsonify({
        "total_logs": mappings_summary["total_logs"],
        "mapped_logs": mappings_summary["mapped_logs"],
        "framework_coverage": mappings_summary["framework_coverage"],
        "attack_techniques": attack_techniques,
        "car_analytics": car_analytics,
        "d3fend_defenses": d3fend_defenses,
        "engage_techniques": engage_techniques,
        "ips_by_technique": mappings_summary["ips_by_technique"]
    })


@app.route("/api/investigation/report/<ip>", methods=["GET"])
def api_investigation_report(ip):
    """Generate detailed investigation report for a specific IP"""
    try:
        logs = get_logs()
        ip_logs = [log for log in logs if log.get('ip') == ip]
        
        if not ip_logs:
            return jsonify({
                'error': f'No logs found for IP {ip}'
            }), 404
        
        # Get MITRE mappings for this IP
        mappings = log_mitre_mapper.analyze_logs_batch(ip_logs)
        
        # Calculate risk score
        risk_score = calculate_risk_score(ip_logs, mappings)
        
        # Extract key statistics
        successful_logins = len([log for log in ip_logs if log.get('status') == 'success'])
        failed_logins = len([log for log in ip_logs if log.get('status') == 'failure'])
        
        # Get unique techniques
        techniques = set()
        for mapping in mappings:
            if mapping.get('mitre_attack', {}).get('technique_id'):
                techniques.add(mapping['mitre_attack']['technique_id'])
            if mapping.get('mitre_car', {}).get('analytics_id'):
                techniques.add(mapping['mitre_car']['analytics_id'])
        
        # Get time range
        timestamps = [log.get('timestamp') for log in ip_logs if log.get('timestamp')]
        if timestamps:
            first_seen = min(timestamps)
            last_seen = max(timestamps)
        else:
            first_seen = last_seen = None
        
        # Get unique users
        users = set(log.get('user') for log in ip_logs if log.get('user'))
        
        # Detect privilege escalation attempts
        sudo_events = [log for log in ip_logs if 'sudo' in log.get('message', '').lower()]
        
        # Build investigation report
        report = {
            'ip': ip,
            'risk_score': risk_score,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'total_events': len(ip_logs),
            'successful_logins': successful_logins,
            'failed_logins': failed_logins,
            'unique_users': list(users),
            'privilege_escalation_attempts': len(sudo_events),
            'techniques_detected': list(techniques),
            'mitre_mappings': mappings,
            'evidence': ip_logs[:10],  # Show first 10 log entries as evidence
            'attack_timeline': build_attack_timeline(ip_logs),
            'severity': get_severity_from_risk(risk_score)
        }
        
        return jsonify(report)
        
    except Exception as e:
        print(f"[app] ERROR: Could not generate investigation report for {ip}: {e}")
        return jsonify({
            'error': str(e)
        }), 500


def calculate_risk_score(logs, mappings):
    """Calculate risk score based on log patterns and MITRE mappings"""
    score = 0
    
    # Base score from failed logins
    failed_count = len([log for log in logs if log.get('status') == 'failure'])
    score += min(failed_count * 2, 20)  # Max 20 points from failed logins
    
    # Bonus for successful logins (compromise)
    success_count = len([log for log in logs if log.get('status') == 'success'])
    score += success_count * 5  # 5 points per successful login
    
    # MITRE technique severity
    for mapping in mappings:
        if mapping.get('severity') == 'CRITICAL':
            score += 15
        elif mapping.get('severity') == 'HIGH':
            score += 10
        elif mapping.get('severity') == 'MEDIUM':
            score += 5
        elif mapping.get('severity') == 'LOW':
            score += 2
    
    # Privilege escalation bonus
    sudo_events = [log for log in logs if 'sudo' in log.get('message', '').lower()]
    score += len(sudo_events) * 8
    
    # Multiple users bonus (potential credential stuffing)
    users = set(log.get('user') for log in logs if log.get('user'))
    if len(users) > 1:
        score += len(users) * 3
    
    return min(score, 100)  # Cap at 100


def get_severity_from_risk(risk_score):
    """Convert risk score to severity level"""
    if risk_score >= 80:
        return 'CRITICAL'
    elif risk_score >= 60:
        return 'HIGH'
    elif risk_score >= 40:
        return 'MEDIUM'
    else:
        return 'LOW'


# ── MITRE Mapping API Endpoints ───────────────────────────────────────────────────

@app.route("/api/mitre/mappings/all", methods=["GET"])
def api_mitre_mappings_all():
    """Get all log-to-MITRE framework mappings"""
    try:
        logs = get_logs()
        mappings = log_mitre_mapper.analyze_logs_batch(logs)
        
        # Group mappings by framework for easier frontend processing
        framework_data = {
            'attack': log_mitre_mapper.extract_unique_techniques(mappings),
            'car': log_mitre_mapper.extract_unique_analytics(mappings),
            'd3fend': log_mitre_mapper.extract_unique_defenses(mappings),
            'engage': log_mitre_mapper.extract_unique_engage_techniques(mappings)
        }
        
        return jsonify({
            'mappings': mappings,
            'framework_data': framework_data,
            'total_logs': len(logs)
        })
        
    except Exception as e:
        print(f"[app] ERROR: Could not generate MITRE mappings: {e}")
        return jsonify({
            'mappings': [],
            'framework_data': {'attack': [], 'car': [], 'd3fend': [], 'engage': []},
            'total_logs': 0,
            'error': str(e)
        }), 500


@app.route("/api/mitre/mappings/summary", methods=["GET"])
def api_mitre_mappings_summary():
    """Get summary of MITRE mappings"""
    try:
        logs = get_logs()
        summary = log_mitre_mapper.get_technique_summary(logs)
        
        # Add additional summary statistics
        ip_mappings = log_mitre_mapper.get_ip_based_mappings(logs)
        summary['unique_ips'] = len(ip_mappings)
        summary['techniques_detected'] = len(summary['techniques_detected'])
        
        return jsonify(summary)
        
    except Exception as e:
        print(f"[app] ERROR: Could not generate MITRE summary: {e}")
        return jsonify({
            'total_logs': 0,
            'mapped_logs': 0,
            'techniques_detected': {},
            'ips_by_technique': {},
            'framework_coverage': {'attack': [], 'car': [], 'd3fend': [], 'engage': []},
            'unique_ips': 0,
            'error': str(e)
        }), 500


@app.route("/api/mitre/mappings/ip/<ip>", methods=["GET"])
def api_mitre_mappings_by_ip(ip):
    """Get MITRE mappings for a specific IP address"""
    try:
        logs = get_logs()
        ip_logs = [log for log in logs if log.get('ip') == ip]
        
        if not ip_logs:
            return jsonify({
                'ip': ip,
                'mappings': [],
                'message': 'No logs found for this IP address'
            }), 404
        
        mappings = log_mitre_mapper.analyze_logs_batch(ip_logs)
        
        return jsonify({
            'ip': ip,
            'mappings': mappings,
            'total_logs': len(ip_logs),
            'mapped_logs': len([m for m in mappings if m['threat_type']])
        })
        
    except Exception as e:
        print(f"[app] ERROR: Could not get mappings for IP {ip}: {e}")
        return jsonify({
            'ip': ip,
            'mappings': [],
            'error': str(e)
        }), 500


@app.route("/api/mitre/mappings/technique/<technique_id>", methods=["GET"])
def api_mitre_mappings_by_technique(technique_id):
    """Get detailed information about a specific technique"""
    try:
        technique_details = log_mitre_mapper.get_technique_details(technique_id)
        
        if not technique_details.get('threat_type'):
            return jsonify({
                'technique_id': technique_id,
                'message': 'Technique not found'
            }), 404
        
        # Get all logs mapped to this technique
        logs = get_logs()
        mappings = log_mitre_mapper.analyze_logs_batch(logs)
        
        technique_mappings = []
        for mapping in mappings:
            if (mapping['mitre_attack'].get('technique_id') == technique_id or
                mapping['mitre_car'].get('analytics_id') == technique_id or
                mapping['mitre_d3fend'].get('defend_id') == technique_id or
                mapping['mitre_engage'].get('engage_id') == technique_id):
                technique_mappings.append(mapping)
        
        technique_details['mapped_logs'] = technique_mappings
        technique_details['total_mappings'] = len(technique_mappings)
        
        return jsonify(technique_details)
        
    except Exception as e:
        print(f"[app] ERROR: Could not get technique details for {technique_id}: {e}")
        return jsonify({
            'technique_id': technique_id,
            'error': str(e)
        }), 500


@app.route("/api/mitre/mappings/export", methods=["GET"])
def api_mitre_mappings_export():
    """Export all MITRE mappings as JSON"""
    try:
        logs = get_logs()
        mappings = log_mitre_mapper.analyze_logs_batch(logs)
        summary = log_mitre_mapper.get_technique_summary(logs)
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'summary': summary,
            'mappings': mappings,
            'framework_statistics': {
                'attack': len(log_mitre_mapper.extract_unique_techniques(mappings)),
                'car': len(log_mitre_mapper.extract_unique_analytics(mappings)),
                'd3fend': len(log_mitre_mapper.extract_unique_defenses(mappings)),
                'engage': len(log_mitre_mapper.extract_unique_engage_techniques(mappings))
            }
        }
        
        return jsonify(export_data)
        
    except Exception as e:
        print(f"[app] ERROR: Could not export MITRE mappings: {e}")
        return jsonify({
            'error': str(e)
        }), 500


@app.route("/api/mitre/mappings/search", methods=["POST"])
def api_mitre_mappings_search():
    """Search MITRE mappings by various criteria"""
    try:
        body = request.get_json(force=True)
        
        if not body:
            return jsonify({"error": "No search criteria provided"}), 400
        
        logs = get_logs()
        mappings = log_mitre_mapper.analyze_logs_batch(logs)
        
        # Apply search filters
        filtered_mappings = mappings
        
        # Filter by IP
        if 'ip' in body:
            filtered_mappings = [m for m in filtered_mappings 
                               if m['ip_address'] == body['ip']]
        
        # Filter by technique ID
        if 'technique_id' in body:
            tid = body['technique_id']
            filtered_mappings = [m for m in filtered_mappings 
                               if (m['mitre_attack'].get('technique_id') == tid or
                                   m['mitre_car'].get('analytics_id') == tid or
                                   m['mitre_d3fend'].get('defend_id') == tid or
                                   m['mitre_engage'].get('engage_id') == tid)]
        
        # Filter by threat type
        if 'threat_type' in body:
            filtered_mappings = [m for m in filtered_mappings 
                               if m['threat_type'] == body['threat_type']]
        
        # Filter by severity
        if 'severity' in body:
            filtered_mappings = [m for m in filtered_mappings 
                               if m['severity'] == body['severity']]
        
        # Filter by framework
        if 'framework' in body:
            framework = body['framework']
            filtered_mappings = [m for m in filtered_mappings 
                               if log_mitre_mapper.has_framework_mapping(m, framework)]
        
        # Filter by confidence threshold
        if 'min_confidence' in body:
            min_conf = body['min_confidence']
            filtered_mappings = [m for m in filtered_mappings 
                               if m['confidence'] >= min_conf]
        
        return jsonify({
            'search_criteria': body,
            'total_mappings': len(mappings),
            'filtered_mappings': len(filtered_mappings),
            'mappings': filtered_mappings
        })
        
    except Exception as e:
        print(f"[app] ERROR: Could not search MITRE mappings: {e}")
        return jsonify({
            'error': str(e)
        }), 500


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
