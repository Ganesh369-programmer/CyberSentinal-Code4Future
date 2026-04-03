# nvidia_ai/ai_chat_interface.py
# ─────────────────────────────────────────────────────────────────────────────
# Flask Blueprint registered in app.py as:
#   from nvidia_ai.ai_chat_interface import ai_chat_bp
#   app.register_blueprint(ai_chat_bp, url_prefix='/ai')
#
# This is the ONLY file app.py needs to import from nvidia_ai/.
# It imports nvidia_chat.py internally.
#
# Routes exposed:
#   POST /ai/chat      ← main endpoint called by script.js handleSend()
#   POST /ai/clear     ← clear conversation memory for a session
#   GET  /ai/stats     ← live log statistics for dashboard metrics
#   GET  /ai/health    ← quick health check
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import uuid

from flask import Blueprint, request, jsonify, session

# ── Make nvidia_ai importable regardless of working directory ─────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from nvidia_chat import process_chat_query, clear_session, get_live_stats

ai_chat_bp = Blueprint("ai_chat", __name__)


# ── Session ID helper ─────────────────────────────────────────────────────────

def _get_session_id() -> str:
    """
    Stable session ID per browser tab, stored in Flask session cookie.
    Falls back to 'default' if Flask SECRET_KEY is not configured.
    """
    try:
        if "ai_sid" not in session:
            session["ai_sid"]       = str(uuid.uuid4())[:12]
            session.permanent       = True
        return session["ai_sid"]
    except RuntimeError:
        return "default"


# ═════════════════════════════════════════════════════════════════════════════
# POST /ai/chat
# Called by script.js handleSend()
# Body: { "query": "...", "session_id": "optional-override" }
# ═════════════════════════════════════════════════════════════════════════════

@ai_chat_bp.route("/chat", methods=["POST"])
def route_chat():
    body  = request.get_json(force=True) or {}
    query = body.get("query", "").strip()

    if not query:
        return jsonify({"error": "query field is required"}), 400

    # Use session_id from body if provided (JS sends it), else cookie-based
    session_id = body.get("session_id") or _get_session_id()

    # ── Run the full pipeline (load logs → build prompt → call NVIDIA) ────────
    result = process_chat_query(query, session_id=session_id)

    stats = result.get("stats", {})

    return jsonify({
        # Core fields consumed by script.js
        "answer":     result["answer"],
        "source":     result["source"],       # "nvidia_llama4" | "keyword_fallback" | "security_guard"
        "grounded":   result["grounded"],
        "warnings":   result["warnings"],
        "session_id": session_id,

        # Live stats snapshot — script.js uses these to update metric cards
        "stats_snapshot": {
            "total":           stats.get("total", 0),
            "failures":        stats.get("failures", 0),
            "successes":       stats.get("successes", 0),
            "failure_rate":    stats.get("failure_rate", 0),
            "suspicious_ips":  stats.get("suspicious_ips", []),
            "brute_force_ips": stats.get("brute_force_ips", []),
        },
    })


# ═════════════════════════════════════════════════════════════════════════════
# POST /ai/clear
# Body: { "session_id": "..." }
# ═════════════════════════════════════════════════════════════════════════════

@ai_chat_bp.route("/clear", methods=["POST"])
def route_clear():
    body       = request.get_json(force=True) or {}
    session_id = body.get("session_id") or _get_session_id()
    clear_session(session_id)
    return jsonify({
        "cleared":    True,
        "session_id": session_id,
        "message":    "Conversation memory cleared.",
    })


# ═════════════════════════════════════════════════════════════════════════════
# GET /ai/stats
# Returns live log statistics for dashboard metric cards
# ═════════════════════════════════════════════════════════════════════════════

@ai_chat_bp.route("/stats", methods=["GET"])
def route_stats():
    stats = get_live_stats()
    return jsonify(stats)


# ═════════════════════════════════════════════════════════════════════════════
# GET /ai/health
# ═════════════════════════════════════════════════════════════════════════════

@ai_chat_bp.route("/health", methods=["GET"])
def route_health():
    stats = get_live_stats()
    return jsonify({
        "status":      "ok",
        "log_count":   stats.get("total", 0),
        "model":       "meta/llama-4-maverick-17b-128e-instruct",
        "failures":    stats.get("failures", 0),
        "suspicious":  len(stats.get("suspicious_ips", [])),
    })