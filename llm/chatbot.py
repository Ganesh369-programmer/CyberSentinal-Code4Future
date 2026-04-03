# -*- coding: utf-8 -*-
# llm/chatbot.py - CyberSentinel LLM Chatbot Blueprint

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import json
import requests
from flask import Blueprint, request, jsonify

llm_bp = Blueprint("llm", __name__)

OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL   = "llama3.2"
_conversations  = {}
MAX_HISTORY     = 20

SOC_SYSTEM_PROMPT = """You are CyberSentinel, an expert AI Security Operations Center (SOC) Co-Pilot.
You have deep expertise in threat detection, MITRE ATT&CK/CAR/D3FEND/Engage frameworks,
log analysis (Windows, SSH, Netflow, Sudo), SOAR playbooks, and incident response.
You have access to LIVE security data shown below. Give specific, actionable, expert answers.
Reference MITRE IDs (e.g. T1110) when relevant. Keep responses clear with bullet points where helpful."""


def check_ollama():
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        return {"running": True, "models": models}
    except Exception:
        return {"running": False, "models": []}


def ask_ollama(messages, model, system):
    try:
        r = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={"model": model,
                  "messages": [{"role": "system", "content": system}] + messages,
                  "stream": False,
                  "options": {"temperature": 0.3, "num_predict": 1024}},
            timeout=120,
        )
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "").strip()
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        return f"LLM error: {str(e)}"


def get_soc_data():
    """Load all security data including firewall logs"""
    try:
        from detector import load_logs, detect_threats
        from windows_firewall_monitor import read_all_logs
        logs = load_logs()
        # Add firewall logs
        firewall_logs = read_all_logs()
        all_logs = logs + firewall_logs
        alerts = detect_threats(all_logs)
        return all_logs, alerts, firewall_logs
    except Exception as e:
        print(f"[chatbot] SOC data error: {e}")
        return [], [], []


def build_system_prompt(logs, alerts, firewall_logs=None):
    lines = [SOC_SYSTEM_PROMPT, ""]
    if alerts:
        lines.append(f"=== ACTIVE THREATS ({len(alerts)}) ===")
        for a in alerts[:6]:
            lines.append(
                f"  [{a.get('effective_severity','?')}] {a.get('type','?').replace('_',' ').upper()} "
                f"| src={a.get('src_ip','?')} | MITRE={a.get('mitre',{}).get('id','?')} "
                f"| score={a.get('correlation_score',0)}"
            )
    else:
        lines.append("=== NO ACTIVE THREATS ===")
    if logs:
        sources  = {}
        statuses = {}
        ips      = {}
        for l in logs:
            sources[l.get("source","?")] = sources.get(l.get("source","?"),0)+1
            statuses[l.get("status","?")] = statuses.get(l.get("status","?"),0)+1
            ips[l.get("ip","?")] = ips.get(l.get("ip","?"),0)+1
        lines.append(f"\n=== LOG STATS (total={len(logs)}) ===")
        lines.append("  Sources: " + ", ".join(f"{k}={v}" for k,v in sources.items()))
        lines.append("  Statuses: " + ", ".join(f"{k}={v}" for k,v in statuses.items()))
        top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
        lines.append("  Top IPs: " + ", ".join(f"{ip}({n})" for ip,n in top_ips))
        
        # Add firewall-specific stats
        if firewall_logs:
            fw_blocked = len([l for l in firewall_logs if l.get("status") == "blocked"])
            fw_allowed = len([l for l in firewall_logs if l.get("status") == "allowed"])
            lines.append(f"\n=== WINDOWS FIREWALL ===")
            lines.append(f"  Total entries: {len(firewall_logs)}")
            lines.append(f"  Blocked: {fw_blocked} | Allowed: {fw_allowed}")
            # Top blocked IPs
            blocked_ips = {}
            for l in firewall_logs:
                if l.get("status") == "blocked":
                    ip = l.get("ip", "?")
                    blocked_ips[ip] = blocked_ips.get(ip, 0) + 1
            if blocked_ips:
                top_blocked = sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True)[:3]
                lines.append("  Top blocked IPs: " + ", ".join(f"{ip}({n})" for ip,n in top_blocked))
        
        recent = sorted(logs, key=lambda l: l.get("timestamp",""), reverse=True)[:5]
        lines.append("\n=== RECENT EVENTS ===")
        for l in recent:
            lines.append(
                f"  {l.get('timestamp','?')} | {l.get('source','?').upper()} | "
                f"{l.get('status','?')} | ip={l.get('ip','?')}"
                + (f" | user={l.get('user')}" if l.get('user') else "")
            )
    return "\n".join(lines)


def extract_ip(text):
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    return m.group(1) if m else None


def enrich_message(user_msg, logs, alerts, firewall_logs=None):
    lower = user_msg.lower()
    ip    = extract_ip(user_msg)
    parts = []

    if ip and any(k in lower for k in ["timeline","investigate","history","activity"]):
        try:
            from detector import build_attack_timeline
            tl = build_attack_timeline(ip, logs)
            if tl.get("event_count", 0) > 0:
                events = "\n".join(
                    f"  [{e['timestamp']}] {e['category']}: {e['label']}"
                    for e in tl["timeline"][:10]
                )
                parts.append(
                    f"\n[LIVE TIMELINE for {ip}]\n"
                    f"Events:{tl['event_count']} Failures:{tl['auth_failures']} "
                    f"Successes:{tl['auth_successes']} Recon:{tl['recon_events']}\n"
                    f"Narrative: {tl['narrative']}\n{events}"
                )
        except Exception:
            pass

    if any(k in lower for k in ["alert","threat","attack","critical","detected"]):
        if alerts:
            summary = "\n".join(
                f"  [{a.get('effective_severity','?')}] {a.get('type','?').replace('_',' ')} "
                f"from {a.get('src_ip','?')} MITRE:{a.get('mitre',{}).get('id','?')}"
                for a in alerts[:5]
            )
            parts.append(f"\n[LIVE ALERTS]\n{summary}")

    if any(k in lower for k in ["failed","failure","brute"]):
        failures = [l for l in logs if l.get("status") == "failure"]
        if failures:
            lines = "\n".join(
                f"  {l.get('timestamp','?')} {l.get('source','?').upper()} "
                f"user={l.get('user','?')} ip={l.get('ip','?')}"
                for l in failures[-5:]
            )
            parts.append(f"\n[LIVE FAILED LOGINS: {len(failures)} total]\n{lines}")

    if any(k in lower for k in ["firewall","blocked","drop","allow"]):
        if firewall_logs:
            fw_blocked = [l for l in firewall_logs if l.get("status") == "blocked"]
            fw_allowed = [l for l in firewall_logs if l.get("status") == "allowed"]
            lines = [f"\n[LIVE FIREWALL LOGS: {len(firewall_logs)} total]"]
            lines.append(f"  Blocked: {len(fw_blocked)} | Allowed: {len(fw_allowed)}")
            # Show recent firewall events
            recent_fw = sorted(firewall_logs, key=lambda l: l.get("timestamp",""), reverse=True)[:5]
            for l in recent_fw:
                lines.append(
                    f"  {l.get('timestamp','?')} | {l.get('action','?')} | "
                    f"{l.get('protocol','?')} | {l.get('ip','?')}:{l.get('src_port','?')} -> "
                    f"{l.get('dest_ip','?')}:{l.get('port','?')}"
                )
            parts.append("\n".join(lines))
        else:
            parts.append("\n[FIREWALL] No firewall logs available. Ensure Windows Firewall logging is enabled.")

    if any(k in lower for k in ["mitre","technique","tactic"]):
        try:
            from mitre_map import get_all_mappings
            mappings = get_all_mappings()
            lines = "\n".join(
                f"  {m['threat_type']}: {m['technique_id']} ({m['technique_name']}) - {m['tactic']} [{m['severity']}]"
                for m in mappings
            )
            parts.append(f"\n[LIVE MITRE MAPPINGS]\n{lines}")
        except Exception:
            pass

    if any(k in lower for k in ["playbook","soar","respond","response","block"]):
        try:
            from soar import get_all_playbook_names
            pbs = get_all_playbook_names()
            lines = "\n".join(f"  {p['name']}: {p['description']}" for p in pbs)
            parts.append(f"\n[LIVE SOAR PLAYBOOKS]\n{lines}")
        except Exception:
            pass

    return user_msg + "".join(parts) if parts else user_msg


def fallback_response(query, logs, alerts):
    lower = query.lower()
    ip    = extract_ip(query)

    if ip and any(k in lower for k in ["timeline","investigate","history","activity"]):
        try:
            from detector import build_attack_timeline
            tl = build_attack_timeline(ip, logs)
            if tl["event_count"] == 0:
                return f"No events found for IP {ip}."
            events = "\n".join(
                f"* [{e['timestamp']}] {e['category']}: {e['label']}"
                for e in tl["timeline"][-8:]
            )
            return (
                f"**Attack Timeline: {ip}**\n\n{tl['narrative']}\n\n"
                f"Events: {tl['event_count']} | Failures: {tl['auth_failures']} | "
                f"Successes: {tl['auth_successes']} | Recon: {tl['recon_events']}\n\n{events}"
            )
        except Exception:
            pass

    if ip and any(k in lower for k in ["block","ban","deny"]):
        return (
            f"**Block IP: {ip}**\n\n"
            f"```\niptables -I INPUT -s {ip} -j DROP\niptables -I OUTPUT -d {ip} -j DROP\n```\n"
            f"Or POST to /api/block-ip to trigger the simulated SOAR action."
        )

    if any(k in lower for k in ["alert","threat","attack","suspicious","detected"]):
        if not alerts:
            return f"No active threats detected across {len(logs)} log events."
        lines = [f"**{len(alerts)} Active Threat(s)**\n"]
        for a in alerts:
            sev = a.get("effective_severity","?")
            typ = a.get("type","?").replace("_"," ").title()
            src = a.get("src_ip","?")
            mid = a.get("mitre",{}).get("id","?")
            sc  = a.get("correlation_score",0)
            lines.append(f"**[{sev}] {typ}**\n  Source: `{src}` | MITRE: `{mid}` | Score: {sc}")
            if a.get("evidence"):
                lines.append(f"  Evidence: {a['evidence'][0]}")
            lines.append("")
        return "\n".join(lines)

    if any(k in lower for k in ["fail","brute"]):
        failures = [l for l in logs if l.get("status") == "failure"]
        lines = "\n".join(
            f"* {l.get('timestamp','?')} | {l.get('source','?').upper()} | "
            f"user=`{l.get('user','?')}` | ip=`{l.get('ip','?')}`"
            for l in failures[-5:]
        )
        return f"**Failed Logins: {len(failures)} total**\n\n{lines}"

    if any(k in lower for k in ["summary","overview","report","status"]):
        sources = list({l.get("source") for l in logs})
        top = "\n".join(
            f"* [{a.get('effective_severity','?')}] {a.get('type','?').replace('_',' ').title()} from `{a.get('src_ip','?')}`"
            for a in alerts[:3]
        ) if alerts else "No active threats."
        return (
            f"**SOC Status**\n\n* Log events: **{len(logs)}**\n"
            f"* Sources: {', '.join(sources)}\n"
            f"* Active threats: **{len(alerts)}**\n\n**Top Threats:**\n{top}"
        )

    if any(k in lower for k in ["mitre","technique","tactic"]):
        try:
            from mitre_map import get_all_mappings
            mappings = get_all_mappings()
            lines = ["**MITRE ATT&CK Mappings**\n"]
            for m in mappings:
                lines.append(f"**{m['technique_id']}** {m['technique_name']} [{m['severity']}]\n  Tactic: {m['tactic']}\n")
            return "\n".join(lines)
        except Exception:
            pass

    if any(k in lower for k in ["playbook","soar"]):
        try:
            from soar import get_all_playbook_names
            pbs = get_all_playbook_names()
            lines = ["**SOAR Playbooks**\n"]
            for p in pbs:
                lines.append(f"**{p['name']}**\n  {p['description']}\n")
            return "\n".join(lines)
        except Exception:
            pass

    return (
        "**CyberSentinel SOC Co-Pilot**\n\n"
        "* `Show active threats`\n* `Summarize logs`\n* `Show failed logins`\n"
        "* `Investigate 185.220.101.47`\n* `Block 185.220.101.47`\n"
        "* `MITRE mappings`\n* `Show playbooks`\n\n"
        "*Ollama offline - start with `ollama serve` then `ollama pull llama3.2`*"
    )


@llm_bp.route("/api/chat", methods=["POST"])
def api_chat():
    body       = request.get_json(force=True) or {}
    user_msg   = body.get("message", "").strip()
    session_id = body.get("session_id", "default")
    if not user_msg:
        return jsonify({"error": "message field is required"}), 400

    logs, alerts = get_soc_data()
    system       = build_system_prompt(logs, alerts)
    history      = _conversations.get(session_id, [])
    enriched     = enrich_message(user_msg, logs, alerts)
    history.append({"role": "user", "content": enriched})
    if len(history) > MAX_HISTORY:
        history = history[-MAX_HISTORY:]

    ollama_status = check_ollama()
    fallback_used = False

    if ollama_status["running"]:
        models   = ollama_status["models"]
        model    = next((m for m in models if DEFAULT_MODEL in m), models[0] if models else DEFAULT_MODEL)
        response = ask_ollama(history, model, system)
        if response is None:
            fallback_used = True
            model    = "fallback"
            response = fallback_response(user_msg, logs, alerts)
    else:
        fallback_used = True
        model    = "fallback"
        response = fallback_response(user_msg, logs, alerts)

    history.append({"role": "assistant", "content": response})
    _conversations[session_id] = history

    return jsonify({
        "response": response, "session_id": session_id,
        "model": model, "fallback": fallback_used,
        "log_count": len(logs), "alert_count": len(alerts),
    })


@llm_bp.route("/api/chat/status", methods=["GET"])
def api_chat_status():
    status       = check_ollama()
    logs, alerts = get_soc_data()
    return jsonify({
        "ollama": status,
        "soc_data": {"log_count": len(logs), "alert_count": len(alerts)},
        "model": DEFAULT_MODEL,
        "active_sessions": len(_conversations),
    })


@llm_bp.route("/api/chat/history", methods=["GET"])
def api_chat_history():
    session_id = request.args.get("session_id", "default")
    history    = _conversations.get(session_id, [])
    clean = []
    for msg in history:
        content = re.sub(r"\n\[LIVE [^\]]*\].*?(?=\n\[LIVE |\Z)", "", msg["content"], flags=re.DOTALL).strip()
        clean.append({"role": msg["role"], "content": content})
    return jsonify({"session_id": session_id, "history": clean})


@llm_bp.route("/api/chat/clear", methods=["POST"])
def api_chat_clear():
    body       = request.get_json(force=True) or {}
    session_id = body.get("session_id", "default")
    _conversations[session_id] = []
    return jsonify({"status": "cleared", "session_id": session_id})