/* ══════════════════════════════════════════════════════════════
   CYBERSENTINEL — NVIDIA AI CHAT PANEL (chat_patch.js)
   Replace the AI CHAT section in script.js with this file,
   OR include this after script.js in index.html.

   Connects to:  POST /ai/chat   (nvidia_client.py via Flask blueprint)
   Replaces:     POST /api/query (old keyword-only engine)
   ══════════════════════════════════════════════════════════════ */

// ── Session ID (persisted in localStorage for conversation memory) ─────────
let AI_SESSION_ID = localStorage.getItem("cs_session_id") || (() => {
  const id = "sess_" + Math.random().toString(36).slice(2, 10);
  localStorage.setItem("cs_session_id", id);
  return id;
})();

// ── Override: replace old handleSend with NVIDIA-backed version ────────────
// This shadows the handleSend() defined in script.js

async function handleSend() {
  const input = el("chatInput");
  const raw   = input.value.trim();
  if (!raw) return;

  appendUserMessage(raw);
  input.value = "";
  input.focus();

  const typingId = showTyping();

  const data = await fetchJSON("/ai/chat", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      query:      raw,
      session_id: AI_SESSION_ID,
    }),
  });

  removeTyping(typingId);

  if (!data) {
    appendBotMessage(
      "⛔ AI backend unreachable. Check that Flask is running with the NVIDIA blueprint registered.",
      "error"
    );
    return;
  }

  // ── Update session if server rotated it ───────────────────────────────────
  if (data.session_id && data.session_id !== AI_SESSION_ID) {
    AI_SESSION_ID = data.session_id;
    localStorage.setItem("cs_session_id", AI_SESSION_ID);
  }

  // ── Update AI source badge ────────────────────────────────────────────────
  const sourceLabels = {
    "nvidia_llama4":    "NVIDIA · LLAMA-4",
    "keyword_fallback": "OFFLINE MODE",
    "security_guard":   "BLOCKED",
    "error":            "ERROR",
  };
  const badgeEl = el("aiSourceTag");
  if (badgeEl) {
    badgeEl.textContent = sourceLabels[data.source] || "AI ENGINE";
    badgeEl.style.color = data.source === "nvidia_llama4"
      ? "var(--green)" : data.source === "keyword_fallback"
      ? "var(--orange)" : "var(--red)";
  }

  // ── Format response HTML ───────────────────────────────────────────────────
  let html = data.answer
    ? data.answer
        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")  // bold
        .replace(/\*(.*?)\*/g, "<em>$1</em>")               // italic
        .replace(/^• /gm, "▸ ")                             // bullet style
        .replace(/\n/g, "<br>")
    : "No response.";

  // ── Hallucination warning banner ───────────────────────────────────────────
  const warnHtml = (data.warnings || []).length
    ? `<div class="ai-warn-box">${data.warnings.map(w => `⚠ ${w}`).join("<br>")}</div>`
    : "";

  // ── Live stats snapshot in footer ─────────────────────────────────────────
  const snap = data.stats_snapshot || {};
  const statsHtml = snap.total
    ? `<div class="ai-stats-snap">
         <span>📊 ${snap.total} events</span>
         <span>🔴 ${snap.failures} failures</span>
         <span>🚨 ${(snap.suspicious_ips||[]).length} suspicious IPs</span>
       </div>`
    : "";

  appendBotMessage(html + warnHtml + statsHtml, data.source, []);

  // ── Auto-update dashboard metrics if stats changed ─────────────────────────
  if (snap.total) {
    _updateMetricsFromSnap(snap);
  }
}

// ── Quick chip handler (same as before, but now routes to NVIDIA) ──────────
function sendChip(q) {
  el("chatInput").value = q;
  handleSend();
}

// ── Clear conversation button (add to your header or modal if needed) ───────
async function clearAIConversation() {
  await fetchJSON("/ai/clear", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ session_id: AI_SESSION_ID }),
  });
  appendBotMessage(
    "🗑 Conversation history cleared. Starting fresh session.",
    "system"
  );
}

// ── Investigate IP using NVIDIA analysis endpoint ──────────────────────────
async function investigateIPWithNvidia(ip) {
  el("investigateModal").classList.remove("hidden");
  el("modalBackdrop").classList.remove("hidden");
  el("modalBody").innerHTML = `
    <div class="loading-state">
      <div class="loading-dots"><span></span><span></span><span></span></div>
      <span>NVIDIA AI analyzing ${ip}…</span>
    </div>`;

  // Parallel: existing investigation + NVIDIA deep analysis
  const [baseData, aiData] = await Promise.all([
    fetchJSON("/api/investigate", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ ip }),
    }),
    fetchJSON("/ai/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ ip, session_id: AI_SESSION_ID }),
    }),
  ]);

  if (!baseData && !aiData) {
    el("modalBody").innerHTML = `<div class="empty-state">Failed to load investigation for ${ip}.</div>`;
    return;
  }

  const playbooks  = baseData ? (baseData.playbooks || []).slice(0, 1) : [];
  const mitre      = baseData ? (baseData.mitre || []).slice(0, 2) : [];
  const evidence   = baseData && baseData.alerts && baseData.alerts[0]
    ? (baseData.alerts[0].evidence || []) : [];
  const riskScore  = baseData ? (baseData.risk_score || 0) : 0;
  const summary    = baseData ? (baseData.summary || "") : "";
  const aiExplain  = aiData   ? (aiData.answer || "") : "";
  const aiSource   = aiData   ? (aiData.source || "nvidia_llama4") : "";
  const aiWarnings = aiData   ? (aiData.warnings || []) : [];

  el("modalBody").innerHTML = `

    <!-- Risk + IP header -->
    <div class="modal-section">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
        <div class="risk-score"><span class="risk-label">RISK</span> ${riskScore}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--blue)">${ip}</div>
        ${aiData ? `<span class="panel-tag" style="margin-left:auto">${sourceLabels[aiSource]||"AI"}</span>` : ""}
      </div>
      ${summary ? `<div class="modal-narrative">${summary}</div>` : ""}
    </div>

    <!-- NVIDIA AI Explanation -->
    ${aiExplain ? `
    <div class="modal-section">
      <div class="modal-section-title">
        🤖 NVIDIA AI ANALYSIS — ${aiSource === "nvidia_llama4" ? "LLAMA-4 GROUNDED" : "OFFLINE MODE"}
      </div>
      <div class="llm-explanation">${aiExplain.replace(/\*\*(.*?)\*\*/g,"<strong>$1</strong>").replace(/\n/g,"<br>")}</div>
      ${aiWarnings.map(w => `<div class="msg-warning">⚠ ${w}</div>`).join("")}
    </div>` : ""}

    <!-- MITRE -->
    ${mitre.length ? `
    <div class="modal-section">
      <div class="modal-section-title">MITRE ATT&CK MAPPING</div>
      ${mitre.map(m => `
        <div class="playbook-step">
          <div class="step-num">${m.technique_id}</div>
          <div class="step-info">
            <div class="step-action">${m.technique_name}</div>
            <div class="step-desc">${m.tactic} · Severity: ${m.severity}</div>
          </div>
        </div>`).join("")}
    </div>` : ""}

    <!-- Evidence -->
    ${evidence.length ? `
    <div class="modal-section">
      <div class="modal-section-title">EVIDENCE (${evidence.length} log entries)</div>
      ${evidence.map(e => `<div class="evidence-line">▸ ${e}</div>`).join("")}
    </div>` : ""}

    <!-- SOAR Playbook -->
    ${playbooks.length ? `
    <div class="modal-section">
      <div class="modal-section-title">SOAR RESPONSE — ${playbooks[0].name || ""}</div>
      ${(playbooks[0].steps || []).map((s, i) => `
        <div class="playbook-step">
          <div class="step-num">${i + 1}</div>
          <div class="step-info">
            <div class="step-action">[${s.action}]</div>
            <div class="step-desc">${s.description}</div>
            <div class="step-cmd">${s.command || ""}</div>
          </div>
        </div>`).join("")}
    </div>` : ""}

    <div style="text-align:center;padding-top:10px;display:flex;gap:8px;justify-content:center">
      <button class="action-btn danger" onclick="blockIP('${ip}');closeModal()">🚫 Block IP</button>
      <button class="action-btn" onclick="clearAIConversation()">🗑 Clear Memory</button>
    </div>`;
}

// ── Helper: source label map (shared with handleSend) ─────────────────────
const sourceLabels = {
  "nvidia_llama4":    "NVIDIA · LLAMA-4",
  "keyword_fallback": "OFFLINE MODE",
  "security_guard":   "BLOCKED",
  "error":            "ERROR",
};

// ── Update dashboard metric cards from AI stats snapshot ──────────────────
function _updateMetricsFromSnap(snap) {
  // Only update if elements exist (dashboard may not have all panels)
  const safeSet = (id, val) => { const e = el(id); if (e) e.textContent = val; };
  const safeBar = (id, pct) => animBar(id, pct);

  if (snap.total) {
    safeSet("mc-total", snap.total);
    safeBar("mc-total-bar", 100);
  }
  if (snap.failures !== undefined) {
    safeSet("mc-fail", snap.failures);
    safeBar("mc-fail-bar", snap.total ? Math.round(snap.failures / snap.total * 100) : 0);
  }
}

// ── Override: investigateIP globally to use NVIDIA version ─────────────────
// Comment this out if you want to keep the original investigate modal.
const investigateIP = investigateIPWithNvidia;

// ── CSS additions injected at runtime ─────────────────────────────────────
(function injectStyles() {
  const style = document.createElement("style");
  style.textContent = `
    .ai-warn-box {
      margin-top: 8px;
      padding: 7px 12px;
      background: rgba(255,159,67,0.08);
      border: 1px solid rgba(255,159,67,0.25);
      border-left: 3px solid var(--orange);
      border-radius: 0 var(--r) var(--r) 0;
      font-family: var(--mono);
      font-size: 9.5px;
      color: var(--orange);
      line-height: 1.6;
    }
    .ai-stats-snap {
      display: flex;
      gap: 14px;
      margin-top: 8px;
      padding: 5px 10px;
      background: rgba(0,180,255,0.04);
      border: 1px solid var(--border);
      border-radius: var(--r);
      font-family: var(--mono);
      font-size: 9px;
      color: var(--t2);
    }
    #aiSourceTag {
      transition: color 0.3s;
    }
  `;
  document.head.appendChild(style);
})();

console.log("[CyberSentinel] NVIDIA AI chat engine loaded. Session:", AI_SESSION_ID);