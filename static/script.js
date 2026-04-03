/* ══════════════════════════════════════════════════
   CYBERSENTINEL — script.js
   index.html AI chat  →  POST /ai/chat  →  NVIDIA
   ══════════════════════════════════════════════════ */

const API = "";  // same origin as Flask

// ── State ─────────────────────────────────────────────────────────────────────
let allAlerts   = [];
let allLogs     = [];
let alertFilter = "all";
let logFilter   = "all";
let logSearch   = "";
let suspiciousIPs = new Set();

// Session ID stored in localStorage so conversation memory persists across
// page refreshes (same browser tab = same session = same NVIDIA history)
let AI_SESSION_ID = localStorage.getItem("cs_ai_sid") || (() => {
  const id = "sid_" + Math.random().toString(36).slice(2, 10);
  localStorage.setItem("cs_ai_sid", id);
  return id;
})();

// ── Boot ───────────────────────────────────────────────────────────────────────
window.addEventListener("DOMContentLoaded", async () => {
  initMatrix();
  startClock();

  appendBotMessage(
    `🖥️ <strong>CyberSentinel SOC Co-Pilot initializing…</strong><br><br>` +
    `Connecting to backend · Loading auth logs · Initializing NVIDIA AI…`,
    "system"
  );

  const health = await fetchJSON("/api/health");
  if (!health) {
    setStatus(false);
    appendBotMessage(
      "⛔ Flask backend is not responding.<br>" +
      "<code>python app.py</code> — then refresh.",
      "error"
    );
    return;
  }

  setStatus(true);
  await Promise.all([loadAlerts(), loadLogs(), loadMITREMappings()]);

  // Greet with live data from /ai/stats
  const aiStats = await fetchJSON("/ai/stats");
  const total   = aiStats ? aiStats.total    : allLogs.length;
  const fails   = aiStats ? aiStats.failures : 0;
  const suspCnt = aiStats ? aiStats.suspicious_ips.length : 0;

  appendBotMessage(
    `✅ <strong>Backend connected · NVIDIA AI ready.</strong><br><br>` +
    `Monitoring <span style="color:var(--blue)">${total} auth events</span> · ` +
    `<span style="color:var(--red)">${fails} failures</span> · ` +
    `<span style="color:var(--orange)">${suspCnt} suspicious IPs</span>.<br><br>` +
    `Ask me anything about the security logs — I answer from real data.`,
    "nvidia_llama4"
  );

  // Auto-alert on threats
  if (allAlerts.length > 0) {
    const top = allAlerts[0];
    setTimeout(() =>
      showAlert(`${top.effective_severity} threat: ${top.type.replace(/_/g," ").toUpperCase()} from ${top.src_ip}`)
    , 1000);
  }

  // Polling
  setInterval(refreshAlerts, 15000);
  setInterval(loadLogs,       5000);
});

// ═════════════════════════════════════════════════════════════════════════════
// FETCH HELPER
// ═════════════════════════════════════════════════════════════════════════════

async function fetchJSON(url, options = {}) {
  try {
    const res = await fetch(API + url, options);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    console.error(`[fetch] ${url}:`, e.message);
    return null;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// ALERT FEED  (/api/alerts)
// ═════════════════════════════════════════════════════════════════════════════

async function loadAlerts() {
  const data = await fetchJSON("/api/alerts");
  if (!data) return;

  allAlerts     = data.alerts || [];
  suspiciousIPs = new Set(allAlerts.map(a => a.src_ip));

  const sc = data.severity_counts || {};
  animCount("hs-critical", sc.CRITICAL || 0);
  animCount("hs-high",     sc.HIGH     || 0);

  // Metric cards
  el("mc-threats").textContent = allAlerts.length;
  el("mc-ips").textContent     = suspiciousIPs.size;
  animBar("mc-threats-bar", Math.min(100, allAlerts.length * 12));
  animBar("mc-ips-bar",     Math.min(100, suspiciousIPs.size * 20));

  renderAlertFeed();
  populateIPSelect();
}

async function refreshAlerts() {
  const prev = allAlerts.length;
  await loadAlerts();
  if (allAlerts.length > prev) {
    const newest = allAlerts[0];
    document.querySelectorAll(".alert-card")[0]?.classList.add("new-alert");
    showAlert(`New threat: ${newest.type.replace(/_/g," ").toUpperCase()} from ${newest.src_ip}`);
  }
}

function setAlertFilter(f, btn) {
  alertFilter = f;
  document.querySelectorAll(".alert-panel .pill-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  renderAlertFeed();
}

function renderAlertFeed() {
  const feed = el("alertFeed");
  const list = alertFilter === "all"
    ? allAlerts
    : allAlerts.filter(a => a.effective_severity === alertFilter);

  if (!list.length) {
    feed.innerHTML = `<div class="empty-state">✅ No alerts for this filter.<br>System appears clean.</div>`;
    return;
  }

  feed.innerHTML = list.map(a => {
    const mb = a.mitre ? `<div class="mitre-badge">⬡ ${a.mitre.id} — ${a.mitre.name}</div>` : "";
    const cb = a.car ? `<div class="car-badge">🔬 ${a.car.id} — ${a.car.name}</div>` : "";
    return `
      <div class="alert-card ${a.effective_severity}" onclick="investigateIP('${a.src_ip}')">
        <div class="alert-top">
          <span class="alert-type">${a.type.replace(/_/g," ").toUpperCase()}</span>
          <span class="sev-badge ${a.effective_severity}">${a.effective_severity}</span>
        </div>
        <div class="alert-ip">⬡ ${a.src_ip} → ${a.dest_ip || "?"}</div>
        <div class="alert-meta">
          <span>🕐 ${a.first_seen || "?"}</span>
          <span>Score: ${a.correlation_score || 0}</span>
          ${a.cross_source_hit ? '<span style="color:var(--orange)">MULTI-SOURCE</span>' : ""}
        </div>
        ${mb}
        ${cb}
        <div class="alert-actions">
          <button class="action-btn" onclick="event.stopPropagation();investigateIP('${a.src_ip}')">🔍 Investigate</button>
          <button class="action-btn" onclick="event.stopPropagation();loadTimeline('${a.src_ip}')">📊 Timeline</button>
          <button class="action-btn danger" onclick="event.stopPropagation();blockIP('${a.src_ip}')">🚫 Block IP</button>
        </div>
      </div>`;
  }).join("");
}

// ═════════════════════════════════════════════════════════════════════════════
// LOG TABLE  (/api/auth/logs)
// ═════════════════════════════════════════════════════════════════════════════

async function loadLogs() {
  const data = await fetchJSON("/api/auth/logs");
  if (!data) return;

  allLogs = data.logs || [];
  el("mc-total").textContent = allLogs.length;
  animCount("hs-events", allLogs.length);

  const fails = allLogs.filter(l => l.status === "failure").length;
  el("mc-fail").textContent = fails;
  animBar("mc-fail-bar", allLogs.length ? Math.round(fails / allLogs.length * 100) : 0);

  renderLogTable();
}

function filterLogs(mode) {
  logFilter = mode;
  el("toggleAll").classList.toggle("active",    mode === "all");
  el("toggleThreats").classList.toggle("active", mode === "threats");
  renderLogTable();
}

function filterLogsSearch(val) {
  logSearch = val.toLowerCase();
  renderLogTable();
}

function renderLogTable() {
  const body = el("logTableBody");
  let data = logFilter === "threats"
    ? allLogs.filter(l => l.status === "failure" || suspiciousIPs.has(l.ip))
    : allLogs;

  if (logSearch) {
    data = data.filter(l =>
      (l.user   || "").toLowerCase().includes(logSearch) ||
      (l.ip     || "").includes(logSearch) ||
      (l.timestamp || "").includes(logSearch) ||
      (l.status || "").includes(logSearch) ||
      (l.source || "").toLowerCase().includes(logSearch)
    );
  }

  if (!data.length) {
    body.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:18px;font-family:var(--mono);font-size:10px">No logs match</td></tr>`;
    return;
  }

  body.innerHTML = data.map(l => {
    const susp = suspiciousIPs.has(l.ip);
    const time = (l.timestamp || "").split(" ")[1] || l.timestamp || "?";
    const st   = l.status === "success" ? "success" : l.status === "scan" ? "scan" : "failure";
    const stL  = l.status === "success" ? "OK" : l.status === "scan" ? "SCAN" : "FAIL";
    return `<tr class="${susp ? "suspicious" : ""}">
      <td class="td-time">${time}</td>
      <td class="td-src">${l.source || "?"}</td>
      <td class="td-user">${l.user || "N/A"}</td>
      <td class="td-ip">${l.ip || "?"}</td>
      <td><span class="badge ${st}">${stL}</span></td>
    </tr>`;
  }).join("");
}

// ═════════════════════════════════════════════════════════════════════════════
// TIMELINE  (/api/timeline/<ip>)
// ═════════════════════════════════════════════════════════════════════════════

function populateIPSelect() {
  const sel = el("ipSelect");
  const ips = [...new Set(allAlerts.map(a => a.src_ip))];
  sel.innerHTML = `<option value="">— Select IP —</option>` +
    ips.map(ip => `<option value="${ip}">${ip}</option>`).join("");
}

async function loadTimeline(ip) {
  if (!ip) return;
  el("ipSelect").value = ip;
  el("timelineWrap").innerHTML = `<div class="timeline-placeholder"><div class="loading-dots"><span></span><span></span><span></span></div></div>`;

  const data = await fetchJSON(`/api/timeline/${ip}`);
  if (!data || !data.timeline) {
    el("timelineWrap").innerHTML = `<div class="timeline-placeholder">No events found for ${ip}.</div>`;
    return;
  }

  el("timelineWrap").innerHTML = `
    <div class="timeline-narrative">${data.narrative || ""}</div>
    ${(data.timeline || []).map(e => `
      <div class="tl-event">
        <span class="tl-time">${(e.timestamp||"").split(" ")[1]||""}</span>
        <div class="tl-dot ${e.category}"></div>
        <div>
          <div class="tl-label">${e.label}</div>
          <div class="tl-src">${e.source} ${e.dest_ip && e.dest_ip !== "?" ? "→ "+e.dest_ip : ""}</div>
        </div>
      </div>`).join("")}`;
}

// ═════════════════════════════════════════════════════════════════════════════
// SOAR: BLOCK IP  (/api/block-ip)
// ═════════════════════════════════════════════════════════════════════════════

async function blockIP(ip) {
  const data = await fetchJSON("/api/block-ip", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ ip }),
  });
  if (!data) return;

  appendBotMessage(
    `🚫 <strong>SOAR — Block IP</strong><br><br>` +
    `IP <span style="color:var(--red)">${ip}</span> flagged for blocking.<br>` +
    `Status: <span style="color:var(--t2)">${data.status}</span><br>` +
    `<code style="color:var(--t3);font-size:9px">${data.command}</code>`,
    "soar"
  );
  showAlert(`SOAR: IP ${ip} block triggered (simulated).`);
}

// ═════════════════════════════════════════════════════════════════════════════
// INVESTIGATE MODAL  (/api/investigate)
// ═════════════════════════════════════════════════════════════════════════════

async function investigateIP(ip) {
  el("investigateModal").classList.remove("hidden");
  el("modalBackdrop").classList.remove("hidden");
  el("modalBody").innerHTML = `<div class="loading-state"><div class="loading-dots"><span></span><span></span><span></span></div><span>Investigating ${ip}…</span></div>`;

  const data = await fetchJSON("/api/investigate", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ ip }),
  });

  if (!data) {
    el("modalBody").innerHTML = `<div class="empty-state">Failed to load report for ${ip}.</div>`;
    return;
  }

  const playbooks = (data.playbooks || []).slice(0, 1);
  const mitre     = (data.mitre     || []).slice(0, 2);
  const evidence  = data.alerts && data.alerts[0] ? (data.alerts[0].evidence || []) : [];

  el("modalBody").innerHTML = `
    <div class="modal-section">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
        <div class="risk-score"><span class="risk-label">RISK</span> ${data.risk_score || 0}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--blue)">${ip}</div>
      </div>
      <div class="modal-narrative">${data.summary || "No summary available."}</div>
    </div>
    ${mitre.length ? `
    <div class="modal-section">
      <div class="modal-section-title">MITRE ATT&CK</div>
      ${mitre.map(m=>`<div class="playbook-step">
        <div class="step-num">${m.technique_id}</div>
        <div class="step-info">
          <div class="step-action">${m.technique_name}</div>
          <div class="step-desc">${m.tactic} · ${m.severity}</div>
        </div></div>`).join("")}
    </div>` : ""}
    ${evidence.length ? `
    <div class="modal-section">
      <div class="modal-section-title">EVIDENCE</div>
      ${evidence.map(e=>`<div class="evidence-line">▸ ${e}</div>`).join("")}
    </div>` : ""}
    ${playbooks.length ? `
    <div class="modal-section">
      <div class="modal-section-title">SOAR PLAYBOOK — ${playbooks[0].name||""}</div>
      ${(playbooks[0].steps||[]).map((s,i)=>`<div class="playbook-step">
        <div class="step-num">${i+1}</div>
        <div class="step-info">
          <div class="step-action">[${s.action}]</div>
          <div class="step-desc">${s.description}</div>
          <div class="step-cmd">${s.command||""}</div>
        </div></div>`).join("")}
    </div>` : ""}
    <div style="text-align:center;padding-top:10px">
      <button class="action-btn danger" onclick="blockIP('${ip}');closeModal()">🚫 Block This IP</button>
    </div>`;
}

function closeModal() {
  el("investigateModal").classList.add("hidden");
  el("modalBackdrop").classList.add("hidden");
}

// ═════════════════════════════════════════════════════════════════════════════
// ██████████████████████  AI CHAT  ████████████████████████████████████████████
//
//  FULL FLOW:
//  User types in index.html → handleSend() runs →
//  POST /ai/chat with { query, session_id } →
//  Flask → nvidia_ai/ai_chat_interface.py → nvidia_chat.py →
//    1. loads real_json/auth_logs.json
//    2. computes stats (failures, suspicious IPs, etc.)
//    3. builds grounded system prompt with live log data
//    4. sends [system_prompt + conversation history + user query] to NVIDIA
//    5. NVIDIA Llama-4 answers based on actual log data
//    6. hallucination guard checks invented IPs
//  → returns { answer, source, warnings, stats_snapshot } →
//  handleSend() renders answer in chat bubble
//
// ═════════════════════════════════════════════════════════════════════════════

function sendChip(q) {
  el("chatInput").value = q;
  handleSend();
}

async function handleSend() {
  const input = el("chatInput");
  const raw   = input.value.trim();
  if (!raw) return;

  // Show user bubble immediately
  appendUserMessage(raw);
  input.value = "";
  input.focus();

  // Show typing dots while waiting for NVIDIA
  const typingId = showTyping();

  // ── POST to /ai/chat ─────────────────────────────────────────────────────
  // This goes to: nvidia_ai/ai_chat_interface.py → nvidia_chat.py → NVIDIA API
  const data = await fetchJSON("/ai/chat", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      query:      raw,
      session_id: AI_SESSION_ID,   // keeps conversation memory across messages
    }),
  });

  removeTyping(typingId);

  // ── Handle response ───────────────────────────────────────────────────────
  if (!data) {
    appendBotMessage(
      "⛔ Could not reach the AI backend.<br>" +
      "Check Flask is running and <code>nvidia_ai/ai_chat_interface.py</code> is registered.",
      "error"
    );
    return;
  }

  // Update session if server assigned a new one
  if (data.session_id) {
    AI_SESSION_ID = data.session_id;
    localStorage.setItem("cs_ai_sid", AI_SESSION_ID);
  }

  // ── Update the AI source badge in panel header ────────────────────────────
  const sourceMap = {
    "nvidia_llama4":    "NVIDIA · LLAMA-4",
    "keyword_fallback": "OFFLINE MODE",
    "security_guard":   "⛔ BLOCKED",
    "error":            "ERROR",
  };
  const badge = el("aiSourceTag");
  if (badge) {
    badge.textContent = sourceMap[data.source] || "AI ENGINE";
    badge.style.color =
      data.source === "nvidia_llama4"    ? "var(--green)"  :
      data.source === "keyword_fallback" ? "var(--orange)" : "var(--red)";
  }

  // ── Format answer (markdown-lite) ─────────────────────────────────────────
  let html = (data.answer || "No response.")
    .replace(/\*\*(.*?)\*\*/g,  "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g,      "<em>$1</em>")
    .replace(/^• /gm,           "▸ ")
    .replace(/\n/g,             "<br>");

  // ── Hallucination / safety warnings ───────────────────────────────────────
  if (data.warnings && data.warnings.length) {
    html += `<div class="ai-warn-box">${data.warnings.map(w => `⚠ ${w}`).join("<br>")}</div>`;
  }

  // ── Live stats footer (from stats_snapshot) ────────────────────────────────
  const snap = data.stats_snapshot || {};
  if (snap.total) {
    html +=
      `<div class="ai-stats-snap">` +
      `<span>📊 ${snap.total} events</span>` +
      `<span>🔴 ${snap.failures} failures</span>` +
      `<span>⚠ ${(snap.suspicious_ips||[]).length} suspicious IPs</span>` +
      `</div>`;

    // Also update dashboard metric cards silently
    const safeSet = (id, v) => { const e = el(id); if (e) e.textContent = v; };
    safeSet("mc-total", snap.total);
    safeSet("mc-fail",  snap.failures);
    if (snap.total) animBar("mc-fail-bar", Math.round(snap.failures / snap.total * 100));
  }

  appendBotMessage(html, data.source);
}

// Enter key sends message
document.addEventListener("DOMContentLoaded", () => {
  const inp = el("chatInput");
  if (inp) {
    inp.addEventListener("keydown", e => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
    });
  }
});

// ── Chat render helpers ────────────────────────────────────────────────────────

function appendUserMessage(text) {
  const msgs = el("chatMessages");
  const d = document.createElement("div");
  d.className = "msg user";
  d.innerHTML = `
    <div class="msg-avatar">⬟</div>
    <div class="msg-content">
      <div class="msg-meta">OPERATOR · ${fmtTime()}</div>
      <div class="msg-bubble">${escapeHTML(text)}</div>
    </div>`;
  msgs.appendChild(d);
  msgs.scrollTop = msgs.scrollHeight;
}

function appendBotMessage(html, source = "system") {
  const msgs = el("chatMessages");
  const d = document.createElement("div");
  d.className = "msg bot";
  const srcLabel = {
    "nvidia_llama4":    "NVIDIA · LLAMA-4",
    "keyword_fallback": "OFFLINE",
    "security_guard":   "BLOCKED",
    "soar":             "SOAR ENGINE",
    "system":           "SYSTEM",
    "error":            "ERROR",
  }[source] || source.toUpperCase();

  d.innerHTML = `
    <div class="msg-avatar">⬡</div>
    <div class="msg-content">
      <div class="msg-meta">SENTINEL-AI · ${fmtTime()}</div>
      <div class="msg-bubble">${html}</div>
      <div class="msg-source">◈ ${srcLabel}</div>
    </div>`;
  msgs.appendChild(d);
  msgs.scrollTop = msgs.scrollHeight;
}

function showTyping() {
  const msgs = el("chatMessages");
  const id   = "typing_" + Date.now();
  const d    = document.createElement("div");
  d.className = "msg bot";
  d.id = id;
  d.innerHTML = `
    <div class="msg-avatar">⬡</div>
    <div class="msg-content">
      <div class="msg-meta">SENTINEL-AI · NVIDIA processing…</div>
      <div class="typing-bubble">
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
      </div>
    </div>`;
  msgs.appendChild(d);
  msgs.scrollTop = msgs.scrollHeight;
  return id;
}

function removeTyping(id) {
  const t = document.getElementById(id);
  if (t) t.remove();
}

// ═════════════════════════════════════════════════════════════════════════════
// UI UTILITIES
// ═════════════════════════════════════════════════════════════════════════════

function setStatus(ok) {
  const badge = el("systemStatus");
  const text  = el("statusText");
  if (badge) badge.classList.toggle("error", !ok);
  if (text)  text.textContent = ok ? "SYSTEM ONLINE" : "BACKEND OFFLINE";
  const dot = badge?.querySelector(".pulse-dot");
  if (dot) dot.style.background = ok ? "var(--green)" : "var(--red)";
}

function showAlert(msg) {
  el("alertMsg").textContent = msg;
  el("alertBanner").classList.remove("hidden");
}

function closeAlert() {
  el("alertBanner").classList.add("hidden");
}

function animCount(id, target) {
  const e = el(id); if (!e) return;
  let cur = 0;
  const step = Math.max(1, Math.ceil(target / 20));
  const t = setInterval(() => {
    cur = Math.min(cur + step, target);
    e.textContent = cur;
    if (cur >= target) clearInterval(t);
  }, 40);
}

function animBar(id, pct) {
  const b = el(id);
  if (b) setTimeout(() => { b.style.width = Math.min(100, Math.max(0, pct)) + "%"; }, 100);
}

function startClock() {
  const upd = () => {
    const c = el("headerClock");
    if (c) c.textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
  };
  upd(); setInterval(upd, 1000);
}

function fmtTime() {
  return new Date().toLocaleTimeString("en-US",
    { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function el(id) { return document.getElementById(id); }

function escapeHTML(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ═════════════════════════════════════════════════════════════════════════════
// MATRIX RAIN BACKGROUND
// ═════════════════════════════════════════════════════════════════════════════

function initMatrix() {
  const canvas = el("matrixCanvas");
  if (!canvas) return;
  const ctx  = canvas.getContext("2d");
  const rs   = () => { canvas.width = innerWidth; canvas.height = innerHeight; };
  rs(); window.addEventListener("resize", rs);

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()";
  const fs    = 12;
  let cols  = Math.floor(innerWidth / fs);
  let drops = Array(cols).fill(0);
  window.addEventListener("resize", () => {
    cols = Math.floor(innerWidth / fs); drops = Array(cols).fill(0);
  });

  setInterval(() => {
    ctx.fillStyle = "rgba(2,11,20,0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#00ff88";
    ctx.font = fs + "px Share Tech Mono";
    drops.forEach((y, i) => {
      ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * fs, y * fs);
      if (y * fs > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }, 50);
}

// ── Inject CSS for ai-warn-box and ai-stats-snap (no extra file needed) ───────
(function injectStyles() {
  const s = document.createElement("style");
  s.textContent = `
    .ai-warn-box {
      margin-top: 8px; padding: 6px 10px;
      background: rgba(255,159,67,0.07);
      border: 1px solid rgba(255,159,67,0.25);
      border-left: 3px solid var(--orange);
      border-radius: 0 6px 6px 0;
      font-family: var(--mono); font-size: 9px;
      color: var(--orange); line-height: 1.6;
    }
    .ai-stats-snap {
      display: flex; gap: 12px; flex-wrap: wrap;
      margin-top: 7px; padding: 5px 9px;
      background: rgba(0,180,255,0.04);
      border: 1px solid rgba(0,180,255,0.12);
      border-radius: 6px;
      font-family: var(--mono); font-size: 9px; color: var(--t2);
    }
    .msg-source {
      font-family: var(--mono); font-size: 8px;
      color: var(--purple); margin-top: 3px; letter-spacing: .5px;
    }
  `;
  document.head.appendChild(s);
})();

// ═════════════════════════════════════════════════════════════════════════════
// MITRE MAPPINGS (/api/mitre-mappings)
// ═════════════════════════════════════════════════════════════════════════════

async function loadMITREMappings() {
  const data = await fetchJSON("/api/mitre-mappings");
  if (!data) return;

  renderMITRESummary(data);
}

function renderMITRESummary(data) {
  const content = el("mitreContent");
  
  const coverage = data.framework_coverage || {};
  const attackCount = coverage.attack ? coverage.attack.length : 0;
  const carCount = coverage.car ? coverage.car.length : 0;
  const d3fendCount = coverage.d3fend ? coverage.d3fend.length : 0;
  const engageCount = coverage.engage ? coverage.engage.length : 0;
  
  const attackTechs = Object.values(data.attack_techniques || {}).slice(0, 3);
  const carAnalytics = Object.values(data.car_analytics || {}).slice(0, 2);
  
  content.innerHTML = `
    <div class="mitre-stats">
      <div class="mitre-stat">
        <span class="mitre-stat-label">ATT&CK</span>
        <span class="mitre-stat-val">${attackCount}</span>
      </div>
      <div class="mitre-stat">
        <span class="mitre-stat-label">CAR</span>
        <span class="mitre-stat-val">${carCount}</span>
      </div>
      <div class="mitre-stat">
        <span class="mitre-stat-label">D3FEND</span>
        <span class="mitre-stat-val">${d3fendCount}</span>
      </div>
      <div class="mitre-stat">
        <span class="mitre-stat-label">ENGAGE</span>
        <span class="mitre-stat-val">${engageCount}</span>
      </div>
    </div>
    
    ${attackTechs.length > 0 ? `
      <div class="mitre-section">
        <div class="mitre-section-title">🎯 Top ATT&CK Techniques</div>
        <div class="mitre-items">
          ${attackTechs.map(tech => `
            <div class="mitre-item attack">
              <span class="mitre-id">${tech.technique_id}</span>
              <span class="mitre-name">${tech.technique_name}</span>
              <span class="mitre-tactic">${tech.tactic}</span>
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}
    
    ${carAnalytics.length > 0 ? `
      <div class="mitre-section">
        <div class="mitre-section-title">🔬 CAR Analytics</div>
        <div class="mitre-items">
          ${carAnalytics.map(analytic => `
            <div class="mitre-item car">
              <span class="mitre-id">${analytic.analytics_id}</span>
              <span class="mitre-name">${analytic.analytics_name}</span>
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}
    
    <div class="mitre-footer">
      <span>📊 ${data.mapped_logs}/${data.total_logs} logs mapped</span>
      <a href="/mitre-mapping" class="mitre-link">View Details →</a>
    </div>
  `;
}