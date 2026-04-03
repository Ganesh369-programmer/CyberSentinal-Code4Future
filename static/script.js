/* ══════════════════════════════════════════════════
   CYBERSENTINEL — BACKEND-CONNECTED DASHBOARD JS
   All data comes from Flask API at /api/*
   ══════════════════════════════════════════════════ */

const API = "";   // same origin — Flask serves both HTML and API

// ── State ─────────────────────────────────────────────────────────────────────
let allAlerts   = [];
let allLogs     = [];
let alertFilter = "all";
let logFilter   = "all";
let logSearch   = "";
let suspiciousIPs = new Set();
let pollTimer   = null;

// ── Init ──────────────────────────────────────────────────────────────────────
window.addEventListener("DOMContentLoaded", async () => {
  initMatrix();
  startClock();
  await bootSequence();
  pollTimer = setInterval(refreshAlerts, 15000);   // refresh alerts every 15s
});

async function bootSequence() {
  appendBotMessage(
    `🖥️ <strong>CyberSentinel SOC Co-Pilot initializing…</strong><br><br>` +
    `Connecting to Flask backend at <span style="color:var(--blue)">localhost:5000</span>…`,
    "system"
  );

  const health = await fetchJSON("/api/health");
  if (!health) {
    setStatus(false);
    appendBotMessage("⛔ Backend connection failed. Make sure Flask is running: <code>python app.py</code>", "error");
    return;
  }

  setStatus(true);
  await Promise.all([loadAlerts(), loadLogs()]);

  appendBotMessage(
    `✅ <strong>Backend connected.</strong><br><br>` +
    `Loaded <span style="color:var(--blue)">${allLogs.length} log events</span> · ` +
    `<span style="color:var(--red)">${allAlerts.length} threats detected</span>.<br><br>` +
    `Type a natural language query or click a chip below.`,
    "llama3"
  );

  if (allAlerts.length > 0) {
    const top = allAlerts[0];
    setTimeout(() => showAlert(
      `${top.effective_severity} threat: ${top.type.replace(/_/g," ").toUpperCase()} from ${top.src_ip}`
    ), 1000);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// API FETCHERS
// ═══════════════════════════════════════════════════════════════════════════════

async function fetchJSON(url, options = {}) {
  try {
    const res = await fetch(API + url, options);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    console.error(`[API] ${url}`, e.message);
    return null;
  }
}

// ── Load & render alerts ──────────────────────────────────────────────────────
async function loadAlerts() {
  const data = await fetchJSON("/api/alerts");
  if (!data) return;

  allAlerts = data.alerts || [];
  suspiciousIPs = new Set(allAlerts.map(a => a.src_ip));

  // Header stats
  const sc = data.severity_counts || {};
  animCount("hs-critical", sc.CRITICAL || 0);
  animCount("hs-high",     sc.HIGH     || 0);
  animCount("hs-events",   allLogs.length || 0);

  // Metric cards (top of panel 2)
  el("mc-threats").textContent = allAlerts.length;
  el("mc-ips").textContent     = suspiciousIPs.size;
  animBar("mc-threats-bar", Math.min(100, allAlerts.length * 15));
  animBar("mc-ips-bar",     Math.min(100, suspiciousIPs.size * 20));

  renderAlertFeed();
  populateIPSelect();
}

async function refreshAlerts() {
  const prev = allAlerts.length;
  await loadAlerts();
  if (allAlerts.length > prev) {
    const newest = allAlerts[0];
    flashNewAlert(newest);
    showAlert(`New threat detected: ${newest.type.replace(/_/g," ").toUpperCase()} from ${newest.src_ip}`);
  }
}

// ── Load & render logs ────────────────────────────────────────────────────────
async function loadLogs() {
  const data = await fetchJSON("/api/logs");
  if (!data) return;

  allLogs = data.logs || [];
  el("mc-total").textContent = allLogs.length;

  const failures = allLogs.filter(l => l.status === "failure").length;
  el("mc-fail").textContent = failures;
  animBar("mc-fail-bar", Math.round((failures / allLogs.length) * 100));

  animCount("hs-events", allLogs.length);
  renderLogTable();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALERT FEED RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

function setAlertFilter(f, btn) {
  alertFilter = f;
  document.querySelectorAll(".alert-panel .pill-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  renderAlertFeed();
}

function renderAlertFeed() {
  const feed = el("alertFeed");
  let filtered = alertFilter === "all"
    ? allAlerts
    : allAlerts.filter(a => a.effective_severity === alertFilter);

  if (!filtered.length) {
    feed.innerHTML = `<div class="empty-state">✅ No alerts match this filter.<br>System appears clean.</div>`;
    return;
  }

  feed.innerHTML = filtered.map((a, i) => {
    const mitreBadge = a.mitre
      ? `<div class="mitre-badge">⬡ ${a.mitre.id} — ${a.mitre.name}</div>` : "";
    const corr = a.correlated_threats && a.correlated_threats.length
      ? `<span class="badge scan">+${a.correlated_threats.length} correlated</span> ` : "";

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
        ${mitreBadge}
        <div class="alert-actions">
          <button class="action-btn" onclick="event.stopPropagation();investigateIP('${a.src_ip}')">🔍 Investigate</button>
          <button class="action-btn" onclick="event.stopPropagation();loadTimeline('${a.src_ip}')">📊 Timeline</button>
          <button class="action-btn danger" onclick="event.stopPropagation();blockIP('${a.src_ip}')">🚫 Block IP</button>
        </div>
      </div>`;
  }).join("");
}

function flashNewAlert(alert) {
  const cards = document.querySelectorAll(".alert-card");
  if (cards.length > 0) cards[0].classList.add("new-alert");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOG TABLE RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

function filterLogs(mode) {
  logFilter = mode;
  el("toggleAll").classList.toggle("active", mode === "all");
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
      (l.user || "").toLowerCase().includes(logSearch) ||
      (l.ip || "").includes(logSearch) ||
      (l.timestamp || "").includes(logSearch) ||
      (l.status || "").includes(logSearch) ||
      (l.source || "").includes(logSearch)
    );
  }

  if (!data.length) {
    body.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:20px;font-family:var(--mono);font-size:10px">No logs match</td></tr>`;
    return;
  }

  body.innerHTML = data.map(l => {
    const susp = suspiciousIPs.has(l.ip);
    const time = (l.timestamp || "").split(" ")[1] || l.timestamp || "?";
    return `<tr class="${susp ? "suspicious" : ""}">
      <td class="td-time">${time}</td>
      <td class="td-src">${l.source || "?"}</td>
      <td class="td-user">${l.user || "N/A"}</td>
      <td class="td-ip">${l.ip || "?"}</td>
      <td><span class="badge ${l.status === "success" ? "success" : l.status === "scan" ? "scan" : "failure"}">${l.status === "success" ? "OK" : l.status === "scan" ? "SCAN" : "FAIL"}</span></td>
    </tr>`;
  }).join("");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIMELINE
// ═══════════════════════════════════════════════════════════════════════════════

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

  const events = data.timeline || [];
  el("timelineWrap").innerHTML = `
    <div class="timeline-narrative">${data.narrative || ""}</div>
    ${events.map(e => `
      <div class="tl-event">
        <span class="tl-time">${(e.timestamp||"").split(" ")[1]||""}</span>
        <div class="tl-dot ${e.category}"></div>
        <div>
          <div class="tl-label">${e.label}</div>
          <div class="tl-src">${e.source} ${e.dest_ip && e.dest_ip !== "?" ? "→ "+e.dest_ip : ""}</div>
        </div>
      </div>`).join("")}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOAR: BLOCK IP
// ═══════════════════════════════════════════════════════════════════════════════

async function blockIP(ip) {
  const data = await fetchJSON("/api/block-ip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  if (!data) return;

  appendBotMessage(
    `🚫 <strong>SOAR Action Executed</strong><br><br>` +
    `IP <span style="color:var(--red)">${ip}</span> flagged for blocking.<br>` +
    `<span style="color:var(--t3)">Status: ${data.status}</span><br>` +
    `<code style="color:var(--t2);font-size:10px">${data.command}</code>`,
    "soar"
  );
  showAlert(`SOAR: IP ${ip} block action triggered (simulated).`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVESTIGATION MODAL
// ═══════════════════════════════════════════════════════════════════════════════

async function investigateIP(ip) {
  el("investigateModal").classList.remove("hidden");
  el("modalBackdrop").classList.remove("hidden");
  el("modalBody").innerHTML = `<div class="loading-state"><div class="loading-dots"><span></span><span></span><span></span></div><span>Investigating ${ip}…</span></div>`;

  const data = await fetchJSON("/api/investigate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });

  if (!data) {
    el("modalBody").innerHTML = `<div class="empty-state">Failed to load investigation for ${ip}.</div>`;
    return;
  }

  const playbooks = (data.playbooks || []).slice(0, 1);
  const explanation = data.explanations && data.explanations[0];
  const mitre = (data.mitre || []).slice(0, 2);
  const evidence = data.alerts && data.alerts[0] ? data.alerts[0].evidence || [] : [];

  el("modalBody").innerHTML = `
    <!-- Summary -->
    <div class="modal-section">
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
        <div class="risk-score"><span class="risk-label">RISK</span> ${data.risk_score || 0}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--blue)">${ip}</div>
      </div>
      <div class="modal-narrative">${data.summary || "No summary available."}</div>
    </div>

    ${explanation ? `
    <!-- AI Explanation -->
    <div class="modal-section">
      <div class="modal-section-title">AI ANALYSIS (${explanation.source || "llama3"})</div>
      <div class="llm-explanation">${(explanation.answer || "").replace(/\n/g,"<br>")}</div>
      ${(explanation.warnings||[]).map(w=>`<div class="msg-warning">⚠ ${w}</div>`).join("")}
    </div>` : ""}

    ${mitre.length ? `
    <!-- MITRE -->
    <div class="modal-section">
      <div class="modal-section-title">MITRE ATT&CK MAPPING</div>
      ${mitre.map(m=>`
        <div class="playbook-step">
          <div class="step-num">${m.technique_id}</div>
          <div class="step-info">
            <div class="step-action">${m.technique_name}</div>
            <div class="step-desc">${m.tactic} · Severity: ${m.severity}</div>
            <div class="step-desc">${(m.description||"").slice(0,150)}…</div>
          </div>
        </div>`).join("")}
    </div>` : ""}

    ${evidence.length ? `
    <!-- Evidence -->
    <div class="modal-section">
      <div class="modal-section-title">EVIDENCE (${evidence.length} log entries)</div>
      ${evidence.map(e=>`<div class="evidence-line">▸ ${e}</div>`).join("")}
    </div>` : ""}

    ${playbooks.length ? `
    <!-- SOAR Playbook -->
    <div class="modal-section">
      <div class="modal-section-title">SOAR RESPONSE PLAYBOOK — ${playbooks[0].name||""}</div>
      ${(playbooks[0].steps||[]).map((s,i)=>`
        <div class="playbook-step">
          <div class="step-num">${i+1}</div>
          <div class="step-info">
            <div class="step-action">[${s.action}]</div>
            <div class="step-desc">${s.description}</div>
            <div class="step-cmd">${s.command||""}</div>
          </div>
        </div>`).join("")}
    </div>` : ""}

    <div style="text-align:center;padding-top:10px">
      <button class="action-btn danger" onclick="blockIP('${ip}');closeModal()">🚫 Block This IP</button>
    </div>`;
}

function closeModal() {
  el("investigateModal").classList.add("hidden");
  el("modalBackdrop").classList.add("hidden");
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI CHAT — connected to /api/query
// ═══════════════════════════════════════════════════════════════════════════════

const chatMessages = el_lazy("chatMessages");

function sendChip(q) {
  el("chatInput").value = q;
  handleSend();
}

async function handleSend() {
  const input = el("chatInput");
  const raw   = input.value.trim();
  if (!raw) return;

  appendUserMessage(raw);
  input.value = "";
  input.focus();

  const typingId = showTyping();

  const data = await fetchJSON("/api/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: raw }),
  });

  removeTyping(typingId);

  if (!data) {
    appendBotMessage("⛔ Backend unreachable. Check that Flask is running.", "error");
    return;
  }

  // Update AI source badge
  el("aiSourceTag").textContent = data.source === "llama3"
    ? "LLAMA3 · GROUNDED" : data.source === "keyword_fallback"
    ? "KEYWORD MODE" : data.source === "soar" ? "SOAR ENGINE" : "NLP ENGINE";

  let html = data.answer ? data.answer.replace(/\n/g, "<br>") : "No response.";

  // Render data tables inline
  if (data.type === "log_filter" && data.data && data.data.length) {
    html += buildChatTable(
      ["TIMESTAMP","SOURCE","USER","IP ADDRESS","STATUS"],
      data.data.map(l => [
        l.timestamp, l.source, l.user||"N/A", l.ip,
        `<span class="badge ${l.status==="success"?"success":l.status==="scan"?"scan":"failure"}">${l.status.toUpperCase()}</span>`
      ]),
      data.data.map(l => suspiciousIPs.has(l.ip))
    );
  }

  if (data.type === "threat_list" && data.data && data.data.length) {
    html += buildChatTable(
      ["IP","TYPE","SEVERITY","MITRE"],
      data.data.slice(0,6).map(a => [
        a.src_ip,
        a.type.replace(/_/g," "),
        `<span class="badge ${a.effective_severity==="CRITICAL"||a.effective_severity==="HIGH"?"failure":a.effective_severity==="MEDIUM"?"scan":"success"}">${a.effective_severity}</span>`,
        a.mitre ? a.mitre.id : "?"
      ]),
      data.data.map(() => true)
    );
  }

  if (data.type === "mitre_list" && data.data) {
    html += buildChatTable(
      ["ID","TECHNIQUE","TACTIC","SEVERITY"],
      data.data.map(m => [m.technique_id, m.technique_name, m.tactic, m.severity]),
      []
    );
  }

  if (data.type === "soar_action" && data.data && data.data.steps) {
    html += "<br>" + data.data.steps.map((s,i) =>
      `<div style="font-size:10px;color:var(--t2);padding:2px 0">${i+1}. [${s.action}] ${s.description.slice(0,80)}</div>`
    ).join("");
  }

  appendBotMessage(html, data.source, data.warnings);
}

el("chatInput").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
});

// ── Chat helpers ──────────────────────────────────────────────────────────────
function appendUserMessage(text) {
  const msgs = el("chatMessages");
  const div  = document.createElement("div");
  div.className = "msg user";
  div.innerHTML = `
    <div class="msg-avatar">⬟</div>
    <div class="msg-content">
      <div class="msg-meta">OPERATOR · ${fmtTime()}</div>
      <div class="msg-bubble">${escapeHTML(text)}</div>
    </div>`;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function appendBotMessage(html, source = "system", warnings = []) {
  const msgs = el("chatMessages");
  const div  = document.createElement("div");
  div.className = "msg bot";
  const src  = source ? `<div class="msg-source">◈ ${source.toUpperCase()}</div>` : "";
  const warn = warnings && warnings.length
    ? warnings.map(w => `<div class="msg-warning">⚠ ${w}</div>`).join("") : "";
  div.innerHTML = `
    <div class="msg-avatar">⬡</div>
    <div class="msg-content">
      <div class="msg-meta">SENTINEL-AI · ${fmtTime()}</div>
      <div class="msg-bubble">${html}</div>
      ${src}${warn}
    </div>`;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function showTyping() {
  const msgs = el("chatMessages");
  const id   = "typing_" + Date.now();
  const div  = document.createElement("div");
  div.className = "msg bot";
  div.id = id;
  div.innerHTML = `
    <div class="msg-avatar">⬡</div>
    <div class="msg-content">
      <div class="msg-meta">SENTINEL-AI · ANALYZING</div>
      <div class="typing-bubble">
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
      </div>
    </div>`;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
  return id;
}

function removeTyping(id) {
  const t = document.getElementById(id);
  if (t) t.remove();
}

function buildChatTable(headers, rows, suspicious = []) {
  const ths = headers.map(h => `<th>${h}</th>`).join("");
  const trs = rows.map((row, i) =>
    `<tr class="${suspicious[i] ? "suspicious" : ""}">${row.map(cell => `<td>${cell}</td>`).join("")}</tr>`
  ).join("");
  return `<table class="chat-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// UI UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

function setStatus(ok) {
  const badge = el("systemStatus");
  const text  = el("statusText");
  badge.classList.toggle("error", !ok);
  text.textContent = ok ? "SYSTEM ONLINE" : "BACKEND OFFLINE";
  const dot = badge.querySelector(".pulse-dot");
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
  const elmt = el(id);
  let cur = 0;
  const step = Math.max(1, Math.ceil(target / 20));
  const t = setInterval(() => {
    cur = Math.min(cur + step, target);
    elmt.textContent = cur;
    if (cur >= target) clearInterval(t);
  }, 40);
}

function animBar(id, pct) {
  const b = el(id);
  if (b) setTimeout(() => { b.style.width = Math.min(100, pct) + "%"; }, 100);
}

function startClock() {
  const update = () => {
    el("headerClock").textContent =
      new Date().toLocaleTimeString("en-US", { hour12: false });
  };
  update();
  setInterval(update, 1000);
}

function fmtTime() {
  return new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function el(id) { return document.getElementById(id); }
function el_lazy(id) { return { get: () => document.getElementById(id) }; }
function escapeHTML(s) { return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

// ═══════════════════════════════════════════════════════════════════════════════
// MATRIX RAIN
// ═══════════════════════════════════════════════════════════════════════════════

function initMatrix() {
  const canvas = el("matrixCanvas");
  const ctx    = canvas.getContext("2d");
  const resize = () => { canvas.width = innerWidth; canvas.height = innerHeight; };
  resize();
  window.addEventListener("resize", resize);

  const chars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()";
  const fs     = 12;
  let cols = Math.floor(canvas.width / fs);
  let drops = Array(cols).fill(0);
  window.addEventListener("resize", () => {
    cols = Math.floor(canvas.width / fs);
    drops = Array(cols).fill(0);
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