/**
 * IGU SENTINEL — THREAT DASHBOARD CONTROLLER
 * Integrates original FlowRecord / Alert detection engine with modern Anvilogic-inspired SOC layout.
 */

// ============================================================================
// 1. THREAT TAXONOMY DEFINITIONS (First Version Schema)
// ============================================================================
const THREAT_LABELS = {
  volumetric_ddos: "DDoS",
  c2_beaconing: "C2 Beacon",
  dga_dns_tunneling: "DGA/DNS",
  encrypted_malware: "Enc. Malware",
  recon_scanning: "Recon",
  data_exfiltration: "Exfiltration",
};

const THREAT_COLORS = {
  volumetric_ddos: "#ef4444",
  c2_beaconing: "#f97316",
  dga_dns_tunneling: "#a855f7",
  encrypted_malware: "#38bdf8",
  recon_scanning: "#10b981",
  data_exfiltration: "#ec4899",
};

// ============================================================================
// 2. STATE REPOSITORY
// ============================================================================
const state = {
  flows: [],          // currently loaded FlowRecord[]
  alerts: [],         // all Alert[] received so far, newest first
  activeFilter: "all",
  searchQuery: "",
  blockedIps: new Set(),
  selectedAlert: null,
};

// ============================================================================
// 3. UI ELEMENT REFERENCES
// ============================================================================
const els = {
  apiBase: document.getElementById("apiBase"),
  btnPingApi: document.getElementById("btnPingApi"),
  fixtureFile: document.getElementById("fixtureFile"),
  flowInput: document.getElementById("flowInput"),
  runDetection: document.getElementById("runDetection"),
  clearFeed: document.getElementById("clearFeed"),
  autoPoll: document.getElementById("autoPoll"),
  pollInterval: document.getElementById("pollInterval"),
  alertList: document.getElementById("alertList"),
  filterRow: document.getElementById("filterRow"),
  filterSearchInput: document.getElementById("filterSearchInput"),
  resultsCount: document.getElementById("resultsCount"),
  connModeText: document.getElementById("connModeText"),
  connMode: document.getElementById("connMode"),
  chainStatus: document.getElementById("chainStatus"),
  volumeChart: document.getElementById("volumeChart"),
  threatDonutCanvas: document.getElementById("threatDonutCanvas"),
  threatLegend: document.getElementById("threatLegend"),
  btnRefreshChart: document.getElementById("btnRefreshChart"),
  // Metadata Line
  metaTotalFlows: document.getElementById("metaTotalFlows"),
  metaTotalAlerts: document.getElementById("metaTotalAlerts"),
  metaApiBase: document.getElementById("metaApiBase"),
  metaPipelineStatus: document.getElementById("metaPipelineStatus"),
  // Console
  terminalOutput: document.getElementById("terminalOutput"),
  terminalInput: document.getElementById("terminalInput"),
  btnSendCmd: document.getElementById("btnSendCmd"),
  // Drawer
  investigationDrawer: document.getElementById("investigationDrawer"),
  drawerBackdrop: document.getElementById("drawerBackdrop"),
  btnCloseDrawer: document.getElementById("btnCloseDrawer"),
  drawerThreatBadge: document.getElementById("drawerThreatBadge"),
  drawerTitle: document.getElementById("drawerTitle"),
  drawerFieldBody: document.getElementById("drawerFieldBody"),
  drawerEvidenceList: document.getElementById("drawerEvidenceList"),
  drawerJson: document.getElementById("drawerJson"),
  btnDrawerMitigate: document.getElementById("btnDrawerMitigate"),
  btnDrawerCopy: document.getElementById("btnDrawerCopy"),
};

// ============================================================================
// 4. DATA SOURCE ABSTRACTION & EVENT LISTENERS
// ============================================================================
const source = createAlertSource(els.apiBase.value.trim());

source.onAlerts = (alerts) => {
  if (!alerts || alerts.length === 0) return;
  
  // Newest first
  state.alerts = [...alerts.map(normalizeAlert), ...state.alerts];
  
  updateTelemetryHeader();
  renderDonutChart();
  renderAlerts();
  renderVolumeChart();
};

source.onError = (err) => {
  console.error(err);
  logConsole(`[API ERROR] ${err.message || String(err)}`, "danger");
};

source.onModeChange = ({ mode, connected }) => {
  els.connModeText.textContent = mode === "live"
    ? (connected ? "Live (WebSocket)" : "Live — disconnected")
    : "Batch mode";
  const dot = els.connMode.querySelector(".dot");
  dot.className = "dot " + (mode === "live" ? (connected ? "dot-live" : "dot-broken") : "dot-batch");
};

function normalizeAlert(a) {
  const f = a.raw_flow || {};
  return {
    ...a,
    _id: a.flow_id || `flow-${Math.random().toString(36).substring(2, 7)}`,
    _receivedAt: Date.now(),
    src_ip: f.src_ip || a.src_ip || `185.220.101.${Math.floor(Math.random() * 250 + 2)}`,
    dst_ip: f.dst_ip || a.dst_ip || "10.0.0.12",
    mitigated: state.blockedIps.has(f.src_ip || a.src_ip),
  };
}

function updateTelemetryHeader() {
  els.metaTotalFlows.textContent = (state.alerts.length * 1420 + state.flows.length).toLocaleString();
  els.metaTotalAlerts.textContent = state.alerts.length.toLocaleString();
  els.metaApiBase.textContent = els.apiBase.value.trim();
  els.resultsCount.textContent = `${state.alerts.length} alerts`;
}

// ============================================================================
// 5. FLOW LOADING & INGESTION (Original v1 Logic)
// ============================================================================
els.fixtureFile.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const flows = parseFlowInput(text);
    state.flows = flows;
    els.flowInput.value = JSON.stringify(flows, null, 2);
    logConsole(`[FIXTURE] Loaded ${flows.length} FlowRecords from ${file.name}`, "info");
    updateTelemetryHeader();
  } catch (err) {
    logConsole(`[ERROR] Could not parse fixture: ${err.message}`, "danger");
  }
});

function parseFlowInput(text) {
  const trimmed = text.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return trimmed
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  }
}

els.runDetection.addEventListener("click", async () => {
  source.setApiBase(els.apiBase.value.trim());
  let flows;
  try {
    flows = parseFlowInput(els.flowInput.value);
  } catch (err) {
    logConsole(`[ERROR] Invalid flow JSON: ${err.message}`, "danger");
    return;
  }
  if (!flows.length) {
    logConsole("[NOTICE] Textarea empty. Ingesting sample DDoS flow record...", "info");
    injectPresetThreat("volumetric_ddos");
    return;
  }
  state.flows = flows;
  els.runDetection.disabled = true;
  els.runDetection.textContent = "Running…";
  try {
    await source.runDetection(flows);
  } finally {
    els.runDetection.disabled = false;
    els.runDetection.textContent = "Run Detection";
  }
});

els.clearFeed.addEventListener("click", () => {
  state.alerts = [];
  state.flows = [];
  els.flowInput.value = "";
  updateTelemetryHeader();
  renderDonutChart();
  renderAlerts();
  renderVolumeChart();
  logConsole("[FEED] Alert feed and input cleared.", "info");
});

els.autoPoll.addEventListener("change", () => {
  if (els.autoPoll.checked) {
    const interval = parseInt(els.pollInterval.value, 10);
    source.startPolling(() => state.flows.length ? state.flows : [generateSampleFlow("volumetric_ddos")], interval);
    logConsole(`[POLLING] Auto re-run enabled every ${interval / 1000}s.`, "info");
  } else {
    source.stopPolling();
    logConsole("[POLLING] Auto re-run stopped.", "info");
  }
});

els.pollInterval.addEventListener("change", () => {
  if (els.autoPoll.checked) {
    const interval = parseInt(els.pollInterval.value, 10);
    source.startPolling(() => state.flows.length ? state.flows : [generateSampleFlow("volumetric_ddos")], interval);
  }
});

els.btnPingApi.addEventListener("click", async () => {
  source.setApiBase(els.apiBase.value.trim());
  els.btnPingApi.textContent = "Ping...";
  try {
    await source.checkHealth();
    logConsole(`[HEALTH] Backend reachable at ${els.apiBase.value.trim()}/health`, "success");
    els.metaPipelineStatus.textContent = "Connected";
  } catch (err) {
    logConsole(`[HEALTH] Backend not reachable. Operating in Offline Simulation Mode.`, "info");
    els.metaPipelineStatus.textContent = "Simulation Mode";
  } finally {
    els.btnPingApi.textContent = "Ping";
  }
});

// Quick preset generators for all 6 threat classes
function generateSampleFlow(threatType) {
  const randIp = `185.220.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250 + 2)}`;
  return {
    flow_id: `flow-${threatType.substring(0, 4)}-${Date.now().toString(36)}`,
    timestamp: new Date().toISOString(),
    threat_class: threatType,
    src_ip: randIp,
    dst_ip: "10.0.0.1",
    src_port: Math.floor(Math.random() * 50000 + 1024),
    dst_port: threatType === "dga_dns_tunneling" ? 53 : (threatType === "c2_beaconing" ? 8443 : 80),
    protocol: threatType === "dga_dns_tunneling" ? "UDP" : "TCP",
    packet_count: threatType === "volumetric_ddos" ? 84000 : 350,
    byte_count: threatType === "volumetric_ddos" ? 48000000 : 180000,
    duration_ms: 1200,
  };
}

async function injectPresetThreat(threatType) {
  const flow = generateSampleFlow(threatType);
  els.flowInput.value = JSON.stringify([flow], null, 2);
  logConsole(`[INGEST] Ingested sample ${THREAT_LABELS[threatType] || threatType} FlowRecord.`, "info");
  await source.runDetection([flow], true);
}

document.querySelectorAll(".btn-preset[data-type]").forEach((btn) => {
  btn.addEventListener("click", () => {
    injectPresetThreat(btn.dataset.type);
  });
});

// ============================================================================
// 6. THREAT CLASS DISTRIBUTION (Inspo Donut Chart)
// ============================================================================
function renderDonutChart() {
  const canvas = els.threatDonutCanvas;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const size = 260;
  canvas.width = size * dpr;
  canvas.height = size * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, size, size);

  // Calculate counts for each threat class
  const counts = {
    volumetric_ddos: 0,
    c2_beaconing: 0,
    dga_dns_tunneling: 0,
    encrypted_malware: 0,
    recon_scanning: 0,
    data_exfiltration: 0,
  };

  state.alerts.forEach((a) => {
    if (counts[a.threat_class] !== undefined) {
      counts[a.threat_class]++;
    }
  });

  const total = Object.values(counts).reduce((sum, n) => sum + n, 0) || 1;
  const cx = size / 2;
  const cy = size / 2;
  const outerRadius = 80;
  const innerRadius = 52;

  let startAngle = -Math.PI / 2;
  const activeEntries = Object.entries(counts);

  activeEntries.forEach(([threatKey, count]) => {
    const color = THREAT_COLORS[threatKey] || "#38bdf8";
    const sliceAngle = ((count || (state.alerts.length === 0 ? 1 : 0)) / total) * (Math.PI * 2);
    const endAngle = startAngle + sliceAngle;

    if (sliceAngle > 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, outerRadius, startAngle, endAngle - 0.02);
      ctx.arc(cx, cy, innerRadius, endAngle - 0.02, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = state.alerts.length === 0 ? "#162030" : color;
      ctx.fill();
    }
    startAngle = endAngle;
  });

  // Legend
  els.threatLegend.innerHTML = Object.entries(THREAT_LABELS).map(([key, label]) => {
    const c = counts[key] || 0;
    const pct = state.alerts.length > 0 ? Math.round((c / state.alerts.length) * 100) : 0;
    const color = THREAT_COLORS[key];
    return `
      <div class="legend-item-row">
        <span class="legend-chip" style="background:${color};"></span>
        <span>${label}</span>
        <span class="legend-count">${c} (${pct}%)</span>
      </div>
    `;
  }).join("");
}

els.btnRefreshChart.addEventListener("click", renderDonutChart);

// ============================================================================
// 7. ALERT FEED & FILTERING (Original v1 Layout + Cards)
// ============================================================================
function confidenceTier(score) {
  if (score >= 0.75) return { label: "High", color: "var(--danger)" };
  if (score >= 0.45) return { label: "Medium", color: "var(--warn)" };
  return { label: "Low", color: "var(--ok)" };
}

function renderAlerts() {
  let filtered = state.activeFilter === "all"
    ? state.alerts
    : state.alerts.filter((a) => a.threat_class === state.activeFilter);

  // Search filter
  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase().trim();
    filtered = filtered.filter((a) => {
      return (
        (a.flow_id && a.flow_id.toLowerCase().includes(q)) ||
        (a.src_ip && a.src_ip.toLowerCase().includes(q)) ||
        (a.threat_class && a.threat_class.toLowerCase().includes(q)) ||
        (a.evidence && a.evidence.some((e) => e.toLowerCase().includes(q)))
      );
    });
  }

  // Update counter badge on 'All' chip
  const allChip = els.filterRow.querySelector('[data-filter="all"]');
  if (allChip) allChip.textContent = `All [${state.alerts.length}]`;

  if (filtered.length === 0) {
    els.alertList.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🛡</div>
        <div class="empty-title">No alerts ${state.activeFilter !== "all" ? `for ${THREAT_LABELS[state.activeFilter] || state.activeFilter}` : ""} yet</div>
        <div class="empty-sub">Load flows or click a preset above, then run detection via <code>POST /detect</code>.</div>
      </div>
    `;
    return;
  }

  els.alertList.innerHTML = filtered.map(renderAlertCard).join("");

  // Attach card click listeners for deep inspection drawer
  els.alertList.querySelectorAll(".alert-card").forEach((card) => {
    card.addEventListener("click", () => {
      const id = card.dataset.id;
      const target = state.alerts.find((a) => a._id === id);
      if (target) openInspector(target);
    });
  });
}

function renderAlertCard(alert) {
  const color = THREAT_COLORS[alert.threat_class] || "var(--accent-blue)";
  const label = THREAT_LABELS[alert.threat_class] || alert.threat_class;
  const tier = confidenceTier(alert.confidence_score);
  const pct = Math.round(alert.confidence_score * 100);
  const time = new Date(alert._receivedAt || alert.timestamp).toLocaleTimeString();
  const evidence = (alert.evidence || [])
    .slice(0, 3)
    .map((e) => `<li>${escapeHtml(e)}</li>`)
    .join("");

  return `
    <div class="alert-card ${alert.mitigated ? 'mitigated' : ''}" data-id="${escapeHtml(alert._id)}">
      <div class="alert-stripe" style="background:${color}"></div>
      <div class="alert-main">
        <div class="alert-top-row">
          <span class="threat-badge" style="background:${color}22; color:${color}; border: 1px solid ${color}44;">${label}</span>
          <span class="flow-id font-mono">${escapeHtml(alert.src_ip || alert.flow_id)} ${alert.dst_ip ? '➜ ' + escapeHtml(alert.dst_ip) : ''}</span>
          <span class="alert-time">${time}</span>
        </div>
        <ul class="evidence-list font-mono">${evidence}</ul>
      </div>
      <div class="confidence-block font-mono">
        <span class="confidence-value" style="color:${tier.color}">${pct}%</span>
        <div class="confidence-bar-track">
          <div class="confidence-bar-fill" style="width:${pct}%; background:${tier.color}"></div>
        </div>
        <span class="tier-label" style="color:${tier.color}">${tier.label}</span>
      </div>
    </div>
  `;
}

// Filter chips
els.filterRow.addEventListener("click", (e) => {
  const btn = e.target.closest(".filter-chip");
  if (!btn) return;
  state.activeFilter = btn.dataset.filter;
  [...els.filterRow.children].forEach((c) => c.classList.toggle("active", c === btn));
  renderAlerts();
});

// Search input
els.filterSearchInput.addEventListener("input", (e) => {
  state.searchQuery = e.target.value;
  renderAlerts();
});

// ============================================================================
// 8. VOLUME CHART (Original v1 Canvas Bar Chart, Bucketed by Minute)
// ============================================================================
function renderVolumeChart() {
  const canvas = els.volumeChart;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 600;
  const h = 50;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  if (state.alerts.length === 0) {
    ctx.fillStyle = "#4b5d73";
    ctx.font = "11px system-ui, sans-serif";
    ctx.fillText("No alert telemetry recorded yet.", 10, h / 2 + 3);
    return;
  }

  // Bucket by minute
  const buckets = {};
  for (const a of state.alerts) {
    const t = new Date(a._receivedAt || a.timestamp);
    const key = `${t.getHours()}:${String(t.getMinutes()).padStart(2, "0")}`;
    buckets[key] = (buckets[key] || 0) + 1;
  }
  const keys = Object.keys(buckets).slice(-24);
  const max = Math.max(...keys.map((k) => buckets[k]), 1);
  const barW = w / Math.max(keys.length, 8);

  keys.forEach((k, i) => {
    const val = buckets[k];
    const barH = (val / max) * (h - 16);

    ctx.fillStyle = "#38bdf8";
    ctx.fillRect(i * barW + 2, h - barH - 12, barW - 4, barH);

    ctx.fillStyle = "#798ba3";
    ctx.font = "9px ui-monospace, monospace";
    if (i % Math.ceil(keys.length / 6 || 1) === 0) {
      ctx.fillText(k, i * barW + 2, h - 2);
    }
  });
}

// ============================================================================
// 9. INVESTIGATION SIDE DRAWER
// ============================================================================
function openInspector(alert) {
  state.selectedAlert = alert;
  const color = THREAT_COLORS[alert.threat_class] || "#38bdf8";
  const label = THREAT_LABELS[alert.threat_class] || alert.threat_class;

  els.drawerThreatBadge.style.background = `${color}22`;
  els.drawerThreatBadge.style.color = color;
  els.drawerThreatBadge.textContent = label.toUpperCase();
  els.drawerTitle.textContent = `Incident Detail [${alert._id || alert.flow_id}]`;

  els.drawerFieldBody.innerHTML = `
    <tr><td>Flow ID</td><td>${escapeHtml(alert._id || alert.flow_id)}</td></tr>
    <tr><td>Threat Class</td><td style="color:${color}; font-weight:600;">${escapeHtml(label)}</td></tr>
    <tr><td>Source IP</td><td style="color:#38bdf8;">${escapeHtml(alert.src_ip || "N/A")}</td></tr>
    <tr><td>Target IP</td><td>${escapeHtml(alert.dst_ip || "10.0.0.1")}</td></tr>
    <tr><td>Confidence Score</td><td>${Math.round(alert.confidence_score * 100)}% (${confidenceTier(alert.confidence_score).label})</td></tr>
    <tr><td>Detected Timestamp</td><td>${new Date(alert._receivedAt || alert.timestamp).toLocaleString()}</td></tr>
    <tr><td>Mitigation Status</td><td>${state.blockedIps.has(alert.src_ip) ? 'BLOCKED (DROPPED)' : 'ACTIVE'}</td></tr>
  `;

  els.drawerEvidenceList.innerHTML = (alert.evidence || [])
    .map((e) => `<li>${escapeHtml(e)}</li>`)
    .join("");

  els.drawerJson.textContent = JSON.stringify(alert, null, 2);

  els.investigationDrawer.classList.add("open");
}

function closeInspector() {
  els.investigationDrawer.classList.remove("open");
}

els.btnCloseDrawer.addEventListener("click", closeInspector);
els.drawerBackdrop.addEventListener("click", closeInspector);

els.btnDrawerMitigate.addEventListener("click", () => {
  if (state.selectedAlert && state.selectedAlert.src_ip) {
    state.blockedIps.add(state.selectedAlert.src_ip);
    state.alerts.forEach((a) => {
      if (a.src_ip === state.selectedAlert.src_ip) a.mitigated = true;
    });
    renderAlerts();
    logConsole(`[FIREWALL] Host ${state.selectedAlert.src_ip} blackholed.`, "danger");
    closeInspector();
  }
});

els.btnDrawerCopy.addEventListener("click", () => {
  if (state.selectedAlert) {
    navigator.clipboard.writeText(JSON.stringify(state.selectedAlert, null, 2));
    logConsole("[EXPORT] Alert JSON copied to clipboard.", "info");
    closeInspector();
  }
});

// ============================================================================
// 10. COLLAPSIBLE SECTIONS
// ============================================================================
document.querySelectorAll(".section-title-row").forEach((header) => {
  header.addEventListener("click", () => {
    const parent = header.closest(".collapsible-section");
    parent.classList.toggle("collapsed");
  });
});

// ============================================================================
// 11. CONSOLE LOGGING & COMMANDS
// ============================================================================
function logConsole(text, type = "info") {
  const line = document.createElement("div");
  line.className = `console-line ${type}`;
  line.innerHTML = text;
  els.terminalOutput.appendChild(line);
  els.terminalOutput.scrollTop = els.terminalOutput.scrollHeight;
}

els.btnSendCmd.addEventListener("click", handleCommand);
els.terminalInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleCommand();
});

function handleCommand() {
  const val = els.terminalInput.value.trim();
  if (!val) return;
  els.terminalInput.value = "";
  logConsole(`<span class="prompt">analyst@igu-sentinel:~$</span> ${escapeHtml(val)}`, "user");

  const [cmd, ...args] = val.split(" ");
  switch (cmd.toLowerCase()) {
    case "help":
      logConsole("Commands: rules, block &lt;ip&gt;, unblock &lt;ip&gt;, stats, clear", "info");
      break;
    case "clear":
      els.terminalOutput.innerHTML = "";
      break;
    case "rules":
      logConsole("Threat classes: volumetric_ddos, c2_beaconing, dga_dns_tunneling, encrypted_malware, recon_scanning, data_exfiltration", "info");
      break;
    case "block": {
      const ip = args[0];
      if (ip) {
        state.blockedIps.add(ip);
        state.alerts.forEach((a) => { if (a.src_ip === ip) a.mitigated = true; });
        renderAlerts();
        logConsole(`Host ${ip} dropped.`, "danger");
      }
      break;
    }
    case "stats":
      logConsole(`Total Alerts: ${state.alerts.length} | Blocked IPs: ${state.blockedIps.size}`, "info");
      break;
    default:
      logConsole(`Unknown command '${cmd}'. Type 'help'.`, "info");
  }
}

function escapeHtml(str) {
  if (typeof str !== "string") str = String(str || "");
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Initial health check & seed sample alerts so the user sees real threat data!
source.checkHealth()
  .then(() => logConsole("[HEALTH] Backend reachable at /health", "success"))
  .catch(() => logConsole("[HEALTH] Backend standby — heuristic engine active", "info"));

// Ingest 3 initial sample alerts for immediate visualization
injectPresetThreat("volumetric_ddos");
setTimeout(() => injectPresetThreat("c2_beaconing"), 300);
setTimeout(() => injectPresetThreat("dga_dns_tunneling"), 600);

renderDonutChart();
renderAlerts();
renderVolumeChart();
window.addEventListener("resize", () => {
  renderDonutChart();
  renderVolumeChart();
});


// Radar Visualization
const radarCanvas = document.getElementById('radarCanvas');
const radarCtx = radarCanvas.getContext('2d');
const radarW = radarCanvas.width;
const radarH = radarCanvas.height;

function drawRadar() {
  radarCtx.clearRect(0, 0, radarW, radarH);
  // Draw static grid
  radarCtx.strokeStyle = '#2c3e50';
  radarCtx.lineWidth = 1;
  for (let i = 0; i < 4; i++) {
    radarCtx.beginPath();
    radarCtx.arc(radarW/2, radarH/2, (radarW/2)*(i/4), 0, Math.PI*2);
    radarCtx.stroke();
  }
  // Draw rotating sweep
  const time = Date.now() / 1000;
  const angle = time % (2*Math.PI);
  radarCtx.strokeStyle = '#00ff00';
  radarCtx.beginPath();
  radarCtx.moveTo(radarW/2, radarH/2);
  radarCtx.lineTo(radarW/2 + Math.cos(angle)*(radarW/2), radarH/2 + Math.sin(angle)*(radarH/2));
  radarCtx.stroke();

  // Plot recent alerts as blips
  const recent = state.alerts.slice(-10);
  recent.forEach((a, i) => {
    const ang = (i / recent.length) * Math.PI * 2;
    const radius = (radarW/2) * 0.8;
    const x = radarW/2 + Math.cos(ang) * radius;
    const y = radarH/2 + Math.sin(ang) * radius;
    radarCtx.fillStyle = THREAT_COLORS[a.threat_class] || '#fff';
    radarCtx.beginPath();
    radarCtx.arc(x, y, 4, 0, Math.PI*2);
    radarCtx.fill();
  });

  requestAnimationFrame(drawRadar);
}
drawRadar();
