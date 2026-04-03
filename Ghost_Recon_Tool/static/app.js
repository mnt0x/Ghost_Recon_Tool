const AppStore = {
  currentReport: null,
  currentReportScanId: null,
  currentScanId: null,
  currentDomain: "",
  lastEventTs: 0,
  livenessProbeInFlight: false,
  eventSource: null,
  currentMode: "balanced",
  queueRefreshTimer: null,
  queueFetchInFlight: false,
  queueIntervalMs: 8000,
  viewedScanId: null,
  activeScans: {},
  resultFragmentCache: {},
  resultSectionCache: {},
  infraSelections: {},
  infraFilters: {},
  sectionPages: {},
  largeResultBrowsers: {},
};

function $(id) { return document.getElementById(id); }
function qsa(sel, root) { return (root || document).querySelectorAll(sel); }
function parseJsonSafe(raw, fallback) {
  try { return JSON.parse(raw || ""); } catch (_) { return fallback; }
}

function isSettledScanStatus(status) {
  return ["done", "saved"].includes(String(status || "").toLowerCase());
}

function activeScanState(scanId) {
  return AppStore.activeScans[String(scanId || AppStore.currentScanId || "")] || {};
}

function isSettledScan(scanId) {
  const ids = [scanId, AppStore.currentScanId, AppStore.viewedScanId]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  return ids.some((id) => isSettledScanStatus(activeScanState(id).status));
}

function stopActiveScanPolling() {
  clearInterval(timerInterval);
  timerInterval = null;
  AppStore.livenessProbeInFlight = false;
}

function markScanSettled(scanId, partial) {
  const settledId = String(scanId || AppStore.currentScanId || AppStore.viewedScanId || "");
  if (settledId) {
    upsertScanState(settledId, { status: "done", ...(partial || {}) });
  }
  AppStore.lastEventTs = Date.now();
  updateProgress(100);
  hideUiError();
  stopActiveScanPolling();
}

function showUiError(msg, scanId) {
  const txt = msg || "UI error, check report";
  if (txt === "No SSE events in 30s. Scan may still be running." && isSettledScan(scanId)) {
    hideUiError();
    return;
  }
  const ex = $("ui-error-banner");
  if (ex) { ex.textContent = txt; ex.style.display = "block"; return; }
  const b = document.createElement("div");
  b.id = "ui-error-banner";
  b.className = "ui-error-banner";
  b.textContent = txt;
  document.body.appendChild(b);
}

function hideUiError() {
  const ex = $("ui-error-banner");
  if (ex) { ex.style.display = "none"; }
}

function showActionBanner(msg, actions) {
  const text = String(msg || "").trim() || "Unexpected state";
  let box = $("scan-state-banner");
  if (!box) {
    box = document.createElement("div");
    box.id = "scan-state-banner";
    box.style.cssText = "position:fixed;top:62px;right:20px;z-index:1200;max-width:480px;background:rgba(15,23,42,.96);border:1px solid rgba(239,68,68,.45);border-radius:10px;padding:12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.45)";
    document.body.appendChild(box);
  }
  box.innerHTML = "";
  const title = document.createElement("div");
  title.style.cssText = "font-size:13px;font-weight:700;color:#fecaca;margin-bottom:8px";
  title.textContent = text;
  box.appendChild(title);
  const row = document.createElement("div");
  row.style.cssText = "display:flex;gap:8px;flex-wrap:wrap";
  (actions || []).forEach((action) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = action.label || "Action";
    btn.onclick = action.onClick;
    row.appendChild(btn);
  });
  box.appendChild(row);
}

function hideActionBanner() {
  const box = $("scan-state-banner");
  if (box) { box.remove(); }
}

function flashError(msg) {
  const el = document.createElement("div");
  el.className = "flash-toast";
  el.style.background = "rgba(239,68,68,.16)";
  el.style.borderColor = "rgba(239,68,68,.55)";
  el.style.color = "#fecaca";
  el.textContent = msg || "Operation failed";
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2600);
}

function closeActiveEventSource() {
  if (AppStore.eventSource) {
    try { AppStore.eventSource.close(); } catch (_) {}
    AppStore.eventSource = null;
  }
}

function stopActiveScanUi() {
  stopActiveScanPolling();
  closeActiveEventSource();
  AppStore.viewedScanId = null;
  AppStore.lastEventTs = 0;
  hideUiError();
}

function removeRenderedResults() {
  qsa("#results-page").forEach((el) => el.remove());
}

function showHomeShell() {
  const overlay = $("scan-overlay");
  if (overlay) { overlay.classList.remove("visible"); }
  if ($("home-page")) { $("home-page").style.display = ""; }
  removeRenderedResults();
  hideUiError();
  hideActionBanner();
}

function goHome(pushStateFlag = true, focusInput = false) {
  stopActiveScanUi();
  if (AppStore.currentScanId) {
    upsertScanState(AppStore.currentScanId, {
      domain: AppStore.currentDomain,
      mode: AppStore.currentMode,
      status: "running",
    });
  }
  AppStore.currentScanId = null;
  if (!$("home-page")) {
    window.location.href = "/";
    return;
  }
  showHomeShell();
  if (pushStateFlag) {
    window.history.pushState({ view: "home" }, "", "/");
  }
  if (focusInput) {
    setTimeout(() => $("domain-input")?.focus(), 40);
  }
}

function openNewScanTab() {
  const targetUrl = "/?view=new-scan";
  const tab = window.open(targetUrl, "_blank", "noopener,noreferrer");
  if (tab) {
    try { tab.opener = null; } catch (_) {}
  }
}

function isNewScanIntent() {
  const params = new URLSearchParams(window.location.search || "");
  const view = (params.get("view") || "").toLowerCase();
  const flag = (params.get("new_scan") || "").toLowerCase();
  return view === "new-scan" || flag === "1" || flag === "true";
}

function openScanQueue() {
  if ($("home-page")) {
    goHome(false, false);
    window.history.pushState({ view: "scans" }, "", "/scans");
    setTimeout(() => {
      const panel = $("scan-queue-panel");
      if (panel) { panel.scrollIntoView({ behavior: "smooth", block: "start" }); }
      refreshScanQueue(true);
    }, 40);
    return;
  }
  window.location.href = "/scans";
}

function pushScanHistoryPath(scanId, phase) {
  if (!scanId) { return; }
  const kind = phase === "results" ? "results" : "scan";
  const path = `/${kind}/${encodeURIComponent(scanId)}`;
  window.history.pushState({ view: kind, scan_id: scanId }, "", path);
}

function updateActiveScansCounter() {
  const countEl = $("active-scans-count");
  if (!countEl) { return; }
  const scans = Object.values(AppStore.activeScans || {});
  const activeCount = scans.filter((s) => ["queued", "running"].includes(String(s.status || ""))).length;
  countEl.textContent = String(activeCount);
}

function upsertScanState(scanId, partial) {
  if (!scanId) { return; }
  const prev = AppStore.activeScans[scanId] || { scan_id: scanId };
  AppStore.activeScans[scanId] = { ...prev, ...(partial || {}), scan_id: scanId };
  updateActiveScansCounter();
}

function handleHistoryNavigation() {
  const path = window.location.pathname || "/";
  if (path === "/" || path === "") {
    goHome(false, isNewScanIntent());
    return;
  }
  if (path === "/scans") {
    goHome(false, false);
    setTimeout(() => {
      const panel = $("scan-queue-panel");
      if (panel) { panel.scrollIntoView({ behavior: "smooth", block: "start" }); }
      refreshScanQueue(true);
    }, 40);
    return;
  }
  const scanMatch = path.match(/^\/scan\/([^/]+)$/);
  if (scanMatch) {
    const scanId = decodeURIComponent(scanMatch[1] || "");
    if (!scanId) {
      showActionBanner("Scan not found / expired", [
        { label: "Go Home", onClick: () => goHome(true, false) },
      ]);
      return;
    }
    fetch(`/api/scan/${encodeURIComponent(scanId)}/status`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((st) => {
        if (!st || !st.status || !["queued", "running", "done"].includes(st.status)) {
          showActionBanner("Scan not found / expired", [
            { label: "Go Home", onClick: () => goHome(true, false) },
          ]);
          return;
        }
        if (st.status === "done") {
          loadResults(scanId, { push: false });
          return;
        }
        reattachScan(scanId, st.domain || "scan", { push: false });
      })
      .catch(() => {
        showActionBanner("Scan not found / expired", [
          { label: "Go Home", onClick: () => goHome(true, false) },
        ]);
      });
    return;
  }
  const resultMatch = path.match(/^\/results\/([^/]+)$/);
  if (resultMatch && $("home-page")) {
    const scanId = decodeURIComponent(resultMatch[1] || "");
    if (scanId) { loadResults(scanId, { push: false }); }
  }
}

function logLine(cls, text) {
  const body = $("console-log");
  if (!body) { return; }
  const d = document.createElement("div");
  d.className = `cl-${cls}`;
  d.textContent = text;
  body.appendChild(d);
  if (body.children.length > 200) { body.removeChild(body.children[0]); }
  body.scrollTop = body.scrollHeight;
}

function setOverlayRunning() {
  const run = $("overlay-scanning");
  if (run) { run.textContent = "Running..."; }
}

function setOverlayStatus(text) {
  const el = $("overlay-status");
  if (el) { el.textContent = text || "Running..."; }
}

function startOverlayTimer() {
  if (timerInterval) { clearInterval(timerInterval); }
  timerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - scanStart) / 1000);
    const m = String(Math.floor(elapsed / 60)).padStart(2, "0");
    const s = String(elapsed % 60).padStart(2, "0");
    const t = $("overlay-timer");
    if (t) { t.textContent = `${m}:${s}`; }
    if (Date.now() - AppStore.lastEventTs > 30000) {
      maybeProbeLivenessAndWarn();
    }
  }, 1000);
}

let selectedMode = "balanced";
function validateDomain(input) {
  const v = (input?.value || "").trim();
  const valid = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v);
  const icon = $("domain-valid-icon");
  const btn = $("launch-btn");
  if (icon) {
    if (v.length === 0) { icon.textContent = ""; input.style.borderColor = ""; }
    else if (valid) { icon.textContent = "OK"; input.style.borderColor = "var(--success)"; }
    else { icon.textContent = "X"; input.style.borderColor = "var(--danger)"; }
  }
  if (btn) { btn.disabled = !valid; }
}

function selectMode(mode) {
  selectedMode = mode;
  qsa(".mode-card").forEach((c) => c.classList.remove("selected"));
  const card = document.querySelector(`[data-mode="${mode}"]`);
  if (card) { card.classList.add("selected"); }
}

function launchScan() {
  const domain = ($("domain-input")?.value || "").trim();
  if (!domain) { return; }
  const overlay = $("scan-overlay");
  if (!overlay) { return; }
  overlay.classList.add("visible");
  if ($("overlay-domain")) { $("overlay-domain").textContent = domain; }
  if ($("overlay-mode-badge")) { $("overlay-mode-badge").textContent = selectedMode.toUpperCase(); }
  if ($("home-page")) { $("home-page").style.display = "none"; }
  AppStore.currentDomain = domain;
  AppStore.currentMode = selectedMode;
  hideActionBanner();
  startScan(domain, selectedMode);
}

let scanStart = Date.now();
let timerInterval = null;
let modulesDone = 0;
let totalModules = 19;
const MODULE_MAP = {
  "DNS Intelligence": "dns",
  "Subdomain Enumeration": "subdomains",
  "Email Discovery": "emails",
  "Technology Detection": "tech",
  "WHOIS Intelligence": "whois",
  "IP Intelligence": "ip",
  "SSL Intelligence": "ssl",
  "Web Archive": "archive",
  "Breach Intelligence": "breach",
  "Reputation Intel": "rep",
  "Cloud Assets": "cloud",
  "Takeover Detection": "takeover",
  "Typosquat Detection": "typo",
  "Security Headers": "headers",
  "Social Footprint": "social",
  "ASN Intelligence": "asn",
  "Vulnerability Intelligence": "vulns",
  "Risk Scoring": "score",
  "Correlations": "corr",
};

function setModuleStatus(key, status, count) {
  const card = $(`mod-${key}`);
  const si = $(`mods-${key}`);
  if (!card || !si) { return; }
  if (status === "running") { card.className = "module-card running"; si.textContent = "..."; }
  else if (status === "done") { card.className = "module-card done"; si.textContent = count != null ? `OK ${count}` : "OK"; }
  else if (status === "failed") { card.className = "module-card failed"; si.textContent = "ERR"; }
}

function animCount(id, target) {
  const el = $(id);
  if (!el) { return; }
  const cur = parseInt(el.textContent, 10) || 0;
  const nTarget = parseInt(target, 10) || 0;
  if (nTarget <= cur) { return; }
  const step = Math.ceil((nTarget - cur) / 12);
  let v = cur;
  const t = setInterval(() => {
    v = Math.min(v + step, nTarget);
    el.textContent = String(v);
    if (v >= nTarget) { clearInterval(t); }
  }, 50);
}

function updateProgress(pct) {
  const bar = $("overlay-bar");
  const lbl = $("overlay-pct");
  if (bar) { bar.style.width = `${pct}%`; }
  if (lbl) { lbl.textContent = `${pct}%`; }
}

function processScanEvent(es, eventType, d, domain) {
  const eventScanId = String((d && d.scan_id) || AppStore.currentScanId || "");
  if (eventScanId) {
    upsertScanState(eventScanId, {
      domain: (d && d.domain) || domain || AppStore.currentDomain || "",
      mode: (d && d.mode) || AppStore.currentMode || "",
      updated_at: new Date().toISOString(),
    });
  }
  if (eventType === "phase") {
    const key = MODULE_MAP[d.name] || String(d.name || "").toLowerCase().replace(/\s+/g, "-");
    if (d.status === "running") {
      setModuleStatus(key, "running");
      setOverlayStatus(d.name || "Running...");
      logLine("info", `[*] ${d.name}...`);
      if (eventScanId) {
        upsertScanState(eventScanId, { status: "running", progress: { phase: d.name || "", status: "running" } });
      }
    } else if (d.status === "done") {
      modulesDone += 1;
      setModuleStatus(key, "done", d.count);
      if (d.name === "Subdomain Enumeration") { animCount("cnt-subs", d.count || 0); }
      if (d.name === "Email Discovery") { animCount("cnt-emails", d.count || 0); }
      if (d.name === "IP Intelligence") { animCount("cnt-ips", d.count || 0); }
      if (d.name === "IP Intelligence" && d.ports != null) { animCount("cnt-ports", d.ports || 0); }
      if (d.name === "Vulnerability Intelligence") { animCount("cnt-vulns", d.count || 0); }
      const phaseDuration = d.duration_seconds != null ? ` (${d.duration_seconds}s)` : "";
      setOverlayStatus(`${d.name} done${phaseDuration}`);
      updateProgress(Math.min(95, Math.round((modulesDone / Math.max(1, totalModules)) * 100)));
      if ((d.count || 0) > 0) { logLine("plus", `[+] ${d.name} -> ${d.count} found${phaseDuration}`); }
      if (eventScanId) {
        const counterPatch = {};
        if (d.name === "Subdomain Enumeration") { counterPatch.subdomains = d.count || 0; }
        if (d.name === "Email Discovery") { counterPatch.emails = d.count || 0; }
        if (d.name === "IP Intelligence") { counterPatch.ips = d.count || 0; }
        if (d.name === "IP Intelligence" && d.ports != null) { counterPatch.ports = d.ports || 0; }
        if (d.name === "Vulnerability Intelligence") { counterPatch.vulns = d.count || 0; }
        upsertScanState(eventScanId, {
          status: "running",
          progress: { phase: d.name || "", status: "done", count: d.count || 0, duration_seconds: d.duration_seconds || 0 },
          counters: { ...(AppStore.activeScans[eventScanId]?.counters || {}), ...counterPatch },
          phase_durations: { ...(AppStore.activeScans[eventScanId]?.phase_durations || {}), [d.name || ""]: d.duration_seconds || 0 },
        });
      }
    }
    return;
  }
  if (eventType === "log") {
    const lvl = String(d.level || "").toLowerCase();
    if (lvl.includes("!!!!")) { logLine("crit", `[!!!] ${d.message || ""}`); }
    else if (lvl.includes("!")) { logLine("warn", `[!] ${d.message || ""}`); }
    else if (lvl.includes("+")) { logLine("plus", `[+] ${d.message || ""}`); }
    else { logLine("info", `[*] ${d.message || ""}`); }
    return;
  }
  if (eventType === "complete") {
    const s = d.summary || {};
    const ips = s.ips != null ? s.ips : s.ip_records;
    const ports = s.ports != null ? s.ports : 0;
    const vulns = s.vulns != null ? s.vulns : s.vulnerabilities;
    if (s.subdomains != null) { animCount("cnt-subs", s.subdomains); }
    if (s.emails != null) { animCount("cnt-emails", s.emails); }
    if (ips != null) { animCount("cnt-ips", ips); }
    if (ports != null) { animCount("cnt-ports", ports); }
    if (vulns != null) { animCount("cnt-vulns", vulns); }
    const providers = d.providers || {};
    logLine("plus", `[+] Done! ${(s.subdomains || 0)} subs | ${(s.emails || 0)} emails | ${(ips || 0)} ips | ${(ports || 0)} ports | ${(vulns || 0)} vulns | providers ok:${providers.success || 0} partial:${providers.partial || 0} failed:${providers.failed || 0}`);
    markScanSettled(eventScanId, { counters: s, providers });
    return;
  }
  if (eventType === "saved") {
    markScanSettled(eventScanId, {
      downloads: {
        zip: `/api/download/${encodeURIComponent(eventScanId)}/zip`,
        json: `/api/download/${encodeURIComponent(eventScanId)}/json`,
        txt: `/api/download/${encodeURIComponent(eventScanId)}/txt`,
        html: `/api/download/${encodeURIComponent(eventScanId)}/html`,
        standalone: `/api/download/${encodeURIComponent(eventScanId)}/html-standalone`,
        entity_graph: `/api/download/${encodeURIComponent(eventScanId)}/entity-graph.json`,
      },
    });
    AppStore.currentScanId = d.scan_id || AppStore.currentScanId;
    localStorage.removeItem("grt_active_scan_id");
    logLine("plus", "[+] Scan complete! Loading results...");
    setTimeout(() => loadResults(d.scan_id, { push: true }), 800);
    refreshScanQueue(true);
    return;
  }
  if (eventType === "error") {
    stopActiveScanUi();
    logLine("minus", `[-] Error: ${d.message || "Unknown error"}`);
    if (eventScanId) {
      upsertScanState(eventScanId, { status: "failed", last_error: d.message || "Unknown error" });
    }
    localStorage.removeItem("grt_active_scan_id");
    showUiError("SSE stream failed");
    showActionBanner("SSE stream failed", [
      {
        label: "Reattach",
        onClick: () => {
          if (AppStore.currentScanId) {
            reattachScan(AppStore.currentScanId, AppStore.currentDomain || "scan", { push: true });
          }
        },
      },
      { label: "Go Home", onClick: () => goHome(true, false) },
    ]);
    refreshScanQueue();
    return;
  }
  if (eventType === "cancelled") {
    stopActiveScanUi();
    logLine("warn", "[!] Scan cancelled");
    if (eventScanId) {
      upsertScanState(eventScanId, { status: "cancelled" });
    }
    localStorage.removeItem("grt_active_scan_id");
    showUiError("Scan cancelled");
    showActionBanner("Scan cancelled", [
      { label: "Go Home", onClick: () => goHome(true, false) },
      { label: "Open Scan Queue", onClick: () => openScanQueue() },
    ]);
    refreshScanQueue();
    return;
  }
  if (eventType === "start") {
    AppStore.currentScanId = d.scan_id || AppStore.currentScanId;
    if (AppStore.currentScanId) {
      AppStore.viewedScanId = AppStore.currentScanId;
      localStorage.setItem("grt_active_scan_id", AppStore.currentScanId);
      pushScanHistoryPath(AppStore.currentScanId, "scan");
      upsertScanState(AppStore.currentScanId, {
        domain: d.domain || domain || AppStore.currentDomain || "",
        mode: d.mode || AppStore.currentMode || "",
        status: d.status || "running",
      });
    }
    hideActionBanner();
    totalModules = d.total_modules || totalModules;
    setOverlayStatus(`Queued ${totalModules} modules`);
    logLine("info", `[*] Scan started for ${domain} (modules: ${totalModules})`);
    updateProgress(2);
    return;
  }
  if (eventType === "source_metrics" || eventType === "source_coverage") {
    const c = Object.keys(d.sources || {}).length;
    let success = 0;
    let partial = 0;
    let failed = 0;
    Object.values(d.sources || {}).forEach((row) => {
      const status = String((row && row.status) || "ok").toLowerCase();
      if (["ok", "derived_ok"].includes(status)) { success += 1; }
      else if (["partial", "timeout_partial", "fail_partial", "derived"].includes(status)) { partial += 1; }
      else if (!["blocked_missing_api_key", "blocked_target_requests_policy"].includes(status)) { failed += 1; }
    });
    logLine("info", `[*] ${d.module || "module"} source metrics: ${c} sources | ok:${success} partial:${partial} failed:${failed}`);
    if (eventScanId) {
      upsertScanState(eventScanId, {
        providers: {
          success: (AppStore.activeScans[eventScanId]?.providers?.success || 0) + success,
          partial: (AppStore.activeScans[eventScanId]?.providers?.partial || 0) + partial,
          failed: (AppStore.activeScans[eventScanId]?.providers?.failed || 0) + failed,
        },
      });
    }
    return;
  }
  if (eventType === "ping") {
    setOverlayRunning();
  }
}
function startScan(domain, mode) {
  modulesDone = 0;
  scanStart = Date.now();
  AppStore.currentScanId = null;
  AppStore.lastEventTs = Date.now();
  AppStore.livenessProbeInFlight = false;
  closeActiveEventSource();
  startOverlayTimer();
  fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, mode }),
  })
    .then((r) => (r.ok ? r.json() : null))
    .then((payload) => {
      const scanId = payload && payload.scan_id ? String(payload.scan_id) : "";
      if (!scanId) { throw new Error("Missing scan_id"); }
      AppStore.currentScanId = scanId;
      AppStore.viewedScanId = scanId;
      localStorage.setItem("grt_active_scan_id", scanId);
      pushScanHistoryPath(scanId, "scan");
      upsertScanState(scanId, {
        domain,
        mode,
        status: "queued",
        progress: { phase: "queued", status: "queued" },
      });
      const es = new EventSource(`/scan/stream/${encodeURIComponent(scanId)}`);
      AppStore.eventSource = es;
      bindScanEventSource(es, domain, scanId);
    })
    .catch(() => {
      const url = `/scan/stream?domain=${encodeURIComponent(domain)}&mode=${mode}`;
      const es = new EventSource(url);
      AppStore.eventSource = es;
      bindScanEventSource(es, domain, null);
    });
}

function startScanAttach(scanId, domain) {
  modulesDone = 0;
  scanStart = Date.now();
  AppStore.currentScanId = scanId;
  AppStore.viewedScanId = scanId;
  AppStore.currentDomain = domain || AppStore.currentDomain || "";
  AppStore.lastEventTs = Date.now();
  AppStore.livenessProbeInFlight = false;
  closeActiveEventSource();
  startOverlayTimer();
  const url = `/scan/stream/${encodeURIComponent(scanId)}`;
  const es = new EventSource(url);
  AppStore.eventSource = es;
  bindScanEventSource(es, AppStore.currentDomain || "scan", scanId);
}

function bindScanEventSource(es, domain, expectedScanId) {
  const shouldProcess = (payload) => {
    if (!expectedScanId) { return true; }
    const sid = String((payload && payload.scan_id) || AppStore.currentScanId || "");
    return !sid || sid === String(expectedScanId);
  };
  const safe = (eventType, parser = (e) => parseJsonSafe(e.data, {})) => {
    es.addEventListener(eventType, (e) => {
      AppStore.lastEventTs = Date.now();
      hideUiError();
      try {
        const d = parser(e);
        if (!shouldProcess(d)) { return; }
        processScanEvent(es, eventType, d, domain);
      } catch (err) {
        console.error("SSE event error", eventType, err);
        showUiError(`Render error on ${eventType}`);
      }
    });
  };
  safe("source_metrics");
  safe("source_coverage");
  safe("start");
  safe("phase");
  safe("log");
  safe("ping");
  safe("saved");
  safe("error");
  safe("cancelled");
  safe("complete");
  es.addEventListener("batch", (e) => {
    AppStore.lastEventTs = Date.now();
    hideUiError();
    try {
      const arr = parseJsonSafe(e.data, []);
      if (!Array.isArray(arr)) { return; }
      arr.forEach((item) => {
        try {
          if (!shouldProcess(item.data || {})) { return; }
          processScanEvent(es, item.event || "", item.data || {}, domain);
        } catch (innerErr) {
          console.error("SSE batch item error", innerErr, item);
          showUiError("UI error, check report");
        }
      });
    } catch (err) {
      console.error("SSE batch parse error", err);
      showUiError("Invalid SSE batch payload");
    }
  });
  es.onerror = () => {
    const activeScanId = expectedScanId || AppStore.currentScanId || "";
    if (isSettledScan(activeScanId)) {
      hideUiError();
      stopActiveScanPolling();
      probeResultFragment(activeScanId, 3)
        .then((ready) => {
          if (!ready) { return; }
          stopActiveScanUi();
          loadResults(activeScanId, { push: true });
        })
        .catch(() => null);
      return;
    }
    if (!activeScanId) {
      showUiError("SSE disconnected");
      return;
    }
    probeScanStatus(activeScanId)
      .then((alive) => {
        if (alive) {
          showUiError("SSE disconnected");
          return;
        }
        return probeResultFragment(activeScanId, 3).then((ready) => {
          if (ready) {
            stopActiveScanUi();
            loadResults(activeScanId, { push: true });
            return;
          }
          showUiError("SSE disconnected");
        });
      })
      .catch(() => showUiError("SSE disconnected"));
  };
}

function probeResultFragment(scanId, retries) {
  if (!scanId) { return Promise.resolve(false); }
  let attempt = 0;
  const run = () => fetch(`/api/result-fragment/${scanId}?_t=${Date.now()}`, { cache: "no-store" })
    .then((r) => r.ok)
    .catch(() => false)
    .then((ok) => {
      if (ok) { return true; }
      attempt += 1;
      if (attempt > retries) { return false; }
      return new Promise((resolve) => setTimeout(resolve, 500)).then(run);
    });
  return run();
}

function probeScanStatus(scanId) {
  if (!scanId) { return Promise.resolve(false); }
  return fetch(`/api/scan/${encodeURIComponent(scanId)}/status`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((st) => !!(st && ["queued", "running"].includes(st.status)));
}

function maybeProbeLivenessAndWarn() {
  const overlay = $("scan-overlay");
  if (!overlay || !overlay.classList.contains("visible")) {
    hideUiError();
    return;
  }
  if (!AppStore.currentScanId) {
    setOverlayRunning();
    return;
  }
  const scanState = activeScanState(AppStore.currentScanId);
  if ([...["failed", "cancelled"], "done", "saved"].includes(String(scanState.status || "").toLowerCase())) {
    stopActiveScanPolling();
    hideUiError();
    return;
  }
  if (!AppStore.eventSource) {
    hideUiError();
    return;
  }
  if (AppStore.livenessProbeInFlight) { return; }
  AppStore.livenessProbeInFlight = true;
  fetch(`/api/scan/${encodeURIComponent(AppStore.currentScanId)}/status`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((st) => {
      if (!st) {
        if (isSettledScanStatus(activeScanState(AppStore.currentScanId).status)) {
          hideUiError();
          stopActiveScanPolling();
          return;
        }
        showUiError("No SSE events in 30s. Scan may still be running.", AppStore.currentScanId);
        return;
      }
      const status = String(st.status || "").toLowerCase();
      if (["done", "saved"].includes(status)) {
        markScanSettled(AppStore.currentScanId);
        loadResults(AppStore.currentScanId, { push: true });
        return;
      }
      if (!["queued", "running"].includes(status)) {
        showUiError("No SSE events in 30s. Scan may still be running.", AppStore.currentScanId);
        return;
      }
      const counters = st.counters || {};
      if (counters.subdomains != null) { animCount("cnt-subs", counters.subdomains); }
      if (counters.emails != null) { animCount("cnt-emails", counters.emails); }
      if (counters.ips != null) { animCount("cnt-ips", counters.ips); }
      if (counters.ports != null) { animCount("cnt-ports", counters.ports); }
      if (counters.vulns != null) { animCount("cnt-vulns", counters.vulns); }
      if (st.phase) { setOverlayStatus(st.phase); }
      if (st.progress != null) { updateProgress(Math.max(2, Math.min(99, parseInt(st.progress, 10) || 0))); }
      AppStore.lastEventTs = Date.now();
      setOverlayRunning();
      hideUiError();
    })
    .finally(() => {
      AppStore.livenessProbeInFlight = false;
    });
}

function loadResults(scanId, opts) {
  const pushHistory = !(opts && opts.push === false);
  AppStore.currentScanId = scanId || AppStore.currentScanId;
  stopActiveScanUi();
  hideActionBanner();
  if (scanId) {
    upsertScanState(scanId, { status: "done" });
    scheduleQueueRefresh();
  }
  const cacheEntry = AppStore.resultFragmentCache[scanId] || null;
  if (cacheEntry && (Date.now() - Number(cacheEntry.ts || 0) < 15000)) {
    return Promise.resolve(cacheEntry.html).then((html) => {
      removeRenderedResults();
      document.body.insertAdjacentHTML("beforeend", html);
      if ($("home-page")) { $("home-page").style.display = "none"; }
      if (pushHistory) { pushScanHistoryPath(scanId, "results"); }
      initSections();
      initSidebarScroll();
      initDropdowns();
      initDownloadLinks();
      initSortableTables();
      initFindingsUi();
      initResultsWorkspace(scanId);
      initLargeResultBrowsers(scanId);
      AppStore.currentReportScanId = scanId;
    });
  }
  fetch(`/api/result-fragment/${scanId}`)
    .then((r) => { if (!r.ok) { throw new Error(`HTTP ${r.status}`); } return r.text(); })
    .then((html) => {
      AppStore.resultFragmentCache[scanId] = { ts: Date.now(), html };
      const overlay = $("scan-overlay");
      if (overlay) {
        overlay.style.transition = "opacity .5s";
        overlay.style.opacity = "0";
      }
      setTimeout(() => {
        try {
          if (overlay) {
            overlay.classList.remove("visible");
            overlay.style.opacity = "";
          }
          removeRenderedResults();
          document.body.insertAdjacentHTML("beforeend", html);
          window.scrollTo({ top: 0, behavior: "smooth" });
          if ($("home-page")) { $("home-page").style.display = "none"; }
          if (pushHistory) { pushScanHistoryPath(scanId, "results"); }
          initSections();
          initSidebarScroll();
          initDropdowns();
          initDownloadLinks();
          initSortableTables();
          initFindingsUi();
          initResultsWorkspace(scanId);
          initLargeResultBrowsers(scanId);
          if (AppStore.currentReportScanId !== scanId || !AppStore.currentReport) {
            fetch(`/api/result/${scanId}`)
              .then((r) => (r.ok ? r.json() : null))
              .then((payload) => {
                if (payload && typeof payload === "object") {
                  AppStore.currentReport = payload.report || payload;
                  AppStore.currentReportScanId = scanId;
                }
              })
              .catch(() => null);
          }
        } catch (err) {
          console.error("Result fragment render error", err);
          showUiError("UI error, check report");
        }
      }, 500);
    })
    .catch((err) => {
      logLine("minus", `[-] Failed to load results: ${err.message || "unknown error"}`);
      showUiError("Results page render failed");
      showActionBanner("Scan not found / expired", [
        { label: "Go Home", onClick: () => goHome(true, false) },
      ]);
    });
}

function toggleSection(key) {
  const body = $(`sbody-${key}`);
  const chev = $(`chev-${key}`);
  const hdr = body ? body.previousElementSibling : null;
  if (!body) { return; }
  const isOpen = body.style.maxHeight && body.style.maxHeight !== "0px";
  if (isOpen) {
    body.style.maxHeight = "0px";
    if (chev) { chev.classList.add("rotated"); }
    if (hdr) { hdr.classList.remove("open"); }
  } else {
    body.style.maxHeight = `${body.scrollHeight + 200}px`;
    if (chev) { chev.classList.remove("rotated"); }
    if (hdr) { hdr.classList.add("open"); }
  }
}

function initSections() {
  qsa(".section-body").forEach((body) => {
    const isOpen = body.dataset.default === "open" || body.previousElementSibling?.classList.contains("open");
    body.style.maxHeight = isOpen ? `${body.scrollHeight + 200}px` : "0px";
  });
}

function scrollTo(id) {
  const el = document.getElementById(id);
  if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); }
  return false;
}

function initSidebarScroll() {
  const sections = qsa('[id^="sec-"]');
  const links = qsa(".sb-link");
  if (!sections.length || !links.length || typeof IntersectionObserver === "undefined") { return; }
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (en.isIntersecting) {
        links.forEach((l) => l.classList.remove("active"));
        const lnk = document.querySelector(`.sb-link[href="#${en.target.id}"]`);
        if (lnk) { lnk.classList.add("active"); }
      }
    });
  }, { rootMargin: "-20% 0px -70% 0px", threshold: 0 });
  sections.forEach((s) => obs.observe(s));
}

function _scanQueueRows(scans) {
  const formatStartedAt = (raw) => {
    if (raw == null || raw === "") { return "-"; }
    if (typeof raw === "number") {
      const dt = new Date(raw * 1000);
      if (!Number.isNaN(dt.getTime())) { return dt.toISOString().slice(0, 19).replace("T", " "); }
    }
    const txt = String(raw);
    return txt.replace("T", " ").slice(0, 19);
  };
  const statusBadge = (status) => {
    const st = String(status || "").toLowerCase();
    if (st === "running") { return `<span class="badge badge-blue">running</span>`; }
    if (st === "queued") { return `<span class="badge badge-yellow">queued</span>`; }
    if (st === "done") { return `<span class="badge badge-green">done</span>`; }
    if (st === "failed") { return `<span class="badge badge-red">failed</span>`; }
    if (st === "cancelled") { return `<span class="badge badge-gray">cancelled</span>`; }
    return `<span class="badge badge-gray">${st || "unknown"}</span>`;
  };
  return scans.slice(0, 40).map((s) => {
    const providerSummary = s.providers || {};
    const phaseDurations = s.phase_durations || {};
    const currentPhaseDuration = s.phase && phaseDurations[s.phase] ? ` (${phaseDurations[s.phase]}s)` : "";
    const actions = [];
    if (s.scan_id) {
      actions.push(`<button class="btn btn-ghost btn-sm" onclick="openScanById('${s.scan_id}')">Open</button>`);
    }
    if (s.status === "queued" || s.status === "running") {
      actions.push(`<button class="btn btn-ghost btn-sm" onclick="cancelScan('${s.scan_id}')">Cancel</button>`);
      actions.push(`<button class="btn btn-ghost btn-sm" onclick="reattachScan('${s.scan_id}','${s.domain || ""}')">Reattach</button>`);
    }
    if (s.status === "done") {
      actions.push(`<a class="btn btn-ghost btn-sm" href="/results/${s.scan_id}">Open results</a>`);
    }
    return `<tr>
      <td class="mono">${s.scan_id || ""}</td>
      <td class="mono">${s.domain || ""}</td>
      <td>${s.mode || ""}</td>
      <td>${statusBadge(s.status)}</td>
      <td>${s.phase || "-"}${currentPhaseDuration}<div class="tiny">ok:${providerSummary.success || 0} partial:${providerSummary.partial || 0} failed:${providerSummary.failed || 0}</div></td>
      <td class="mono">${formatStartedAt(s.started_at)}</td>
      <td>${s.duration_seconds || 0}s</td>
      <td>${actions.join(" ")}</td>
    </tr>`;
  }).join("");
}

function shouldPollScanQueue(force) {
  if (force) { return true; }
  const path = window.location.pathname || "/";
  const homeQueueVisible = Boolean($("scan-queue-panel"));
  const resultsQueue = $("results-scan-queue");
  const resultsQueueVisible = Boolean(resultsQueue && resultsQueue.style.display !== "none" && !resultsQueue.hidden);
  const overlayVisible = Boolean($("scan-overlay") && $("scan-overlay").classList.contains("visible"));
  const activeKnownScans = Object.values(AppStore.activeScans || {}).some((s) => ["queued", "running"].includes(String(s.status || "")));
  if (overlayVisible || activeKnownScans) { return true; }
  if (path === "/scans" || path.startsWith("/scan/")) { return true; }
  return homeQueueVisible || resultsQueueVisible;
}

function refreshScanQueue(force) {
  if (!shouldPollScanQueue(force)) {
    scheduleQueueRefresh();
    return;
  }
  if (AppStore.queueFetchInFlight) { return; }
  AppStore.queueFetchInFlight = true;
  fetch("/api/scans", { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : { scans: [] }))
    .then((payload) => {
      const scans = Array.isArray(payload.scans) ? payload.scans : [];
      const next = {};
      scans.forEach((s) => {
        const sid = String(s.scan_id || "");
        if (!sid) { return; }
        const prev = AppStore.activeScans[sid] || {};
        next[sid] = { ...prev, ...s, scan_id: sid };
      });
      AppStore.activeScans = next;
      updateActiveScansCounter();
      const rows = _scanQueueRows(scans);
      const bodies = [$("scan-queue-body"), $("results-scan-queue-body")];
      bodies.forEach((body) => {
        if (body) { body.innerHTML = rows; }
      });
    })
    .catch(() => null)
    .finally(() => {
      AppStore.queueFetchInFlight = false;
      scheduleQueueRefresh();
    });
}

function queueRefreshMs() {
  if (!shouldPollScanQueue(false)) { return 0; }
  const activeKnownScans = Object.values(AppStore.activeScans || {}).some((s) => ["queued", "running"].includes(String(s.status || "")));
  if (typeof document !== "undefined" && document.hidden) { return activeKnownScans ? 30000 : 0; }
  if ((window.location.pathname || "").startsWith("/results/")) { return activeKnownScans ? 15000 : 60000; }
  return 8000;
}

function scheduleQueueRefresh() {
  const targetMs = queueRefreshMs();
  if (AppStore.queueRefreshTimer && AppStore.queueIntervalMs === targetMs) { return; }
  if (AppStore.queueRefreshTimer) {
    clearTimeout(AppStore.queueRefreshTimer);
    AppStore.queueRefreshTimer = null;
  }
  if (!targetMs) {
    AppStore.queueIntervalMs = 0;
    return;
  }
  AppStore.queueIntervalMs = targetMs;
  AppStore.queueRefreshTimer = window.setTimeout(() => {
    AppStore.queueRefreshTimer = null;
    refreshScanQueue(false);
  }, targetMs);
}

function cancelScan(scanId) {
  fetch(`/api/scan/${encodeURIComponent(scanId)}/cancel`, { method: "POST" })
    .then(() => refreshScanQueue())
    .catch(() => flashError("Cancel failed"));
}

function openScanById(scanId) {
  if (!scanId) { return; }
  fetch(`/api/scan/${encodeURIComponent(scanId)}/status`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((st) => {
      if (!st || !st.status) {
        showActionBanner("Scan not found / expired", [{ label: "Go Home", onClick: () => goHome(true, false) }]);
        return;
      }
      if (["queued", "running"].includes(st.status)) {
        reattachScan(scanId, st.domain || "scan", { push: true });
        return;
      }
      loadResults(scanId, { push: true });
    })
    .catch(() => showActionBanner("Scan not found / expired", [{ label: "Go Home", onClick: () => goHome(true, false) }]));
}

function reattachScan(scanId, domain, opts) {
  const pushHistory = !(opts && opts.push === false);
  const overlay = $("scan-overlay");
  if (!overlay) {
    window.location.href = "/";
    return;
  }
  stopActiveScanUi();
  hideActionBanner();
  removeRenderedResults();
  overlay.classList.add("visible");
  if ($("overlay-domain")) { $("overlay-domain").textContent = domain || "scan"; }
  if ($("overlay-mode-badge")) { $("overlay-mode-badge").textContent = "ATTACH"; }
  if ($("home-page")) { $("home-page").style.display = "none"; }
  localStorage.setItem("grt_active_scan_id", scanId);
  if (pushHistory) { pushScanHistoryPath(scanId, "scan"); }
  startScanAttach(scanId, domain || "scan");
}

function toggleResultsQueue() {
  const panel = $("results-scan-queue");
  if (!panel) {
    openScanQueue();
    return;
  }
  const open = panel.style.display !== "none";
  panel.style.display = open ? "none" : "block";
  if (!open) {
    refreshScanQueue();
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function toggleErrorsDetail() {
  const el = $("errors-detail-table");
  if (!el) { return; }
  el.style.display = (el.style.display === "none" || !el.style.display) ? "block" : "none";
}

function initSortableTables() {
  qsa(".data-table").forEach((tbl) => {
    const headers = qsa("thead th", tbl);
    headers.forEach((th, idx) => {
      if (th.dataset.sortBound === "1") { return; }
      th.dataset.sortBound = "1";
      th.style.cursor = "pointer";
      th.addEventListener("click", () => {
        const asc = th.dataset.asc !== "1";
        th.dataset.asc = asc ? "1" : "0";
        const body = tbl.querySelector("tbody");
        if (!body) { return; }
        const rows = Array.from(body.querySelectorAll("tr"));
        rows.sort((a, b) => {
          const av = (a.cells[idx]?.textContent || "").trim().toLowerCase();
          const bv = (b.cells[idx]?.textContent || "").trim().toLowerCase();
          return asc
            ? av.localeCompare(bv, undefined, { numeric: true })
            : bv.localeCompare(av, undefined, { numeric: true });
        });
        rows.forEach((r) => body.appendChild(r));
      });
    });
  });
}

function filterVulns(sev, btn) {
  qsa(".vfilt").forEach((b) => b.classList.remove("active"));
  if (btn) { btn.classList.add("active"); }
  qsa(".vuln-card").forEach((c) => c.classList.toggle("hidden", sev !== "ALL" && c.dataset.sev !== sev));
}

function toggleVuln(id) {
  const el = $(id);
  if (el) { el.classList.toggle("hidden"); }
}

function filterTable(tableId, val, colIdx) {
  const tbl = $(tableId);
  if (!tbl) { return; }
  const q = (val || "").toLowerCase();
  qsa("tbody tr", tbl).forEach((tr) => {
    const cell = tr.cells[colIdx];
    tr.style.display = ((cell && cell.textContent.toLowerCase().includes(q)) || q === "") ? "" : "none";
  });
}

function copyAllSubdomains() {
  const rows = qsa("#sub-table tbody tr");
  const text = [...rows].map((r) => r.cells[0]?.textContent?.trim()).filter(Boolean).join("\n");
  navigator.clipboard?.writeText(text).then(() => flash(`Copied ${rows.length} subdomains!`));
}

function copyAllEmails() {
  const rows = qsa("#email-table tbody tr");
  const text = [...rows].map((r) => r.cells[0]?.textContent?.trim()).filter(Boolean).join("\n");
  navigator.clipboard?.writeText(text).then(() => flash(`Copied ${rows.length} emails!`));
}

function copyText(text) {
  const value = String(text || "").trim();
  if (!value) { return; }
  navigator.clipboard?.writeText(value).then(() => flash(`Copied: ${value}`));
}

function copyBulkText(text, successMessage) {
  const value = String(text || "").trim();
  if (!value) { return; }
  const notify = () => flash(successMessage || "Copied.");
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(value).then(notify).catch(() => flashError("Copy failed."));
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = value;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
    notify();
  } catch (_) {
    flashError("Copy failed.");
  } finally {
    document.body.removeChild(ta);
  }
}

function exportTableCsv(tableId, fileName) {
  const table = $(tableId);
  if (!table) { return; }
  const rows = Array.from(table.querySelectorAll("tr"));
  const csv = rows.map((row) => {
    const cols = Array.from(row.querySelectorAll("th,td"));
    return cols.map((cell) => {
      const txt = (cell.textContent || "").replace(/\s+/g, " ").trim();
      const esc = txt.replace(/"/g, "\"\"");
      return `"${esc}"`;
    }).join(",");
  }).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName || `${tableId}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function flash(msg) {
  const el = document.createElement("div");
  el.className = "flash-toast";
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2000);
}

function toggleDropdown(id) {
  const dd = $(id);
  if (dd) { dd.classList.toggle("open"); }
}

function initDropdowns() {
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".dropdown")) {
      qsa(".dropdown-menu").forEach((m) => m.classList.remove("open"));
    }
  });
}

function downloadFile(url, fallbackName) {
  return fetch(url, { cache: "no-store" })
    .then((r) => {
      if (!r.ok) { throw new Error(`HTTP ${r.status}`); }
      const cd = r.headers.get("content-disposition") || "";
      let fileName = fallbackName || "ghost_recon_report";
      const m = cd.match(/filename=\"?([^\";]+)\"?/i);
      if (m && m[1]) { fileName = m[1]; }
      return r.blob().then((blob) => ({ blob, fileName }));
    })
    .then(({ blob, fileName }) => {
      const href = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = href;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(href);
    })
    .catch((err) => {
      console.error("Download failed", err);
      flashError("Download failed. Please retry.");
    });
}

function initDownloadLinks() {
  qsa("a.js-download").forEach((a) => {
    if (a.dataset.bound === "1") { return; }
    a.dataset.bound = "1";
    a.addEventListener("click", (ev) => {
      ev.preventDefault();
      downloadFile(a.getAttribute("href"), a.dataset.file || "ghost_recon_report");
    });
  });
}

function largeBrowserState(scanId, kind) {
  const key = `${scanId}:${kind}`;
  if (!AppStore.largeResultBrowsers[key]) {
    AppStore.largeResultBrowsers[key] = {
      loading: false,
      loaded: false,
      items: [],
      total: 0,
      page: 1,
      query: "",
    };
  }
  return AppStore.largeResultBrowsers[key];
}

function browserSliceMeta(filtered, page, pageSize) {
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(totalPages, Math.max(1, page));
  const start = (safePage - 1) * pageSize;
  return {
    totalPages,
    page: safePage,
    start,
    rows: filtered.slice(start, start + pageSize),
  };
}

function renderSubdomainBrowser(scanId) {
  const root = $("subdomain-browser");
  const tbody = $("sub-table-body");
  if (!root || !tbody) { return; }
  const state = largeBrowserState(scanId, "subdomains");
  const search = $("subdomain-browser-search");
  const meta = $("subdomain-browser-meta");
  const prev = $("subdomain-browser-prev");
  const next = $("subdomain-browser-next");
  const q = String(search?.value || state.query || "").toLowerCase();
  state.query = q;
  const filtered = state.items.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  const pageInfo = browserSliceMeta(filtered, state.page, 100);
  state.page = pageInfo.page;
  tbody.innerHTML = pageInfo.rows.map((row) => `
    <tr>
      <td class="mono copyable-cell" data-copy-value="${escapeHtml(row.name || row.subdomain || row.host || "")}" style="color:var(--accent-2);font-weight:600">${escapeHtml(row.name || row.subdomain || row.host || "")}</td>
      <td class="mono" style="color:var(--text-2);font-size:11px">${escapeHtml(((row.ips || row.resolved_ips || [])).join(", ") || "-")}</td>
      <td>${escapeHtml(((row.open_ports || row.ports || [])).join(", ") || "-")}</td>
      <td>${(row.tags || []).slice(0, 5).map((tag) => `<span class="badge badge-gray">${escapeHtml(tag)}</span>`).join(" ") || '<span style="color:var(--text-3)">-</span>'}</td>
      <td>${row.cloud_provider ? `<span class="badge badge-cyan">${escapeHtml(row.cloud_provider)}</span>` : '<span style="color:var(--text-3)">-</span>'}</td>
      <td>${escapeHtml(String(row.takeover_status || row.status || "-"))}</td>
      <td><span style="color:var(--accent);font-family:var(--font-mono);font-size:11px">${escapeHtml(String(row.relevance_score || row.score || 0))}/10</span></td>
      <td style="font-size:11px;color:var(--text-3)">${escapeHtml((row.sources || []).join(", ")) || "-"}</td>
      <td><span class="badge badge-gray">${escapeHtml(String((row.source_attribution || []).length || (row.sources || []).length || 0))}</span></td>
    </tr>
  `).join("") || '<tr><td colspan="9" class="mono">No subdomains matched the current filter.</td></tr>';
  if (meta) {
    const loaded = state.items.length;
    meta.textContent = state.loaded
      ? `Showing ${filtered.length ? `${pageInfo.start + 1}-${Math.min(filtered.length, pageInfo.start + 100)}` : "0"} of ${filtered.length} matches · ${loaded}/${state.total || loaded} loaded`
      : "Loading full list...";
  }
  if (prev) { prev.disabled = state.page <= 1; }
  if (next) { next.disabled = state.page >= pageInfo.totalPages; }
}

function renderArchiveBrowser(scanId) {
  const root = $("archive-browser");
  const tbody = $("archive-browser-body");
  if (!root || !tbody) { return; }
  const state = largeBrowserState(scanId, "archive");
  const search = $("archive-browser-search");
  const meta = $("archive-browser-meta");
  const prev = $("archive-browser-prev");
  const next = $("archive-browser-next");
  const q = String(search?.value || state.query || "").toLowerCase();
  state.query = q;
  const filtered = state.items.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  const pageInfo = browserSliceMeta(filtered, state.page, 50);
  state.page = pageInfo.page;
  tbody.innerHTML = pageInfo.rows.map((row) => `
    <tr>
      <td class="mono" style="font-size:11px;word-break:break-all;max-width:540px"><a href="${escapeHtml(row.url || "")}" target="_blank" style="color:var(--accent)">${escapeHtml(row.url || "")}</a></td>
      <td class="mono">${escapeHtml(row.timestamp || "") || "-"}</td>
      <td>${escapeHtml(String(row.status_code || "")) || "-"}</td>
      <td>${escapeHtml(row.mime_type || "") || "-"}</td>
    </tr>
  `).join("") || '<tr><td colspan="4" class="mono">No archive URLs matched the current filter.</td></tr>';
  if (meta) {
    const loaded = state.items.length;
    meta.textContent = state.loaded
      ? `Showing ${filtered.length ? `${pageInfo.start + 1}-${Math.min(filtered.length, pageInfo.start + 50)}` : "0"} of ${filtered.length} matches · ${loaded} loaded`
      : "Loading archive URLs...";
  }
  if (prev) { prev.disabled = state.page <= 1; }
  if (next) { next.disabled = state.page >= pageInfo.totalPages; }
}

function loadAllSubdomains(scanId) {
  const state = largeBrowserState(scanId, "subdomains");
  if (state.loading || state.loaded) { return Promise.resolve(); }
  state.loading = true;
  let offset = 0;
  const items = [];
  const fetchPage = () => fetch(`/api/result-data/${encodeURIComponent(scanId)}/subdomains?offset=${offset}&limit=1000`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((payload) => {
      const pageItems = Array.isArray(payload.data) ? payload.data : [];
      items.push(...pageItems);
      state.total = Number(payload.total || items.length || 0);
      offset += pageItems.length;
      state.items = items.slice();
      renderSubdomainBrowser(scanId);
      if (payload.has_more && pageItems.length) {
        return fetchPage();
      }
      state.loaded = true;
      state.items = items.slice();
      renderSubdomainBrowser(scanId);
    })
    .catch((err) => {
      const meta = $("subdomain-browser-meta");
      if (meta) { meta.textContent = `Failed to load full subdomain list: ${err.message || "unknown error"}`; }
    })
    .finally(() => {
      state.loading = false;
    });
  return fetchPage();
}

function loadArchiveBrowser(scanId) {
  const state = largeBrowserState(scanId, "archive");
  if (state.loading || state.loaded) { return Promise.resolve(); }
  state.loading = true;
  return fetch(`/api/result-data/${encodeURIComponent(scanId)}/archive`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((payload) => {
      const data = payload && payload.data ? payload.data : {};
      state.items = Array.isArray(data.all_urls) ? data.all_urls.slice() : (Array.isArray(data.all) ? data.all.slice() : []);
      state.total = Number(data.total_urls || state.items.length || 0);
      state.loaded = true;
      renderArchiveBrowser(scanId);
    })
    .catch((err) => {
      const meta = $("archive-browser-meta");
      if (meta) { meta.textContent = `Failed to load archive browser: ${err.message || "unknown error"}`; }
    })
    .finally(() => {
      state.loading = false;
    });
}

function initLargeResultBrowsers(scanId) {
  if (!scanId) { return; }
  const subSearch = $("subdomain-browser-search");
  const subPrev = $("subdomain-browser-prev");
  const subNext = $("subdomain-browser-next");
  if (subSearch && subSearch.dataset.bound !== "1") {
    subSearch.dataset.bound = "1";
    subSearch.addEventListener("input", () => {
      const state = largeBrowserState(scanId, "subdomains");
      state.page = 1;
      renderSubdomainBrowser(scanId);
    });
  }
  if (subPrev && subPrev.dataset.bound !== "1") {
    subPrev.dataset.bound = "1";
    subPrev.addEventListener("click", () => {
      const state = largeBrowserState(scanId, "subdomains");
      state.page = Math.max(1, state.page - 1);
      renderSubdomainBrowser(scanId);
    });
  }
  if (subNext && subNext.dataset.bound !== "1") {
    subNext.dataset.bound = "1";
    subNext.addEventListener("click", () => {
      const state = largeBrowserState(scanId, "subdomains");
      state.page += 1;
      renderSubdomainBrowser(scanId);
    });
  }
  const archiveSearch = $("archive-browser-search");
  const archivePrev = $("archive-browser-prev");
  const archiveNext = $("archive-browser-next");
  if (archiveSearch && archiveSearch.dataset.bound !== "1") {
    archiveSearch.dataset.bound = "1";
    archiveSearch.addEventListener("input", () => {
      const state = largeBrowserState(scanId, "archive");
      state.page = 1;
      renderArchiveBrowser(scanId);
    });
  }
  if (archivePrev && archivePrev.dataset.bound !== "1") {
    archivePrev.dataset.bound = "1";
    archivePrev.addEventListener("click", () => {
      const state = largeBrowserState(scanId, "archive");
      state.page = Math.max(1, state.page - 1);
      renderArchiveBrowser(scanId);
    });
  }
  if (archiveNext && archiveNext.dataset.bound !== "1") {
    archiveNext.dataset.bound = "1";
    archiveNext.addEventListener("click", () => {
      const state = largeBrowserState(scanId, "archive");
      state.page += 1;
      renderArchiveBrowser(scanId);
    });
  }
  renderSubdomainBrowser(scanId);
  renderArchiveBrowser(scanId);
  loadAllSubdomains(scanId);
  loadArchiveBrowser(scanId);
}

function openEvidenceModal(payload) {
  const modal = $("evidence-modal");
  if (!modal) { return; }
  $("ev-title").textContent = payload.title || "Evidence";
  $("ev-source").textContent = payload.source || "n/a";
  $("ev-confidence").textContent = payload.confidence || "n/a";
  $("ev-severity").textContent = payload.severity || "INFO";
  $("ev-first-seen").textContent = payload.firstSeen || "-";
  $("ev-last-seen").textContent = payload.lastSeen || "-";
  $("ev-evidence").textContent = payload.evidence || "No evidence text";
  $("ev-refs").textContent = payload.refs || "n/a";
  modal.classList.add("open");
}

function closeEvidenceModal() {
  const modal = $("evidence-modal");
  if (modal) { modal.classList.remove("open"); }
}

function findingFreshnessTag(lastSeenRaw) {
  if (!lastSeenRaw) { return "unknown"; }
  const ts = new Date(lastSeenRaw);
  if (Number.isNaN(ts.getTime())) { return "unknown"; }
  const days = (Date.now() - ts.getTime()) / 86400000;
  if (days <= 30) { return "fresh"; }
  if (days <= 120) { return "stale"; }
  return "old";
}

function applyFindingFilters() {
  const source = $("finding-filter-source")?.value || "all";
  const conf = $("finding-filter-confidence")?.value || "all";
  const sev = $("finding-filter-severity")?.value || "all";
  const fresh = $("finding-filter-freshness")?.value || "all";
  qsa("#top-findings-body tr").forEach((row) => {
    const rowSource = row.dataset.source || "";
    const rowConf = parseFloat(row.dataset.confidence || "0");
    const rowSev = row.dataset.severity || "INFO";
    const rowFresh = findingFreshnessTag(row.dataset.lastSeen || "");
    let ok = true;
    if (source !== "all" && source !== rowSource) { ok = false; }
    if (sev !== "all" && sev !== rowSev) { ok = false; }
    if (fresh !== "all" && fresh !== rowFresh) { ok = false; }
    if (conf === "high" && rowConf < 0.8) { ok = false; }
    if (conf === "medium" && (rowConf < 0.5 || rowConf >= 0.8)) { ok = false; }
    if (conf === "low" && rowConf >= 0.5) { ok = false; }
    row.style.display = ok ? "" : "none";
  });
}

function applyEmailFilters() {
  const source = $("email-filter-source")?.value || "";
  const conf = $("email-filter-confidence")?.value || "all";
  const fresh = $("email-filter-freshness")?.value || "all";
  qsa("#email-table tbody tr").forEach((row) => {
    const rowSource = row.dataset.emailSource || "";
    const rowConf = parseFloat(row.dataset.emailConfidence || "0");
    const rowFresh = findingFreshnessTag(row.dataset.emailLastSeen || "");
    let ok = true;
    if (source && !row.textContent.toLowerCase().includes(source.toLowerCase())) { ok = false; }
    if (fresh !== "all" && fresh !== rowFresh) { ok = false; }
    if (conf === "high" && rowConf < 0.8) { ok = false; }
    if (conf === "medium" && (rowConf < 0.5 || rowConf >= 0.8)) { ok = false; }
    if (conf === "low" && rowConf >= 0.5) { ok = false; }
    row.style.display = ok ? "" : "none";
  });
}

function initFindingsUi() {
  qsa(".ev-open").forEach((btn) => {
    btn.addEventListener("click", () => {
      openEvidenceModal({
        title: btn.dataset.title,
        source: btn.dataset.source,
        confidence: btn.dataset.confidence,
        severity: btn.dataset.severity,
        firstSeen: btn.dataset.firstSeen,
        lastSeen: btn.dataset.lastSeen,
        evidence: btn.dataset.evidence,
        refs: btn.dataset.refs,
      });
    });
  });
  qsa("#finding-filter-source,#finding-filter-confidence,#finding-filter-severity,#finding-filter-freshness").forEach((el) => {
    el.addEventListener("change", applyFindingFilters);
  });
  qsa("#email-filter-source,#email-filter-confidence,#email-filter-freshness").forEach((el) => {
    el.addEventListener("change", applyEmailFilters);
  });
  const closeBtn = $("evidence-modal-close");
  if (closeBtn) { closeBtn.addEventListener("click", closeEvidenceModal); }
  const modal = $("evidence-modal");
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) { closeEvidenceModal(); }
    });
  }
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function resultCacheKey(scanId, section) {
  return `${scanId}:${section}`;
}

function sectionCacheEntry(scanId, section) {
  const key = resultCacheKey(scanId, section);
  if (!AppStore.resultSectionCache[key]) {
    AppStore.resultSectionCache[key] = {
      items: [],
      total: 0,
      offset: 0,
      hasMore: false,
      payload: null,
      loading: false,
      loaded: false,
    };
  }
  return AppStore.resultSectionCache[key];
}

function severityBadge(severity) {
  const sev = String(severity || "INFO").toUpperCase();
  return `<span class="sev sev-${sev}">${sev}</span>`;
}

function yesNoBadge(flag, positiveLabel, negativeLabel) {
  return flag
    ? `<span class="badge badge-green">${positiveLabel || "yes"}</span>`
    : `<span class="badge badge-gray">${negativeLabel || "no"}</span>`;
}

function hostnameTagList(name) {
  const value = String(name || "").toLowerCase();
  const map = [
    ["api", "badge-blue"],
    ["auth", "badge-purple"],
    ["admin", "badge-red"],
    ["vpn", "badge-orange"],
    ["mail", "badge-yellow"],
    ["dev", "badge-cyan"],
    ["git", "badge-gray"],
    ["cdn", "badge-indigo"],
  ];
  return map
    .filter(([needle]) => value.includes(needle))
    .map(([needle, cls]) => `<span class="badge ${cls}">${needle}</span>`)
    .join(" ");
}

function normalizeRowsData(payload) {
  if (!payload || typeof payload !== "object") { return []; }
  if (Array.isArray(payload.data)) { return payload.data; }
  return [];
}

function renderEmptyState(message) {
  return `<div class="empty-state"><div class="ei">-</div>${escapeHtml(message || "No data")}</div>`;
}

function renderTableShell(tableId, columns, rowsHtml, extra) {
  const header = columns.map((col) => `<th>${escapeHtml(col.label)}</th>`).join("");
  return `
    ${extra || ""}
    <div class="table-shell">
      <table class="data-table result-data-table" id="${tableId}">
        <thead><tr>${header}</tr></thead>
        <tbody>${rowsHtml || `<tr><td colspan="${columns.length}">No data</td></tr>`}</tbody>
      </table>
    </div>
  `;
}

function sectionSearchValue(section) {
  const input = document.querySelector(`[data-section-search="${section}"]`);
  return String(input?.value || "").toLowerCase();
}

function renderSubdomainsSection(section, rows, state) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No subdomains captured."); }
  const scanId = AppStore.currentReportScanId || AppStore.currentScanId || "";
  const pageKey = `${scanId}:${section}`;
  const totalPages = Math.max(1, Math.ceil(filtered.length / 100));
  const currentPage = Math.min(totalPages, Math.max(1, Number(AppStore.sectionPages[pageKey] || 1)));
  const start = (currentPage - 1) * 100;
  const pageRows = filtered.slice(start, start + 100);
  AppStore.sectionPages[pageKey] = currentPage;
  const totalAvailable = Number(state.total || rows.length || 0);
  const body = pageRows.map((row) => `
    <tr>
      <td class="mono copyable-cell" data-copy-value="${escapeHtml(row.name || "")}">${escapeHtml(row.name || "")}</td>
      <td>${hostnameTagList(row.name)} ${(row.tags || []).slice(0, 6).map((tag) => `<span class="badge badge-gray">${escapeHtml(tag)}</span>`).join(" ")}</td>
      <td>${escapeHtml(((row.ips || row.resolved_ips || [])).join(", "))}</td>
      <td>${escapeHtml(((row.open_ports || row.ports || [])).join(", "))}</td>
      <td>${escapeHtml((row.sources || []).join(", "))}</td>
      <td>${escapeHtml(String(row.relevance_score || 0))}</td>
    </tr>
  `).join("");
  const note = `
    <div class="lazy-preview-note"><strong>${totalAvailable.toLocaleString()} subdomains found</strong>${q ? ` · ${filtered.length.toLocaleString()} match filter` : ""} · showing ${start + 1}-${Math.min(filtered.length, start + 100)}</div>
    ${totalPages > 1 ? `
      <div class="infra-filter-row">
        <button class="btn btn-ghost btn-sm" type="button" data-section-page="${section}" data-page="${Math.max(1, currentPage - 1)}" ${currentPage <= 1 ? "disabled" : ""}>Prev</button>
        <span class="coverage-pill">Page ${currentPage} / ${totalPages}</span>
        <button class="btn btn-ghost btn-sm" type="button" data-section-page="${section}" data-page="${Math.min(totalPages, currentPage + 1)}" ${currentPage >= totalPages ? "disabled" : ""}>Next</button>
      </div>
    ` : ""}
    ${state.total > rows.length ? `<div class="lazy-preview-note">Loaded ${rows.length} of ${state.total} rows. Use Load more to continue.</div>` : ""}
  `;
  return renderTableShell("sub-table", [
    { label: "Hostname" }, { label: "Keywords / Tags" }, { label: "IPs" }, { label: "Ports" }, { label: "Sources" }, { label: "Rank" },
  ], body, note);
}

function renderEmailsSection(section, rows, state) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No emails captured."); }
  const body = filtered.map((row) => `
    <tr>
      <td class="mono copyable-cell" data-copy-value="${escapeHtml(row.email || "")}">${escapeHtml(row.email || "")}</td>
      <td>${escapeHtml(row.role || row.role_category || "")}</td>
      <td>${escapeHtml((row.sources || []).join(", "))}</td>
      <td>${escapeHtml((row.source_attribution || []).map((item) => item && item.source ? item.source : "").filter(Boolean).slice(0, 6).join(", ")) || "-"}</td>
      <td>${escapeHtml(String(row.confidence || ""))}</td>
    </tr>
  `).join("");
  const totalAvailable = Number(state.total || rows.length || 0);
  const emailPattern = ((((AppStore.currentReport || {}).data || {}).email_pattern) || {});
  return renderTableShell("email-table", [
    { label: "Email" }, { label: "Role" }, { label: "Sources" }, { label: "Evidence Source" }, { label: "Confidence" },
  ], body, `<div class="lazy-preview-note"><strong>${totalAvailable.toLocaleString()} emails found</strong>${q ? ` · ${filtered.length.toLocaleString()} match filter` : ""} · showing ${filtered.length.toLocaleString()}</div>${emailPattern.pattern ? `<div class="lazy-preview-note">Pattern detected: ${escapeHtml(emailPattern.pattern)}${emailPattern.confidence ? ` (${escapeHtml(String(emailPattern.confidence))}% confidence)` : ""}</div>` : ""}${state.total > rows.length ? `<div class="lazy-preview-note">Loaded ${rows.length.toLocaleString()} of ${state.total.toLocaleString()} rows. Use Load more to continue.</div>` : ""}`);
}

function renderIpsSection(section, rows, state) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No infrastructure records captured."); }
  const selectionKey = AppStore.currentReportScanId || AppStore.currentScanId || (($("results-page") && $("results-page").dataset.scanId) || "");
  const quickFilter = AppStore.infraFilters[selectionKey] || "all";
  const scoped = filtered.filter((row) => infraFilterMatch(row, quickFilter));
  const selectedIp = AppStore.infraSelections[selectionKey] || (scoped[0] && scoped[0].ip) || "";
  const selectedRow = scoped.find((row) => String(row.ip || "") === selectedIp) || scoped[0] || filtered[0];
  if (selectedRow) {
    AppStore.infraSelections[selectionKey] = String(selectedRow.ip || "");
  }
  const metrics = infraMetrics(rows, sectionCacheEntry(selectionKey, "asn").payload);
  const body = scoped.map((row) => {
    const classification = infraClassification(row);
    const selected = selectedRow && String(selectedRow.ip || "") === String(row.ip || "");
    return `
      <tr class="infra-row ${selected ? "selected" : ""}" data-infra-select="${escapeHtml(row.ip || "")}">
        <td class="mono"><span class="copyable-cell" data-copy-value="${escapeHtml(row.ip || "")}">${escapeHtml(row.ip || "")}</span></td>
        <td><span class="badge ${classification.badge}">${classification.label}</span></td>
        <td class="mono">${escapeHtml(row.asn || "")}</td>
        <td>${escapeHtml(row.org || "")}</td>
        <td>${escapeHtml(row.country || "")}</td>
        <td>${escapeHtml((row.open_ports || row.ports || []).join(", "))}</td>
        <td class="infra-host-cell" title="${escapeHtml(row.rdns || "")}">
          ${row.rdns ? `<span class="copyable-cell" data-copy-value="${escapeHtml(row.rdns)}">${escapeHtml(row.rdns)}</span>` : '<span class="infra-muted">No hostname</span>'}
        </td>
      </tr>
    `;
  }).join("");
  const asnPayload = sectionCacheEntry(selectionKey, "asn").payload;
  return `
    <div class="infra-summary-strip">
      <div class="infra-metric"><span>Total IPs</span><strong>${metrics.total}</strong></div>
      <div class="infra-metric"><span>Possible origins</span><strong>${metrics.origins}</strong></div>
      <div class="infra-metric"><span>CDN / edge</span><strong>${metrics.edge}</strong></div>
      <div class="infra-metric"><span>Countries</span><strong>${metrics.countries}</strong></div>
      <div class="infra-metric"><span>Unique ASNs</span><strong>${metrics.asns}</strong></div>
    </div>
    <div class="infra-filter-row">
      ${["all", "possible_origin", "edge", "with_ports", "suspicious"].map((name) => `
        <button class="btn btn-ghost btn-sm infra-filter-btn ${quickFilter === name ? "active" : ""}" type="button" data-infra-filter="${name}">
          ${name === "all" ? "All" : name === "possible_origin" ? "Possible origin" : name === "edge" ? "Edge / CDN" : name === "with_ports" ? "With ports" : "Suspicious"}
        </button>
      `).join("")}
    </div>
    <div class="infra-console">
      <div class="infra-table-pane">
        ${renderTableShell("ips-table", [
          { label: "IP" }, { label: "Class" }, { label: "ASN" }, { label: "Org" }, { label: "Country" }, { label: "Ports" }, { label: "Hostname" },
        ], body, state.total > scoped.length ? `<div class="lazy-preview-note">Loaded ${scoped.length} of ${state.total} rows.</div>` : "")}
      </div>
      <div class="infra-detail-pane">
        ${renderInfrastructureDetail(selectedRow, asnPayload)}
      </div>
    </div>
  `;
}

function renderCertsSection(section, rows, state) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No certificate records captured."); }
  const body = filtered.map((row) => `
    <tr>
      <td>${escapeHtml(row.subject || row.common_name || "")}</td>
      <td>${escapeHtml(row.issuer || "")}</td>
      <td>${escapeHtml(row.not_after || "")}</td>
      <td>${(row.san_entries || []).length}</td>
      <td>${row.expired ? '<span class="badge badge-red">expired</span>' : yesNoBadge((row.days_left || 999) <= 30, 'expiring soon', 'valid')}</td>
    </tr>
  `).join("");
  return renderTableShell("certs-table", [
    { label: "Subject" }, { label: "Issuer" }, { label: "Not After" }, { label: "SAN Count" }, { label: "Status" },
  ], body);
}

function renderTechnologiesSection(section, rows) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No technologies captured."); }
  const cards = filtered.map((row) => `
    <article class="tech-card">
      <div class="tech-name">${escapeHtml(row.name || "")}</div>
      <div class="tech-meta">${escapeHtml(row.category || "")}</div>
      <div class="tech-meta">Confidence ${escapeHtml(String(row.confidence || ""))}${row.version ? ` · v${escapeHtml(String(row.version || ""))}` : ""}</div>
      <div class="tech-meta">Evidence source: ${escapeHtml((row.sources || []).join(", ")) || "-"}</div>
      <div class="tech-meta">${escapeHtml(row.evidence || "")}</div>
    </article>
  `).join("");
  return `<div class="tech-grid">${cards}</div>`;
}

function renderVulnsSection(section, rows, state) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No vulnerability findings captured."); }
  const sorted = filtered.slice().sort((a, b) => {
    const order = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    return (order[String(b.severity || "INFO").toUpperCase()] || 0) - (order[String(a.severity || "INFO").toUpperCase()] || 0);
  });
  const body = sorted.map((row) => `
    <tr>
      <td>${severityBadge(row.severity)}</td>
      <td class="mono">${row.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(row.cve_id)}" target="_blank">${escapeHtml(row.cve_id)}</a>` : escapeHtml(row.title || "")}</td>
      <td>${escapeHtml(row.affected_asset || "")}</td>
      <td>${escapeHtml(row.description || row.title || "")}</td>
      <td>${escapeHtml(row.source || "")}</td>
      <td>${escapeHtml(String(row.confidence || ""))}</td>
    </tr>
  `).join("");
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  sorted.forEach((row) => {
    const sev = String(row.severity || "INFO").toUpperCase();
    sevCounts[sev] = (sevCounts[sev] || 0) + 1;
  });
  return renderTableShell("vulns-table", [
    { label: "Severity" }, { label: "CVE / Title" }, { label: "Asset" }, { label: "Summary" }, { label: "Source" }, { label: "Confidence" },
  ], body, `<div class="lazy-preview-note"><strong>${Number(state.total || rows.length || 0).toLocaleString()} vulnerabilities</strong> · CRITICAL ${sevCounts.CRITICAL} · HIGH ${sevCounts.HIGH} · MEDIUM ${sevCounts.MEDIUM} · LOW ${sevCounts.LOW}</div>${state.total > filtered.length ? `<div class="lazy-preview-note">Loaded ${filtered.length.toLocaleString()} of ${state.total.toLocaleString()} rows.</div>` : ""}`);
}

function renderDorksSection(section, rows) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No dorks captured."); }
  const body = filtered.map((row) => `
    <tr>
      <td>${escapeHtml(row.source || "")}</td>
      <td>${escapeHtml(row.category || "")}</td>
      <td>${severityBadge(row.severity || "INFO")}</td>
      <td>${row.url ? `<a href="${escapeHtml(row.url)}" target="_blank">${escapeHtml(row.url)}</a>` : "-"}</td>
      <td>${escapeHtml(row.snippet || "")}</td>
    </tr>
  `).join("");
  return renderTableShell("dorks-table", [
    { label: "Source" }, { label: "Category" }, { label: "Severity" }, { label: "URL" }, { label: "Snippet" },
  ], body);
}

function renderCloudSection(section, rows) {
  const q = sectionSearchValue(section);
  const filtered = rows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  if (!filtered.length) { return renderEmptyState("No cloud assets captured."); }
  const body = filtered.map((row) => `
    <tr>
      <td>${escapeHtml(row.asset_type || "")}</td>
      <td>${escapeHtml(row.name || "")}</td>
      <td>${row.url ? `<a href="${escapeHtml(row.url)}" target="_blank">${escapeHtml(row.url)}</a>` : "-"}</td>
      <td>${yesNoBadge(Boolean(row.public), "public", "private")}</td>
      <td>${escapeHtml(row.classification || "")}</td>
    </tr>
  `).join("");
  return renderTableShell("cloud-table", [
    { label: "Type" }, { label: "Name" }, { label: "URL" }, { label: "Exposure" }, { label: "Classification" },
  ], body);
}

function renderArchiveSection(payload, state) {
  const archive = payload && payload.data ? payload.data : {};
  const q = sectionSearchValue("archive");
  const allRows = Array.isArray(archive.all_urls) ? archive.all_urls : (Array.isArray(archive.all) ? archive.all : []);
  const scanId = AppStore.currentReportScanId || AppStore.currentScanId || "";
  const pageKey = `${scanId}:archive`;
  const filteredRows = allRows.filter((row) => JSON.stringify(row || {}).toLowerCase().includes(q));
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / 50));
  const currentPage = Math.min(totalPages, Math.max(1, Number(AppStore.sectionPages[pageKey] || 1)));
  const start = (currentPage - 1) * 50;
  const pageRows = filteredRows.slice(start, start + 50);
  AppStore.sectionPages[pageKey] = currentPage;
  const queryParams = Array.isArray(archive.query_params) ? archive.query_params : [];
  const apiProfiles = Array.isArray(archive.api_endpoint_profiles) ? archive.api_endpoint_profiles : [];
  const robots = Array.isArray(archive.historical_robots) ? archive.historical_robots : [];
  const sitemaps = Array.isArray(archive.historical_sitemaps) ? archive.historical_sitemaps : [];
  const archiveBody = pageRows.map((row) => `
    <tr>
      <td class="mono">${escapeHtml(row.url || "")}</td>
      <td>${escapeHtml(row.timestamp || "")}</td>
      <td>${escapeHtml(String(row.status_code || ""))}</td>
      <td>${escapeHtml(row.mime_type || "")}</td>
    </tr>
  `).join("");
  const archiveTable = renderTableShell("archive-all-urls", [
    { label: "URL" }, { label: "Timestamp" }, { label: "Status" }, { label: "MIME" },
  ], archiveBody, `
    <div class="lazy-preview-note"><strong>${Number(archive.total_retrieved || archive.total || allRows.length || 0).toLocaleString()} archive URLs</strong>${q ? ` · ${filteredRows.length.toLocaleString()} match filter` : ""} · showing ${filteredRows.length ? `${start + 1}-${Math.min(filteredRows.length, start + 50)}` : "0"}</div>
    ${totalPages > 1 ? `
      <div class="infra-filter-row">
        <button class="btn btn-ghost btn-sm" type="button" data-section-page="archive" data-page="${Math.max(1, currentPage - 1)}" ${currentPage <= 1 ? "disabled" : ""}>Prev</button>
        <span class="coverage-pill">Page ${currentPage} / ${totalPages}</span>
        <button class="btn btn-ghost btn-sm" type="button" data-section-page="archive" data-page="${Math.min(totalPages, currentPage + 1)}" ${currentPage >= totalPages ? "disabled" : ""}>Next</button>
      </div>
    ` : ""}
  `);
  const groups = [
    ["Sensitive Files", archive.sensitive_files || []],
    ["Interesting Paths", archive.interesting_paths || []],
    ["API Endpoints", archive.api_endpoints || []],
    ["Admin Paths", archive.admin_paths || []],
    ["JavaScript", archive.js_files || []],
    ["Documents", archive.documents || []],
    ["Fallback URLs", archive.uncategorized_urls || []],
  ];
  const cards = groups.map(([label, rows]) => {
    const filtered = rows.filter((row) => String((row && row.url) || "").toLowerCase().includes(q));
    if (!filtered.length) { return ""; }
    const items = filtered.slice(0, 50).map((row) => `
      <tr>
        <td class="mono">${escapeHtml(row.url || "")}</td>
        <td>${escapeHtml(row.timestamp || "")}</td>
        <td>${escapeHtml(String(row.status_code || ""))}</td>
        <td>${escapeHtml(row.mime_type || "")}</td>
      </tr>
    `).join("");
    const accent = label === "Sensitive Files" ? `<div class="section-alert alert-red">Sensitive archive hits stay pinned at the top.</div>` : "";
    return `
      <div class="archive-group">
        <div class="card-title-row">
          <h3>${escapeHtml(label)}</h3>
          <span class="badge badge-gray">${filtered.length.toLocaleString()}</span>
        </div>
        ${accent}
        <div class="lazy-preview-note">Showing first ${Math.min(filtered.length, 50).toLocaleString()} of ${filtered.length.toLocaleString()} in this category.</div>
        ${renderTableShell(`archive-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, [
          { label: "URL" }, { label: "Timestamp" }, { label: "Status" }, { label: "MIME" },
        ], items)}
      </div>
    `;
  }).join("");
  const metaCards = `
    ${(apiProfiles.length || queryParams.length || robots.length || sitemaps.length) ? `
      <div class="archive-group">
        <div class="card-title-row"><h3>Archive Intelligence</h3></div>
        <div class="coverage-summary-row">
          ${queryParams.slice(0, 12).map((row) => `<span class="coverage-pill">${escapeHtml(row.name)} (${escapeHtml(String(row.count || 0))})</span>`).join("")}
        </div>
        ${apiProfiles.length ? renderTableShell("archive-api-profiles", [
          { label: "Host" }, { label: "Path" }, { label: "Query Params" },
        ], apiProfiles.slice(0, 20).map((row) => `<tr><td>${escapeHtml(row.host || "")}</td><td class="mono">${escapeHtml(row.path || "")}</td><td>${escapeHtml((row.query_params || []).join(", "))}</td></tr>`).join("")) : ""}
        ${robots.length ? `<div class="tiny-note">Historical robots: ${robots.map((row) => escapeHtml(row)).join(" | ")}</div>` : ""}
        ${sitemaps.length ? `<div class="tiny-note">Historical sitemaps: ${sitemaps.map((row) => escapeHtml(row)).join(" | ")}</div>` : ""}
      </div>
    ` : ""}
  `;
  return `${archiveTable}${metaCards}${cards}` || renderEmptyState("No archive rows matched the current filter.");
}

function renderAsnSection(payload) {
  const data = payload && payload.data ? payload.data : {};
  const list = Array.isArray(data.list) ? data.list : [];
  if (!list.length) { return '<div class="infra-inline-empty">ASN enrichment is not available for this scan. Infrastructure detail still uses persisted IP evidence and classification.</div>'; }
  const body = list.map((row) => `
    <tr>
      <td class="mono">${escapeHtml(row.asn || "")}</td>
      <td>${escapeHtml(row.name || "")}</td>
      <td>${escapeHtml(row.description || "")}</td>
      <td>${escapeHtml(row.country || "")}</td>
      <td>${escapeHtml(String(row.total_ipv4_ranges || 0))}</td>
    </tr>
  `).join("");
  return renderTableShell("asn-table", [
    { label: "ASN" }, { label: "Name" }, { label: "Description" }, { label: "Country" }, { label: "IPv4 Ranges" },
  ], body);
}

function infraClassification(row) {
  const ports = Array.isArray(row.open_ports) ? row.open_ports : (Array.isArray(row.ports) ? row.ports : []);
  const rdns = String(row.rdns || "").toLowerCase();
  const org = String(row.org || "").toLowerCase();
  if (row.cdn || /cloudflare|akamai|fastly|cloudfront|imperva/.test(org)) {
    return {
      key: "edge",
      label: "edge / CDN",
      badge: "badge-indigo",
      reason: "Provider signal indicates edge/CDN infrastructure rather than a likely origin host.",
    };
  }
  if (ports.length || /origin|internal|direct/.test(rdns)) {
    return {
      key: "possible_origin",
      label: "possible origin",
      badge: "badge-orange",
      reason: "Observed ports and naming suggest this host may sit closer to origin infrastructure.",
    };
  }
  if (ports.length >= 3 || ports.some((p) => [22, 3389, 5432, 2375, 9200].includes(Number(p)))) {
    return {
      key: "suspicious",
      label: "suspicious",
      badge: "badge-red",
      reason: "Port profile exposes services that deserve analyst review.",
    };
  }
  return {
    key: "observed",
    label: "observed infra",
    badge: "badge-gray",
    reason: "Passive evidence observed the host, but classification remains neutral.",
  };
}

function infraFilterMatch(row, filterName) {
  const classification = infraClassification(row);
  const ports = Array.isArray(row.open_ports) ? row.open_ports : (Array.isArray(row.ports) ? row.ports : []);
  if (filterName === "possible_origin") { return classification.key === "possible_origin"; }
  if (filterName === "edge") { return classification.key === "edge"; }
  if (filterName === "with_ports") { return ports.length > 0; }
  if (filterName === "suspicious") { return classification.key === "suspicious"; }
  return true;
}

function infraMetrics(rows, asnPayload) {
  const countries = new Set();
  const asns = new Set();
  let origins = 0;
  let edge = 0;
  rows.forEach((row) => {
    const classification = infraClassification(row);
    if (classification.key === "possible_origin") { origins += 1; }
    if (classification.key === "edge") { edge += 1; }
    if (row.country) { countries.add(String(row.country)); }
    if (row.asn) { asns.add(String(row.asn)); }
  });
  const asnData = asnPayload && asnPayload.data ? asnPayload.data : {};
  if (Array.isArray(asnData.list)) {
    asnData.list.forEach((row) => {
      if (row && row.asn) { asns.add(String(row.asn)); }
    });
  }
  return {
    total: rows.length,
    origins,
    edge,
    countries: countries.size,
    asns: asns.size,
  };
}

function resolveAsnDetail(row, asnPayload) {
  const data = asnPayload && asnPayload.data ? asnPayload.data : {};
  const list = Array.isArray(data.list) ? data.list : [];
  const byAsn = data.by_asn && typeof data.by_asn === "object" ? data.by_asn : {};
  if (row.asn && byAsn[row.asn]) { return byAsn[row.asn]; }
  return list.find((item) => item && String(item.asn || "") === String(row.asn || "")) || null;
}

function renderInfrastructureDetail(row, asnPayload) {
  if (!row) { return renderEmptyState("Select an IP to inspect infrastructure details."); }
  const classification = infraClassification(row);
  const asnDetail = resolveAsnDetail(row, asnPayload);
  const evidence = [];
  if (row.cdn) { evidence.push("cdn flag"); }
  if ((row.open_ports || row.ports || []).length) { evidence.push(`ports: ${(row.open_ports || row.ports || []).join(", ")}`); }
  if (row.rdns) { evidence.push(`rdns: ${row.rdns}`); }
  if (row.shared_hosting && row.shared_hosting.length) { evidence.push(`shared hosting: ${row.shared_hosting.length}`); }
  return `
    <div class="infra-detail-card">
      <div class="card-title-row">
        <h3>Infrastructure Detail</h3>
        <span class="badge ${classification.badge}">${classification.label}</span>
      </div>
      <div class="infra-detail-grid">
        <div><span>IP</span><strong class="mono copyable-cell" data-copy-value="${escapeHtml(row.ip || "")}">${escapeHtml(row.ip || "")}</strong></div>
        <div><span>Hostname</span><strong class="infra-ellipsis copyable-cell" data-copy-value="${escapeHtml(row.rdns || "")}" title="${escapeHtml(row.rdns || "")}">${escapeHtml(row.rdns || "No hostname")}</strong></div>
        <div><span>ASN</span><strong>${escapeHtml(row.asn || (asnDetail && asnDetail.asn) || "Unknown")}</strong></div>
        <div><span>Organization</span><strong>${escapeHtml(row.org || (asnDetail && asnDetail.name) || "Unknown")}</strong></div>
        <div><span>Country</span><strong>${escapeHtml(row.country || (asnDetail && asnDetail.country) || "Unknown")}</strong></div>
        <div><span>Ports</span><strong>${escapeHtml((row.open_ports || row.ports || []).join(", ") || "None observed")}</strong></div>
      </div>
      <div class="infra-reason-box">
        <div class="infra-reason-title">Why this classification</div>
        <div>${escapeHtml(classification.reason)}</div>
      </div>
      <div class="infra-evidence-list">
        <div class="infra-reason-title">Evidence available</div>
        ${evidence.length ? evidence.map((item) => `<div class="infra-evidence-line">${escapeHtml(item)}</div>`).join("") : '<div class="infra-inline-empty">No extra passive evidence persisted for this host.</div>'}
      </div>
      <div class="infra-asn-box">
        <div class="infra-reason-title">ASN intelligence</div>
        ${asnDetail ? `
          <div class="infra-asn-grid">
            <div><span>Name</span><strong>${escapeHtml(asnDetail.name || "")}</strong></div>
            <div><span>Description</span><strong>${escapeHtml(asnDetail.description || "")}</strong></div>
            <div><span>Country</span><strong>${escapeHtml(asnDetail.country || "")}</strong></div>
            <div><span>IPv4 ranges</span><strong>${escapeHtml(String(asnDetail.total_ipv4_ranges || 0))}</strong></div>
          </div>
        ` : '<div class="infra-inline-empty">ASN enrichment is empty for this IP. The host view remains usable from IP-level evidence.</div>'}
      </div>
    </div>
  `;
}

function renderReputationSection(payload) {
  const data = payload && payload.data ? payload.data : {};
  const entries = Object.entries(data || {});
  if (!entries.length) { return renderEmptyState("No reputation hits persisted."); }
  const body = entries.map(([source, row]) => `
    <tr>
      <td>${escapeHtml(source)}</td>
      <td>${escapeHtml(Object.entries(row || {}).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(" | ").slice(0, 280))}</td>
    </tr>
  `).join("");
  return renderTableShell("reputation-table", [
    { label: "Source" }, { label: "Evidence" },
  ], body);
}

function renderSocialSection(payload) {
  const data = payload && payload.data ? payload.data : {};
  const profiles = data.profiles && typeof data.profiles === "object" ? Object.entries(data.profiles) : [];
  const apps = Array.isArray(data.ios_apps) ? data.ios_apps : [];
  const repos = Array.isArray(data.github_repos) ? data.github_repos : [];
  const packages = Array.isArray(data.npm_packages) ? data.npm_packages : [];
  if (!profiles.length && !apps.length && !repos.length && !packages.length) {
    return renderEmptyState("No social footprint persisted.");
  }
  const profileRows = profiles.map(([name, value]) => `
    <tr><td>${escapeHtml(name)}</td><td>${escapeHtml(typeof value === "string" ? value : JSON.stringify(value))}</td></tr>
  `).join("");
  const appRows = apps.map((row) => `<tr><td>${escapeHtml(row.name || row.title || "")}</td><td>${escapeHtml(row.url || row.bundle || "")}</td></tr>`).join("");
  const repoRows = repos.slice(0, 12).map((row) => `<tr><td>${escapeHtml(row.name || "")}</td><td>${escapeHtml(row.language || "")}</td><td>${escapeHtml(String(row.stars || 0))}</td></tr>`).join("");
  const packageRows = packages.slice(0, 12).map((row) => `<tr><td>${escapeHtml(row.name || "")}</td><td>${escapeHtml(row.url || "")}</td></tr>`).join("");
  return `
    ${profileRows ? renderTableShell("social-profiles-table", [{ label: "Profile" }, { label: "Evidence" }], profileRows) : ""}
    ${appRows ? renderTableShell("social-apps-table", [{ label: "App" }, { label: "Reference" }], appRows) : ""}
    ${repoRows ? renderTableShell("social-repos-table", [{ label: "Repo" }, { label: "Language" }, { label: "Stars" }], repoRows) : ""}
    ${packageRows ? renderTableShell("social-packages-table", [{ label: "Package" }, { label: "Reference" }], packageRows) : ""}
  `;
}

function renderSectionContent(section, payload, state) {
  const rows = normalizeRowsData(payload);
  switch (section) {
    case "subdomains": return renderSubdomainsSection(section, rows, state);
    case "emails": return renderEmailsSection(section, rows, state);
    case "ips": return renderIpsSection(section, rows, state);
    case "certs": return renderCertsSection(section, rows, state);
    case "techs": return renderTechnologiesSection(section, rows, state);
    case "vulns": return renderVulnsSection(section, rows, state);
    case "dorks": return renderDorksSection(section, rows, state);
    case "cloud": return renderCloudSection(section, rows, state);
    case "archive": return renderArchiveSection(payload, state);
    case "asn": return renderAsnSection(payload);
    case "reputation": return renderReputationSection(payload);
    case "social": return renderSocialSection(payload);
    default: return renderEmptyState("Unsupported section.");
  }
}

function findSectionShell(section) {
  return document.querySelector(`[data-result-panel="${section}"]`);
}

function renderSectionState(scanId, section) {
  const shell = findSectionShell(section);
  if (!shell) {
    if (section === "asn") { renderSectionState(scanId, "ips"); }
    return;
  }
  const state = sectionCacheEntry(scanId, section);
  const status = shell.querySelector(".lazy-section-status");
  const content = shell.querySelector(".lazy-section-content");
  if (status) {
    status.textContent = state.loading
      ? "Loading..."
      : (state.loaded ? `${state.items.length || state.total || 0} record(s) ready.` : "Loading on demand.");
  }
  if (!state.payload) { return; }
  if (!content) {
    if (section === "asn") { renderSectionState(scanId, "ips"); }
    return;
  }
  content.innerHTML = renderSectionContent(section, state.payload, state);
  if (section === "ips") { bindInfrastructureUi(scanId); }
  if (section === "subdomains" || section === "archive") { bindSectionPagination(scanId, section); }
  if (section === "asn") { renderSectionState(scanId, "ips"); }
  const loadMoreNeeded = state.hasMore && Array.isArray(state.items) && state.items.length > 0;
  if (loadMoreNeeded) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = `Load more (${state.items.length}/${state.total})`;
    btn.onclick = () => loadSectionData(scanId, section, { append: true });
    content.appendChild(btn);
  }
  initSortableTables();
}

function bindSectionPagination(scanId, section) {
  qsa(`[data-section-page="${section}"]`).forEach((btn) => {
    if (btn.dataset.bound === "1") { return; }
    btn.dataset.bound = "1";
    btn.addEventListener("click", () => {
      AppStore.sectionPages[`${scanId}:${section}`] = Number(btn.dataset.page || 1);
      renderSectionState(scanId, section);
    });
  });
}

function loadSectionData(scanId, section, opts) {
  const state = sectionCacheEntry(scanId, section);
  if (state.loading) { return Promise.resolve(); }
  if (state.loaded && !(opts && opts.append)) {
    renderSectionState(scanId, section);
    return Promise.resolve();
  }
  const shell = findSectionShell(section);
  if (!shell) { return Promise.resolve(); }
  state.loading = true;
  renderSectionState(scanId, section);
  const nextOffset = (opts && opts.append) ? state.offset : 0;
  const limit = ["subdomains", "emails", "ips", "vulns"].includes(section) ? 250 : 120;
  const query = nextOffset ? `?offset=${nextOffset}&limit=${limit}` : `?limit=${limit}`;
  return fetch(`${shell.dataset.endpoint}${query}`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((payload) => {
      state.payload = payload;
      if (Array.isArray(payload.data)) {
        state.items = (opts && opts.append) ? state.items.concat(payload.data) : payload.data.slice();
        state.offset = state.items.length;
        state.total = Number(payload.total || state.items.length || 0);
        state.hasMore = Boolean(payload.has_more);
        state.payload = { ...payload, data: state.items.slice() };
      } else {
        state.total = Number(payload.total || 0);
        state.hasMore = false;
      }
      state.loaded = true;
    })
    .catch((err) => {
      const content = shell.querySelector(".lazy-section-content");
      if (content) { content.innerHTML = renderEmptyState(`Failed to load section: ${err.message || "unknown error"}`); }
    })
    .finally(() => {
      state.loading = false;
      renderSectionState(scanId, section);
    });
}

function fetchAllSectionRows(scanId, section) {
  const shell = findSectionShell(section);
  if (!scanId || !shell || !shell.dataset.endpoint) {
    return Promise.resolve([]);
  }
  const state = sectionCacheEntry(scanId, section);
  const cachedRows = Array.isArray(state.items) ? state.items.slice() : [];
  const cachedTotal = Number(state.total || cachedRows.length || 0);
  if (state.loaded && !state.hasMore && cachedRows.length && cachedRows.length >= cachedTotal) {
    return Promise.resolve(cachedRows);
  }
  const limit = 1000;
  const loadBatch = (offset, rows) => fetch(`${shell.dataset.endpoint}?offset=${offset}&limit=${limit}`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((payload) => {
      const batch = Array.isArray(payload.data) ? payload.data : [];
      const nextRows = rows.concat(batch);
      const total = Number(payload.total || nextRows.length || 0);
      if (payload.has_more && nextRows.length < total) {
        return loadBatch(nextRows.length, nextRows);
      }
      return nextRows;
    });
  return loadBatch(0, []);
}

function bindInfrastructureUi(scanId) {
  qsa("[data-infra-filter]").forEach((btn) => {
    if (btn.dataset.bound === "1") { return; }
    btn.dataset.bound = "1";
    btn.addEventListener("click", () => {
      AppStore.infraFilters[scanId] = btn.dataset.infraFilter || "all";
      renderSectionState(scanId, "ips");
    });
  });
  qsa("[data-infra-select]").forEach((row) => {
    if (row.dataset.bound === "1") { return; }
    row.dataset.bound = "1";
    row.addEventListener("click", () => {
      AppStore.infraSelections[scanId] = row.dataset.infraSelect || "";
      renderSectionState(scanId, "ips");
    });
  });
}

function sectionGroupForPanel(panelId) {
  const mapping = {
    subdomains: ["subdomains"],
    emails: ["emails"],
    infrastructure: ["ips", "asn"],
    ssl: ["certs"],
    archive: ["archive"],
    technologies: ["techs"],
    vulnerabilities: ["vulns"],
    dorks: ["dorks"],
    cloud: ["cloud"],
    intelligence: ["social", "reputation"],
  };
  return mapping[panelId] || [];
}

function activateResultTab(panelId, scanId) {
  qsa(".result-tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.resultTab === panelId));
  qsa(".result-panel").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === panelId));
  sectionGroupForPanel(panelId).forEach((section) => loadSectionData(scanId, section));
}

function exportSectionCsv(section, scanId) {
  if (section === "subdomains" && scanId) {
    downloadFile(`/api/download/${encodeURIComponent(scanId)}/csv_subdomains`, `ghost_recon_${scanId}_subdomains.csv`);
    return;
  }
  const state = sectionCacheEntry(scanId, section);
  const rows = Array.isArray(state.items) ? state.items : [];
  if (!rows.length) {
    flashError("Load the section first.");
    return;
  }
  const headers = Object.keys(rows[0] || {});
  const lines = [
    headers.join(","),
    ...rows.map((row) => headers.map((key) => {
      const value = Array.isArray(row[key]) ? row[key].join("|") : row[key];
      const text = String(value == null ? "" : value).replace(/"/g, "\"\"");
      return `"${text}"`;
    }).join(",")),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = `${scanId}_${section}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(href);
}

function copySectionLines(section, scanId) {
  const state = sectionCacheEntry(scanId, section);
  const cachedRows = Array.isArray(state.items) ? state.items : [];
  const rowsPromise = (scanId && (section === "subdomains" || section === "emails"))
    ? fetchAllSectionRows(scanId, section)
    : Promise.resolve(cachedRows);
  rowsPromise
    .then((rows) => {
      let lines = [];
      if (section === "subdomains") {
        lines = rows.map((row) => String(row.name || row.subdomain || row.host || "").trim()).filter(Boolean);
      } else if (section === "emails") {
        lines = rows.map((row) => String(row.email || "").trim()).filter(Boolean);
      }
      if (!lines.length) {
        flashError("No rows available to copy.");
        return;
      }
      const label = section === "subdomains" ? "subdomains" : section;
      copyBulkText(lines.join("\n"), `Copied ${lines.length} ${label}!`);
    })
    .catch((err) => {
      console.error("Bulk copy failed", err);
      flashError("Copy failed. Please retry.");
    });
}

function bindSectionSearch(scanId) {
  qsa("[data-section-search]").forEach((input) => {
    if (input.dataset.bound === "1") { return; }
    input.dataset.bound = "1";
    input.addEventListener("input", () => {
      const section = input.dataset.sectionSearch;
      renderSectionState(scanId, section);
    });
  });
}

function bindSectionExports(scanId) {
  qsa("[data-export-section]").forEach((btn) => {
    if (btn.dataset.bound === "1") { return; }
    btn.dataset.bound = "1";
    btn.addEventListener("click", () => exportSectionCsv(btn.dataset.exportSection, scanId));
  });
  qsa("[data-copy-section]").forEach((btn) => {
    if (btn.dataset.bound === "1") { return; }
    btn.dataset.bound = "1";
    btn.addEventListener("click", () => copySectionLines(btn.dataset.copySection, scanId));
  });
}

function bindRawLoader(scanId) {
  qsa("[data-load-raw]").forEach((btn) => {
    if (btn.dataset.bound === "1") { return; }
    btn.dataset.bound = "1";
    btn.addEventListener("click", () => {
      const viewer = $("raw-json-viewer");
      if (viewer) { viewer.textContent = "Loading canonical JSON..."; }
      fetch(`/api/result/${encodeURIComponent(scanId)}`, { cache: "no-store" })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
        .then((payload) => {
          if (viewer) { viewer.textContent = JSON.stringify(payload, null, 2); }
        })
        .catch((err) => {
          if (viewer) { viewer.textContent = `Failed to load canonical JSON: ${err.message || "unknown error"}`; }
        });
    });
  });
}

function initResultsWorkspace(scanId) {
  if (!scanId || !$("results-page")) { return; }
  qsa(".result-tab").forEach((tab) => {
    if (tab.dataset.bound === "1") { return; }
    tab.dataset.bound = "1";
    tab.addEventListener("click", () => activateResultTab(tab.dataset.resultTab, scanId));
  });
  bindSectionSearch(scanId);
  bindSectionExports(scanId);
  bindRawLoader(scanId);
  activateResultTab("overview", scanId);
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && $("domain-input") === document.activeElement && !($("launch-btn")?.disabled)) {
    launchScan();
  }
  if (e.key === "Escape") {
    closeEvidenceModal();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  window.onpopstate = () => {
    handleHistoryNavigation();
  };
  initSections();
  initSidebarScroll();
  initDropdowns();
  initDownloadLinks();
  initSortableTables();
  initFindingsUi();
  initResultsWorkspace(($("results-page") && $("results-page").dataset.scanId) || "");
  initLargeResultBrowsers(($("results-page") && $("results-page").dataset.scanId) || "");
  const observer = typeof IntersectionObserver !== "undefined" ? new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (en.isIntersecting) {
        qsa(".score-bar-fill", en.target).forEach((bar) => { bar.style.width = bar.style.width || "0%"; });
      }
    });
  }) : null;
  if (observer) { qsa(".score-grid").forEach((g) => observer.observe(g)); }
  document.addEventListener("click", (ev) => {
    const target = ev.target?.closest?.(".copyable-cell");
    if (!target) { return; }
    copyText(target.getAttribute("data-copy-value") || target.textContent || "");
  });
  refreshScanQueue(shouldPollScanQueue(true));
  scheduleQueueRefresh();
  document.addEventListener("visibilitychange", scheduleQueueRefresh);
  const activeScan = localStorage.getItem("grt_active_scan_id") || "";
  if (activeScan && $("home-page") && !window.location.pathname.startsWith("/scan/") && !isNewScanIntent()) {
    fetch(`/api/scan/${encodeURIComponent(activeScan)}/status`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((st) => {
        if (!st || !st.status || !["queued", "running"].includes(st.status)) {
          localStorage.removeItem("grt_active_scan_id");
          return;
        }
        reattachScan(activeScan, st.domain || "scan", { push: false });
      })
      .catch(() => null);
  }
  handleHistoryNavigation();
});

