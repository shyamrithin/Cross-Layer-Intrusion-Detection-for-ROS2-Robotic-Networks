/* ============================================================================
 * File        : app.js
 * Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
 * Course      : 21ECC402P - Computer Communication and Network Security
 * Author      : Shyam Rithin S (RA2311004010308)
 * Description : Front-end logic for the IDS Monitor. Polls /api/state
 *               incrementally, keeps a rolling sample buffer, draws the live
 *               strip charts on <canvas>, wires the menus / toolbar toggles to
 *               the detector-control and capture/record endpoints, renders the
 *               packet-list event log with a detail pane, the episode
 *               scoreboard and the attack catalogue.
 * ==========================================================================*/
"use strict";

const $ = id => document.getElementById(id);
const esc = s => (s == null ? "" : String(s)).replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const cls = (el, c) => el.setAttribute("class", c);
const fmt = (x, d) => (x == null || isNaN(x)) ? "—" : Number(x).toFixed(d);
const clamp = (x, a, b) => Math.max(a, Math.min(b, x));

const UI = {
  cat: null, sel: null, cfg: {},
  samples: [], wire: [], lastS: 0, lastW: 0, lastSeq: 0,
  tele: {}, procs: [], episodes: [], mode: "none",
  capturing: false, recording: null, flags: {},
  logFilter: "", logSel: null, eventsById: {},
  paused: false, show: { flow: 1, charts: 1, safety: 1, pub: 1, ep: 1 },
  WIN: 120,
};

/* ---------------------------------------------------------------- menus */
function closeMenus() { document.querySelectorAll(".menu .m.open").forEach(m => m.classList.remove("open")); }
document.addEventListener("click", e => {
  const m = e.target.closest(".menu .m");
  if (m && !e.target.closest(".drop")) {
    const was = m.classList.contains("open"); closeMenus();
    if (!was) m.classList.add("open"); e.stopPropagation(); return;
  }
  const mi = e.target.closest(".mi");
  if (mi && mi.dataset.act) { menuAction(mi.dataset.act); closeMenus(); return; }
  if (!e.target.closest(".drop")) closeMenus();
});
document.querySelectorAll(".menu .m").forEach(m => m.addEventListener("mouseenter", () => {
  if (document.querySelector(".menu .m.open")) { closeMenus(); m.classList.add("open"); }
}));

function menuAction(a) {
  switch (a) {
    case "cap-on": toggleCapture(); break;
    case "cap-wireshark": run("t_wireshark"); break;
    case "rec-on": toggleRecord(); break;
    case "exp-samples": location.href = "/api/export.csv"; break;
    case "exp-episodes": location.href = "/api/episodes.csv"; break;
    case "clear": post("/api/clear", {}).then(() => { UI.samples = []; UI.wire = []; UI.lastS = 0; UI.lastW = 0; }); break;
    case "p-safety": setParam("safety_enabled"); break;
    case "p-net": setParam("net_enabled"); break;
    case "p-phy": setParam("phy_enabled"); break;
    case "launch-sel": if (UI.sel) run(UI.sel.id); break;
    case "stop-atk": post("/api/stop_all", { tools: false }); break;
    case "stop-all": post("/api/stop_all", { tools: true }); break;
    case "f-phys": $("filter").value = "physics"; renderCatalog(); break;
    case "f-net": $("filter").value = "network"; renderCatalog(); break;
    case "f-clear": $("filter").value = ""; renderCatalog(); break;
    case "v-flow": case "v-charts": case "v-safety": case "v-pub": case "v-ep":
      { const k = a.slice(2); UI.show[k] = !UI.show[k]; $("v-" + k).classList.toggle("hidden", !UI.show[k]);
        $("ck-" + a).textContent = UI.show[k] ? "✓" : ""; } break;
    case "v-pause": UI.paused = !UI.paused; $("ck-v-pause").textContent = UI.paused ? "✓" : ""; break;
    case "help-about": alert("Cross-Layer IDS Monitor\n\nAnalyst workstation for the ROS 2 cross-layer intrusion detection bench. The detector fuses a network layer (publisher identity + DDS discovery churn) and a physics layer (command-vs-motion residual + CUSUM). An inline safety filter turns detection into prevention by replacing a flagged command with the authorized one.\n\nResults here are SIMULATION; hardware is Phase 2."); break;
    case "help-run": alert("Demo / run\n\n1. ids demo gazebo      (bench; wait for 'IDS armed')\n2. ids console          (this dashboard, http://localhost:8088)\n\nFrom the dashboard: pick an attack on the left and Launch, or toggle the Safety filter in the toolbar. Capture > Start wire capture feeds the DDS traffic chart; Capture > Open Wireshark shows the packets.\n\nSafety on vs off: run the same attack with the Safety toggle on, then off, and compare 'Peak dev' in the episode scoreboard."); break;
    case "help-ablation": alert("Layer ablation\n\nTurn one detector layer off (Net layer / Phy layer) and launch an attack to show each layer's blind spot:\n  • discovery flood  → caught by NETWORK only\n  • node-name spoof   → caught by PHYSICS only\n  • both on           → fused, catches both\n\nThis is the core thesis: each layer catches attacks the other is blind to."); break;
  }
}

/* ---------------------------------------------------------------- api */
async function post(url, body) {
  try { return await (await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) })).json(); }
  catch (e) { return { ok: false, error: String(e) }; }
}
async function run(id) { const r = await post("/api/run", { id }); if (!r.ok && !r.dry_run) alert("Could not launch: " + (r.error || "unknown")); }
function setParam(name) { const cur = UI.tele[name] !== false; post("/api/param", { name, value: !cur }); }
function toggleCapture() { post("/api/capture", { on: !UI.capturing }); }
function toggleRecord() { post("/api/record", { on: !UI.recording }); }

/* ---------------------------------------------------------------- catalogue */
function atkHTML(a) {
  const ly = a.layer || "none";
  const flags = [];
  if (a.danger) flags.push('<span class="flag">sudo</span>');
  if (a.runs_on === "robot_host") flags.push('<span class="flag host">host</span>');
  if (a.needs) flags.push(`<span class="flag host">${esc(a.needs)}</span>`);
  return `<div class="atk ${ly}" data-id="${esc(a.id)}">
    <div class="edge"></div>
    <div class="b"><div class="t">${esc(a.label)}</div>
      <div class="meta"><span class="lchip ${ly}">${ly === "none" ? "passive" : ly}</span>${flags.join("")}</div></div>
    <div class="slot"></div></div>`;
}
function renderCatalog() {
  const q = ($("filter").value || "").toLowerCase().trim();
  const match = a => !q || [a.label, a.cat, a.layer, a.id, a.desc, a.method].some(x => (x || "").toLowerCase().includes(q));
  const groups = {}; let n = 0;
  UI.cat.attacks.filter(match).forEach(a => { (groups[a.cat] = groups[a.cat] || []).push(a); n++; });
  let html = "";
  for (const [c, list] of Object.entries(groups))
    html += `<div class="grp">${esc(c)}<span class="ct">${list.length}</span></div>` + list.map(atkHTML).join("");
  const tools = UI.cat.tools.filter(match);
  if (tools.length) html += `<div class="grp">Network tools<span class="ct">${tools.length}</span></div>` + tools.map(atkHTML).join("");
  $("catalog").innerHTML = html || '<div class="none-msg">no profiles match the filter</div>';
  $("atkcount").textContent = n;
  document.querySelectorAll(".atk").forEach(r => {
    r.addEventListener("click", () => pick(r.dataset.id));
    if (UI.sel && r.dataset.id === UI.sel.id) r.classList.add("sel");
  });
}
function pick(id) {
  UI.sel = [...UI.cat.attacks, ...UI.cat.tools].find(a => a.id === id); if (!UI.sel) return;
  document.querySelectorAll(".atk").forEach(r => r.classList.toggle("sel", r.dataset.id === id));
  const c = $("selcmd"), b = $("launch");
  c.textContent = UI.sel.cmd_resolved; c.classList.remove("empty");
  const liveIds = new Set(UI.procs.filter(p => p.running).map(p => p.id));
  if (liveIds.has(id)) { b.textContent = "Stop"; b.className = "go on stop"; b.disabled = false;
    b.onclick = () => { const p = UI.procs.find(x => x.id === id && x.running); if (p) post("/api/stop", { pid: p.pid }); }; }
  else { b.textContent = "Launch"; b.className = "go on"; b.disabled = false; b.onclick = () => run(id); }
}

/* ---------------------------------------------------------------- charts */
const CHARTS = [
  { id: "res", nm: "Consistency residual r vs ε", h: 54,
    series: [{ k: "r", c: "#9a5a00", lb: "r" }, { k: "eps", c: "#bf2f26", lb: "ε", dash: 1 }], auto: "res" },
  { id: "cus", nm: "CUSUM S vs τ", h: 54,
    series: [{ k: "S", c: "#6b45c4", lb: "S" }, { k: "tau", c: "#bf2f26", lb: "τ", dash: 1 }], max: 6 },
  { id: "cmd", nm: "Angular cmd: wire vs authorized", h: 54,
    series: [{ k: "ww", c: "#bf2f26", lb: "wire ω" }, { k: "aw", c: "#1b7a49", lb: "auth ω" }], sym: 1, pad: 0.3 },
  { id: "dev", nm: "Track deviation (true) & odom drift", h: 54,
    series: [{ k: "xte", c: "#1760c4", lb: "xte" }, { k: "derr", c: "#949cab", lb: "drift" }], sym: 1, pad: 0.1 },
  { id: "net", nm: "DDS traffic (wire capture)", h: 54, wire: 1,
    series: [{ k: "pkts", c: "#1760c4", lb: "pkts/s", ax: "l" }, { k: "sedp", c: "#bf2f26", lb: "sedp/s", ax: "r" }] },
];
const CV = {};
function buildCharts() {
  const box = $("charts"); box.innerHTML = "";
  CHARTS.forEach(ch => {
    const leg = ch.series.map(s => `<span><i style="background:${s.c}${s.dash ? ";border-top:1px dashed " + s.c + ";height:0" : ""}"></i>${s.lb} <b id="rd-${ch.id}-${s.k}">—</b></span>`).join("");
    const el = document.createElement("div"); el.className = "chart";
    el.innerHTML = `<div class="chh"><span class="nm">${ch.nm}</span><span class="leg">${leg}</span></div>
      <canvas id="cv-${ch.id}"></canvas>`;
    box.appendChild(el);
    const cv = $("cv-" + ch.id); CV[ch.id] = cv;
  });
  sizeCharts();
}
function sizeCharts() {
  const dpr = window.devicePixelRatio || 1;
  CHARTS.forEach(ch => {
    const cv = CV[ch.id]; if (!cv) return;
    const w = cv.clientWidth || cv.parentElement.clientWidth;
    cv.width = w * dpr; cv.height = ch.h * dpr; cv.style.height = ch.h + "px";
    const g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0);
  });
}
window.addEventListener("resize", () => { sizeCharts(); drawCharts(); });

function seriesExtent(ch, t0, t1) {
  let lo = Infinity, hi = -Infinity, any = false;
  const data = ch.wire ? UI.wire : UI.samples;
  for (const p of data) {
    if (p.ts < t0 || p.ts > t1) continue;
    for (const s of ch.series) {
      if (ch.id === "net" && s.ax === "r") continue;
      const v = p[s.k]; if (v == null || isNaN(v)) continue;
      any = true; lo = Math.min(lo, v); hi = Math.max(hi, v);
    }
  }
  if (!any) return [0, 1];
  if (ch.max != null) return [0, ch.max];
  if (ch.sym) { const m = Math.max(Math.abs(lo), Math.abs(hi), ch.pad || 0.1); return [-m * 1.15, m * 1.15]; }
  if (ch.auto === "res") { hi = Math.max(hi, (lastSample() || {}).eps * 3 || 0.03); }
  const pad = (hi - lo) * 0.12 || 0.01; return [Math.min(0, lo) - (ch.sym ? pad : 0), hi + pad];
}
function lastSample() { return UI.samples[UI.samples.length - 1]; }

function drawCharts() {
  if (!UI.samples.length && !UI.wire.length) return;
  const now = Date.now() / 1000;
  const t1 = UI.paused ? (lastSample() || { ts: now }).ts : now;
  const t0 = t1 - UI.WIN;
  CHARTS.forEach(ch => {
    const cv = CV[ch.id], g = cv.getContext("2d");
    const W = cv.clientWidth, H = ch.h;
    g.clearRect(0, 0, W, H);
    const data = ch.wire ? UI.wire : UI.samples;
    const [lo, hi] = seriesExtent(ch, t0, t1);
    const X = t => clamp((t - t0) / UI.WIN, 0, 1) * (W - 2) + 1;
    const Y = v => H - 4 - clamp((v - lo) / (hi - lo || 1), 0, 1) * (H - 8);
    // zero line for symmetric charts
    g.strokeStyle = "#e7e9ed"; g.lineWidth = 1;
    if (ch.sym) { g.beginPath(); g.moveTo(0, Y(0)); g.lineTo(W, Y(0)); g.stroke(); }
    // attack shading from samples
    shadeAttacks(g, X, H, t0, t1);
    // right axis (net sedp) scaled independently
    let rhi = 1;
    if (ch.id === "net") { for (const p of UI.wire) if (p.ts >= t0) rhi = Math.max(rhi, p.sedp); }
    ch.series.forEach(s => {
      g.beginPath(); g.lineWidth = s.dash ? 1.2 : 1.4; g.strokeStyle = s.c;
      if (s.dash) g.setLineDash([4, 3]); else g.setLineDash([]);
      let started = false, last = null;
      for (const p of data) {
        if (p.ts < t0 - 1 || p.ts > t1 + 1) continue;
        let v = p[s.k]; if (v == null || isNaN(v)) { started = false; continue; }
        const yv = (ch.id === "net" && s.ax === "r") ? Y(lo + (v / rhi) * (hi - lo)) : Y(v);
        const x = X(p.ts);
        if (!started) { g.moveTo(x, yv); started = true; } else g.lineTo(x, yv);
        last = v;
      }
      g.stroke(); g.setLineDash([]);
      const rd = $(`rd-${ch.id}-${s.k}`);
      if (rd) rd.textContent = last == null ? "—" : (Math.abs(last) >= 100 ? last.toFixed(0) : last.toFixed(s.k === "eps" || s.k === "r" ? 4 : 2));
    });
  });
}
function shadeAttacks(g, X, H, t0, t1) {
  let runStart = null, prev = 0;
  for (const p of UI.samples) {
    if (p.atk && !prev) runStart = p.ts;
    if (!p.atk && prev && runStart != null) { band(g, X, H, runStart, p.ts); runStart = null; }
    prev = p.atk;
  }
  if (prev && runStart != null) band(g, X, H, runStart, t1);
  // detection marks
  g.strokeStyle = "#bf2f2655"; g.lineWidth = 1;
  let pa = 0;
  for (const p of UI.samples) { if (p.alarm && !pa) { g.beginPath(); const x = X(p.ts); g.moveTo(x, 0); g.lineTo(x, H); g.stroke(); } pa = p.alarm; }
}
function band(g, X, H, a, b) { g.fillStyle = "#bf2f260e"; const xa = X(a), xb = X(b); g.fillRect(xa, 0, Math.max(1, xb - xa), H); }

/* ---------------------------------------------------------------- poll + render */
async function tick() {
  let s;
  try { s = await (await fetch(`/api/state?s=${UI.lastS}&w=${UI.lastW}&e=${UI.lastSeq}`)).json(); }
  catch (e) { cls($("armpill"), "pill"); $("armtext").textContent = "no server"; return; }
  // merge incremental
  if (s.samples && s.samples.length) { UI.samples.push(...s.samples); UI.lastS = s.samples[s.samples.length - 1].ts; }
  if (s.wire && s.wire.length) { UI.wire.push(...s.wire); UI.lastW = s.wire[s.wire.length - 1].ts; }
  const cut = (lastSample() ? lastSample().ts : Date.now() / 1000) - 620;
  while (UI.samples.length && UI.samples[0].ts < cut) UI.samples.shift();
  while (UI.wire.length && UI.wire[0].ts < cut) UI.wire.shift();
  if (s.events && s.events.length) { s.events.forEach(e => UI.eventsById[e.seq] = e); UI.lastSeq = s.events[s.events.length - 1].seq; }
  UI.tele = s.tele || {}; UI.procs = s.procs || []; UI.episodes = s.episodes || [];
  UI.mode = s.mode; UI.capturing = s.capturing; UI.recording = s.recording; UI.flags = s.flags || {};
  UI.teleAge = s.tele_age;
  render(s);
  drawCharts();
}

function render(s) {
  const t = UI.tele, has = Object.keys(t).length > 0;
  const stale = UI.teleAge == null || UI.teleAge > 5;
  const cal = has && t.calibrating, armed = has && t.armed, alarm = has && !!t.alarm;
  const netEn = has ? t.net_enabled !== false : true;
  const phyEn = has ? t.phy_enabled !== false : true;
  const safeEn = has ? t.safety_enabled !== false : true;
  const engaged = has && !!t.safety_engaged;

  // arm pill
  const ap = $("armpill");
  if (!has || stale) { cls(ap, "pill"); $("armtext").textContent = has ? "signal lost" : "waiting for detector"; }
  else if (cal) { cls(ap, "pill cal"); $("armtext").textContent = "Calibrating " + fmt(t.calib_remaining, 0) + "s"; }
  else if (alarm) { cls(ap, "pill alarm"); $("armtext").textContent = "Intrusion"; }
  else if (armed) { cls(ap, "pill armed"); $("armtext").textContent = "Armed"; }
  else { cls(ap, "pill"); $("armtext").textContent = "Idle"; }

  // toggles
  [["tgl-safety", safeEn, "safety_enabled"], ["tgl-net", netEn, "net_enabled"], ["tgl-phy", phyEn, "phy_enabled"]]
    .forEach(([id, on, k]) => { const el = $(id); el.classList.toggle("on", on);
      el.classList.toggle("danger", id === "tgl-safety" && !on); });
  $("tgl-safety").classList.toggle("danger", !safeEn);
  $("tgl-safety2").classList.toggle("on", safeEn);
  $("ck-safety").textContent = safeEn ? "✓" : "";
  $("ck-net").textContent = netEn ? "✓" : "";
  $("ck-phy").textContent = phyEn ? "✓" : "";
  $("safe2lb").textContent = "Safety filter " + (safeEn ? "ON" : "OFF");

  // flow
  cls($("n-net"), "nd " + (!netEn ? "dim" : (t.net_fired ? "neton" : "")));
  cls($("n-phy"), "nd " + (!phyEn ? "dim" : (t.phy_fired ? "phyon" : "")));
  cls($("n-fuse"), "nd " + (cal ? "cal" : (alarm ? "alarm" : "ok")));
  cls($("n-wire"), "nd " + (t.net_fired ? "neton" : ""));
  let ss = "nd", sub = "pass-through";
  if (alarm && safeEn) { ss = "nd alarm"; sub = "blocking"; }
  else if (alarm && !safeEn) { ss = "nd cal"; sub = "bypassed"; }
  else if (armed) { ss = "nd ok"; }
  cls($("n-safe"), ss); $("safe-sub").textContent = sub;

  // safety panel
  const sp = $("safety");
  sp.className = "safety" + (engaged && safeEn ? " engaged" : (engaged && !safeEn ? " bypass" : ""));
  $("safe-st").textContent = engaged ? (safeEn ? "ENGAGED" : "BYPASSED") : "CLEAR";
  $("safe-mode").textContent = engaged ? (safeEn ? "intrusion blocked" : "filter disabled") : "forwarding wire";
  $("safe-drv").textContent = (engaged && safeEn) ? "authorized command" : "wire (cmd_vel_raw)";
  $("safe-en").textContent = safeEn ? "yes" : "no (ablation)";
  if (has && engaged) $("safe-rel").textContent = `${fmt(t.safety_quiet, 1)} / ${fmt(t.release_s, 1)} s`;
  else $("safe-rel").textContent = "—";

  // publishers
  if (has && Array.isArray(t.publishers)) {
    const allow = new Set(t.allowlist || []);
    $("pubs").innerHTML = t.publishers.length ? t.publishers.map(n => {
      const ok = allow.has(n);
      return `<div class="pub ${ok ? "ok" : "rogue"}"><span class="dot"></span><span class="nm">${esc(n)}</span>
        <span class="tag">${ok ? "allowlisted" : "rogue"}</span></div>`;
    }).join("") : '<div class="none-msg">no publishers seen</div>';
  }

  // episodes
  renderEpisodes();

  // catalogue live marks + selected-row button
  const live = new Set(UI.procs.filter(p => p.running).map(p => p.id));
  document.querySelectorAll(".atk").forEach(el => {
    const on = live.has(el.dataset.id); el.classList.toggle("live", on);
    const slot = el.querySelector(".slot"); if (slot) slot.innerHTML = on ? '<span class="runled"></span>' : "";
  });
  if (UI.sel) pickButtonState(UI.sel.id, live);

  // processes
  const running = UI.procs.filter(p => p.running);
  $("runct").textContent = running.length; $("sb-run").textContent = running.length;
  $("stopall").disabled = running.length === 0;
  $("procs").innerHTML = running.length ? running.map(p =>
    `<div class="proc"><span class="age">${p.secs}s</span>
     <span class="nm" title="${esc(p.cmd)}">${esc(p.label)}</span>
     <button class="k" onclick="post('/api/stop',{pid:${p.pid}})">Stop</button></div>`).join("")
    : '<div class="none-msg">no processes running</div>';

  // capture/record indicators
  $("recbtn").classList.toggle("on", !!UI.recording);
  $("recbtn").textContent = UI.recording ? "● Recording" : "Record";
  $("ck-rec").textContent = UI.recording ? "✓" : "";
  $("ck-cap").textContent = UI.capturing ? "✓" : "";
  $("sb-cap").innerHTML = UI.capturing ? '<span class="on">● capture</span>' : '<span class="dotlink" onclick="toggleCapture()">start capture</span>';
  $("sb-rec").innerHTML = UI.recording ? '<span class="hot">● rec</span>' : "";
  const fb = $("flagbadge");
  if (UI.flags.demo) { fb.classList.remove("hidden"); fb.textContent = "DEMO FEED"; }
  else if (UI.flags.dry_run) { fb.classList.remove("hidden"); fb.textContent = "DRY RUN"; }
  else fb.classList.add("hidden");

  renderLog();

  // status bar
  const sbs = $("sb-state");
  sbs.innerHTML = stale ? "<b>—</b>" : cal ? '<b class="warn">CALIBRATING</b>' :
    alarm ? '<b class="hot">INTRUSION</b>' : armed ? '<b class="on">CLEAR</b>' : "<b>IDLE</b>";
  if (has) { $("sb-eps").textContent = fmt(t.eps, 4); $("sb-res").textContent = fmt(t.residual, 4);
    $("sb-cus").textContent = `${fmt(t.cusum, 2)}/${fmt(t.cusum_tau, 1)}`; }
  $("sb-safe").innerHTML = (engaged && safeEn) ? '<b class="hot">ENGAGED</b>' :
    (engaged && !safeEn ? '<b class="warn">BYPASSED</b>' : '<b class="on">clear</b>');
  const lay = []; if (t.net_fired) lay.push("NET"); if (t.phy_fired) lay.push("PHY");
  $("sb-layers").innerHTML = lay.length ? "<b>" + lay.join("+") + "</b>" : "—";
  $("sb-drift").textContent = s.derr != null ? fmt(s.derr, 3) + " m" : "—";
}

function pickButtonState(id, live) {
  const b = $("launch"); if (!UI.sel || UI.sel.id !== id) return;
  if (live.has(id)) { b.textContent = "Stop"; b.className = "go on stop";
    b.onclick = () => { const p = UI.procs.find(x => x.id === id && x.running); if (p) post("/api/stop", { pid: p.pid }); }; }
  else { b.textContent = "Launch"; b.className = "go on"; b.onclick = () => run(id); }
}

function renderEpisodes() {
  const tb = $("eptb"); $("ep-ct").textContent = UI.episodes.length;
  if (!UI.episodes.length) { tb.innerHTML = '<tr><td colspan="7" class="none-msg" style="font-family:var(--sans)">no episodes yet — launch an attack</td></tr>'; return; }
  tb.innerHTML = UI.episodes.slice().reverse().map(e => {
    const safe = e.safety ? '<span class="tag2 on">on</span>' : '<span class="tag2 off">off</span>';
    const det = e.detected ? (e.latency === 0 ? "&lt;0.05s" : fmt(e.latency, 2) + "s") : '<span class="tag2 no">missed</span>';
    const blk = e.detected ? (e.blocked ? '<span class="tag2 blk">blocked</span>' : '<span class="tag2 no">not blk</span>') : "";
    return `<tr><td>${e.n}</td><td class="lbl" title="${esc(e.attack)}">${esc(e.attack)}</td>
      <td>${safe}</td><td>${det} ${blk}</td><td>${esc(e.layer || "—")}</td>
      <td>${fmt(e.peak, 3)} m</td><td>${e.recovery != null ? fmt(e.recovery, 2) + "s" : "—"}</td></tr>`;
  }).join("");
}

/* ---------------------------------------------------------------- event log */
const SEV_CLASS = { alert: "alert", warn: "warn", ok: "ok", info: "", sys: "sys" };
function renderLog() {
  const q = UI.logFilter;
  const evs = Object.values(UI.eventsById).sort((a, b) => a.seq - b.seq).slice(-400)
    .filter(e => !q || [e.src, e.msg, e.layer, e.sev].some(x => (x || "").toLowerCase().includes(q)));
  const rows = evs.slice(-160);
  const log = $("log");
  const atBottom = log.parentElement.scrollTop + log.parentElement.clientHeight >= log.parentElement.scrollHeight - 40;
  log.innerHTML = rows.map(e => {
    let rc = SEV_CLASS[e.sev] || "";
    if (e.layer === "NET" && e.sev !== "alert") rc = "net";
    if (e.layer === "PHY" && e.sev !== "alert") rc = "phy";
    const tm = new Date(e.ts * 1000).toTimeString().slice(0, 8);
    const selc = UI.logSel === e.seq ? " sel" : "";
    return `<tr class="${rc}${selc}" data-seq="${e.seq}"><td>${tm}</td><td>${esc(e.src)}</td><td>${esc(e.layer || "")}</td><td title="${esc(e.msg)}">${esc(e.msg)}</td></tr>`;
  }).join("");
  log.querySelectorAll("tr").forEach(tr => tr.addEventListener("click", () => showDetail(+tr.dataset.seq)));
  if (atBottom && !UI.logSel) log.parentElement.scrollTop = log.parentElement.scrollHeight;
}
function showDetail(seq) {
  UI.logSel = UI.logSel === seq ? null : seq;
  const d = $("detail");
  if (!UI.logSel) { d.classList.add("hidden"); renderLog(); return; }
  const e = UI.eventsById[seq]; if (!e) return;
  d.classList.remove("hidden");
  d.innerHTML = `<div class="dh">${new Date(e.ts * 1000).toTimeString().slice(0, 8)} · ${esc(e.src)}${e.layer ? " · " + e.layer : ""} · ${e.sev}</div>${esc(e.msg)}${e.detail ? "\n\n" + esc(e.detail) : ""}`;
  renderLog();
}

/* ---------------------------------------------------------------- toggles wiring */
document.querySelectorAll(".tgl[data-p]").forEach(el => el.addEventListener("click", () => setParam(el.dataset.p)));
$("stopall").addEventListener("click", () => post("/api/stop_all", { tools: true }));
$("recbtn").addEventListener("click", toggleRecord);
$("filter").addEventListener("input", renderCatalog);
$("logfilter").addEventListener("input", e => { UI.logFilter = e.target.value.toLowerCase().trim(); renderLog(); });
$("logclear").addEventListener("click", () => { UI.eventsById = {}; UI.logSel = null; $("detail").classList.add("hidden"); renderLog(); });
document.addEventListener("keydown", e => {
  if (e.target.tagName === "INPUT") return;
  if (e.key === "Enter" && UI.sel) run(UI.sel.id);
});

/* ---------------------------------------------------------------- boot */
async function boot() {
  try { UI.cat = await (await fetch("/api/catalog")).json(); }
  catch (e) { $("armtext").textContent = "no server"; return; }
  UI.cfg = UI.cat.config || {}; UI.flags = UI.cat.flags || {};
  $("sb-dom").textContent = UI.cfg.domain || "42";
  $("pub-topic").textContent = UI.cfg.cmd_topic || "/cmd_vel_raw";
  $("env").innerHTML = [["Domain", UI.cfg.domain || "42"], ["RMW", "Fast DDS"], ["Transport", "UDP"],
    ["Robot", UI.cfg.robot_ip || "—"], ["Iface", UI.cfg.iface || "—"]]
    .map(([k, v]) => `<div class="c"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join("");
  renderCatalog(); buildCharts();
  tick(); setInterval(tick, 500);
}
boot();
