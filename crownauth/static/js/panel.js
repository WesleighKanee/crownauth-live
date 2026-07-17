/* Owner console — authenticated live control */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const state = {
  session: localStorage.getItem("oc_session") || "",
  settings: {},
  licenses: [],
  plans: [],
  sessions: [],
  minted: [],
  mintedFull: [],
  view: "dash",
  authed: false,
};

function downloadText(filename, text, mime = "text/plain") {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 500);
}

async function downloadCsvExport() {
  const q = encodeURIComponent($("#keySearch")?.value || "");
  const st = encodeURIComponent($("#keyStatus")?.value || "");
  const headers = {};
  if (state.session) headers["Authorization"] = "Bearer " + state.session;
  const res = await fetch(`/api/licenses/export.csv?q=${q}&status=${st}`, {
    headers,
    credentials: "same-origin",
  });
  if (res.status === 401) {
    logout(false);
    throw new Error("Session expired — sign in again");
  }
  if (!res.ok) throw new Error("Export failed");
  const text = await res.text();
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  downloadText(`whitecrown_licenses_${stamp}.csv`, text, "text/csv;charset=utf-8");
  toast("CSV downloaded");
}

async function api(path, opts = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (state.session) headers["Authorization"] = "Bearer " + state.session;
  const res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    logout(false);
    throw new Error("Session expired — sign in again");
  }
  if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
  return data;
}

function toast(msg, bad = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.style.borderColor = bad ? "rgba(243,18,96,.5)" : "rgba(61,214,140,.35)";
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2800);
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function shortKey(k) {
  if (!k) return "—";
  if (k.length < 22) return k;
  return k.slice(0, 14) + "…" + k.slice(-8);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function showApp(on) {
  state.authed = on;
  const login = $("#loginScreen");
  const app = $("#appRoot");
  if (login) {
    login.classList.toggle("hidden", on);
    // never leave password field non-interactive
    const pw = $("#loginPw");
    const btn = $("#btnLogin");
    if (pw) {
      pw.classList.remove("hidden");
      pw.disabled = false;
      pw.readOnly = false;
      pw.style.pointerEvents = "auto";
    }
    if (btn) {
      btn.classList.remove("hidden");
      btn.disabled = false;
    }
  }
  if (app) app.classList.toggle("hidden", !on);
  if (!on) {
    // focus password so user can type immediately
    setTimeout(() => {
      const pw = $("#loginPw");
      if (pw && !login.classList.contains("hidden")) {
        try {
          pw.focus({ preventScroll: false });
        } catch (_) {
          pw.focus();
        }
      }
    }, 50);
  }
}

function logout(call = true) {
  state.session = "";
  localStorage.removeItem("oc_session");
  if (call) fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  showApp(false);
}

async function trySession() {
  try {
    const st = await fetch("/auth/status", { credentials: "same-origin" }).then((r) => r.json());
    const title = $("#loginTitle");
    const sub = $("#loginSub");
    if (title) title.textContent = "Sign in";
    if (sub) sub.textContent = (st.app_name || "WhiteCrown") + " owner panel";
    if ($("#brandName")) $("#brandName").textContent = (st.app_name || "WHITECROWN").toUpperCase().slice(0, 14);

    // No password mode: open straight in
    if (!st.password_required) {
      if ($("#btnLogout")) $("#btnLogout").classList.add("hidden");
      showApp(true);
      setView("dash");
      return;
    }

    if ($("#btnLogout")) $("#btnLogout").classList.remove("hidden");

    // Network blocked (only if allowlist still on)
    if (st.ip_allowed === false) {
      showApp(false);
      if (title) title.textContent = "Access blocked";
      if ($("#loginErr")) {
        $("#loginErr").textContent = "This network is not allowed. Turn off IP allowlist or use local PC.";
        $("#loginErr").classList.remove("hidden");
      }
      return;
    }

    // Already signed in?
    if (st.authed || state.session) {
      try {
        if (state.session) await api("/api/dashboard");
        showApp(true);
        setView("dash");
        return;
      } catch (_) {
        // bad/expired session — fall through to login form
        state.session = "";
        localStorage.removeItem("oc_session");
      }
    }
  } catch (_) {
    /* show login form */
  }
  showApp(false);
}

function setView(name) {
  state.view = name;
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${name}`)?.classList.remove("hidden");
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const titles = {
    dash: ["Home", "Fleet overview & emergency controls"],
    keys: ["Licenses", "Ban, extend, reset devices — live timers"],
    mint: ["Create keys", "Issue keys for buyers"],
    sessions: ["Online now", "Live sessions (also shown on Licenses)"],
    plans: ["Plans", "Templates for minting"],
    security: ["Live controls", "Policy that applies without rebuild"],
    blacklist: ["Blocks", "Device / IP deny list"],
    audit: ["Activity", "What you and the server did"],
    resellers: ["Resellers", "Limited accounts that only mint keys"],
    brand: ["Settings", "Brand + deploy host for APK"],
  };
  const t = titles[name] || [name, ""];
  if ($("#viewTitle")) $("#viewTitle").textContent = t[0];
  if ($("#viewSub")) $("#viewSub").textContent = t[1];
  if ($("#mobileTitle")) $("#mobileTitle").textContent = t[0];
  closeMobileNav();
  refreshView();
}

function openMobileNav() {
  const app = $("#appRoot");
  const scrim = $("#navScrim");
  if (app) app.classList.add("nav-open");
  if (scrim) scrim.hidden = false;
}

function closeMobileNav() {
  const app = $("#appRoot");
  const scrim = $("#navScrim");
  if (app) app.classList.remove("nav-open");
  if (scrim) scrim.hidden = true;
}

async function refreshDash() {
  const d = await api("/api/dashboard");
  state.settings = d.settings || {};
  const s = d.stats || {};
  $("#statGrid").innerHTML = [
    ["Active keys", s.licenses_active, "good"],
    ["Online now", s.sessions_live, "live"],
    ["Devices", s.devices, ""],
    ["Banned", s.licenses_banned, "bad"],
  ]
    .map(
      ([label, val, tone]) =>
        `<div class="card stat-card ${tone}"><div class="stat-val">${val ?? 0}</div><div class="stat-label">${label}</div></div>`
    )
    .join("");
  $("#pillApp").textContent = state.settings.app_name || "App";
  const mode = state.settings.kill_switch ? "KILL" : state.settings.maintenance ? "MAINT" : state.settings.force_online ? "ONLINE" : "HYBRID";
  $("#pillMode").textContent = mode;
  $("#pillMode").className = "pill" + (state.settings.kill_switch ? " bad" : "");
  const host = state.settings.client_api_host || "127.0.0.1";
  const warn = host === "127.0.0.1" || host === "localhost";
  $("#posture").innerHTML = [
    `require online: <b style="color:var(--text)">${!!state.settings.force_online}</b>`,
    `stealth: <b style="color:var(--text)">${!!state.settings.stealth_mode}</b>`,
    `session TTL: <b style="color:var(--text)">${state.settings.session_ttl_sec}s</b>`,
    `heartbeat: <b style="color:var(--text)">${state.settings.heartbeat_sec}s</b>`,
    `client host: <b style="color:${warn ? "var(--bad)" : "var(--good)"}">${esc(host)}</b>${warn ? " ← phones cannot use this" : ""}`,
    `kill: <b style="color:${state.settings.kill_switch ? "var(--bad)" : "var(--good)"}">${!!state.settings.kill_switch}</b>`,
  ].join("<br/>");
}

function formatCountdownLocal(rem) {
  rem = Math.max(0, Math.floor(Number(rem) || 0));
  const d = Math.floor(rem / 86400);
  rem %= 86400;
  const h = Math.floor(rem / 3600);
  rem %= 3600;
  const m = Math.floor(rem / 60);
  const s = rem % 60;
  const pad = (n) => String(n).padStart(2, "0");
  if (d > 0) return `${d}d ${pad(h)}:${pad(m)}:${pad(s)}`;
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

function urgencyClass(rem) {
  rem = Number(rem) || 0;
  if (rem <= 0) return "critical";
  if (rem <= 300) return "critical"; // ≤5 min
  if (rem <= 3600) return "urgent"; // ≤1 hour
  return "";
}

function timerCellHtml(L) {
  const st = L.timer_state || "unknown";
  const exp = Number(L.expires_at || 0);
  const rem = Number(L.remaining_seconds);
  const sn = Number(L.server_now || Math.floor(Date.now() / 1000));
  if (st === "live" && exp > 0) {
    const urg = urgencyClass(rem);
    return `<span class="countdown live mono ${urg}" data-exp="${exp}" data-sn="${sn}" data-state="live">${esc(
      L.countdown || formatCountdownLocal(rem)
    )}</span>`;
  }
  if (st === "pending") {
    return `<span class="countdown pending" data-state="pending">${esc(L.countdown || "first use")}</span>`;
  }
  if (st === "lifetime") {
    return `<span class="countdown life" data-state="lifetime">lifetime</span>`;
  }
  if (st === "expired") {
    return `<span class="countdown expired" data-state="expired">expired</span>`;
  }
  if (st === "banned") {
    return `<span class="countdown banned" data-state="banned">banned</span>`;
  }
  return `<span class="countdown">${esc(L.countdown || "—")}</span>`;
}

function tickCountdowns() {
  const now = Math.floor(Date.now() / 1000);
  $$("#keyBody .countdown.live").forEach((el) => {
    const exp = Number(el.dataset.exp || 0);
    const sn = Number(el.dataset.sn || now);
    const drift = now - sn;
    const rem = exp - (sn + drift);
    el.classList.remove("urgent", "critical");
    if (rem <= 0) {
      el.textContent = "expired";
      el.classList.remove("live");
      el.classList.add("expired");
      el.dataset.state = "expired";
    } else {
      el.textContent = formatCountdownLocal(rem);
      const urg = urgencyClass(rem);
      if (urg) el.classList.add(urg);
    }
  });
}

async function refreshKeys() {
  const q = encodeURIComponent($("#keySearch").value || "");
  const st = encodeURIComponent($("#keyStatus").value || "");
  const d = await api(`/api/licenses?q=${q}&status=${st}`);
  state.licenses = d.items || [];
  const body = $("#keyBody");
  body.innerHTML = "";
  for (const L of state.licenses) {
    const tr = document.createElement("tr");
    const tier = L.tier || "std";
    tr.dataset.id = L.id;
    const online = !!L.online;
    const onlineHtml = online
      ? `<span class="tag online" title="IP ${esc(L.online_ip || "")} · device ${esc(L.online_hwid || "")}">● online${
          L.online_count > 1 ? " ×" + L.online_count : ""
        }</span><div style="color:var(--muted);font-size:10px;margin-top:4px">${esc(L.online_ip || "")}</div>`
      : `<span class="tag offline">offline</span>`;
    tr.innerHTML = `
      <td data-label="ID">${L.id}</td>
      <td data-label="Customer">${esc(L.customer || "—")}<div style="color:var(--muted);font-size:11px">${esc(L.note || "")}</div></td>
      <td class="mono" data-label="Key" title="${esc(L.token)}">${esc(shortKey(L.token))}</td>
      <td data-label="Online">${onlineHtml}</td>
      <td data-label="Tier"><span class="tag ${tier}">${tier}</span></td>
      <td data-label="Status"><span class="tag ${L.status}">${L.status}</span></td>
      <td data-label="Devices">${L.max_devices}</td>
      <td data-label="Package">${esc(L.duration_label || "—")}</td>
      <td class="timer-cell" data-label="Timer">${timerCellHtml(L)}</td>
      <td class="actions" data-label="Actions"></td>`;
    const act = tr.querySelector(".actions");
    act.append(
      btn("Copy", async () => {
        await navigator.clipboard.writeText(L.token);
        toast("Copied");
      })
    );
    if (online && L.online_jti) {
      act.append(
        btn("Kick", async () => {
          await api("/api/sessions/kick", { method: "POST", body: JSON.stringify({ jti: L.online_jti }) });
          toast("Kicked session");
          refreshKeys();
        }, true)
      );
    }
    act.append(
      btn(L.status === "banned" ? "Unban" : "Ban", async () => {
        if (L.status === "banned") await api("/api/licenses/unban", { method: "POST", body: JSON.stringify({ id: L.id }) });
        else {
          const reason = prompt("Ban reason", "leaked") || "";
          await api("/api/licenses/ban", { method: "POST", body: JSON.stringify({ id: L.id, reason }) });
        }
        toast("Updated");
        refreshKeys();
      }, L.status !== "banned"),
      btn("+30m", async () => {
        await api("/api/licenses/extend", { method: "POST", body: JSON.stringify({ id: L.id, duration_custom: "30:00" }) });
        toast("+30 min");
        refreshKeys();
      }),
      btn("+1h", async () => {
        await api("/api/licenses/extend", { method: "POST", body: JSON.stringify({ id: L.id, duration_value: 1, duration_unit: "hours" }) });
        toast("+1 hour");
        refreshKeys();
      }),
      btn("+1d", async () => {
        await api("/api/licenses/extend", { method: "POST", body: JSON.stringify({ id: L.id, duration_value: 1, duration_unit: "days" }) });
        toast("+1 day");
        refreshKeys();
      }),
      btn("+7d", async () => {
        await api("/api/licenses/extend", { method: "POST", body: JSON.stringify({ id: L.id, days: 7 }) });
        toast("+7 days");
        refreshKeys();
      }),
      btn("Reset devices", async () => {
        await api("/api/licenses/hwid_reset", { method: "POST", body: JSON.stringify({ id: L.id }) });
        toast("Devices cleared");
      }),
      btn("Delete", async () => {
        if (!confirm("Delete this license forever?")) return;
        await api("/api/licenses/delete", { method: "POST", body: JSON.stringify({ id: L.id }) });
        refreshKeys();
      }, true)
    );
    body.appendChild(tr);
  }
  tickCountdowns();
}

function btn(label, fn, danger = false) {
  const b = document.createElement("button");
  b.className = "btn" + (danger ? " danger" : "");
  b.textContent = label;
  b.onclick = () => fn().catch((e) => toast(e.message, true));
  return b;
}

function planSeconds(p) {
  if (p.duration_seconds > 0) return Number(p.duration_seconds);
  if (p.duration_days > 0) return Number(p.duration_days) * 86400;
  return 0;
}

function humanDur(sec) {
  sec = Number(sec) || 0;
  if (sec <= 0) return "Lifetime";
  if (sec < 3600) return Math.max(1, Math.round(sec / 60)) + " min";
  if (sec < 86400) {
    const h = sec / 3600;
    return (h === Math.floor(h) ? h : h.toFixed(1)) + "h";
  }
  const d = sec / 86400;
  if (d < 7) return (d === Math.floor(d) ? d : d.toFixed(1)) + "d";
  if (d < 30) return (d / 7).toFixed(d % 7 === 0 ? 0 : 1) + "w";
  return (d / 30).toFixed(1) + "mo";
}

async function refreshPlans() {
  const d = await api("/api/plans");
  state.plans = d.items || [];
  $("#planBody").innerHTML = state.plans
    .map((p) => {
      const sec = planSeconds(p);
      return `<tr style="cursor:pointer" data-id="${p.id}">
        <td>${esc(p.name)}</td>
        <td>${esc(p.duration_human || humanDur(sec))}</td>
        <td>${p.max_devices}</td>
        <td><span class="tag ${p.tier}">${p.tier}</span></td>
        <td>${esc(p.price_note || "—")}</td>
        <td>${p.active ? "yes" : "no"}</td></tr>`;
    })
    .join("");
  $$("#planBody tr").forEach((tr) => {
    tr.onclick = () => {
      const p = state.plans.find((x) => x.id == tr.dataset.id);
      if (!p) return;
      $("#planId").value = p.id;
      $("#planName").value = p.name;
      const sec = planSeconds(p);
      if (sec <= 0) {
        $("#planDurVal").value = 0;
        $("#planDurUnit").value = "lifetime";
      } else if (sec < 3600) {
        $("#planDurVal").value = Math.round(sec / 60);
        $("#planDurUnit").value = "minutes";
      } else if (sec < 86400) {
        $("#planDurVal").value = Math.round(sec / 3600);
        $("#planDurUnit").value = "hours";
      } else if (sec % (7 * 86400) === 0) {
        $("#planDurVal").value = sec / (7 * 86400);
        $("#planDurUnit").value = "weeks";
      } else {
        $("#planDurVal").value = Math.round(sec / 86400);
        $("#planDurUnit").value = "days";
      }
      $("#planDevs").value = p.max_devices;
      $("#planTier").value = p.tier;
      $("#planPrice").value = p.price_note || "";
    };
  });
  const sel = $("#mintPlan");
  const cur = sel.value;
  sel.innerHTML =
    `<option value="custom">— none —</option>` +
    state.plans
      .filter((p) => p.active)
      .map((p) => {
        const sec = planSeconds(p);
        return `<option value="${p.id}">${esc(p.name)} (${esc(p.duration_human || humanDur(sec))})</option>`;
      })
      .join("");
  if (cur) sel.value = cur;
  updateMintPreview();
}

function applyPlanToMint() {
  const id = $("#mintPlan").value;
  if (!id || id === "custom") {
    updateMintPreview();
    return;
  }
  const p = state.plans.find((x) => String(x.id) === String(id));
  if (!p) return;
  const sec = planSeconds(p);
  if (sec <= 0) {
    $("#mintDurVal").value = 0;
    $("#mintDurUnit").value = "lifetime";
  } else if (sec < 3600) {
    $("#mintDurVal").value = Math.round(sec / 60);
    $("#mintDurUnit").value = "minutes";
  } else if (sec < 86400) {
    $("#mintDurVal").value = Math.round(sec / 3600);
    $("#mintDurUnit").value = "hours";
  } else {
    $("#mintDurVal").value = Math.round(sec / 86400);
    $("#mintDurUnit").value = "days";
  }
  $("#mintTier").value = p.tier || "std";
  $("#mintDevs").value = p.max_devices || 1;
  updateMintPreview();
}

function parseCustomDurationClient(raw) {
  if (!raw) return null;
  let s = String(raw).trim().toLowerCase().replace(/\s+/g, "");
  if (!s) return null;
  if (["lifetime", "life", "forever", "0", "unlimited"].includes(s)) return 0;
  const suf = s.match(/^(\d+(?:\.\d+)?)(s|sec|m|min|mins|h|hr|hrs|d|day|days|w|week|weeks)$/);
  if (suf) {
    const n = parseFloat(suf[1]);
    const u = suf[2];
    if (u.startsWith("s")) return Math.round(n);
    if (u.startsWith("m") && !u.startsWith("mo")) return Math.round(n * 60);
    if (u.startsWith("h")) return Math.round(n * 3600);
    if (u.startsWith("d")) return Math.round(n * 86400);
    if (u.startsWith("w")) return Math.round(n * 7 * 86400);
  }
  if (s.includes(":")) {
    const parts = s.split(":").map((x) => parseInt(x, 10));
    if (parts.some((x) => Number.isNaN(x) || x < 0)) return null;
    if (parts.length === 2) {
      // MM:SS  e.g. 30:00 = 30 minutes
      const [a, b] = parts;
      if (b >= 60) return null;
      return a * 60 + b;
    }
    if (parts.length === 3) {
      const [h, m, sec] = parts;
      if (m >= 60 || sec >= 60) return null;
      return h * 3600 + m * 60 + sec;
    }
  }
  return null;
}

function updateMintPreview() {
  const custom = ($("#mintCustom") && $("#mintCustom").value.trim()) || "";
  const unit = $("#mintDurUnit").value;
  const val = Number($("#mintDurVal").value || 0);
  let label = "Lifetime";
  if (custom) {
    const sec = parseCustomDurationClient(custom);
    label = sec === null ? `invalid (${custom})` : sec === 0 ? "Lifetime" : humanDur(sec) + ` [${custom}]`;
  } else if (unit !== "lifetime" && val > 0) {
    label = val + " " + unit;
  }
  const tier = $("#mintTier").value;
  const devs = $("#mintDevs").value || 1;
  const start = $("#mintStart").value === "immediate" ? "starts now" : "starts on first login";
  const qty = $("#mintQty").value || 1;
  if ($("#mintPreview")) {
    $("#mintPreview").textContent = `Preview: ${qty}× ${label} · ${tier} · ${devs} device(s) · ${start}`;
  }
}

async function refreshSessions() {
  const d = await api("/api/sessions");
  state.sessions = d.items || [];
  $("#sessBody").innerHTML = "";
  for (const s of state.sessions) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${esc(String(s.jti).slice(0, 10))}…</td>
      <td>${s.license_id}</td><td>${esc(s.customer || "—")}</td>
      <td class="mono">${esc(String(s.hwid_hash).slice(0, 10))}…</td>
      <td>${esc(s.ip || "—")}</td><td>${fmtTime(s.expires_at)}</td><td class="actions"></td>`;
    tr.querySelector(".actions").append(
      btn("Kick", async () => {
        await api("/api/sessions/kick", { method: "POST", body: JSON.stringify({ jti: s.jti }) });
        toast("Kicked");
        refreshSessions();
      }, true)
    );
    $("#sessBody").appendChild(tr);
  }
}

async function refreshResellers() {
  const d = await api("/api/resellers");
  const host = location.origin;
  if ($("#rsLink")) $("#rsLink").textContent = host + "/reseller";
  const tb = $("#rsBody");
  if (!tb) return;
  tb.innerHTML = "";
  for (const r of d.items || []) {
    const tr = document.createElement("tr");
    const maxd = Math.round((r.max_duration_seconds || 0) / 86400);
    tr.innerHTML = `<td>${esc(r.name)}</td><td>${r.used} / ${r.quota}</td><td>${maxd}d</td><td>${r.max_devices}</td>
      <td>${r.active ? "yes" : "no"}</td>`;
    tb.appendChild(tr);
  }
}

async function refreshBlacklist() {
  const d = await api("/api/blacklist");
  $("#blBody").innerHTML = "";
  for (const b of d.items || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${b.id}</td><td>${esc(b.kind)}</td><td class="mono">${esc(b.value)}</td><td>${esc(b.reason || "")}</td><td class="actions"></td>`;
    tr.querySelector(".actions").append(
      btn("Remove", async () => {
        await api("/api/blacklist/remove", { method: "POST", body: JSON.stringify({ id: b.id }) });
        refreshBlacklist();
      }, true)
    );
    $("#blBody").appendChild(tr);
  }
}

async function refreshAudit() {
  const d = await api("/api/audit");
  $("#auditBody").innerHTML = (d.items || [])
    .map((a) => `<tr><td>${fmtTime(a.ts)}</td><td>${esc(a.actor)}</td><td class="mono">${esc(a.action)}</td><td class="mono">${esc(a.detail || "")}</td></tr>`)
    .join("");
}

function fillSecurityForm() {
  const s = state.settings;
  $("#sForceOnline").checked = !!s.force_online;
  $("#sAllowOffline").checked = !!s.allow_offline_envelope;
  $("#sChallenge").checked = !!s.require_challenge;
  $("#sMaint").checked = !!s.maintenance;
  $("#sKill").checked = !!s.kill_switch;
  $("#sStealth").checked = s.stealth_mode !== false;
  $("#sGeneric").checked = s.generic_errors !== false;
  $("#sTtl").value = s.session_ttl_sec ?? 900;
  $("#sHb").value = s.heartbeat_sec ?? 120;
  $("#sFails").value = s.max_failed_auth ?? 12;
  $("#sBan").value = s.ban_duration_sec ?? 3600;
  $("#sKillMsg").value = s.kill_message || "";
  $("#sMaintMsg").value = s.maintenance_message || "";
  $("#sPanelPath").value = s.panel_path || "/console";
}

function fillBrand() {
  const s = state.settings;
  $("#bName").value = s.app_name || "";
  $("#bTag").value = s.brand_tagline || "";
  $("#bAccent").value = s.theme_accent || "#d4af37";
  $("#bSupport").value = s.support_url || "";
  $("#bDiscord").value = s.discord_url || "";
  $("#bPort").value = s.api_port || 8787;
  $("#bBind").value = s.api_bind || "0.0.0.0";
  $("#bClientHost").value = s.client_api_host || "127.0.0.1";
  $("#bScheme").value = s.client_api_scheme || "http";
  $("#bClientPort").value = s.client_api_port ?? 8787;
  $("#bNote").value = s.seller_note || "";
  document.documentElement.style.setProperty("--accent", s.theme_accent || "#d4af37");
  const host = s.client_api_host || "127.0.0.1";
  const scheme = s.client_api_scheme || "http";
  const cport = Number(s.client_api_port ?? 8787);
  let base;
  if (scheme === "https" && (cport === 0 || cport === 443)) base = `https://${host}`;
  else if (scheme === "http" && (cport === 0 || cport === 80)) base = `http://${host}`;
  else base = `${scheme}://${host}:${cport}`;
  const bad = host === "127.0.0.1" || host === "localhost";
  $("#brandMeta").textContent =
    (bad ? "⚠ Loopback host — only emulators work.\n" : "✓ Non-loopback host.\n") +
    `APK auth URL: ${base}/v2/auth\n` +
    `Panel path: ${s.panel_path || "/console"}\n` +
    `Ban/kill do NOT need rebuild. Host/scheme/port DO.`;
  api("/api/ops/status")
    .then((o) => {
      if ($("#opsStatus")) {
        $("#opsStatus").textContent =
          `GitHub backup: ${o.github_backup ? "env ok" : "env missing"} · host ${o.public_host || "—"}`;
      }
    })
    .catch(() => {});
}

async function refreshView() {
  if (!state.authed) return;
  try {
    if (state.view === "dash") await refreshDash();
    if (state.view === "keys") await refreshKeys();
    if (state.view === "mint") {
      await refreshPlans();
      await refreshDash();
    }
    if (state.view === "sessions") await refreshSessions();
    if (state.view === "plans") await refreshPlans();
    if (state.view === "security") {
      await refreshDash();
      fillSecurityForm();
    }
    if (state.view === "blacklist") await refreshBlacklist();
    if (state.view === "audit") await refreshAudit();
    if (state.view === "resellers") await refreshResellers();
    if (state.view === "brand") {
      await refreshDash();
      fillBrand();
    }
    $("#pillLive").textContent = "● online";
    $("#pillLive").className = "pill live";
  } catch (e) {
    $("#pillLive").textContent = "● error";
    $("#pillLive").className = "pill bad";
    if (String(e.message).includes("sign in")) return;
  }
}

function wire() {
  async function doOwnerLogin() {
    try {
      const err = $("#loginErr");
      if (err) {
        err.classList.add("hidden");
        err.textContent = "";
      }
      const pwEl = $("#loginPw");
      const password = pwEl ? pwEl.value : "";
      if (!password) {
        if (err) {
          err.textContent = "Enter your password";
          err.classList.remove("hidden");
        }
        if (pwEl) pwEl.focus();
        return;
      }
      const r = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ password }),
      }).then((x) => x.json());
      if (!r.ok) throw new Error(r.error || "Wrong password");
      state.session = r.session;
      localStorage.setItem("oc_session", r.session);
      showApp(true);
      setView("dash");
      toast("Signed in");
    } catch (e) {
      const err = $("#loginErr");
      if (err) {
        err.textContent = e.message || "Login failed";
        err.classList.remove("hidden");
      }
      const pwEl = $("#loginPw");
      if (pwEl) {
        pwEl.focus();
        pwEl.select();
      }
    }
  }

  const loginForm = $("#loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      doOwnerLogin();
    });
  }
  if ($("#btnLogin")) $("#btnLogin").onclick = (e) => {
    e.preventDefault();
    doOwnerLogin();
  };
  if ($("#loginPw")) {
    $("#loginPw").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        doOwnerLogin();
      }
    });
  }
  const btnShowPw = $("#btnShowPw");
  if (btnShowPw && $("#loginPw")) {
    btnShowPw.onclick = (e) => {
      e.preventDefault();
      const inp = $("#loginPw");
      const show = inp.type === "password";
      inp.type = show ? "text" : "password";
      btnShowPw.textContent = show ? "Hide" : "Show";
      btnShowPw.setAttribute("aria-label", show ? "Hide password" : "Show password");
      inp.focus();
    };
  }
  if ($("#btnLogout")) $("#btnLogout").onclick = () => logout(true);

  $$("#nav button").forEach((b) => (b.onclick = () => setView(b.dataset.view)));
  if ($("#btnNav")) $("#btnNav").onclick = () => {
    const app = $("#appRoot");
    if (app && app.classList.contains("nav-open")) closeMobileNav();
    else openMobileNav();
  };
  if ($("#navScrim")) $("#navScrim").onclick = () => closeMobileNav();
  // sync mobile live pill with desktop
  const liveSync = () => {
    const src = $("#pillLive");
    const dst = $("#mobileLive");
    if (src && dst) {
      dst.textContent = src.textContent || "●";
      dst.className = src.className;
    }
  };
  setInterval(liveSync, 1500);

  $("#btnKill").onclick = async () => {
    await api("/api/kill", { method: "POST", body: JSON.stringify({ enabled: true }) });
    toast("Kill ON — clients drop next heartbeat");
    refreshDash();
  };
  $("#btnUnkilled").onclick = async () => {
    await api("/api/kill", { method: "POST", body: JSON.stringify({ enabled: false }) });
    toast("Kill OFF");
    refreshDash();
  };
  $("#btnMaintOn").onclick = async () => {
    await api("/api/maintenance", { method: "POST", body: JSON.stringify({ enabled: true }) });
    toast("Maintenance ON");
    refreshDash();
  };
  $("#btnMaintOff").onclick = async () => {
    await api("/api/maintenance", { method: "POST", body: JSON.stringify({ enabled: false }) });
    toast("Maintenance OFF");
    refreshDash();
  };
  $("#btnKickAll").onclick = async () => {
    const r = await api("/api/sessions/kick_all", { method: "POST", body: "{}" });
    toast(`Kicked ${r.n || 0}`);
  };

  $("#btnKeyReload").onclick = () => refreshKeys().catch((e) => toast(e.message, true));
  if ($("#btnExportCsv")) {
    $("#btnExportCsv").onclick = () => downloadCsvExport().catch((e) => toast(e.message, true));
  }
  $("#keySearch").onkeydown = (e) => e.key === "Enter" && refreshKeys();

  $("#mintPlan").onchange = applyPlanToMint;
  $("#mintPreset").onchange = () => {
    const v = $("#mintPreset").value;
    if (!v) return;
    const [amt, unit] = v.split("|");
    $("#mintPlan").value = "custom";
    $("#mintDurVal").value = amt;
    $("#mintDurUnit").value = unit;
    updateMintPreview();
  };
  ["mintDurVal", "mintDurUnit", "mintTier", "mintDevs", "mintStart", "mintQty", "mintCustom"].forEach((id) => {
    const el = $("#" + id);
    if (el) el.addEventListener("input", updateMintPreview);
    if (el) el.addEventListener("change", updateMintPreview);
  });

  $("#btnMint").onclick = async () => {
    try {
      const planVal = $("#mintPlan").value;
      const qty = Math.max(1, Math.min(500, Number($("#mintQty").value || 1)));
      const custom = ($("#mintCustom") && $("#mintCustom").value.trim()) || "";
      if (custom) {
        const sec = parseCustomDurationClient(custom);
        if (sec === null) return toast("Bad custom time. Try 30:00 or 1:30:00 or 45m", true);
      }
      const body = {
        plan_id: planVal && planVal !== "custom" && planVal !== "" ? planVal : null,
        customer: $("#mintCustomer").value,
        note: $("#mintNote").value,
        batch_tag: ($("#mintBatch") && $("#mintBatch").value) || "",
        reseller: ($("#mintReseller") && $("#mintReseller").value) || "",
        qty,
        also_offline: !!( $("#mintOffline") && $("#mintOffline").checked ),
        tier: $("#mintTier").value || "std",
        max_devices: Number($("#mintDevs").value || 1),
        start_mode: $("#mintStart").value || "first_use",
        duration_value: Number($("#mintDurVal").value || 0),
        duration_unit: $("#mintDurUnit").value || "days",
        key_prefix: ($("#mintPrefix") && $("#mintPrefix").value) || "WC",
        key_length: Number(($("#mintKeyLen") && $("#mintKeyLen").value) || 10),
      };
      if (custom) {
        body.duration_custom = custom;
        delete body.duration_value;
        delete body.duration_unit;
      } else if (body.duration_unit === "lifetime") {
        body.lifetime = true;
        body.duration_value = 0;
      }
      if (qty >= 50 && !confirm(`Mint ${qty} keys now?`)) return;
      const r = await api("/api/licenses/create", { method: "POST", body: JSON.stringify(body) });
      state.mintedFull = r.created || [];
      state.minted = state.mintedFull.map((c) => c.token);
      $("#mintOut").textContent = state.mintedFull
        .map((c) => `${c.token}   (${c.duration || "?"} · ${c.tier} · ${c.max_devices} dev)`)
        .join("\n");
      toast(`Created ${state.minted.length}`);
      refreshKeys().catch(() => {});
    } catch (e) {
      toast(e.message || "Mint failed", true);
    }
  };
  $("#btnCopyMinted").onclick = async () => {
    if (!state.minted.length) return toast("Nothing to copy", true);
    await navigator.clipboard.writeText(state.minted.join("\n"));
    toast("Copied");
  };
  if ($("#btnDlMintCsv")) {
    $("#btnDlMintCsv").onclick = () => {
      if (!state.mintedFull.length) return toast("Generate a batch first", true);
      const lines = ["id,token,duration,tier,max_devices,customer,note,start_mode"];
      for (const c of state.mintedFull) {
        const esc = (x) => `"${String(x ?? "").replace(/"/g, '""')}"`;
        lines.push(
          [c.id, c.token, c.duration, c.tier, c.max_devices, c.customer || "", c.note || "", c.start_mode || ""]
            .map(esc)
            .join(",")
        );
      }
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      downloadText(`whitecrown_batch_${stamp}.csv`, lines.join("\n"), "text/csv;charset=utf-8");
      toast("Batch CSV downloaded");
    };
  }
  $("#btnClearMint").onclick = () => {
    state.minted = [];
    state.mintedFull = [];
    $("#mintOut").textContent = "Keys appear here after generate…";
  };

  $("#btnSessReload").onclick = () => refreshSessions();
  $("#btnSessKickAll").onclick = async () => {
    await api("/api/sessions/kick_all", { method: "POST", body: "{}" });
    refreshSessions();
  };

  $("#btnPlanSave").onclick = async () => {
    const body = {
      name: $("#planName").value,
      duration_value: Number($("#planDurVal").value || 0),
      duration_unit: $("#planDurUnit").value || "days",
      max_devices: Number($("#planDevs").value || 1),
      tier: $("#planTier").value,
      price_note: $("#planPrice").value,
      active: true,
    };
    if ($("#planId").value) body.id = Number($("#planId").value);
    await api("/api/plans/upsert", { method: "POST", body: JSON.stringify(body) });
    toast("Plan saved");
    refreshPlans();
  };
  $("#btnPlanNew").onclick = () => {
    $("#planId").value = "";
    $("#planName").value = "";
    $("#planDurVal").value = 1;
    $("#planDurUnit").value = "days";
    $("#planDevs").value = 1;
    $("#planTier").value = "std";
    $("#planPrice").value = "";
  };

  $("#btnSecSave").onclick = async () => {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({
        force_online: $("#sForceOnline").checked,
        allow_offline_envelope: $("#sAllowOffline").checked,
        require_challenge: $("#sChallenge").checked,
        maintenance: $("#sMaint").checked,
        kill_switch: $("#sKill").checked,
        stealth_mode: $("#sStealth").checked,
        generic_errors: $("#sGeneric").checked,
        session_ttl_sec: Number($("#sTtl").value),
        heartbeat_sec: Number($("#sHb").value),
        max_failed_auth: Number($("#sFails").value),
        ban_duration_sec: Number($("#sBan").value),
        kill_message: $("#sKillMsg").value,
        maintenance_message: $("#sMaintMsg").value,
        panel_path: $("#sPanelPath").value || "/console",
      }),
    });
    toast("Live policy applied");
    refreshDash();
  };

  $("#btnPw").onclick = async () => {
    await api("/auth/change_password", {
      method: "POST",
      body: JSON.stringify({ old_password: $("#pwOld").value, new_password: $("#pwNew").value }),
    });
    toast("Password updated");
    $("#pwOld").value = "";
    $("#pwNew").value = "";
  };

  $("#btnBlAdd").onclick = async () => {
    await api("/api/blacklist/add", {
      method: "POST",
      body: JSON.stringify({ kind: $("#blKind").value, value: $("#blVal").value, reason: $("#blReason").value }),
    });
    $("#blVal").value = "";
    refreshBlacklist();
  };

  $("#btnRsCreate").onclick = async () => {
    try {
      const r = await api("/api/resellers/create", {
        method: "POST",
        body: JSON.stringify({
          name: $("#rsName").value,
          password: $("#rsPass").value,
          quota: Number($("#rsQuota").value || 50),
          max_duration_value: Number($("#rsMaxDays").value || 30),
          max_duration_unit: "days",
          max_devices: Number($("#rsMaxDev").value || 1),
          note: $("#rsNote").value,
        }),
      });
      $("#rsOut").textContent = `Created "${r.reseller.name}". Share: ${location.origin}/reseller + their username/password.`;
      $("#rsPass").value = "";
      toast("Reseller created");
      refreshResellers();
    } catch (e) {
      toast(e.message, true);
    }
  };

  $("#btnBrandSave").onclick = async () => {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({
        app_name: $("#bName").value,
        brand_tagline: $("#bTag").value,
        theme_accent: $("#bAccent").value,
        support_url: $("#bSupport").value,
        discord_url: $("#bDiscord").value,
        api_port: Number($("#bPort").value),
        api_bind: $("#bBind").value,
        client_api_host: $("#bClientHost").value.trim(),
        client_api_scheme: $("#bScheme").value,
        client_api_port: Number($("#bClientPort").value),
        seller_note: $("#bNote").value,
      }),
    });
    toast("Saved — rebuild APK if host/scheme changed");
    fillBrand();
  };

  if ($("#btnBackupNow")) {
    $("#btnBackupNow").onclick = async () => {
      try {
        if ($("#backupStatus")) $("#backupStatus").textContent = "Backing up…";
        const r = await api("/api/backup/now", { method: "POST", body: "{}" });
        if ($("#backupStatus")) $("#backupStatus").textContent = r.message || (r.ok ? "ok" : "failed");
        toast(r.ok ? "Backup done" : (r.message || "Backup failed"), !r.ok);
      } catch (e) {
        toast(e.message, true);
      }
    };
  }
  if ($("#btnBackupDrill")) {
    $("#btnBackupDrill").onclick = async () => {
      try {
        if ($("#backupStatus")) $("#backupStatus").textContent = "Running restore drill…";
        const r = await api("/api/backup/drill", { method: "POST", body: "{}" });
        const msg = r.message || (r.ok ? "drill ok" : "drill failed");
        if ($("#backupStatus")) {
          $("#backupStatus").textContent =
            msg + (r.bytes ? ` · ${r.bytes} bytes` : "") + (r.sha ? ` · sha ${r.sha}` : "");
        }
        toast(r.ok ? "Restore drill OK" : msg, !r.ok);
      } catch (e) {
        toast(e.message, true);
      }
    };
  }
}

// Live panel: poll server every 3s on dash/keys/sessions (loader heartbeats independently)
setInterval(() => {
  if (document.hidden || !state.authed) return;
  if (["dash", "keys", "sessions", "security"].includes(state.view)) refreshView();
  else refreshDash().catch(() => {});
}, 3000);

// Smooth countdown every second without full table rebuild
setInterval(() => {
  if (document.hidden || !state.authed) return;
  if (state.view === "keys") tickCountdowns();
}, 1000);

wire();
trySession();
