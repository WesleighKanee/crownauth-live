const $ = (s) => document.querySelector(s);
let session = localStorage.getItem("rs_session") || "";
let me = null;

function toast(msg, bad = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.style.borderColor = bad ? "rgba(251,113,133,.5)" : "rgba(52,211,153,.35)";
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2500);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (session) headers.Authorization = "Bearer " + session;
  const res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    session = "";
    localStorage.removeItem("rs_session");
    show(false);
    throw new Error(data.error || "Please log in");
  }
  if (!res.ok || data.ok === false) throw new Error(data.error || res.statusText);
  return data;
}

function show(on) {
  $("#loginBox").classList.toggle("hidden", on);
  $("#appBox").classList.toggle("hidden", !on);
}

async function loadMe() {
  me = await api("/reseller/api/me");
  $("#who").textContent = "Hi, " + me.name;
  $("#quota").textContent = `Keys left: ${me.left} / ${me.quota} · max length ${Math.round((me.max_duration_seconds || 0) / 86400)}d · max ${me.max_devices} device(s)`;
  $("#devs").max = me.max_devices || 1;
  if (Number($("#devs").value) > me.max_devices) $("#devs").value = me.max_devices;
}

async function loadKeys() {
  const d = await api("/reseller/api/licenses");
  const tb = $("#tbody");
  tb.innerHTML = "";
  for (const L of d.items || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${L.token}</td><td>${L.duration_label || "—"}</td><td>${L.customer || "—"}</td>
      <td><span class="tag ${L.status}">${L.status}</span></td><td class="actions"></td>`;
    const act = tr.querySelector(".actions");
    const copy = document.createElement("button");
    copy.className = "btn";
    copy.textContent = "Copy";
    copy.onclick = () => navigator.clipboard.writeText(L.token).then(() => toast("Copied"));
    act.appendChild(copy);
    if (me && me.can_reset_hwid) {
      const rst = document.createElement("button");
      rst.className = "btn";
      rst.textContent = "Reset device";
      rst.onclick = async () => {
        try {
          await api("/reseller/api/licenses/hwid_reset", { method: "POST", body: JSON.stringify({ id: L.id }) });
          toast("Device reset");
        } catch (e) {
          toast(e.message, true);
        }
      };
      act.appendChild(rst);
    }
    tb.appendChild(tr);
  }
}

async function doResellerLogin() {
  try {
    $("#loginErr").classList.add("hidden");
    const user = $("#user");
    const pass = $("#pass");
    if (user) {
      user.disabled = false;
      user.readOnly = false;
    }
    if (pass) {
      pass.disabled = false;
      pass.readOnly = false;
      pass.style.pointerEvents = "auto";
    }
    const r = await fetch("/reseller/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ name: user ? user.value : "", password: pass ? pass.value : "" }),
    }).then((x) => x.json());
    if (!r.ok) throw new Error(r.error || "Login failed");
    session = r.session;
    localStorage.setItem("rs_session", session);
    show(true);
    await loadMe();
    await loadKeys();
    toast("Logged in");
  } catch (e) {
    $("#loginErr").textContent = e.message;
    $("#loginErr").classList.remove("hidden");
    if ($("#pass")) $("#pass").focus();
  }
}
$("#btnLogin").onclick = (e) => {
  e.preventDefault();
  doResellerLogin();
};
const rsForm = $("#rsForm");
if (rsForm) {
  rsForm.addEventListener("submit", (e) => {
    e.preventDefault();
    doResellerLogin();
  });
}
const btnShowPw = $("#btnShowPw");
if (btnShowPw && $("#pass")) {
  btnShowPw.onclick = (e) => {
    e.preventDefault();
    const inp = $("#pass");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    btnShowPw.textContent = show ? "Hide" : "Show";
    btnShowPw.setAttribute("aria-label", show ? "Hide password" : "Show password");
    inp.focus();
  };
}
setTimeout(() => {
  if ($("#user")) $("#user").focus();
}, 80);

$("#btnLogout").onclick = () => {
  session = "";
  localStorage.removeItem("rs_session");
  fetch("/reseller/api/logout", { method: "POST", credentials: "same-origin" });
  show(false);
};

$("#btnMint").onclick = async () => {
  try {
    const r = await api("/reseller/api/licenses/create", {
      method: "POST",
      body: JSON.stringify({
        duration_value: Number($("#durVal").value || 1),
        duration_unit: $("#durUnit").value,
        qty: Number($("#qty").value || 1),
        max_devices: Number($("#devs").value || 1),
        customer: $("#buyer").value,
        key_length: 8,
        key_prefix: "WC",
      }),
    });
    $("#out").textContent = (r.created || []).map((c) => c.token + "  (" + c.duration + ")").join("\n");
    toast("Created " + (r.created || []).length);
    await loadMe();
    await loadKeys();
  } catch (e) {
    toast(e.message, true);
  }
};

$("#btnRefresh").onclick = () => loadKeys().catch((e) => toast(e.message, true));

(async () => {
  if (!session) return;
  try {
    show(true);
    await loadMe();
    await loadKeys();
  } catch (_) {
    show(false);
  }
})();
