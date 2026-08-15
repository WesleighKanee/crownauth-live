(() => {
  "use strict";
  const KEY = "crown_panel_appearance_v1";
  const defaults = { accent: "#9ad8ff", glass: "balanced", density: "comfortable", motion: "system" };
  const read = () => {
    try { return { ...defaults, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; }
    catch (_) { return { ...defaults }; }
  };
  let prefs = read();

  function apply() {
    const root = document.documentElement;
    root.style.setProperty("--accent", prefs.accent);
    root.style.setProperty("--accent2", prefs.accent);
    root.dataset.glass = prefs.glass;
    root.dataset.density = prefs.density;
    root.dataset.motion = prefs.motion;
  }

  function save(next) {
    prefs = { ...prefs, ...next };
    localStorage.setItem(KEY, JSON.stringify(prefs));
    apply();
  }

  function mount() {
    if (document.querySelector(".appearance-trigger")) return;
    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "appearance-trigger";
    trigger.setAttribute("aria-label", "Customize appearance");
    trigger.setAttribute("aria-expanded", "false");
    trigger.textContent = "Appearance";

    const panel = document.createElement("section");
    panel.className = "appearance-panel";
    panel.hidden = true;
    panel.innerHTML = `
      <div class="appearance-head"><div><b>Appearance</b><span>Saved on this device</span></div><button type="button" data-close aria-label="Close">×</button></div>
      <label>Accent<input data-pref="accent" type="color" value="${prefs.accent}"></label>
      <label>Glass<select data-pref="glass"><option value="soft">Soft</option><option value="balanced">Balanced</option><option value="crystal">Crystal</option></select></label>
      <label>Density<select data-pref="density"><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></label>
      <label>Motion<select data-pref="motion"><option value="system">Follow device</option><option value="full">Full</option><option value="reduced">Reduced</option></select></label>
      <button type="button" class="btn ghost appearance-reset">Reset appearance</button>`;
    document.body.append(trigger, panel);
    panel.querySelector('[data-pref="glass"]').value = prefs.glass;
    panel.querySelector('[data-pref="density"]').value = prefs.density;
    panel.querySelector('[data-pref="motion"]').value = prefs.motion;
    panel.querySelectorAll("[data-pref]").forEach((el) => el.addEventListener("input", () => save({ [el.dataset.pref]: el.value })));
    const close = () => { panel.hidden = true; trigger.setAttribute("aria-expanded", "false"); };
    trigger.onclick = () => { panel.hidden = !panel.hidden; trigger.setAttribute("aria-expanded", String(!panel.hidden)); };
    panel.querySelector("[data-close]").onclick = close;
    panel.querySelector(".appearance-reset").onclick = () => { prefs = { ...defaults }; localStorage.removeItem(KEY); apply(); panel.remove(); trigger.remove(); mount(); };
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  }

  apply();
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount, { once: true }); else mount();
  window.PanelAppearance = { apply, read: () => ({ ...prefs }) };
})();
