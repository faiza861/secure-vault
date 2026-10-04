"use strict";
// SECURITY NOTES
// * All server data is inserted with textContent / property assignment (no HTML parsing), so a hostile
//   file name can never run script in this page (the CSP also forbids inline script).
// * The passphrase lives ONLY in the JS variable `passphrase` and the session token ONLY in `sess`.
//   Neither is written to browser storage, cookies, the URL or any log. Both are cleared on sign out
//   and after 5 minutes without activity. Hosted mode still needs the passphrase on each request
//   because the stateless server derives keys per request (documented limitation).

const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };

const IDLE_LIMIT_MS = 5 * 60 * 1000;
let status = null;
let passphrase = null;      // in memory only
let sess = null;            // { token, absExp, idleMs, lastActive, authAt } - in memory only
let mfaEnabled = null;      // null = not known (locked)
let lockUntil = 0;          // ms timestamp until which the server told us to wait
let idleTimer = null;
let pendingSecret = null;   // MFA secret during enrollment only

class ApiError extends Error {
  constructor(message, httpStatus, code, retryAfter) { super(message); this.status = httpStatus; this.code = code; this.retryAfter = retryAfter || 0; }
}

// ------------------------------------------------------------- messages
function say(text, isError = false) {
  const m = $("msg");
  m.textContent = text; m.className = "msg" + (isError ? " error" : ""); m.hidden = false;
  clearTimeout(say.t); say.t = setTimeout(() => { m.hidden = true; }, 7000);
}
function note(id, text, isError = false) {
  const m = $(id); m.textContent = text || ""; m.className = "msg" + (isError ? " error" : ""); m.hidden = !text;
}

// ----------------------------------------------------------------- API
async function api(path, { method = "GET", json, form, auth = true } = {}) {
  const opts = { method, headers: {} };
  if (json) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(json); }
  if (form) opts.body = form;
  if (sess && auth) opts.headers.Authorization = "Bearer " + sess.token;
  let res;
  try { res = await fetch(path, opts); }
  catch (_) { throw new ApiError("Network error. Check your connection and try again.", 0, "network"); }
  const fresh = res.headers.get("X-Session-Token");
  if (fresh && sess) { sess.token = fresh; sess.lastActive = Date.now(); }   // server refreshes the inactivity clock
  if (!res.ok) {
    let msg = "Request failed.", code = null, retry = 0;
    try { const b = await res.json(); msg = b.error || (b.detail && "Check the values you entered.") || msg; code = b.code || null; retry = b.retry_after || 0; } catch (_) {}
    if (res.status === 429) { retry = retry || Number(res.headers.get("Retry-After")) || 60; lockUntil = Date.now() + retry * 1000; code = "rate_limited"; }
    if (code === "session_expired" || code === "session_invalid") endSession("Your session ended. Sign in again.", false);
    throw new ApiError(msg, res.status, code, retry);
  }
  return res;
}
const body = (extra, code) => ({ passphrase, ...extra, ...(code ? { totp_code: code } : {}) });

const fmtSize = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
const fmtTime = (ts) => new Date(ts * 1000).toLocaleString();
const mmss = (ms) => { const s = Math.max(0, Math.ceil(ms / 1000)); return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0"); };

// One place that turns an error into a calm, specific message. Never leaves the UI stuck.
function fail(e, target) {
  if (e instanceof ApiError && e.code === "cancelled") return;
  let text = e && e.message ? e.message : "Something went wrong.";
  if (e instanceof ApiError && e.code === "rate_limited") text = `Too many attempts, try again in ${Math.max(1, Math.ceil((lockUntil - Date.now()) / 1000))} seconds.`;
  if (target) note(target, text, true); else say(text, true);
  tick();
}
async function busy(buttons, fn) {            // disable while a request is in flight: no double submit
  const list = buttons.filter(Boolean);
  list.forEach((b) => { b.disabled = true; });
  try { return await fn(); } finally { list.forEach((b) => { b.disabled = false; }); tick(); }
}

// -------------------------------------------------------------- dialogs
function openDialog(dlg, opener) {
  dlg._opener = opener || document.activeElement;
  if (typeof dlg.showModal === "function") { if (!dlg.open) dlg.showModal(); } else dlg.setAttribute("open", "");
}
function closeDialog(dlg) {
  if (typeof dlg.close === "function") { if (dlg.open) dlg.close(); } else { dlg.removeAttribute("open"); dlg.dispatchEvent(new Event("close")); }
}
function wireDialog(dlg, onClosed) {
  dlg.addEventListener("close", () => {
    onClosed();
    const back = dlg._opener; dlg._opener = null;
    if (back && document.contains(back) && !back.disabled && !back.hidden) back.focus();   // focus returns to the trigger
  });
  dlg.addEventListener("keydown", (e) => { if (e.key === "Escape" && typeof dlg.showModal !== "function") closeDialog(dlg); });  // fallback only
}

// unlock dialog -----------------------------------------------------------
function openUnlock(opener) {
  note("unlock-msg", "");
  $("unlock-code-wrap").hidden = true; $("unlock-code").value = "";
  openDialog($("unlock-dlg"), opener);
  $("unlock-pass").focus();
  tick();
}
wireDialog($("unlock-dlg"), () => { $("unlock-pass").value = ""; $("unlock-code").value = ""; $("unlock-code-wrap").hidden = true; note("unlock-msg", ""); });
$("unlock-cancel").addEventListener("click", () => closeDialog($("unlock-dlg")));
$("unlock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("unlock-pass").value, code = $("unlock-code").value.trim();
  if (!pw) { note("unlock-msg", "Enter your passphrase.", true); $("unlock-pass").focus(); return; }
  if (Date.now() < lockUntil) { tick(); return; }
  await busy([$("unlock-submit")], async () => {
    try {
      const r = await (await api("/api/session", { method: "POST", auth: false, json: { passphrase: pw, ...(code ? { totp_code: code } : {}) } })).json();
      passphrase = pw;
      sess = { token: r.token, absExp: Date.now() + r.expires_in * 1000, idleMs: r.idle_timeout * 1000, lastActive: Date.now(), authAt: r.authenticated_at };
      mfaEnabled = Boolean(code);
      closeDialog($("unlock-dlg"));
      armIdleTimer(); await refreshMfaState();
      say("Vault unlocked."); await loadStatus(); await loadFiles(true); renderAll();
    } catch (e) {
      if (e.code === "mfa_required") {
        $("unlock-code-wrap").hidden = false; $("unlock-code").focus();
        note("unlock-msg", "Enter the 6-digit code from your authenticator app.");
      } else if (e.code === "invalid_mfa_code") {
        $("unlock-code").value = ""; $("unlock-code").focus(); note("unlock-msg", "That code was not accepted. Use a fresh code (each works once).", true);
      } else fail(e, "unlock-msg");
      loadStatus().catch(() => {});
    }
  });
});

// authenticator-code dialog (step-up) ---------------------------------------
let codeResolver = null;
function askCode(why, opener) {
  return new Promise((resolve) => {
    codeResolver = resolve;
    $("code-why").textContent = why || "This action needs a current 6-digit code. Each code works once, so wait for a new one if you just used it.";
    $("code-input").value = ""; note("code-msg", "");
    openDialog($("code-dlg"), opener); $("code-input").focus();
  });
}
function settleCode(value) { const r = codeResolver; codeResolver = null; if (r) r(value); }
wireDialog($("code-dlg"), () => { $("code-input").value = ""; settleCode(null); });   // closing without submit = cancel
$("code-cancel").addEventListener("click", () => closeDialog($("code-dlg")));
$("code-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const v = $("code-input").value.trim();
  if (!/^[0-9]{6}$/.test(v)) { note("code-msg", "Enter the 6-digit code.", true); $("code-input").focus(); return; }
  settleCode(v); closeDialog($("code-dlg"));
});
// Runs `run(code|null)`. If the server answers mfa_required it asks for a code once and retries.
async function withCode(run, why, opener) {
  try { return await run(null); }
  catch (e) {
    if (!(e instanceof ApiError) || e.code !== "mfa_required") throw e;
    const code = await askCode(why, opener);
    if (!code) throw new ApiError("Cancelled.", 0, "cancelled");
    return await run(code);
  }
}
function needUnlock(opener) { if (passphrase && sess) return false; openUnlock(opener); return true; }

// -------------------------------------------------------- session / lock
function endSession(message, callServer = true) {
  const token = sess && sess.token;
  if (callServer && token) fetch("/api/session/logout", { method: "POST", headers: { Authorization: "Bearer " + token } }).catch(() => {});
  passphrase = null; sess = null; mfaEnabled = null; clearMfaSetup(); clearTimeout(idleTimer);
  $("new-pass").value = "";
  if (message) say(message);
  renderAll(); loadFiles(false).catch(() => {});
}
function armIdleTimer() { clearTimeout(idleTimer); if (passphrase) idleTimer = setTimeout(() => endSession("Signed out after 5 minutes of inactivity."), IDLE_LIMIT_MS); }
["pointerdown", "keydown"].forEach((t) => document.addEventListener(t, () => { if (passphrase) armIdleTimer(); }, { passive: true }));
$("signout-btn").addEventListener("click", () => endSession("Signed out."));
$("signout2-btn").addEventListener("click", () => endSession("Signed out."));
$("open-unlock").addEventListener("click", (e) => openUnlock(e.currentTarget));

$("reauth-btn").addEventListener("click", async (e) => {
  const opener = e.currentTarget;
  if (needUnlock(opener)) return;
  await busy([opener], async () => {
    try {
      const r = await withCode((code) => api("/api/session/reauth", { method: "POST", json: body({}, code) }), "Enter a current code to confirm it is still you.", opener);
      const j = await r.json();
      sess.token = j.token; sess.absExp = Date.now() + j.expires_in * 1000; sess.lastActive = Date.now(); sess.authAt = j.authenticated_at;
      say("Re-authenticated."); renderAll();
    } catch (err) { fail(err); }
  });
});

async function refreshMfaState() {
  if (!sess) { mfaEnabled = null; return; }
  try { mfaEnabled = (await (await api("/api/mfa/status")).json()).enabled; } catch (_) { /* keep previous value */ }
}

// ----------------------------------------------------------------- tabs
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
  document.querySelectorAll(".panel").forEach((p) => { p.hidden = p.id !== "tab-" + b.dataset.tab; });
  if (b.dataset.tab === "security") { loadStatus().catch(() => {}); loadSecurity(); }
}));

// --------------------------------------------------------------- status
async function loadStatus() {
  status = await (await api("/api/status", { auth: false })).json();
  const chip = $("chip");
  if (!status.initialized) { chip.textContent = "No vault yet"; chip.className = "chip"; }
  else {
    chip.textContent = `${status.kem} · ${status.audit_ok ? "audit chain intact" : "AUDIT CHAIN BROKEN"}`;
    chip.className = "chip " + (status.audit_ok ? "ok" : "bad");
  }
  if (status.lockout && status.lockout.locked) lockUntil = Math.max(lockUntil, Date.now() + status.lockout.retry_after * 1000);
  $("setup").hidden = status.initialized;
  $("main-vault").hidden = !status.initialized;
  $("minlen").textContent = status.min_passphrase_length;
  $("maxsize").textContent = fmtSize(status.max_upload_bytes);
  // Public demo: show the notice and switch off the actions the server refuses anyway (see api/main.py block_in_demo)
  const demo = Boolean(status.demo_mode);
  $("demo-banner").hidden = !demo;
  for (const id of ["mfa-enable", "rot-pass", "new-pass"]) {
    const el = $(id);
    el.disabled = demo;
    el.title = demo ? "Switched off in the shared public demo" : "";
  }
  renderAll();
}

$("init-btn").addEventListener("click", async (e) => {
  await busy([e.currentTarget], async () => {
    try {
      await api("/api/init", { method: "POST", auth: false, json: { passphrase: $("init-pass").value } });
      $("init-pass").value = ""; say("Vault created. Unlock it to continue."); await loadStatus(); await loadFiles(false);
      openUnlock($("open-unlock"));
    } catch (err) { fail(err); }
  });
});

// ---------------------------------------------------------------- render
function posture(label, value, sub, cls) {
  const li = el("li", null, cls || ""); li.title = sub;
  li.append(el("span", label, "p-label"), el("strong", value, "p-value"), el("span", sub, "p-sub"));
  return li;
}
function renderAll() {
  const unlocked = Boolean(passphrase && sess);
  $("lock-state").textContent = unlocked ? "Unlocked. Your session is active." : "Locked. Sign in to add files, see file names and download.";
  $("open-unlock").hidden = unlocked; $("signout-btn").hidden = !unlocked;
  $("upload-card").hidden = !unlocked;
  $("reauth-btn").disabled = !unlocked; $("signout2-btn").disabled = !unlocked;

  // posture strip: every item comes from real backend state; no colour-only meaning (each has text)
  const strip = $("posture"); strip.replaceChildren();
  if (status && status.initialized) {
    strip.append(
      !unlocked ? posture("MFA", "Locked", "Unlock to see two-step verification state")
        : mfaEnabled ? posture("MFA", "Enabled", "Authenticator code required for sensitive actions", "good")
          : posture("MFA", "Not enabled", "Only the passphrase protects sensitive actions", "bad"),
      posture("Keys", "Version " + status.key_version, status.key_age_days == null ? "Age unknown" : `${status.key_age_days} day(s) since creation or last rotation`),
      posture("Audit chain", status.audit_ok ? "Verified" : "BROKEN", `${status.audit_length} entries checked`, status.audit_ok ? "good" : "bad"),
      posture("AI model", status.model_loaded ? "Loaded" : "Rules only", status.model_loaded ? "Isolation Forest plus rules" : "No trained model found", status.model_loaded ? "good" : ""),
    );
  }
  // access protection card
  const set = (id, text, cls) => { const n = $(id); n.textContent = text; n.className = cls || ""; };
  set("ap-mfa", !unlocked ? "Locked" : mfaEnabled ? "✓ Enabled" : "Not enabled", mfaEnabled ? "good" : "");
  $("ap-note").textContent = unlocked ? (mfaEnabled ? "A code or a recent re-authentication is needed for sensitive actions." : "Enable two-step verification below to protect sensitive actions.") : "Sign in to see the two-step verification state.";
  set("ap-last", sess ? fmtTime(sess.authAt) : "–");
  const lo = status && status.lockout;
  set("ap-fails", lo ? `${lo.failures_in_window} of ${status.lockout_policy.max_failures}` : "–");
  // MFA card
  $("mfa-locked").hidden = unlocked;
  $("mfa-off").hidden = !(unlocked && mfaEnabled === false && !pendingSecret);
  $("mfa-on").hidden = !(unlocked && mfaEnabled === true);
  $("mfa-setup").hidden = !(unlocked && pendingSecret);
  tick();
}

// Runs every second: session countdown, lockout countdown, and buttons that depend on them.
function tick() {
  const now = Date.now();
  if (sess) {
    const left = Math.min(sess.absExp - now, sess.lastActive + sess.idleMs - now);
    if (left <= 0) { endSession("Your session expired. Sign in again.", false); return; }
    $("ap-session").textContent = "Expires in " + mmss(left); $("ap-session").className = "";
  } else { $("ap-session").textContent = "No active session"; $("ap-session").className = ""; }
  const waiting = lockUntil - now;
  const lockEl = $("ap-lock");
  if (waiting > 0) { lockEl.textContent = `Active, ${mmss(waiting)} remaining`; lockEl.className = "bad"; } else { lockEl.textContent = status ? "None" : "–"; lockEl.className = ""; }
  const dlgOpen = $("unlock-dlg").open || $("unlock-dlg").hasAttribute("open");
  if (waiting > 0 && dlgOpen) {
    note("unlock-msg", `Too many attempts, try again in ${Math.ceil(waiting / 1000)} seconds.`, true);
    $("unlock-submit").disabled = true;
  } else if ($("unlock-submit").disabled && waiting <= 0) {
    $("unlock-submit").disabled = false;
    if ($("unlock-msg").textContent.startsWith("Too many")) note("unlock-msg", "You can try again now.");
  }
}
setInterval(tick, 1000);

// ------------------------------------------------------------------ files
async function loadFiles(unlocked) {
  const res = unlocked ? await api("/api/files/list", { method: "POST", json: body({}) }) : await api("/api/files", { auth: false });
  const files = await res.json();
  const tbody = document.querySelector("#files tbody");
  tbody.replaceChildren();
  $("empty").hidden = files.length > 0;
  for (const f of files) {
    const tr = el("tr");
    tr.append(el("td", f.name || "🔒 encrypted name", "name"), el("td", fmtSize(f.size)), el("td", "v" + f.key_version));
    const actions = el("td");
    const dl = el("button", "Download"); dl.addEventListener("click", () => download(f, dl));
    const rm = el("button", "Delete", "danger"); rm.addEventListener("click", () => remove(f, rm));
    actions.append(dl, " ", rm); tr.append(actions); tbody.append(tr);
  }
}

async function upload(file) {
  if (!file || needUnlock($("open-unlock"))) return;
  try {
    const form = new FormData(); form.append("file", file); form.append("passphrase", passphrase);
    await api("/api/files", { method: "POST", form });
    say(`Encrypted and stored ${file.name}.`);
    await loadFiles(true); await loadStatus();
  } catch (e) { fail(e); }
}
$("file").addEventListener("change", (e) => { upload(e.target.files[0]); e.target.value = ""; });
const drop = $("drop");
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => upload(e.dataTransfer.files[0]));
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } });

async function download(f, btn) {
  if (needUnlock(btn)) return;
  await busy([btn], async () => {
    try {
      const res = await withCode((code) => api(`/api/files/${f.file_id}/download`, { method: "POST", json: body({}, code) }), null, btn);
      const blob = await res.blob();
      const a = el("a"); a.href = URL.createObjectURL(blob); a.download = f.name || "download";
      document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      say("Decrypted and downloaded."); renderAll();
    } catch (e) { fail(e); }
  });
}

async function remove(f, btn) {
  if (needUnlock(btn) || !confirm("Delete this file permanently?")) return;
  await busy([btn], async () => {
    try {
      await withCode((code) => api(`/api/files/${f.file_id}/delete`, { method: "POST", json: body({}, code) }), null, btn);
      say("Deleted."); await loadFiles(true);
    } catch (e) { fail(e); }
  });
}

// --------------------------------------------------------------- security
function renderAlerts(alerts) {
  const list = $("alerts"); list.replaceChildren();
  if (!alerts.length) { list.append(el("li", "No anomalies found.")); return; }
  for (const a of alerts) {
    const li = el("li", null, a.severity);
    li.append(el("span", a.source === "ml" ? "AI" : "Rule", "src"), `${fmtTime(a.window_start)}  ${a.message}`);
    list.append(li);
  }
}

async function loadSecurity() {
  try {
    const a = await (await api("/api/audit?limit=30", { auth: false })).json();
    const badge = $("chain-badge");
    badge.textContent = a.ok ? `Intact (${a.length} entries)` : `BROKEN at entry ${a.problem.index}: ${a.problem.reason}`;
    badge.className = "badge" + (a.ok ? "" : " bad");
    $("head").textContent = a.head;
    const tbody = document.querySelector("#audit tbody"); tbody.replaceChildren();
    for (const e of a.entries) {
      const tr = el("tr"); tr.append(el("td", e.index), el("td", fmtTime(e.ts)), el("td", e.event), el("td", e.hash.slice(0, 12)));
      tbody.append(tr);
    }
  } catch (e) { fail(e); }
}

$("scan-btn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (needUnlock(btn)) return;
  await busy([btn], async () => {
    try {
      const r = await (await withCode((code) => api("/api/security/scan", { method: "POST", json: body({}, code) }), null, btn)).json();
      $("scan-note").textContent = `Scanned ${r.windows_scanned} activity window(s) using ${r.model_loaded ? "rules + Isolation Forest" : "rules only (no trained model found)"}.`;
      renderAlerts(r.alerts); loadSecurity();
    } catch (err) { fail(err); }
  });
});

$("rot-keys").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (needUnlock(btn)) return;
  await busy([btn], async () => {
    try {
      const r = await (await withCode((code) => api("/api/rotate/keys", { method: "POST", json: body({}, code) }), null, btn)).json();
      say(`New ML-KEM key active. ${r.files_rewrapped} file key(s) re-wrapped.`); loadSecurity(); loadStatus();
    } catch (err) { fail(err); }
  });
});

$("rot-pass").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (needUnlock(btn)) return;
  const next = $("new-pass").value;
  if (!next) { say("Enter a new passphrase first.", true); $("new-pass").focus(); return; }
  await busy([btn], async () => {
    try {
      await withCode((code) => api("/api/rotate/passphrase", { method: "POST", json: body({ new_passphrase: next }, code) }), null, btn);
      passphrase = next; $("new-pass").value = ""; say("Passphrase changed."); loadSecurity();
    } catch (err) { fail(err); }
  });
});

// -------------------------------------------------- MFA enrolment card
function clearMfaSetup() {
  pendingSecret = null;
  $("mfa-key").textContent = ""; $("mfa-uri").textContent = ""; $("mfa-uri-wrap").hidden = true;
  const qr = $("mfa-qr"); qr.removeAttribute("src"); qr.hidden = true;
  $("mfa-confirm-code").value = ""; note("mfa-msg", "");
}
$("mfa-enable").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (needUnlock(btn)) return;
  await busy([btn], async () => {
    try {
      const r = await (await api("/api/mfa/enroll", { method: "POST", json: body({}) })).json();
      pendingSecret = r.secret;
      $("mfa-key").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
      if (typeof r.qr === "string" && r.qr.startsWith("data:image/svg+xml")) { $("mfa-qr").src = r.qr; $("mfa-qr").hidden = false; }
      else { $("mfa-uri").textContent = r.uri; $("mfa-uri-wrap").hidden = false; }     // fallback: manual key + otpauth:// text
      note("mfa-msg", ""); renderAll(); $("mfa-confirm-code").focus();
    } catch (err) { fail(err, "mfa-msg"); }
  });
});
$("mfa-cancel").addEventListener("click", () => { clearMfaSetup(); renderAll(); $("mfa-enable").focus(); });
$("mfa-confirm").addEventListener("click", async (e) => {
  const btn = e.currentTarget, code = $("mfa-confirm-code").value.trim();
  if (!/^[0-9]{6}$/.test(code)) { note("mfa-msg", "Enter the 6-digit code from the app.", true); $("mfa-confirm-code").focus(); return; }
  await busy([btn], async () => {
    try {
      await api("/api/mfa/confirm", { method: "POST", json: { passphrase, secret: pendingSecret, code } });
      clearMfaSetup();                  // the secret is never shown again once enrolment completes
      mfaEnabled = true; renderAll(); loadStatus();
      note("mfa-msg", "Two-step verification is on. For the next protected action, wait for a new code.");
    } catch (err) { fail(err, "mfa-msg"); }
  });
});
$("mfa-disable").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (needUnlock(btn)) return;
  const code = await askCode("Enter a current code to switch two-step verification off.", btn);
  if (!code) return;
  await busy([btn], async () => {
    try {
      await api("/api/mfa/disable", { method: "POST", json: { passphrase, totp_code: code } });
      mfaEnabled = false; renderAll(); loadStatus(); note("mfa-msg", "Two-step verification is off.");
    } catch (err) { fail(err, "mfa-msg"); }
  });
});

loadStatus().then(() => status.initialized && loadFiles(false)).catch((e) => say(e.message, true));
