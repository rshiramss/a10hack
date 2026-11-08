"use strict";
// Ward console. Polls /api/state and redraws. Everything shown comes from the gateway;
// all text is set with textContent, so a hostile record can't inject markup.

const HEADERS = { "Content-Type": "application/json", "X-Ward": "1" };
const KEY_KINDS = new Set([
  "SPAWNED", "AUTHENTICATED", "AUTH_FAILED", "RUN_STARTED", "RUN_ENDED", "PLAN_APPROVED",
  "DENIED", "REVOKED", "HANDSHAKE_REFUSED", "OUTPUT_REJECTED", "RESULT_DISCARDED",
  "FORGERY_REFUSED", "INJECTION_FLAGGED", "DELIVERED", "OPERATOR_LOGIN", "OPERATOR_LOGIN_FAILED",
  "POP_REJECTED", "ATTESTATION_FAILED", "BADGE_ROTATED", "STALE_BADGE",
  "APPROVAL_REQUIRED", "APPROVAL_APPROVED", "APPROVAL_DENIED", "APPROVAL_TIMEOUT",
  "ESCALATION", "ESCALATION_ACKED", "ESCALATION_PAGE_FAILED", "MCP_CREDENTIAL_ISSUED",
]);
const ICON = { ALLOW: "✓", DENY: "✗", EVENT: "•" };

const state = { lastSeq: 0, epoch: null, audit: [], filter: "key", open: new Set(), snap: null,
                examplesShown: false, settingsShown: false, mcpRolesShown: false, fresh: new Set(),
                selectedLease: null, showMasterSaw: false };

const $ = (id) => document.getElementById(id);
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "text") node.textContent = v;
    else if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of [].concat(children)) if (child) node.append(child);
  return node;
}
async function post(path, body = {}) {
  const r = await fetch(path, { method: "POST", credentials: "same-origin", headers: HEADERS, body: JSON.stringify(body) });
  try { return await r.json(); } catch { return { ok: false, reason: `HTTP ${r.status}` }; }
}
function say(text, good) {
  const line = $("control-status");
  line.textContent = text;
  line.className = `status-line small ${good ? "good" : "bad"}`;
}
const fmtTime = (ms) => new Date(ms).toLocaleTimeString([], { hour12: false });
const human = (reason) => (reason || "").replace(/^DENY_/, "").replaceAll("_", " ").toLowerCase();

// ---- polling ---------------------------------------------------------------------

async function poll() {
  let response;
  try {
    response = await fetch(`/api/state?after=${state.lastSeq}`, { credentials: "same-origin" });
  } catch { return setTimeout(poll, 1500); }
  if (response.status === 401) { showLogin(); return; }
  const snap = await response.json();
  if (snap.epoch !== state.epoch) {           // console was reset: start the log over
    state.epoch = snap.epoch; state.audit = []; state.lastSeq = 0; state.open.clear();
    state.examplesShown = false; state.settingsShown = false;
    if (snap.audit.length === 0 || snap.audit[0].seq !== 1) { setTimeout(poll, 0); return; }
  }
  for (const entry of snap.audit) { state.audit.push(entry); state.fresh.add(entry.seq); }
  if (snap.audit.length) state.lastSeq = snap.audit[snap.audit.length - 1].seq;
  if (state.audit.length > 800) state.audit = state.audit.slice(-800);
  state.snap = snap;
  showConsole();
  render(snap);
  setTimeout(poll, 450);
}

function render(snap) {
  $("system-id").textContent = snap.system_id;
  $("total-allow").textContent = snap.totals.ALLOW || 0;
  $("total-deny").textContent = snap.totals.DENY || 0;
  const pending = snap.approval_count || 0;
  $("total-approvals").textContent = pending;
  $("approval-badge").hidden = pending === 0;
  const seal = $("chain-seal");
  seal.textContent = snap.chain.ok ? `chain verified · ${snap.chain.rows}` : "chain BROKEN";
  seal.className = `seal ${snap.chain.ok ? "ok" : "broken"}`;
  $("operator-name").textContent = `operator: ${snap.operator}`;
  renderNetwork(snap);
  renderApprovals(snap);
  renderEscalations(snap);
  renderRun(snap);
  renderLog();
  renderChat(snap);
  renderControls(snap);
  state.fresh.clear();
}

function renderApprovals(snap) {
  const pending = (snap.approvals || []).filter((a) => a.status === "pending");
  $("approvals-empty").hidden = pending.length > 0;
  $("approvals").replaceChildren(...pending.map((a) => {
    const evidence = Object.entries(a.evidence || {}).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" · ");
    const args = Object.entries(a.args || {}).map(([k, v]) => `${k}=${v}`).join(", ");
    const approve = el("button", { type: "button", class: "primary", text: "Approve" });
    const deny = el("button", { type: "button", class: "danger-outline", text: "Deny" });
    approve.addEventListener("click", async () => {
      const r = await post(`/api/approvals/${a.approval_id}/approve`);
      say(r.ok ? `Approved ${a.approval_id}` : r.reason, r.ok);
    });
    deny.addEventListener("click", async () => {
      const reason = window.prompt("Denial reason", "not clinically appropriate") || "denied";
      const r = await post(`/api/approvals/${a.approval_id}/deny`, { reason });
      say(r.ok ? `Denied ${a.approval_id}` : r.reason, r.ok);
    });
    return el("li", { class: "approval-card" }, [
      el("div", { class: "approval-title", text: `${a.tool} · ${a.approval_id}` }),
      el("div", { class: "meta", text: `args: ${args}` }),
      evidence ? el("div", { class: "meta", text: `evidence: ${evidence}` }) : null,
      el("div", { class: "approval-actions" }, [approve, deny]),
    ]);
  }));
}

function renderEscalations(snap) {
  const open = (snap.escalations || []).filter((e) => e.status === "open");
  const banner = $("escalation-banner");
  if (!open.length) { banner.hidden = true; banner.replaceChildren(); return; }
  banner.hidden = false;
  banner.replaceChildren(...open.map((e) => {
    const ack = el("button", { type: "button", text: "Acknowledge" });
    ack.addEventListener("click", async () => {
      const r = await post(`/api/escalations/${e.escalation_id}/ack`);
      say(r.ok ? `Acknowledged ${e.escalation_id}` : r.reason, r.ok);
    });
    return el("div", { class: "escalation-item" }, [
      el("span", { text: `Escalation ${e.escalation_id}: ${e.trigger_reason} — ${e.summary}` }),
      e.page_id ? el("span", { class: "meta", text: `paged ${e.page_id}` }) : null,
      ack,
    ]);
  }));
}

// ---- agent network -----------------------------------------------------------------

function busyInstances(snap) {
  const run = snap.runs.find((r) => r.status === "running");
  const busy = new Set();
  if (!run) return busy;
  const active = run.steps.find((s) => s.status === "active" && s.instance);
  if (active) { busy.add(active.instance); busy.add(run.master); }
  return busy;
}

function agentCard(agent, busy) {
  const revoke = el("button", { class: "revoke", type: "button", text: "Revoke" });
  revoke.addEventListener("click", async (event) => {
    event.stopPropagation();
    if (!revoke.classList.contains("confirming")) {
      revoke.classList.add("confirming"); revoke.textContent = "Confirm";
      setTimeout(() => { revoke.classList.remove("confirming"); revoke.textContent = "Revoke"; }, 2500);
      return;
    }
    const r = await post("/api/revoke", { agent_id: agent.agent_id });
    say(r.ok ? `${agent.agent_id} revoked` : `${agent.agent_id}: ${r.reason}`, r.ok);
  });
  const classes = ["agent", agent.status, agent.master ? "master" : "", busy.has(agent.agent_id) ? "busy" : ""];
  return el("div", { class: classes.join(" ") }, [
    el("div", { class: "row" }, [
      el("span", { class: "name", text: agent.agent_id }),
      el("span", { class: `stamp ${agent.status}`, text: agent.status }),
    ]),
    el("div", { class: "row" }, [
      el("span", { class: "meta", text: agent.badge
        ? `badge ${agent.badge} · gen ${agent.generation}${agent.status === "active" ? ` · rotates in ${agent.rotate_in}s` : ""}`
        : "no badge issued" }),
      agent.status === "active" ? revoke : null,
    ]),
    el("div", { class: "idline" }, [
      agent.attested ? el("span", { class: "id-ok", text: "✓ code attested" })
        : agent.attestation_failed ? el("span", { class: "id-bad", text: "✗ attestation failed" }) : null,
      agent.key ? el("span", { class: "id-ok", text: `🔑 key ${agent.key}` }) : null,
    ]),
    agent.run_id ? el("div", { class: "meta", text: `for ${agent.run_id}` }) : null,
    agent.end_reason && agent.status !== "active" ? el("div", { class: "end-reason", text: agent.end_reason }) : null,
  ]);
}

function renderNetwork(snap) {
  const busy = busyInstances(snap);
  const masters = snap.agents.filter((a) => a.master);
  const externals = snap.agents.filter((a) => a.external);
  const shownMasters = masters.filter((a) => a.status === "active").concat(
    masters.filter((a) => a.status !== "active").slice(0, 2));
  const shownExt = externals.filter((a) => a.status === "active").concat(
    externals.filter((a) => a.status !== "active").slice(0, 3));
  $("master-row").replaceChildren(
    ...shownMasters.map((a) => agentCard(a, busy)),
    ...shownExt.map((a) => {
      const card = agentCard(a, busy);
      card.classList.add("external");
      return card;
    }),
  );

  const lanes = snap.roles.filter((r) => !r.master && !r.external).map((role) => {
    const instances = snap.agents.filter((a) => a.role === role.role);
    const live = instances.filter((a) => a.status === "active");
    const ended = instances.filter((a) => a.status !== "active");
    const visible = live.concat(ended.slice(0, live.length ? 1 : 2));
    const hidden = instances.length - visible.length;
    return el("div", { class: "lane" }, [
      el("div", { class: "lane-head", text: role.name }),
      el("div", { class: "lane-desc", text: role.description }),
      el("div", { class: "lane-tools", text: role.tools.join(" · ") }),
      el("div", { class: "instances" }, visible.length
        ? visible.map((a) => agentCard(a, busy))
        : [el("div", { class: "lane-empty", text: "no instance yet — spun up on first consult" })]),
      hidden > 0 ? el("div", { class: "more", text: `+${hidden} earlier instance${hidden > 1 ? "s" : ""}` }) : null,
    ]);
  });
  $("lanes").replaceChildren(...lanes);
}

// ---- current plan --------------------------------------------------------------------

function leaseEvents(leaseId) {
  return state.audit.filter((e) => e.detail && e.detail.lease === leaseId).map((e) => e.kind);
}

function resultChips(step) {
  if (!step.result) return null;
  const chips = Object.entries(step.result).map(([k, v]) => {
    const text = Array.isArray(v) ? (v.length ? v.join(", ") : "none") : String(v === "" ? "—" : v);
    let cls = "kv";
    if ((k === "status" && v === "blocked") || (k === "worst" && v === "major") || (k === "band" && v === "severe")
        || (k === "block_reasons" && v.length) || (k === "covered" && v === false)) cls += " alert";
    if ((k === "status" && v === "drafted") || (k === "covered" && v === true)) cls += " good";
    return el("span", { class: cls }, [el("b", { text: `${k} ` }), text]);
  });
  return el("div", { class: "result" }, chips);
}

function renderRun(snap) {
  const run = snap.runs[0];
  const steps = $("steps");
  const watchdog = $("watchdog");
  if (!run) { steps.replaceChildren(); $("run-empty").hidden = false; watchdog.hidden = true; $("run-meta").textContent = ""; return; }
  $("run-empty").hidden = run.steps.length > 0 || run.plans.length > 0;
  $("run-meta").textContent = `${run.run_id} · ${run.status} · master ${run.master}`;

  const limit = snap.settings.watchdog_seconds;
  watchdog.hidden = run.status !== "running";
  if (run.status === "running") {
    const pct = Math.min(100, (run.idle_seconds / limit) * 100);
    const fill = $("watchdog-fill");
    fill.style.width = `${pct}%`;
    fill.className = `watchdog-fill ${pct > 80 ? "hot" : pct > 50 ? "warn" : ""}`;
    $("watchdog-text").textContent = `${run.idle_seconds.toFixed(1)}s since last progress · revokes at ${limit}s`;
  }

  const items = [];
  for (const plan of run.plans) {
    const n = run.plans.length > 1 ? `Plan ${plan.seq} of ${run.plans.length} · ` : "";
    items.push(el("li", { class: `plan-label ${plan.status}`,
      text: plan.status === "approved"
        ? `${n}${plan.plan_id} · approved, its steps ran:`
        : `${n}${plan.plan_id} · rejected by the gateway, nothing in it ran (${human(plan.reason)}: ${plan.detail})`
          + (plan.seq < run.plans.length ? " — the master sent a corrected plan" : "") }));
    run.steps.filter((s) => s.plan_id === plan.plan_id).forEach((step) => {
      const kinds = leaseEvents(step.lease_id);
      const chip = (label, on, bad) => el("span", { class: `hs ${bad ? "bad" : on ? "on" : ""}`, text: label });
      const rejected = kinds.includes("OUTPUT_REJECTED");
      const refused = kinds.includes("HANDSHAKE_REFUSED");
      const discarded = kinds.includes("RESULT_DISCARDED");
      const args = Object.entries(step.args).map(([k, v]) => `${k}=${v}`).join(", ");
      const selected = state.selectedLease === step.lease_id;
      const li = el("li", { class: `step ${step.status} ${selected ? "selected" : ""}` }, [
        el("span", { class: "step-num", text: String(step.index + 1) }),
        el("div", {}, [
          el("div", { class: "step-call" }, [
            el("span", { class: "agent-ref", text: step.instance || step.agent }), `.${step.tool}(${args})`,
          ]),
          el("div", { class: "handshake" }, [
            chip("signed call", true),
            chip("lease", true),
            chip("delegation signed", kinds.includes("DELEGATED")),
            chip("sealed AES-GCM", kinds.includes("DELEGATED")),
            chip(refused ? "handshake refused" : "handshake", kinds.includes("HANDSHAKE"), refused),
            chip(rejected ? "output rejected" : discarded ? "result discarded" : "typed output",
              kinds.includes("DELIVERED"), rejected || discarded),
          ]),
          step.reason && step.reason !== "OK" ? el("div", { class: "step-sub", text: human(step.reason) }) : null,
          resultChips(step),
        ]),
        el("span", { class: `pill ${step.status}`, text: { used: "done", active: "leased", failed: "failed",
          revoked: "revoked", expired: "expired", unused: "not run",
          awaiting_approval: "awaiting approval" }[step.status] || step.status }),
      ]);
      li.addEventListener("click", () => {
        state.selectedLease = step.lease_id;
        renderHandshake(step.handshake);
        renderRun(state.snap);
      });
      items.push(li);
    });
  }
  steps.replaceChildren(...items);
  if (state.selectedLease) {
    const step = run.steps.find((s) => s.lease_id === state.selectedLease);
    if (step) renderHandshake(step.handshake);
  } else if (run.steps.length) {
    state.selectedLease = run.steps[run.steps.length - 1].lease_id;
    renderHandshake(run.steps[run.steps.length - 1].handshake);
  }
}

function renderHandshake(hs) {
  if (typeof drawHandshake !== "function") return;
  drawHandshake($("handshake-viz"), hs, {
    showMaster: state.showMasterSaw,
    onSelect: (hop) => {},
  });
}

// ---- security log ---------------------------------------------------------------------

function renderLog() {
  const entries = state.audit.filter((e) => state.filter === "all" || KEY_KINDS.has(e.kind)).slice(-250).reverse();
  const items = entries.map((e) => {
    const open = state.open.has(e.seq);
    const button = el("button", { type: "button", onclick: () => {
      if (state.open.has(e.seq)) state.open.delete(e.seq); else state.open.add(e.seq);
      renderLog();
    } }, [
      el("span", { class: "log-time", text: fmtTime(e.ts_ms) }),
      el("span", { class: "log-icon", text: ICON[e.decision] || "•" }),
      el("span", { class: "log-summary" }, [el("span", { class: "log-kind", text: e.kind }), e.summary]),
    ]);
    const detail = { seq: e.seq, run: e.run_id, actor: e.actor, target: e.target, reason: e.reason, ...e.detail };
    return el("li", { class: `log-item ${e.decision} ${state.fresh.has(e.seq) ? "fresh" : ""}` }, [
      button, open ? el("pre", { class: "log-detail", text: JSON.stringify(detail, null, 2) }) : null,
    ]);
  });
  $("log").replaceChildren(...items);
}

// ---- chat ------------------------------------------------------------------------------

// Minimal, safe markdown for model answers: **bold**, `code`, and "- " bullets. Builds DOM
// nodes from text (never innerHTML), so nothing in an answer can become markup.
function inline(text) {
  const nodes = [];
  for (const part of text.split(/(\*\*[^*]+\*\*|`[^`]+`)/)) {
    if (!part) continue;
    if (part.startsWith("**") && part.endsWith("**")) nodes.push(el("b", { text: part.slice(2, -2) }));
    else if (part.startsWith("`") && part.endsWith("`")) nodes.push(el("code", { text: part.slice(1, -1) }));
    else nodes.push(document.createTextNode(part));
  }
  return nodes;
}

function renderAnswer(text) {
  const blocks = [];
  let list = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const bullet = line.match(/^[-*•]\s+(.*)$/);
    if (bullet) {
      if (!list) { list = el("ul"); blocks.push(list); }
      list.append(el("li", {}, inline(bullet[1])));
      continue;
    }
    list = null;
    if (line) blocks.push(el("p", {}, inline(line.replace(/^#+\s*/, ""))));
  }
  return el("div", { class: "body md" }, blocks);
}

function renderChat(snap) {
  const master = snap.agents.find((a) => a.master && a.status === "active");
  $("master-id").replaceChildren(master
    ? el("span", {}, [el("b", { text: master.agent_id }), ` · badge ${master.badge} (gen ${master.generation}, rotates in ${master.rotate_in}s) · model ${snap.llm.model}`])
    : el("span", { text: "No active master. The next request spins up a new one with fresh credentials." }));
  const warn = $("llm-warning");
  warn.hidden = !snap.llm.problem;
  warn.textContent = snap.llm.problem ? `LLM not ready: ${snap.llm.problem}` : "";

  const items = [];
  for (const run of [...snap.runs].reverse()) {
    if (String(run.prompt || "").startsWith("[mcp]")) continue;
    items.push(el("li", { class: "msg user" }, [el("div", { class: "who", text: `you → ${run.master}` }),
      el("div", { class: "body", text: run.prompt })]));
    let body;
    if (run.status === "running") {
      const total = run.steps.length;
      const done = run.steps.filter((s) => s.status === "used").length;
      body = el("div", { class: "body typing", text: total ? `consulting specialists (${done}/${total})` : "planning" });
    } else if (run.status === "done") {
      body = renderAnswer(run.answer || "");
    } else {
      body = el("div", { class: "body", text: `Run ${run.status}. ${run.error || ""}` });
    }
    items.push(el("li", { class: `msg agent ${run.status === "done" ? "" : run.status === "running" ? "" : "failed"}` }, [
      el("div", { class: "who", text: `${run.master} · ${run.run_id}` }), body,
      run.flagged ? el("div", { class: "flag", text: "⚑ injection pattern flagged in this request" }) : null,
    ]));
  }
  const list = $("messages");
  const stick = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
  list.replaceChildren(...items);
  if (stick) list.scrollTop = list.scrollHeight;
  $("send").disabled = snap.busy;

  if (!state.examplesShown) {
    state.examplesShown = true;
    $("examples").replaceChildren(...snap.examples.map((text) => el("button", {
      type: "button", class: `example ${/ignore|admin mode/i.test(text) ? "attack" : ""}`, text, title: text,
      onclick: () => { $("prompt").value = text; send(); },
    })));
  }
}

async function send(event) {
  if (event) event.preventDefault();
  const prompt = $("prompt").value.trim();
  if (!prompt) return;
  const r = await post("/api/chat", { prompt, stuck: $("stuck").checked });
  if (r.ok) {
    $("prompt").value = ""; $("stuck").checked = false;
    document.querySelector(".examples-wrap").open = false;
  }
  else say(r.reason === "BUSY" ? "The master is still working on the last request." : r.reason, false);
}

// ---- controls -----------------------------------------------------------------------------

function renderControls(snap) {
  if (!state.mcpRolesShown && snap.external_roles) {
    state.mcpRolesShown = true;
    $("mcp-role").replaceChildren(...snap.external_roles.map((r) =>
      el("option", { value: r.role, text: `${r.name} (${r.role})` })));
  }
  if (state.settingsShown) return;
  state.settingsShown = true;
  $("watchdog-seconds").value = snap.settings.watchdog_seconds;
  $("step-delay").value = snap.settings.step_delay_ms;
  $("step-delay-text").textContent = `${snap.settings.step_delay_ms} ms`;
  $("replace").checked = snap.settings.replace_revoked_specialists;
}

async function saveSettings() {
  const body = {
    watchdog_seconds: Number($("watchdog-seconds").value),
    step_delay_ms: Number($("step-delay").value),
    replace_revoked_specialists: $("replace").checked,
  };
  $("step-delay-text").textContent = `${body.step_delay_ms} ms`;
  const r = await post("/api/settings", body);
  if (r.ok) $("watchdog-seconds").value = r.settings.watchdog_seconds;
  say(r.ok ? "Settings saved" : r.reason, r.ok);
}

// ---- login --------------------------------------------------------------------------------

function showLogin() { $("login").hidden = false; $("console").hidden = true; $("logout").hidden = true; }
function showConsole() { $("login").hidden = true; $("console").hidden = false; $("logout").hidden = false; }

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    const r = await post("/api/login", { username: data.get("username"), password: data.get("password") });
    if (!r.ok) { $("login-error").textContent = "Wrong username or password."; return; }
    $("login-error").textContent = ""; poll();
  });
  $("logout").addEventListener("click", async () => { await post("/api/logout"); showLogin(); });
  $("chat-form").addEventListener("submit", send);
  $("prompt").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) send(e); });
  for (const id of ["watchdog-seconds", "step-delay", "replace"]) $(id).addEventListener("change", saveSettings);
  $("step-delay").addEventListener("input", () => { $("step-delay-text").textContent = `${$("step-delay").value} ms`; });
  const attack = (id, path) => $(id).addEventListener("click", async () => {
    const r = await post(path);
    say(r.ok ? r.results.map((x) => `${x.attempt}: ${human(x.result)}`).join(" · ") : r.reason, r.ok);
  });
  attack("rogue", "/api/rogue");
  attack("steal", "/api/attack/steal");
  attack("tampered", "/api/attack/tampered");
  $("issue-mcp").addEventListener("click", () => {
    $("mcp-issue").hidden = !$("mcp-issue").hidden;
    $("mcp-issue-out").hidden = true;
  });
  $("mcp-issue-go").addEventListener("click", async () => {
    const role = $("mcp-role").value;
    const r = await post("/api/mcp/issue", { role });
    if (!r.ok) { say(r.reason, false); return; }
    const out = $("mcp-issue-out");
    out.hidden = false;
    out.textContent =
      `client_id=${r.client_id}\nsecret=${r.secret}\nrole=${r.role}\n\n${r.warning}\n` +
      `Set WARD_URL, WARD_CLIENT_ID, WARD_CLIENT_SECRET for scripts/badge_agent.py`;
    say(`Issued ${r.client_id} — copy the secret now`, true);
  });
  $("reset").addEventListener("click", async () => {
    const r = await post("/api/reset");
    state.examplesShown = false; state.settingsShown = false; state.mcpRolesShown = false;
    say(r.ok ? "Fresh gateway, fresh agents, fresh audit log." : r.reason, r.ok);
  });
  document.querySelectorAll(".seg-btn").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".seg-btn").forEach((x) => x.classList.toggle("on", x === b));
    state.filter = b.dataset.filter; renderLog();
  }));
  $("master-saw-toggle").addEventListener("change", (e) => {
    state.showMasterSaw = e.target.checked;
    if (state.snap && state.selectedLease) {
      const run = state.snap.runs[0];
      const step = run && run.steps.find((s) => s.lease_id === state.selectedLease);
      if (step) renderHandshake(step.handshake);
    }
  });
  poll();
});
