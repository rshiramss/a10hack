// Badge monitor console. Polls /api/snapshot once a second and renders with textContent
// only (never innerHTML), so nothing an agent sends can execute in the monitor's browser.
"use strict";

const POLL_MS = 1000;
const CSRF_HEADERS = { "Content-Type": "application/json", "X-Badge-Dashboard": "1" };
const LOW_LEASE_MS = 60_000;

const state = { auditFilter: null, lastSeq: 0, serverOffsetMs: 0, monitor: null, pollTimer: null };
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child !== null && child !== undefined) node.append(child);
  }
  return node;
}

function replaceChildren(container, nodes, emptyText) {
  container.replaceChildren(...(nodes.length ? nodes : [el("li", { class: "empty", text: emptyText })]));
}

const clockTime = (ms) => new Date(ms).toLocaleTimeString([], { hour12: false });
const newKey = () => crypto.randomUUID();

// ---- network ------------------------------------------------------------------

async function fetchSnapshot() {
  const query = state.auditFilter ? `?agent=${encodeURIComponent(state.auditFilter)}` : "";
  const response = await fetch(`/api/snapshot${query}`, { credentials: "same-origin" });
  if (response.status === 401) return null;
  return response.json();
}

async function monitorAction(tool, args) {
  const response = await fetch(`/api/monitor/${tool}`, {
    method: "POST",
    credentials: "same-origin",
    headers: CSRF_HEADERS,
    body: JSON.stringify({ args, idempotency_key: newKey() }),
  });
  return response.json();
}

function reportAction(result, okText) {
  const line = $("action-status");
  line.className = `status-line ${result.ok ? "good" : "bad"}`;
  line.textContent = result.ok ? okText : `${result.reason}: ${result.detail || ""}`;
}

// ---- rendering ----------------------------------------------------------------

function renderMasthead(snap) {
  $("trial-id").textContent = snap.trial_id;
  $("total-allow").textContent = snap.totals.ALLOW;
  $("total-deny").textContent = snap.totals.DENY;
  $("monitor-name").textContent = `signed in: ${snap.monitor}`;
  const seal = $("chain-seal");
  seal.className = `seal ${snap.chain.ok ? "ok" : "broken"}`;
  seal.textContent = snap.chain.ok
    ? `chain verified ✓ ${snap.chain.rows} rows`
    : `chain broken at #${snap.chain.first_bad_seq}`;

  const approved = snap.unblind_requests.filter((r) => r.status === "approved");
  const banner = $("unblind-banner");
  banner.hidden = approved.length === 0;
  banner.textContent = approved
    .map((r) => `EMERGENCY UNBLIND: patient ${r.patient_id} (requested by ${r.requested_by}, approved by ${r.approved_by}) — outcomes flagged`)
    .join("  ·  ");
}

function agentCard(agent) {
  const plan = agent.plans[0];
  const progress = plan
    ? el("div", { class: "progress", title: `next: ${plan.next_tool || "done"}` },
        Array.from({ length: plan.steps_total }, (_, i) => el("span", { class: i < plan.steps_used ? "done" : "" })))
    : null;
  const openTasks = agent.tasks.filter((t) => t.status === "assigned").map((t) => t.task_id);
  const revoke = el("button", { class: "revoke", type: "button", text: "Revoke" });
  revoke.addEventListener("click", async () => {
    if (!revoke.classList.contains("confirming")) {
      revoke.classList.add("confirming");
      revoke.textContent = "Confirm revoke";
      return;
    }
    const result = await monitorAction("revoke_badge", { agent_id: agent.agent_id, reason: "Revoked from dashboard" });
    reportAction(result, `${agent.agent_id} revoked`);
    poll();
  });
  const canRevoke = agent.status !== "revoked" && agent.agent_id !== state.monitor;
  return el("article", { class: `agent ${agent.status}` }, [
    el("span", { class: `stamp ${agent.status}`, text: agent.status }),
    el("div", { class: "agent-name", text: agent.agent_id }),
    el("div", { class: "agent-role", text: agent.role }),
    el("div", { class: "agent-task", text: openTasks.length ? `tasks: ${openTasks.join(", ")}` : "no open tasks" }),
    progress,
    el("div", { class: "agent-actions" }, [
      el("button", { type: "button", text: "Filter feed", onclick: () => setFilter(agent.agent_id) }),
      canRevoke ? revoke : null,
    ]),
  ]);
}

function renderAgents(snap) {
  const nodes = snap.agents.map(agentCard);
  $("agents").replaceChildren(...(nodes.length ? nodes : [el("p", { class: "empty", text: "No agents yet." })]));
}

function auditRow(entry, fresh) {
  const classes = ["audit-row", entry.decision, entry.severity === "high" ? "high" : "", fresh ? "fresh" : ""];
  const what = [entry.agent_id || "unknown", entry.tool ? ` → ${entry.tool}` : ""].join("");
  return el("li", { class: classes.join(" ").trim() }, [
    el("span", { class: "audit-seq", text: `#${entry.seq}` }),
    el("span", { class: "audit-time", text: clockTime(entry.ts_ms) }),
    el("span", { class: "audit-main" }, [
      el("span", { class: "audit-agent", text: what }),
      " ",
      el("span", { class: `reason ${entry.decision}`, text: entry.reason }),
      entry.action && entry.action !== "none" ? el("span", { text: ` [${entry.action}]` }) : null,
    ]),
    entry.detail ? el("span", { class: "audit-detail", text: entry.detail }) : null,
  ]);
}

function renderAudit(snap) {
  const newest = snap.audit.length ? snap.audit[0].seq : 0;
  const nodes = snap.audit.map((entry) => auditRow(entry, state.lastSeq && entry.seq > state.lastSeq));
  state.lastSeq = Math.max(state.lastSeq, newest);
  replaceChildren($("audit"), nodes, "No audit entries.");
  const clear = $("clear-filter");
  clear.hidden = !state.auditFilter;
  clear.textContent = state.auditFilter ? `filter: ${state.auditFilter} ✕` : "";
}

function renderLeases(snap) {
  const nodes = snap.leases.map((lease) => {
    const bar = el("span", {});
    bar.dataset.expires = lease.expires_at_ms;
    const args = Object.entries(lease.bound_args).map(([k, v]) => `${k}=${v}`).join(" ");
    const remaining = el("span", { class: "muted" });
    remaining.dataset.expires = lease.expires_at_ms;
    return el("li", { class: "lease" }, [
      el("div", {}, [el("b", { text: lease.agent_id }), ` step ${lease.step_index + 1}: ${lease.tool} `, el("span", { class: "muted", text: args })]),
      el("div", { class: "lease-bar" }, bar),
      remaining,
    ]);
  });
  replaceChildren($("leases"), nodes, "No active leases.");
  tickCountdowns();
}

function valueChips(value) {
  if (!value) return [el("span", { class: "kv", text: "REJECTED" })];
  return Object.entries(value).flatMap(([key, v]) =>
    v !== null && typeof v === "object"
      ? Object.entries(v).map(([k2, v2]) => el("span", { class: "kv", text: `${k2}=${v2}` }))
      : [el("span", { class: "kv", text: `${key}=${v}` })]);
}

function renderHandoffs(snap) {
  const nodes = snap.handoffs.map((h) => el("li", {
    class: `handoff ${h.valid ? "" : "invalid"} ${h.producer_revoked ? "revoked" : ""}`.trim(),
  }, [
    el("span", { class: "channel", text: h.channel }),
    el("span", { text: `${h.resource_id}${h.slot ? ` slot ${h.slot}` : ""}` }),
    ...valueChips(h.value),
    h.producer_revoked ? el("span", { class: "reason DENY", text: "producer revoked" }) : null,
  ]));
  replaceChildren($("handoffs"), nodes, "No handoffs yet.");
}

function renderOutcomes(snap) {
  const rows = snap.outcomes.map((o) => el("tr", {
    class: [o.flags.length ? "flagged" : "", o.superseded ? "superseded" : ""].join(" ").trim(),
  }, [
    el("td", { text: o.visit_id }),
    el("td", { text: o.slot }),
    el("td", { text: o.measure }),
    el("td", { class: "score", text: o.value }),
    el("td", { text: o.agent_id }),
    el("td", { text: o.flags.join(", ") || (o.submitted ? "final" : "draft") }),
  ]));
  $("outcomes").replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { class: "empty", colspan: "6", text: "No outcomes yet." }))]));
}

function renderEscalations(snap) {
  replaceChildren($("escalations"), snap.escalations.map((e) => el("li", { class: "escalation" }, [
    el("span", { class: "delta", text: e.max_delta }),
    el("span", {}, [el("b", { text: e.visit_id }), el("br"), el("span", { class: "muted", text: "reads disagree — human review" })]),
  ])), "Queue empty.");
  replaceChildren($("alerts"), snap.alerts.map((a) => el("li", { class: "alert", text: `${clockTime(a.created_at_ms)} ${a.kind}: ${a.detail}` })), "No alerts.");
}

function renderRequests(snap) {
  const nodes = snap.unblind_requests.map((r) => {
    const children = [el("b", { text: r.request_id }), `patient ${r.patient_id}`, el("span", { class: "muted", text: `by ${r.requested_by}` }), el("span", { class: `reason ${r.status === "approved" ? "DENY" : "EVENT"}`, text: r.status })];
    if (r.status === "pending" && r.requested_by !== state.monitor) {
      children.push(el("button", { class: "danger", type: "button", text: "Approve (second monitor)", onclick: async () => {
        reportAction(await monitorAction("approve_emergency_unblind", { request_id: r.request_id }), `${r.request_id} approved — single-use lease for 5 minutes`);
        poll();
      } }));
    }
    if (r.status === "approved" && r.approved_by === state.monitor) {
      children.push(el("button", { class: "primary", type: "button", text: "Reveal arm (once)", onclick: async () => {
        const result = await monitorAction("view_emergency_unblind", { request_id: r.request_id });
        const reveal = $("reveal");
        reveal.hidden = !result.ok;
        if (result.ok) reveal.textContent = `Patient ${result.result.patient_id}: ${result.result.arm.toUpperCase()} arm. This lease is now spent.`;
        reportAction(result, "Revealed to you only.");
        poll();
      } }));
    }
    return el("li", { class: "request" }, children);
  });
  replaceChildren($("unblind-requests"), nodes, "No unblind requests.");
}

function render(snap) {
  state.monitor = snap.monitor;
  state.serverOffsetMs = snap.now_ms - Date.now();
  renderMasthead(snap);
  renderAgents(snap);
  renderAudit(snap);
  renderLeases(snap);
  renderHandoffs(snap);
  renderOutcomes(snap);
  renderEscalations(snap);
  renderRequests(snap);
}

function tickCountdowns() {
  const now = Date.now() + state.serverOffsetMs;
  for (const node of document.querySelectorAll("[data-expires]")) {
    const left = Math.max(0, Number(node.dataset.expires) - now);
    if (node.tagName === "SPAN" && node.parentElement.classList.contains("lease-bar")) {
      node.style.transform = `scaleX(${Math.min(1, left / 600_000)})`;
      node.parentElement.classList.toggle("low", left < LOW_LEASE_MS);
    } else {
      node.textContent = `${Math.ceil(left / 1000)}s left`;
    }
  }
}

// ---- control flow -------------------------------------------------------------

function showLogin(isLoggedIn) {
  $("login").hidden = isLoggedIn;
  $("console").hidden = !isLoggedIn;
  $("logout").hidden = !isLoggedIn;
}

async function poll() {
  try {
    const snap = await fetchSnapshot();
    showLogin(Boolean(snap));
    if (snap) render(snap);
  } catch (error) {
    $("action-status").textContent = "Gateway unreachable — retrying…";
  }
}

function setFilter(agentId) {
  state.auditFilter = agentId;
  state.lastSeq = 0;
  poll();
}

$("clear-filter").addEventListener("click", () => setFilter(null));

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const response = await fetch("/auth/login", {
    method: "POST",
    credentials: "same-origin",
    headers: CSRF_HEADERS,
    body: JSON.stringify({ username: form.get("username"), password: form.get("password") }),
  });
  const result = await response.json();
  $("login-error").textContent = result.ok ? "" : result.reason;
  if (result.ok) {
    event.target.reset();
    poll();
  }
});

$("logout").addEventListener("click", async () => {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin", headers: CSRF_HEADERS });
  $("reveal").hidden = true;
  showLogin(false);
});

$("unblind-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const result = await monitorAction("request_emergency_unblind", { patient_id: form.get("patient_id"), reason: form.get("reason") });
  reportAction(result, `Request ${result.result ? result.result.request_id : ""} filed — a second monitor must approve`);
  if (result.ok) event.target.reset();
  poll();
});

poll();
state.pollTimer = setInterval(poll, POLL_MS);
setInterval(tickCountdowns, 250);
