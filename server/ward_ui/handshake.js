"use strict";
// Animated three-lane consult diagram. Data comes from gateway snapshot only.
// textContent / createElement only — never innerHTML with data.

const LANE_X = { caller: 80, gateway: 280, specialist: 480 };
const REDUCE = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function laneTitle(hs, lane) {
  if (lane === "caller") return hs.caller_label || "Caller";
  if (lane === "gateway") return "Gateway";
  return hs.specialist_label || "Specialist";
}

function drawHandshake(container, hs, opts = {}) {
  container.replaceChildren();
  if (!hs || !hs.hops) {
    container.append(el("p", { class: "muted", text: "Select a plan step to inspect the handshake." }));
    return;
  }
  const showMaster = !!opts.showMaster;
  const wrap = el("div", { class: "hs-viz" });
  const svgNS = "http://www.w3.org/2000/svg";
  const height = 56 + hs.hops.length * 44;
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 560 ${height}`);
  svg.setAttribute("class", "hs-svg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Consult handshake sequence");

  for (const [lane, x] of Object.entries(LANE_X)) {
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("x1", x); line.setAttribute("x2", x);
    line.setAttribute("y1", 36); line.setAttribute("y2", height - 8);
    line.setAttribute("class", "hs-lane");
    svg.appendChild(line);
    const label = document.createElementNS(svgNS, "text");
    label.setAttribute("x", x); label.setAttribute("y", 20);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("class", "hs-lane-label");
    label.textContent = laneTitle(hs, lane);
    svg.appendChild(label);
  }

  const arrows = [];
  hs.hops.forEach((hop, index) => {
    const y = 52 + index * 44;
    const x1 = LANE_X[hop.from] || LANE_X.gateway;
    const x2 = LANE_X[hop.to] || LANE_X.gateway;
    const g = document.createElementNS(svgNS, "g");
    g.setAttribute("class", `hs-hop ${hop.status}`);
    g.setAttribute("data-hop", hop.id);
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("x1", x1); line.setAttribute("y1", y);
    line.setAttribute("x2", x2); line.setAttribute("y2", y);
    line.setAttribute("marker-end", "url(#hs-arrow)");
    line.setAttribute("class", "hs-arrow");
    g.appendChild(line);
    const text = document.createElementNS(svgNS, "text");
    text.setAttribute("x", (x1 + x2) / 2);
    text.setAttribute("y", y - 8);
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("class", "hs-hop-label");
    text.textContent = hop.label;
    g.appendChild(text);
    svg.appendChild(g);
    arrows.push(g);
    g.addEventListener("click", () => {
      if (opts.onSelect) opts.onSelect(hop);
    });
  });

  const defs = document.createElementNS(svgNS, "defs");
  const marker = document.createElementNS(svgNS, "marker");
  marker.setAttribute("id", "hs-arrow");
  marker.setAttribute("markerWidth", "8");
  marker.setAttribute("markerHeight", "8");
  marker.setAttribute("refX", "6");
  marker.setAttribute("refY", "3");
  marker.setAttribute("orient", "auto");
  const tip = document.createElementNS(svgNS, "path");
  tip.setAttribute("d", "M0,0 L6,3 L0,6 Z");
  tip.setAttribute("fill", "currentColor");
  marker.appendChild(tip);
  defs.appendChild(marker);
  svg.insertBefore(defs, svg.firstChild);

  wrap.append(svg);
  const inspector = el("pre", { class: "hs-inspector", text: "Click a hop for non-secret details." });
  wrap.append(inspector);
  if (showMaster) {
    wrap.append(el("div", { class: "hs-master-saw" }, [
      el("div", { class: "hs-master-label", text: "What the master actually saw" }),
      el("pre", { class: "hs-master-body", text: hs.master_saw ? JSON.stringify(hs.master_saw, null, 2) : "(nothing delivered)" }),
    ]));
  }
  container.append(wrap);

  const reveal = (i) => {
    if (i >= arrows.length) return;
    arrows[i].classList.add("visible");
    if (arrows[i].classList.contains("fail")) return;
    if (REDUCE) {
      for (let j = i; j < arrows.length; j++) arrows[j].classList.add("visible");
      return;
    }
    setTimeout(() => reveal(i + 1), 280);
  };
  if (REDUCE) arrows.forEach((a) => a.classList.add("visible"));
  else reveal(0);

  opts._setInspector = (hop) => {
    inspector.textContent = JSON.stringify({ id: hop.id, status: hop.status, ...hop.inspector }, null, 2);
  };
}

// el() is defined in app.js; handshake.js loads after it.
