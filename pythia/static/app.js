// Pythia dashboard. Server values are inserted as text only (el() uses textContent).
"use strict";

let current = null;
const badge = (text, kind) => el("span", { class: `badge${kind ? ` badge--${kind}` : ""}` }, text);
const RESULT = { blocked: "bad", forwarded: "good", cached: "accent", error: "warn", refused: "warn" };

function stat(value, label, sub) {
  return el("div", { class: "stat" }, el("div", { class: "stat__value" }, value),
    el("div", { class: "stat__label" }, label), sub ? el("div", { class: "stat__sub" }, sub) : null);
}

function ago(seconds) {
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} days`;
}

function renderHeader(s) {
  const st = $("#state");
  st.textContent = s.blocking ? "blocking" : `paused until ${new Date(s.paused_until).toLocaleTimeString()}`;
  st.className = `badge badge--${s.blocking ? "good" : "warn"}`;
  $("#resume").hidden = s.blocking;
  document.querySelectorAll("#pause-actions [data-minutes]:not(#resume)").forEach((b) => { b.hidden = !s.blocking; });
}

function renderStats(s) {
  $("#stats").replaceChildren(
    stat(s.queries_24h.toLocaleString(), "queries (24 h)", `${s.cached_24h} from cache`),
    stat(s.blocked_24h.toLocaleString(), "blocked (24 h)", `${s.blocked_percent_24h}% of all · ${s.blocked_30d.toLocaleString()} in 30 days`),
    stat(String(s.clients), "devices seen", `since ${ago(s.uptime_s)} ago`),
    stat(s.domains_on_lists.toLocaleString(), "domains on lists", `${s.allow_entries} allowed by you`),
    stat(String(s.errors_24h), "upstream errors (24 h)", s.upstreams.map((u) => `${u.server}${u.failures_in_a_row ? " ✗" : ""}`).join(" · ")),
  );
}

function renderChart(target, series, label) {
  const max = Math.max(1, ...series.map((x) => x.queries));
  $(target).replaceChildren(...series.map((x) => {
    const col = el("div", { class: "col", title: `${label(x)} · ${x.queries} queries, ${x.blocked} blocked` });
    const q = el("div", { class: "q" });
    const b = el("div", { class: "b" });
    q.style.height = `${(100 * (x.queries - x.blocked)) / max}%`;
    b.style.height = `${(100 * x.blocked) / max}%`;
    col.append(q, b);
    return col;
  }));
  $("#legend").textContent = "light: allowed · dark: blocked";
}

function toplist(id, rows, actionLabel, action) {
  const items = rows.map(([name, n]) => el("li", {}, name, el("span", { class: "n" }, String(n)),
    action ? el("button", { class: "rule-x", title: `${actionLabel} ${name}`, onclick: () => action(name) }, "⊕") : null));
  if (!items.length) items.push(el("li", { class: "muted" }, "nothing yet"));
  $(id).replaceChildren(...items);
}

function renderRecent(rows, logging) {
  const q = $("#filter").value.trim().toLowerCase();
  const only = $("#only").value;
  const list = rows.filter((r) => (!only || r.result === only) && (!q || `${r.name} ${r.client}`.toLowerCase().includes(q)));
  if (!logging) {
    $("#recent").replaceChildren(el("tr", {}, el("td", { colspan: 6, class: "muted" }, "Query logging is off (log_queries = false).")));
    return;
  }
  $("#recent").replaceChildren(...list.map((r) => el("tr", {},
    el("td", { class: "mono" }, new Date(r.time * 1000).toLocaleTimeString()),
    el("td", { class: "mono" }, r.client),
    el("td", { class: "name" }, r.name || "–", r.rule && r.result === "blocked" && r.rule !== r.name ? el("span", { class: "muted" }, ` (via ${r.rule})`) : null),
    el("td", {}, r.qtype),
    el("td", {}, badge(r.result, RESULT[r.result])),
    el("td", {}, r.result === "blocked" && r.name
      ? el("button", { class: "btn btn--small btn--ghost", onclick: () => rule("allow", r.name) }, "allow")
      : r.result !== "blocked" && r.name ? el("button", { class: "btn btn--small btn--ghost", onclick: () => rule("block", r.name) }, "block") : null),
  )));
}

function renderRules(allow, block) {
  const list = (id, items, kind) => $(id).replaceChildren(...(items.length ? items.map((d) => el("li", {}, d,
    el("button", { class: "rule-x", title: `remove ${d}`, onclick: () => rule(kind, d, true) }, "×"))) : [el("li", { class: "muted" }, "none")]));
  list("#allow", allow, "allow");
  list("#block", block, "block");
}

function renderLists(s) {
  const rows = Object.entries(s.lists).map(([name, n]) => el("div", { class: "item" }, el("span", {}, name), el("span", { class: "mono" }, n.toLocaleString())));
  rows.push(el("div", { class: "item" }, el("span", { class: "muted" }, "listening"), el("span", { class: "mono" }, s.listening.join(", "))));
  for (const p of s.profiles || []) {
    rows.push(el("div", { class: "item" },
      el("span", {}, `profile ${p.name} `, el("span", { class: "muted" }, `(${p.clients.join(", ")} · ${p.blocked_names} blocked, ${p.allowed_names} allowed${p.bedtime ? ` · bedtime ${p.bedtime}` : ""})`)),
      p.bedtime_now ? badge("bedtime now", "warn") : badge("active", "good")));
  }
  for (const u of s.upstreams) {
    rows.push(el("div", { class: "item" }, el("span", { class: "muted" }, `upstream ${u.server}${u.encrypted ? " 🔒" : " (plain)"}`),
      u.failures_in_a_row ? badge(`${u.failures_in_a_row} failures`, "bad") : badge(u.last_ok ? "ok" : "unused", u.last_ok ? "good" : "")));
  }
  $("#lists").replaceChildren(...rows);
}

function render(data) {
  current = data;
  $("#error").hidden = true;
  const s = data.summary;
  renderHeader(s);
  renderStats(s);
  renderChart("#chart", data.series, (x) => `${new Date(x.hour * 1000).getHours()}:00`);
  renderChart("#chart-days", data.days, (x) => x.date);
  const known = data.days.filter((d) => d.queries).length;
  $("#days-note").textContent = known
    ? `${s.queries_30d.toLocaleString()} queries, ${s.blocked_30d.toLocaleString()} blocked (${s.blocked_percent_30d}%) · ${known} day(s) with data`
    : "no days recorded yet";
  toplist("#top-blocked", data.top_blocked, "allow", (d) => rule("allow", d));
  toplist("#top-allowed", data.top_allowed, "block", (d) => rule("block", d));
  toplist("#clients", data.clients);
  renderRecent(data.recent, data.log_queries);
  renderRules(data.allow, data.block);
  renderLists(s);
}

async function load() {
  try {
    render(await api("/api/state"));
  } catch (err) {
    const e = $("#error");
    e.textContent = `Could not load: ${err.message}`;
    e.hidden = false;
  }
}

async function rule(kind, domain, remove = false) {
  try {
    await api(`/api/${kind}`, { domain, remove });
    toast(`${remove ? "Removed" : kind === "allow" ? "Allowed" : "Blocked"}: ${domain}`);
    load();
  } catch (err) {
    toast(err.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-minutes]").forEach((b) => b.addEventListener("click", async () => {
    render({ ...current, summary: await api("/api/pause", { minutes: Number(b.dataset.minutes) }) });
  }));
  let kind = "allow";
  document.querySelectorAll("#rule [data-kind]").forEach((b) => b.addEventListener("click", () => { kind = b.dataset.kind; }));
  $("#rule").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const d = $("#domain").value.trim();
    if (d) rule(kind, d).then(() => { $("#domain").value = ""; });
  });
  $("#domain").addEventListener("input", async () => {
    const d = $("#domain").value.trim();
    if (!d.includes(".")) { $("#verdict").textContent = ""; return; }
    const v = await api("/api/check", { domain: d }).catch(() => null);
    $("#verdict").textContent = !v || !v.domain ? "" : v.blocked ? `${v.domain} is blocked (by ${v.rule})` : `${v.domain} is allowed${v.rule ? ` (your rule ${v.rule})` : ""}`;
  });
  $("#update").addEventListener("click", async () => { await api("/api/update-lists", {}); toast("Updating lists in the background…"); });
  for (const id of ["#filter", "#only"]) $(id).addEventListener("input", () => current && renderRecent(current.recent, current.log_queries));
  load();
  setInterval(load, 10000);
});
