"""
Web console for the central management server (SIH26148 deliverable 3).

The server speaks JSON to agents; ``GET /`` answers with this page so a human
can dispatch jobs, watch the enrolled fleet and read findings without shelling
out for every request.

Layout constraints shape the design. The container image copies the ``jocky``
package and nothing else, so the whole UI — CSS, markup and JavaScript — lives
inline in this module rather than in a templates directory that would not be
shipped. Nothing is fetched from a third-party host either: the server is
expected to run on a range with no egress, where a CDN reference would render a
blank page. Standard library only, no build step.

The page itself holds no data and no credential, so it is served without a
token (the same reasoning as Grafana's login page). The operator pastes the
server token into the header field, the browser keeps it in ``localStorage``
and attaches it as ``X-JKY-Token`` on every JSON call.

Trust model: the console renders strings an attacker can influence — an agent
chooses its own ``name``/``host`` at enrolment, and a job payload composes its
own finding titles, checks and evidence. The UI therefore builds the DOM with
``document.createElement`` and assigns text through ``textContent`` only;
no markup string ever reaches ``innerHTML``, so a hostile agent name is
displayed as characters rather than parsed as script.
"""
from __future__ import annotations

__all__ = ["DASHBOARD_HTML", "render"]

# The page is one literal so that ``serve`` can answer ``GET /`` with a constant
# and the Dockerfile needs no data files. It is kept formatted for reading: the
# few bytes of indentation are cheaper than an unreadable blob.
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<link rel="icon" href="data:,">
<title>JOCKY - central management console</title>
<style>
:root {
  --bg: #0f1218;
  --panel: #141922;
  --panel-2: #171d28;
  --line: #222836;
  --line-soft: #1d2331;
  --text: #e6e9f0;
  --muted: #98a2b8;
  --accent: #2c5aa8;
  --crit: #d13438;
  --high: #e8590c;
  --med: #d9a800;
  --low: #3b82f6;
  --info: #6b7280;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12.5px;
}
.dim { color: var(--muted); }
header.top {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  padding: 13px 20px;
  background: #12161f;
  border-bottom: 1px solid var(--line);
}
.brand { font-size: 15px; font-weight: 600; letter-spacing: .04em; }
.brand small { display: block; font-weight: 400; color: var(--muted); letter-spacing: 0; font-size: 11.5px; }
.spacer { flex: 1 1 auto; }
.pill {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 3px 10px;
  font-size: 12px;
  color: var(--muted);
  white-space: nowrap;
}
.pill.on { border-color: #1d7a4d; color: #4ade80; }
.pill.off { border-color: #5a2b2b; color: #f87171; }
main { max-width: 1200px; margin: 0 auto; padding: 18px 20px 8px; }
section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 15px 16px;
  margin-bottom: 16px;
}
h2 {
  margin: 0 0 12px;
  font-size: 12.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--muted);
}
h2 .dim { text-transform: none; letter-spacing: 0; font-weight: 400; }
input, select, textarea, button {
  font: inherit;
  color: inherit;
  background: #0f131b;
  border: 1px solid #2a3143;
  border-radius: 7px;
  padding: 7px 10px;
}
input:focus, select:focus, textarea:focus, button:focus { outline: 2px solid var(--accent); }
button { cursor: pointer; background: #1b2230; }
button.primary { background: var(--accent); border-color: #3b6fc4; font-weight: 600; padding: 7px 14px; }
button:disabled { opacity: .55; cursor: progress; }
button.link {
  background: none;
  border: none;
  padding: 0;
  font-size: 12px;
  color: #79aaff;
  text-decoration: underline;
}
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.toolbar.gap { margin-bottom: 12px; }
label.field { display: flex; gap: 6px; align-items: center; color: var(--muted); font-size: 12.5px; }
label.stack { display: flex; flex-direction: column; gap: 6px; color: var(--muted); font-size: 12.5px; }
.hint { margin: 8px 0 0; color: var(--muted); font-size: 12px; }
.ok { color: #4ade80; }
.bad { color: #f87171; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
th {
  color: var(--muted);
  font-size: 11.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .06em;
  white-space: nowrap;
}
tbody tr:hover { background: var(--panel-2); }
.stats { display: flex; flex-wrap: wrap; gap: 10px; }
.stat {
  flex: 1 1 92px;
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 8px 11px;
}
.stat-value { display: block; font-size: 20px; font-weight: 600; }
.stat-label { display: block; font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
.stat-error .stat-value { color: #f87171; }
.stat-ok .stat-value { color: #4ade80; }
.stat-running .stat-value { color: #60a5fa; }
.stat-queued .stat-value { color: var(--med); }
.sev {
  display: inline-block;
  border-radius: 999px;
  padding: 2px 9px;
  font-size: 11.5px;
  font-weight: 600;
  color: #fff;
  white-space: nowrap;
}
.sev-critical { background: var(--crit); }
.sev-high { background: var(--high); }
.sev-medium { background: var(--med); color: #191919; }
.sev-low { background: var(--low); }
.sev-info { background: var(--info); }
.sev-other { background: #374151; }
pre.evidence {
  margin: 6px 0 4px;
  padding: 10px;
  max-height: 360px;
  overflow: auto;
  background: #0c0f16;
  border: 1px solid var(--line);
  border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-word;
}
.banner {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 11px 14px;
  margin-bottom: 16px;
}
.banner-bad { background: #2a1416; border-color: #6d2327; color: #ffd9d9; }
.banner-warn { background: #2a2110; border-color: #6d5a23; color: #ffeec9; }
.banner-info { background: #131c2b; border-color: #274067; color: #d6e4ff; }
.banner-text { flex: 1 1 auto; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px; }
.form-grid .wide { grid-column: 1 / -1; }
textarea {
  min-height: 150px;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12.5px;
}
footer { max-width: 1200px; margin: 0 auto; padding: 0 20px 34px; color: #6f7a90; font-size: 12px; }
@media (max-width: 640px) {
  main { padding: 14px 12px 4px; }
  header.top { padding: 11px 12px; }
  footer { padding: 0 12px 28px; }
}
</style>
</head>
<body>
<header class="top">
  <div class="brand">JOCKY<small>central management console</small></div>
  <div class="spacer"></div>
  <span class="pill" id="version-pill">version unknown</span>
  <span class="pill off" id="conn-pill">disconnected</span>
</header>
<main>
  <div class="banner" id="banner" hidden></div>

  <section>
    <h2>Authentication</h2>
    <form class="toolbar" id="connect-form">
      <label class="field" for="token-input">Token
        <input type="password" id="token-input" size="44" autocomplete="off" spellcheck="false"
               placeholder="token printed by jocky serve">
      </label>
      <button type="submit" class="primary" id="connect-button">Connect</button>
      <button type="button" id="refresh-button">Refresh</button>
      <button type="button" id="forget-button">Forget</button>
      <label class="field"><input type="checkbox" id="auto-toggle" checked> auto-refresh</label>
      <label class="field">every
        <input type="number" id="interval-input" min="2" max="600" step="1" value="10" style="width:72px">
        s
      </label>
    </form>
    <p class="hint">
      The token is stored in this browser only and sent as the X-JKY-Token header.
      This page is served without one; it carries no case data by itself.
    </p>
  </section>

  <section>
    <h2>Agents <span class="dim" id="agents-count"></span></h2>
    <div class="scroll">
      <table>
        <thead>
          <tr><th>Agent id</th><th>Name</th><th>Host</th><th>Last seen</th></tr>
        </thead>
        <tbody id="agents-body"></tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Jobs <span class="dim" id="jobs-count"></span></h2>
    <div class="stats" id="jobs-stats"></div>
    <p class="hint" id="status-meta"></p>
  </section>

  <section>
    <h2>Findings <span class="dim" id="findings-count"></span></h2>
    <div class="stats" id="severity-stats"></div>
    <div class="toolbar gap" style="margin-top:12px">
      <label class="field">severity
        <select id="severity-filter">
          <option value="">any</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
      </label>
      <label class="field">limit
        <select id="limit-select">
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="200" selected>200</option>
          <option value="500">500</option>
          <option value="1000">1000</option>
        </select>
      </label>
    </div>
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>Evidence</th><th>Severity</th><th>Check</th><th>Title</th>
            <th>Agent</th><th>Created</th><th>Job</th>
          </tr>
        </thead>
        <tbody id="findings-body"></tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Submit job</h2>
    <form id="submit-form">
      <div class="form-grid">
        <label class="stack">Kind
          <select id="kind-input">
            <option value="source">source — run the payload as a JOCKY script</option>
            <option value="fileless">fileless — run it with nothing written to disk</option>
          </select>
        </label>
        <label class="stack">Target
          <input type="text" id="target-input" placeholder="agent id, or empty for any agent" spellcheck="false">
        </label>
        <label class="stack wide">Payload
          <textarea id="payload-input" spellcheck="false"
                    placeholder="script or JSON handed to the agent; leave empty to run the kind's default"></textarea>
        </label>
      </div>
      <div class="toolbar" style="margin-top:12px">
        <button type="submit" class="primary" id="submit-button">Queue job</button>
        <span class="hint" id="submit-message"></span>
      </div>
    </form>
  </section>
</main>
<footer>
  Jobs execute with the privileges of the enrolled agent. Everything this console
  displays is stored verbatim from the fleet: treat names, hosts and evidence as
  untrusted text.
</footer>
<script>
"use strict";

var SEVERITIES = ["critical", "high", "medium", "low", "info"];
var JOB_STATUSES = ["queued", "running", "ok", "error"];
var TOKEN_HEADER = "X-JKY-Token";
var STORAGE_PREFIX = "jocky.console.";

var state = {
  token: "",
  connected: false,
  version: "",
  limit: 200,
  severity: "",
  refreshSeconds: 10,
  storedFindings: 0,
  timer: null
};

/* ------------------------------------------------------------------ storage */
/* Every access is guarded: a browser with storage disabled (private mode, a
   locked-down kiosk) must still be able to drive the fleet, it just will not
   remember the token between page loads. */
var storage = {
  get: function (key, fallback) {
    try {
      var value = window.localStorage.getItem(STORAGE_PREFIX + key);
      return value === null ? fallback : value;
    } catch (err) {
      return fallback;
    }
  },
  set: function (key, value) {
    try {
      window.localStorage.setItem(STORAGE_PREFIX + key, String(value));
    } catch (err) {
      return;
    }
  },
  remove: function (key) {
    try {
      window.localStorage.removeItem(STORAGE_PREFIX + key);
    } catch (err) {
      return;
    }
  }
};

/* --------------------------------------------------------------- DOM helpers */
/* Text nodes only. Server-supplied strings are attacker-influenced, so there is
   deliberately no code path here that parses markup. */
function mount(node, children) {
  if (children === null || children === undefined) {
    return;
  }
  if (Array.isArray(children)) {
    children.forEach(function (child) { mount(node, child); });
    return;
  }
  if (typeof children === "string") {
    node.appendChild(document.createTextNode(children));
    return;
  }
  node.appendChild(children);
}

function el(tag, props, children) {
  var node = document.createElement(tag);
  if (props) {
    Object.keys(props).forEach(function (key) {
      var value = props[key];
      if (value === null || value === undefined || value === false) {
        return;
      }
      if (key === "class") {
        node.className = value;
        return;
      }
      if (key === "text") {
        node.textContent = String(value);
        return;
      }
      if (key.indexOf("on") === 0 && typeof value === "function") {
        node.addEventListener(key.slice(2), value);
        return;
      }
      node.setAttribute(key, value === true ? "" : String(value));
    });
  }
  mount(node, children);
  return node;
}

function byId(id) {
  return document.getElementById(id);
}

/* A field the server omitted, or a column that is empty, reads as a dash rather
   than as nothing at all: a blank cell in a fleet table looks like a bug. */
function shown(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  return String(value);
}

function number(value) {
  return typeof value === "number" && isFinite(value) ? value : 0;
}

/* ------------------------------------------------------------------- errors */
function ApiError(kind, status, detail) {
  this.kind = kind;
  this.status = status;
  this.detail = detail || "";
  this.message = "api error: " + kind + (status ? " (" + status + ")" : "");
}
ApiError.prototype = Object.create(Error.prototype);
ApiError.prototype.constructor = ApiError;
ApiError.prototype.name = "ApiError";

/* One place that turns a failure into operator-facing advice. Distinguishing
   401 from 429 from an unreachable host matters: the fixes are different, and
   the server rate-limits failed tokens for 60 seconds, which otherwise looks
   like a hang. */
function diagnose(err) {
  var kind = err && err.kind ? err.kind : "unknown";
  var detail = err && err.detail ? ": " + err.detail : "";
  if (kind === "auth") {
    return {
      level: "bad",
      text: "Token rejected (401)" + detail + ". Paste the token printed by jocky serve at startup; "
        + "ten rejected attempts from one address make the server answer 429 for a minute."
    };
  }
  if (kind === "rate") {
    return {
      level: "warn",
      text: "Rate limited (429). The server refuses further authentication attempts from this address "
        + "for 60 seconds. Wait for the window to pass, then connect again."
    };
  }
  if (kind === "network") {
    return {
      level: "bad",
      text: "Cannot reach the management server." + detail + " Confirm that jocky serve is running, that this "
        + "page was opened from the server's own address rather than a local file, and that this browser "
        + "has accepted its self-signed certificate."
    };
  }
  if (kind === "server") {
    return {
      level: "warn",
      text: "The management server failed to answer" + detail + ". Check its stderr log; this is a server-side fault."
    };
  }
  return {
    level: "warn",
    text: "Request failed" + detail + "."
  };
}

function setBanner(level, message) {
  var banner = byId("banner");
  if (!message) {
    banner.hidden = true;
    banner.replaceChildren();
    return;
  }
  banner.className = "banner banner-" + level;
  banner.replaceChildren(
    el("span", {class: "banner-text", text: message}),
    el("button", {
      type: "button",
      class: "link",
      title: "Dismiss",
      text: "dismiss",
      onclick: clearBanner
    })
  );
  banner.hidden = false;
}

function clearBanner() {
  setBanner("info", "");
}

function showError(err) {
  var advice = diagnose(err);
  setBanner(advice.level, advice.text);
}

/* ---------------------------------------------------------------------- API */
async function readJson(response) {
  var body = await response.text();
  if (!body) {
    return null;
  }
  try {
    return JSON.parse(body);
  } catch (err) {
    throw new ApiError("server", response.status, "the response body was not JSON");
  }
}

async function api(path, options) {
  var opts = options || {};
  var headers = {};
  if (state.token) {
    headers[TOKEN_HEADER] = state.token;
  }
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  var response;
  try {
    response = await fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body,
      cache: "no-store",
      credentials: "same-origin"
    });
  } catch (err) {
    throw new ApiError("network", 0, "");
  }
  var payload = await readJson(response);
  if (!response.ok) {
    var detail = payload && payload.error ? String(payload.error) : String(response.statusText || "");
    if (response.status === 401) {
      throw new ApiError("auth", 401, detail);
    }
    if (response.status === 429) {
      throw new ApiError("rate", 429, detail);
    }
    if (response.status >= 500) {
      throw new ApiError("server", response.status, detail);
    }
    throw new ApiError("http", response.status, detail);
  }
  return payload;
}

/* -------------------------------------------------------------- status panel */
function renderAgents(agents) {
  var body = byId("agents-body");
  body.replaceChildren();
  byId("agents-count").textContent = agents.length + " enrolled";
  if (!agents.length) {
    body.appendChild(emptyRow(4, "No agent has enrolled yet."));
    return;
  }
  agents.forEach(function (agent) {
    var record = agent && typeof agent === "object" ? agent : {};
    body.appendChild(el("tr", null, [
      el("td", {class: "mono", text: shown(record.agent_id)}),
      el("td", {text: shown(record.name)}),
      el("td", {class: "mono", text: shown(record.host)}),
      el("td", {class: "mono dim", text: shown(record.last_seen)})
    ]));
  });
}

function statCard(value, label, extraClass) {
  var card = el("div", {class: "stat" + (extraClass ? " " + extraClass : "")}, [
    el("span", {class: "stat-value", text: String(number(value))}),
    el("span", {class: "stat-label", text: label})
  ]);
  return card;
}

function renderJobs(jobs) {
  var data = jobs && typeof jobs === "object" ? jobs : {};
  var row = byId("jobs-stats");
  row.replaceChildren();
  JOB_STATUSES.forEach(function (name) {
    row.appendChild(statCard(data[name], name, "stat-" + name));
  });
  row.appendChild(statCard(data.total, "total"));
  byId("jobs-count").textContent = number(data.total) + " queued or settled";
}

function renderSeverityStats(summary) {
  var data = summary && typeof summary === "object" ? summary : {};
  var counts = data.by_severity && typeof data.by_severity === "object" ? data.by_severity : {};
  var row = byId("severity-stats");
  row.replaceChildren();
  /* A payload may emit any severity string, so unknown buckets are shown too
     instead of being silently dropped from a total an operator trusts. */
  var extra = Object.keys(counts).filter(function (name) {
    return SEVERITIES.indexOf(String(name).toLowerCase()) < 0;
  }).sort();
  SEVERITIES.concat(extra).forEach(function (name) {
    row.appendChild(el("div", {class: "stat"}, [
      el("span", {class: "stat-value", text: String(number(counts[name]))}),
      el("span", {class: "stat-label", text: String(name)})
    ]));
  });
  state.storedFindings = number(data.total);
  byId("findings-count").textContent = "— " + state.storedFindings + " stored";
}

function renderStatus(status) {
  var data = status && typeof status === "object" ? status : {};
  renderAgents(Array.isArray(data.agents) ? data.agents : []);
  renderJobs(data.jobs);
  renderSeverityStats(data.findings);
  byId("status-meta").textContent = "server time: " + shown(data.server_time);
}

/* ------------------------------------------------------------ findings table */
function severityClass(value) {
  var name = String(value === null || value === undefined ? "" : value).toLowerCase();
  return SEVERITIES.indexOf(name) >= 0 ? "sev sev-" + name : "sev sev-other";
}

function pretty(value) {
  var text;
  try {
    text = JSON.stringify(value, null, 2);
  } catch (err) {
    text = String(value);
  }
  return text === undefined ? "null" : text;
}

function emptyRow(columns, message) {
  return el("tr", null, [
    el("td", {class: "dim", colspan: String(columns), text: message})
  ]);
}

function renderFindings(payload) {
  var body = byId("findings-body");
  var rows = payload && Array.isArray(payload.findings) ? payload.findings : [];
  body.replaceChildren();
  byId("findings-count").textContent =
    "— " + rows.length + " shown of " + state.storedFindings + " stored";
  if (!rows.length) {
    body.appendChild(emptyRow(7, "No finding matches this filter."));
    return;
  }
  rows.forEach(function (entry) {
    var finding = entry && typeof entry === "object" ? entry : {};
    var detail = el("tr", {hidden: true}, [
      el("td", {colspan: "7"}, [
        el("pre", {class: "evidence", text: pretty(finding.evidence)})
      ])
    ]);
    var toggle = el("button", {
      type: "button",
      class: "link",
      "aria-expanded": "false",
      text: "show"
    });
    toggle.addEventListener("click", function () {
      var opening = detail.hidden;
      detail.hidden = !opening;
      toggle.textContent = opening ? "hide" : "show";
      toggle.setAttribute("aria-expanded", opening ? "true" : "false");
    });
    body.appendChild(el("tr", {class: "finding"}, [
      el("td", null, [toggle]),
      el("td", null, [el("span", {class: severityClass(finding.severity), text: shown(finding.severity)})]),
      el("td", {class: "mono", text: shown(finding.check)}),
      el("td", {text: shown(finding.title)}),
      el("td", {class: "mono", text: shown(finding.agent_id)}),
      el("td", {class: "mono dim", text: shown(finding.created_at)}),
      el("td", {class: "mono dim", text: shown(finding.job_id)})
    ]));
    body.appendChild(detail);
  });
}

/* --------------------------------------------------------------- refreshing */
function setConnection(connected) {
  state.connected = connected;
  var pill = byId("conn-pill");
  pill.className = "pill " + (connected ? "on" : "off");
  pill.textContent = connected ? "connected" : "disconnected";
  byId("refresh-button").disabled = !connected;
  if (!connected) {
    stopTimer();
  }
}

function setVersion(version) {
  state.version = version ? String(version) : "";
  byId("version-pill").textContent = state.version ? "server " + state.version : "version unknown";
}

function findingsPath() {
  var query = "?limit=" + encodeURIComponent(String(state.limit));
  if (state.severity) {
    query += "&severity=" + encodeURIComponent(state.severity);
  }
  return "/v1/findings" + query;
}

async function refresh() {
  try {
    var status = await api("/v1/status");
    renderStatus(status);
    var findings = await api(findingsPath());
    renderFindings(findings);
    setConnection(true);
    if (state.timer === null) {
      restartTimer();
    }
    clearBanner();
  } catch (err) {
    /* A rejected token is the one failure worth stopping for: the server locks
       an address out after ten bad attempts, so retrying on a timer would turn
       a typo into a minute-long outage. Everything else (a restart, a dropped
       connection) keeps the schedule and just says so. */
    if (err && err.kind === "auth") {
      setConnection(false);
    }
    showError(err);
  }
}

function stopTimer() {
  if (state.timer !== null) {
    window.clearInterval(state.timer);
    state.timer = null;
  }
}

function restartTimer() {
  stopTimer();
  if (!state.connected || !byId("auto-toggle").checked) {
    return;
  }
  state.timer = window.setInterval(refresh, Math.max(2, state.refreshSeconds) * 1000);
}

async function connect() {
  state.token = byId("token-input").value.trim();
  clearBanner();
  byId("connect-button").disabled = true;
  try {
    /* Health first: it is unauthenticated, so it separates "the server is not
       there" from "the token is wrong" before any 401 can pollute the
       failure counter the server keeps per address. */
    var health = await api("/v1/health");
    setVersion(health && health.version);
    var status = await api("/v1/status");
    renderStatus(status);
    var findings = await api(findingsPath());
    renderFindings(findings);
    storage.set("token", state.token);
    storage.set("limit", state.limit);
    setConnection(true);
    restartTimer();
  } catch (err) {
    setConnection(false);
    showError(err);
  } finally {
    byId("connect-button").disabled = false;
  }
}

/* ------------------------------------------------------------- job dispatch */
/* btoa takes a byte string, and a payload is text: this round-trip is the
   dependency-free way to get UTF-8 bytes through it, so a script containing
   non-ASCII survives to the agent intact. */
function toBase64(text) {
  if (!text) {
    return "";
  }
  return btoa(unescape(encodeURIComponent(text)));
}

function submitMessage(text, ok) {
  var target = byId("submit-message");
  target.className = ok ? "hint ok" : "hint bad";
  target.textContent = text;
}

async function submitJob(event) {
  event.preventDefault();
  var kind = byId("kind-input").value.trim();
  var target = byId("target-input").value.trim();
  var payload = byId("payload-input").value;
  if (!kind) {
    submitMessage("Kind is required: it selects what the agent runs.", false);
    byId("kind-input").focus();
    return;
  }
  if (!state.connected) {
    submitMessage("Connect with a valid token before queueing a job.", false);
    return;
  }
  var body = {
    kind: kind,
    payload_b64: toBase64(payload),
    target: target ? target : null
  };
  byId("submit-button").disabled = true;
  try {
    var result = await api("/v1/jobs/submit", {method: "POST", body: JSON.stringify(body)});
    submitMessage("queued " + shown(result && result.job_id)
      + " for " + (target ? target : "any agent")
      + " (" + payload.length + " payload characters)", true);
    refresh();
  } catch (err) {
    var advice = diagnose(err);
    submitMessage(advice.text, false);
    showError(err);
  } finally {
    byId("submit-button").disabled = false;
  }
}

/* --------------------------------------------------------------------- init */
function init() {
  var tokenInput = byId("token-input");
  tokenInput.value = storage.get("token", "");
  /* Seeded before the check below: a token restored from a previous visit is
     the normal case, and the operator expects the console to come back up
     already connected rather than to have to paste it again. */
  state.token = tokenInput.value.trim();

  var intervalInput = byId("interval-input");
  var storedInterval = parseInt(storage.get("interval", "10"), 10);
  state.refreshSeconds = isFinite(storedInterval) && storedInterval >= 2 ? storedInterval : 10;
  intervalInput.value = String(state.refreshSeconds);

  var limitSelect = byId("limit-select");
  var storedLimit = parseInt(storage.get("limit", "200"), 10);
  state.limit = isFinite(storedLimit) ? storedLimit : 200;
  limitSelect.value = String(state.limit);

  byId("connect-form").addEventListener("submit", function (event) {
    event.preventDefault();
    connect();
  });
  byId("refresh-button").addEventListener("click", refresh);
  byId("forget-button").addEventListener("click", function () {
    setConnection(false);
    storage.remove("token");
    state.token = "";
    tokenInput.value = "";
    clearBanner();
    setBanner("info", "Stored token removed from this browser.");
    tokenInput.focus();
  });
  byId("auto-toggle").addEventListener("change", restartTimer);
  intervalInput.addEventListener("change", function () {
    var parsed = parseInt(intervalInput.value, 10);
    state.refreshSeconds = isFinite(parsed) && parsed >= 2 ? parsed : 10;
    intervalInput.value = String(state.refreshSeconds);
    storage.set("interval", state.refreshSeconds);
    restartTimer();
  });
  byId("severity-filter").addEventListener("change", function (event) {
    state.severity = event.target.value;
    if (state.connected) {
      refresh();
    }
  });
  limitSelect.addEventListener("change", function (event) {
    state.limit = parseInt(event.target.value, 10) || 200;
    storage.set("limit", state.limit);
    if (state.connected) {
      refresh();
    }
  });
  /* A token edited after connecting would otherwise be used by the next poll
     while the pill still claims the old one worked. */
  tokenInput.addEventListener("input", function () {
    if (state.token !== tokenInput.value.trim()) {
      setConnection(false);
    }
  });
  byId("submit-form").addEventListener("submit", submitJob);

  setConnection(false);
  if (state.token) {
    connect();
  }
}

init();
</script>
</body>
</html>
"""


def render() -> bytes:
    """Return the console page as UTF-8 bytes.

    Encoding once here rather than in the request path keeps the handler a
    single write of a constant; the page has no variable parts, so there is
    nothing per-request to assemble.
    """
    return DASHBOARD_HTML.encode("utf-8")
