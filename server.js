const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || process.env.APP_PORT || 4173);
const BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const SESSION_COOKIE = "esc_session";
const SESSION_TTL_SECONDS = 60 * 60 * 12;

const providers = {
  arive: {
    name: "ARIVE",
    category: "LOS / POS",
    color: "#2563eb",
    access: "Private Zapier app; direct API only if enabled by ARIVE for your account.",
    mode: "webhook"
  },
  bntouch: {
    name: "BNTouch",
    category: "Mortgage CRM",
    color: "#0f766e",
    access: "REST/API access where enabled, plus Zapier and native integrations.",
    mode: "api-or-webhook"
  },
  loanofficerai: {
    name: "LoanOfficer.ai",
    category: "AI Mortgage CRM",
    color: "#7c3aed",
    access: "Vendor-managed integrations; use API credentials if provisioned.",
    mode: "vendor-assisted"
  },
  myhomeiq: {
    name: "myhomeIQ",
    category: "Homeowner Intelligence",
    color: "#ea580c",
    access: "CRM/LOS/spreadsheet sync; use vendor API only if provisioned.",
    mode: "webhook-or-import"
  },
  cinc: {
    name: "CINC",
    category: "Real Estate CRM",
    color: "#16a34a",
    access: "CINC Public API, Zapier, and integration partners.",
    mode: "api-or-webhook"
  },
  zillow: {
    name: "Zillow / Bridge",
    category: "Property Data",
    color: "#0284c7",
    access: "Bridge API after Zillow Group data access approval.",
    mode: "display-only",
    displayOnly: true
  }
};

let store = {
  records: [
    demo("demo-lead-001", "cinc", "lead", "Avery Parker", "New buyer lead", "Hot", 625000),
    demo("demo-loan-001", "arive", "loan", "Morgan Lee", "Processing", "Active", 482500),
    demo("demo-contact-001", "bntouch", "contact", "Riley Dawson", "Past client nurture", "Warm", 0),
    demo("demo-opportunity-001", "loanofficerai", "opportunity", "Jordan Smith", "Rate drop alert", "High priority", 390000),
    demo("demo-insight-001", "myhomeiq", "property", "Taylor Brooks", "Likely to move", "Watch", 715000)
  ],
  events: [
    event("cinc", "New buyer lead received", "2026-05-21T14:05:00.000Z"),
    event("arive", "Loan moved to Processing", "2026-05-21T13:20:00.000Z"),
    event("bntouch", "Campaign engagement recorded", "2026-05-21T12:45:00.000Z")
  ]
};

function demo(id, provider, type, name, stage, status, value) {
  return {
    id,
    provider,
    type,
    name,
    email: `${name.toLowerCase().replace(/ /g, ".")}@example.com`,
    phone: "(555) 010-2200",
    stage,
    source: providers[provider].name,
    status,
    value,
    owner: "Joshua",
    address: "",
    updatedAt: new Date().toISOString(),
    notes: "Demo record"
  };
}

function event(provider, message, createdAt = new Date().toISOString()) {
  return { id: `evt-${crypto.randomUUID()}`, provider, message, createdAt };
}

function send(res, status, body, contentType = "application/json; charset=utf-8", headers = {}) {
  res.writeHead(status, { "Content-Type": contentType, "Cache-Control": "no-store", ...headers });
  res.end(contentType.includes("json") ? JSON.stringify(body, null, 2) : body);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

function getAuthUsername() {
  return process.env.LOGIN_USERNAME || process.env.ADMIN_USERNAME || "admin";
}

function getAuthPassword() {
  return process.env.LOGIN_PASSWORD || process.env.ADMIN_PASSWORD || "";
}

function getSessionSecret() {
  return process.env.SESSION_SECRET || process.env.WEBHOOK_SECRET || getAuthPassword();
}

function isAuthConfigured() {
  return Boolean(getAuthPassword() && getSessionSecret());
}

function safeStringEqual(left, right) {
  const leftHash = crypto.createHash("sha256").update(String(left)).digest();
  const rightHash = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
}

function parseCookies(req) {
  return Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const equals = part.indexOf("=");
        if (equals === -1) return [part, ""];
        return [part.slice(0, equals), decodeURIComponent(part.slice(equals + 1))];
      })
  );
}

function signSession(payload) {
  return crypto.createHmac("sha256", getSessionSecret()).update(payload).digest("base64url");
}

function createSessionToken(username) {
  const payload = Buffer.from(
    JSON.stringify({
      username,
      expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000
    })
  ).toString("base64url");
  return `${payload}.${signSession(payload)}`;
}

function readSession(req) {
  if (!isAuthConfigured()) return null;
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token || !token.includes(".")) return null;
  const [payload, signature] = token.split(".");
  if (!safeStringEqual(signature, signSession(payload))) return null;

  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!session.username || Number(session.expiresAt) < Date.now()) return null;
    return session;
  } catch (error) {
    return null;
  }
}

function isAuthenticated(req) {
  return Boolean(readSession(req));
}

function cookieSecurity(req) {
  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").toLowerCase();
  const host = String(req.headers.host || "").toLowerCase();
  return forwardedProto === "https" || (!host.startsWith("localhost") && !host.startsWith("127.0.0.1"));
}

function sessionCookie(req, token) {
  const secure = cookieSecurity(req) ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}${secure}`;
}

function clearCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

function summary(records) {
  const value = records.reduce((total, record) => total + Number(record.value || 0), 0);
  return {
    count: records.length,
    value,
    valueFormatted: new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(value),
    hot: records.filter((record) => ["hot", "high priority"].includes(String(record.status).toLowerCase())).length,
    loans: records.filter((record) => record.type === "loan").length
  };
}

function connectors() {
  return Object.entries(providers).map(([id, provider]) => ({
    id,
    name: provider.name,
    category: provider.category,
    color: provider.color,
    access: provider.access,
    syncMode: provider.mode,
    webhookPath: `/api/webhooks/${id}`,
    status: provider.mode.includes("webhook") ? "Webhook ready" : "Needs credentials"
  }));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error("Body must be valid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function readFormOrJson(req) {
  return new Promise((resolve, reject) => {
    const contentType = String(req.headers["content-type"] || "");
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 100_000) {
        reject(new Error("Request body is too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        if (contentType.includes("application/json")) {
          resolve(body ? JSON.parse(body) : {});
          return;
        }
        resolve(Object.fromEntries(new URLSearchParams(body).entries()));
      } catch (error) {
        reject(new Error("Login request could not be read"));
      }
    });
    req.on("error", reject);
  });
}

function normalize(provider, payload) {
  const data = Array.isArray(payload) ? payload[0] || {} : payload || {};
  const name = data.name || data.fullName || [data.firstName, data.lastName].filter(Boolean).join(" ") || "Unnamed record";
  const amount = Number(data.value || data.loanAmount || data.homeValue || data.purchasePrice || 0);
  return {
    id: `${provider}-${data.id || data.recordId || crypto.randomUUID()}`,
    provider,
    type: data.type || (provider === "arive" ? "loan" : provider === "myhomeiq" || provider === "zillow" ? "property" : provider === "loanofficerai" ? "opportunity" : "lead"),
    name,
    email: data.email || "",
    phone: data.phone || data.mobile || "",
    stage: data.stage || data.loanStage || data.pipelineStage || "New",
    source: data.source || providers[provider].name,
    status: data.status || data.priority || "New",
    value: Number.isFinite(amount) ? amount : 0,
    owner: data.owner || data.assignedTo || data.loanOfficer || "",
    address: [data.propertyAddress || data.address, data.city, data.state, data.zip].filter(Boolean).join(", "),
    updatedAt: new Date().toISOString(),
    notes: data.notes || data.summary || "",
    raw: data
  };
}

function loginPage(message = "") {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in | 8 Step Close</title>
<style>
:root{--bg:#f5f7f6;--surface:#fff;--border:#d8e0dc;--text:#1d2522;--muted:#61706a;--green:#12715b;--red:#b91c1c;--shadow:0 20px 50px rgba(22,35,30,.12)}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}.login{width:min(100%,420px);background:var(--surface);border:1px solid var(--border);border-radius:8px;box-shadow:var(--shadow);padding:28px}.brand{display:flex;gap:12px;align-items:center;margin-bottom:24px}.mark{display:grid;place-items:center;width:44px;height:44px;border-radius:8px;background:#25443a;color:white;font-weight:800}.brand span{display:block;color:var(--muted);font-size:.9rem;margin-top:2px}h1{font-size:1.6rem;margin:0 0 18px}.field{display:grid;gap:7px;margin-bottom:14px}.field span{font-weight:750}.input{width:100%;min-height:44px;border:1px solid var(--border);border-radius:6px;padding:9px 11px;font:inherit}.button{width:100%;min-height:44px;border:0;border-radius:6px;background:var(--green);color:white;font:inherit;font-weight:800;cursor:pointer}.error{border:1px solid #f0b4b4;background:#fff0f0;color:var(--red);border-radius:6px;padding:10px;margin-bottom:14px}.setup{border:1px solid #f1d18a;background:#fff8e8;color:#6c4305;border-radius:6px;padding:10px;line-height:1.45}
</style>
</head>
<body>
<main class="login">
<div class="brand"><div class="mark">8C</div><div><strong>8 Step Close</strong><span>Unified pipeline</span></div></div>
<h1>Sign in</h1>
${isAuthConfigured() ? "" : '<div class="setup">Login is not configured yet. Add LOGIN_USERNAME, LOGIN_PASSWORD, and SESSION_SECRET in Render.</div>'}
${message ? `<div class="error">${message}</div>` : ""}
<form method="post" action="/api/login">
<label class="field"><span>Username</span><input class="input" name="username" autocomplete="username" required></label>
<label class="field"><span>Password</span><input class="input" name="password" type="password" autocomplete="current-password" required></label>
<button class="button" type="submit">Sign in</button>
</form>
</main>
</body>
</html>`;
}

function page() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>8 Step Close</title>
<style>
:root{--bg:#f5f7f6;--surface:#fff;--border:#d8e0dc;--text:#1d2522;--muted:#61706a;--green:#12715b;--shadow:0 16px 40px rgba(22,35,30,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.app{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}.side{background:#17211d;color:#f7fbf8;padding:22px}.brand{display:flex;gap:12px;align-items:center;margin-bottom:30px}.mark{display:grid;place-items:center;width:44px;height:44px;border-radius:8px;background:#25443a;font-weight:800}.brand span{display:block;color:#aec3ba;font-size:.84rem}.nav{display:grid;gap:6px}.nav a{color:#dbe8e2;text-decoration:none;padding:10px 12px;border-radius:6px}.nav a:first-child,.nav a:hover{background:rgba(255,255,255,.1);color:#fff}.main{padding:28px;max-width:1480px}.top{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:22px}.eyebrow{margin:0 0 6px;color:var(--green);font-size:.78rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}h1{margin:0;font-size:clamp(1.8rem,3vw,2.6rem)}button,.button{border:1px solid var(--border);border-radius:6px;min-height:40px;padding:0 14px;background:#fff;font:inherit;font-weight:750}.primary{background:var(--green);color:#fff;border-color:var(--green)}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}.metric,.panel,.connector{background:var(--surface);border:1px solid var(--border);border-radius:8px;box-shadow:var(--shadow)}.metric{padding:18px}.metric span{color:var(--muted)}.metric strong{display:block;margin-top:10px;font-size:1.9rem}.grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,.75fr);gap:18px;margin-bottom:18px}.panel{padding:18px}.panel-head{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:16px}.panel h2{margin:0}.connectors{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.connector{box-shadow:none;padding:15px}.source{display:flex;gap:10px;align-items:flex-start}.dot{width:12px;height:12px;border-radius:50%;background:var(--green);margin-top:6px}.connector p{color:var(--muted);line-height:1.45;min-height:62px}.chip{display:inline-flex;align-items:center;min-height:26px;border-radius:999px;padding:0 9px;background:#eef3f0;color:#2d4039;font-size:.78rem;font-weight:700;margin:0 6px 6px 0}.good{background:#dff5e9;color:#17603c}.warn{background:#fff2d7;color:#8a4a06}.event{border-left:3px solid var(--green);background:#eef3f0;border-radius:6px;padding:10px 12px;margin-bottom:10px}.event span{display:block;color:var(--muted);font-size:.82rem}.filters{display:flex;gap:10px;flex-wrap:wrap}.input{min-height:40px;border:1px solid var(--border);border-radius:6px;background:#fff;color:var(--text);padding:8px 10px}.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px}table{width:100%;min-width:860px;border-collapse:collapse;background:#fff}th,td{padding:12px 14px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}th{background:#f1f5f3;color:#40514a;font-size:.78rem;text-transform:uppercase}.pill{display:inline-flex;align-items:center;min-height:28px;border-radius:999px;padding:0 10px;background:#e7f2ff;color:#144d8b;font-weight:800;font-size:.8rem}.notice{margin-top:14px;border:1px solid #f1d18a;border-radius:8px;background:#fff8e8;color:#6c4305;padding:12px;line-height:1.45}textarea{width:100%;min-height:180px;font-family:Consolas,monospace}.webhook-list code{overflow-wrap:anywhere}
@media(max-width:1180px){.metrics,.connectors{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr}}@media(max-width:780px){.app{grid-template-columns:1fr}.metrics,.connectors{grid-template-columns:1fr}.top,.panel-head{align-items:flex-start;flex-direction:column}.main{padding:18px}}
</style>
</head>
<body>
<div class="app"><aside class="side"><div class="brand"><div class="mark">8C</div><div><strong>8 Step Close</strong><span>Unified pipeline</span></div></div><nav class="nav"><a href="#overview">Overview</a><a href="#connectors">Connectors</a><a href="#records">Records</a><a href="#webhooks">Webhooks</a></nav></aside>
<main class="main"><header class="top"><div><p class="eyebrow">Today</p><h1>8 Step Close</h1></div><div><button id="refresh">Refresh</button> <button id="sync" class="primary">Check Sync</button> <button id="logout">Log Out</button></div></header>
<section id="overview" class="metrics"><article class="metric"><span>Total records</span><strong id="totalRecords">0</strong></article><article class="metric"><span>Pipeline value</span><strong id="pipelineValue">$0</strong></article><article class="metric"><span>Hot items</span><strong id="hotItems">0</strong></article><article class="metric"><span>Active loans</span><strong id="activeLoans">0</strong></article></section>
<section class="grid"><div id="connectors" class="panel"><div class="panel-head"><div><p class="eyebrow">Data sources</p><h2>Connectors</h2></div><span id="updated"></span></div><div id="connectorGrid" class="connectors"></div></div><div class="panel"><div class="panel-head"><div><p class="eyebrow">Activity</p><h2>Recent Events</h2></div></div><div id="events"></div></div></section>
<section id="records" class="panel"><div class="panel-head"><div><p class="eyebrow">Unified view</p><h2>Records</h2></div><div class="filters"><input id="search" class="input" type="search" placeholder="Search records"><select id="provider" class="input"><option value="all">All sources</option></select><select id="type" class="input"><option value="all">All types</option><option value="lead">Leads</option><option value="loan">Loans</option><option value="contact">Contacts</option><option value="property">Properties</option><option value="opportunity">Opportunities</option></select></div></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Source</th><th>Type</th><th>Stage</th><th>Status</th><th>Value</th><th>Updated</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<section id="webhooks" class="grid"><div class="panel"><p class="eyebrow">Inbound data</p><h2>Webhook Tester</h2><form id="webhookForm"><p><select id="webhookProvider" class="input"></select></p><p><textarea id="payload" class="input"></textarea></p><button class="primary">Send Test Event</button></form></div><div class="panel"><p class="eyebrow">Setup</p><h2>Webhook URLs</h2><div id="webhookList" class="webhook-list"></div><div class="notice">Zillow / Bridge is marked display-only. Approved property data should be shown live according to Bridge/Zillow terms instead of silently saved.</div></div></section>
</main></div>
<script>
const fmt=new Intl.NumberFormat("en-US",{style:"currency",currency:"USD",maximumFractionDigits:0});let connectors=[],records=[];
async function api(path,opt={}){const res=await fetch(path,{headers:{"Content-Type":"application/json"},...opt});const data=await res.json();if(!res.ok)throw new Error(data.error||"Request failed");return data}
function date(v){return new Intl.DateTimeFormat("en-US",{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"}).format(new Date(v))}
async function load(){const s=await api("/api/status");connectors=s.connectors;document.querySelector("#totalRecords").textContent=s.summary.count;document.querySelector("#pipelineValue").textContent=s.summary.valueFormatted;document.querySelector("#hotItems").textContent=s.summary.hot;document.querySelector("#activeLoans").textContent=s.summary.loans;document.querySelector("#updated").textContent="Updated "+date(s.generatedAt);renderConnectors();renderOptions();renderEvents(s.recentEvents);await loadRecords()}
function renderOptions(){const p=document.querySelector("#provider"),w=document.querySelector("#webhookProvider");p.innerHTML='<option value="all">All sources</option>';w.innerHTML='';connectors.forEach(c=>{p.insertAdjacentHTML("beforeend",'<option value="'+c.id+'">'+c.name+'</option>');w.insertAdjacentHTML("beforeend",'<option value="'+c.id+'">'+c.name+'</option>')});document.querySelector("#payload").value=JSON.stringify({firstName:"Casey",lastName:"Williams",email:"casey@example.com",phone:"(555) 016-2204",stage:"New lead",status:"Hot",value:540000,source:"Website"},null,2);document.querySelector("#webhookList").innerHTML=connectors.map(c=>'<p><strong>'+c.name+'</strong><br><code>POST '+location.origin+c.webhookPath+'</code></p>').join("")}
function renderConnectors(){document.querySelector("#connectorGrid").innerHTML=connectors.map(c=>'<article class="connector"><div class="source"><span class="dot" style="background:'+c.color+'"></span><div><strong>'+c.name+'</strong><br><span>'+c.category+'</span></div></div><p>'+c.access+'</p><span class="chip '+(c.status.includes("Ready")||c.status.includes("ready")?"good":"warn")+'">'+c.status+'</span><span class="chip">'+c.syncMode+'</span><p><button onclick="test(\\''+c.id+'\\')">Test</button> <button onclick="sync(\\''+c.id+'\\')">Sync</button></p></article>').join("")}
function renderEvents(events){document.querySelector("#events").innerHTML=(events||[]).map(e=>'<div class="event"><strong>'+e.message+'</strong><span>'+e.provider+' · '+date(e.createdAt)+'</span></div>').join("")}
async function loadRecords(){const p=document.querySelector("#provider").value,t=document.querySelector("#type").value,q=document.querySelector("#search").value;const data=await api("/api/records?provider="+encodeURIComponent(p)+"&type="+encodeURIComponent(t)+"&q="+encodeURIComponent(q));records=data.records;document.querySelector("#rows").innerHTML=records.map(r=>'<tr><td><strong>'+r.name+'</strong><br><small>'+[r.email,r.phone].filter(Boolean).join(" · ")+'</small></td><td>'+((connectors.find(c=>c.id===r.provider)||{}).name||r.provider)+'</td><td>'+r.type+'</td><td>'+r.stage+'</td><td><span class="pill">'+r.status+'</span></td><td>'+(r.value?fmt.format(r.value):"")+'</td><td>'+date(r.updatedAt)+'</td></tr>').join("")||'<tr><td colspan="7">No records found.</td></tr>'}
async function test(id){const r=await api("/api/test/"+id,{method:"POST",body:"{}"});alert(r.status+"\\n"+r.detail)}
async function sync(id){await api("/api/sync/"+id,{method:"POST",body:"{}"});await load()}
document.querySelector("#refresh").onclick=load;document.querySelector("#sync").onclick=async()=>{for(const c of connectors)await sync(c.id)};document.querySelector("#logout").onclick=async()=>{await fetch("/api/logout",{method:"POST"});location.href="/login"};document.querySelector("#provider").onchange=loadRecords;document.querySelector("#type").onchange=loadRecords;document.querySelector("#search").oninput=loadRecords;document.querySelector("#webhookForm").onsubmit=async e=>{e.preventDefault();const id=document.querySelector("#webhookProvider").value;const r=await api("/api/webhooks/"+id,{method:"POST",body:document.querySelector("#payload").value});alert(r.warning||"Saved "+r.records.length+" record.");await load()};load();
</script>
</body></html>`;
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const parts = url.pathname.split("/").filter(Boolean);
  const isWebhook = req.method === "POST" && parts[0] === "api" && parts[1] === "webhooks";
  const isPublicApi = url.pathname === "/api/health" || url.pathname === "/api/login" || url.pathname === "/api/logout";

  try {
    if (req.method === "GET" && url.pathname === "/login") {
      if (isAuthenticated(req)) {
        redirect(res, "/");
        return;
      }
      send(res, 200, loginPage(), "text/html; charset=utf-8");
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/login") {
      if (!isAuthConfigured()) {
        send(res, 503, { error: "Login is not configured yet." });
        return;
      }
      const body = await readFormOrJson(req);
      const username = String(body.username || "");
      const password = String(body.password || "");
      const valid = safeStringEqual(username, getAuthUsername()) && safeStringEqual(password, getAuthPassword());
      if (!valid) {
        if (String(req.headers["content-type"] || "").includes("application/json")) {
          send(res, 401, { error: "Invalid username or password" });
        } else {
          send(res, 401, loginPage("Invalid username or password."), "text/html; charset=utf-8");
        }
        return;
      }
      res.setHeader("Set-Cookie", sessionCookie(req, createSessionToken(username)));
      if (String(req.headers["content-type"] || "").includes("application/json")) {
        send(res, 200, { ok: true, username });
      } else {
        redirect(res, "/");
      }
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/logout") {
      res.setHeader("Set-Cookie", clearCookie());
      send(res, 200, { ok: true });
      return;
    }
    if (!isAuthenticated(req) && !isPublicApi && !isWebhook) {
      if (url.pathname.startsWith("/api/")) {
        send(res, 401, { error: "Login required" });
      } else {
        redirect(res, "/login");
      }
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/health") {
      send(res, 200, { ok: true, app: "8 Step Close", baseUrl: BASE_URL, generatedAt: new Date().toISOString() });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/status") {
      send(res, 200, { generatedAt: new Date().toISOString(), summary: summary(store.records), connectors: connectors(), recentEvents: store.events.slice(-8).reverse() });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/records") {
      const provider = url.searchParams.get("provider");
      const type = url.searchParams.get("type");
      const q = String(url.searchParams.get("q") || "").toLowerCase();
      let records = store.records.slice();
      if (provider && provider !== "all") records = records.filter((record) => record.provider === provider);
      if (type && type !== "all") records = records.filter((record) => record.type === type);
      if (q) records = records.filter((record) => [record.name, record.email, record.phone, record.stage, record.status].join(" ").toLowerCase().includes(q));
      send(res, 200, { records });
      return;
    }
    if (req.method === "POST" && parts[0] === "api" && parts[1] === "test" && providers[parts[2]]) {
      send(res, 200, { ok: true, status: "Webhook endpoint is available", detail: `${providers[parts[2]].name} can send approved events to /api/webhooks/${parts[2]}.` });
      return;
    }
    if (req.method === "POST" && parts[0] === "api" && parts[1] === "sync" && providers[parts[2]]) {
      const item = event(parts[2], `${providers[parts[2]].name} sync check completed`);
      store.events.push(item);
      send(res, 200, { ok: true, status: "Sync checked", detail: "Real sync begins after vendor credentials are added.", event: item });
      return;
    }
    if (req.method === "POST" && parts[0] === "api" && parts[1] === "webhooks" && providers[parts[2]]) {
      const provider = parts[2];
      const payload = await readBody(req);
      const record = normalize(provider, payload);
      const stored = !providers[provider].displayOnly;
      if (stored) store.records.unshift(record);
      const item = event(provider, stored ? `${providers[provider].name} webhook saved 1 record` : `${providers[provider].name} payload received for display preview only`);
      store.events.push(item);
      send(res, 202, { accepted: true, stored, records: [record], event: item, warning: stored ? null : "This connector is marked display-only; payload was not stored." });
      return;
    }
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      send(res, 200, page(), "text/html; charset=utf-8");
      return;
    }
    send(res, 404, { error: "Not found" });
  } catch (error) {
    send(res, 500, { error: error.message || "Server error" });
  }
}

http.createServer(handle).listen(PORT, () => {
  console.log(`8 Step Close running at http://localhost:${PORT}`);
});
