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
    access: "Zapier triggers for buyer/seller leads; custom webhook/API only if provisioned.",
    mode: "zapier-webhook"
  },
  cinc: {
    name: "CINC",
    category: "Real Estate CRM",
    color: "#16a34a",
    access: "CINC Public API, Zapier, and integration partners.",
    mode: "api-or-webhook"
  },
  zillow: {
    name: "Zillow Lender Contacts",
    category: "Lender Leads",
    color: "#0284c7",
    access: "Zillow co-marketing posting URL for lender contact notifications.",
    mode: "posting-url"
  }
};

let store = {
  records: [
    demo("demo-lead-001", "cinc", "lead", "Avery Parker", "New buyer lead", "Hot", 625000),
    demo("demo-application-001", "arive", "loan", "Morgan Lee", "Loan Set-up", "Active", 482500),
    demo("demo-preapproval-001", "loanofficerai", "opportunity", "Jordan Smith", "Pre-approved", "High priority", 390000),
    demo("demo-disclosures-001", "arive", "loan", "Sam Rivera", "Disclosures sent", "Active", 510000),
    demo("demo-loan-cycle-001", "arive", "loan", "Casey Williams", "Approved with Conditions", "Active", 455000),
    demo("demo-closed-001", "arive", "loan", "Jamie Chen", "Funded", "Loan Funded", 460000),
    demo("demo-contact-001", "bntouch", "contact", "Riley Dawson", "Past client nurture", "Warm", 0),
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
    status: provider.mode.includes("posting") ? "Posting URL ready" : provider.mode.includes("webhook") ? "Webhook ready" : "Needs credentials"
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

function nested(data, paths, fallback = "") {
  for (const path of paths) {
    const value = path.split(".").reduce((current, key) => {
      if (current === undefined || current === null) return undefined;
      return current[key];
    }, data);
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return fallback;
}

function flattenAriveLoan(payload) {
  const data = Array.isArray(payload) ? payload[0] || {} : payload || {};
  const firstName = nested(data, [
    "borrower.firstName",
    "borrower_first_name",
    "Borrower First Name",
    "primaryBorrower.firstName",
    "firstName"
  ]);
  const lastName = nested(data, [
    "borrower.lastName",
    "borrower_last_name",
    "Borrower Last Name",
    "primaryBorrower.lastName",
    "lastName"
  ]);
  const coFirstName = nested(data, ["coBorrower.firstName", "co_borrower_first_name", "Co-Borrower First Name"]);
  const coLastName = nested(data, ["coBorrower.lastName", "co_borrower_last_name", "Co-Borrower Last Name"]);
  const borrowerName = nested(data, [
    "borrower.fullName",
    "borrowerName",
    "Borrower Name",
    "primaryBorrower.fullName",
    "name",
    "fullName"
  ], `${firstName} ${lastName}`.trim());
  const loanStage = nested(data, [
    "loanStageName",
    "Loan Stage Name (Arive)",
    "Loan Stage Name",
    "loan.stageName",
    "loan.stage",
    "loanStatus",
    "Loan Status",
    "status",
    "milestone",
    "stage"
  ], "ARIVE loan update");
  const loanAmount = Number(nested(data, [
    "loanAmount",
    "loan_amount",
    "Loan Amount",
    "loan.loanAmount",
    "baseLoanAmount",
    "purchasePrice",
    "Purchase Price",
    "property.purchasePrice",
    "value"
  ], 0));
  const propertyAddress = nested(data, [
    "property.fullAddress",
    "propertyAddress",
    "Property Address",
    "subjectPropertyAddress",
    "property.street",
    "streetAddress",
    "address"
  ]);
  const city = nested(data, ["property.city", "Property City", "city"]);
  const state = nested(data, ["property.state", "Property State", "state"]);
  const zip = nested(data, ["property.zip", "property.zipCode", "Property Zip", "zip", "zipCode"]);
  const loanOfficer = nested(data, ["loanOfficer.fullName", "loanOfficer", "Loan Officer", "loName", "owner"]);
  const processor = nested(data, ["processor.fullName", "processor", "Processor"]);
  const coordinator = nested(data, ["loanCoordinator.fullName", "loanCoordinator", "Loan Coordinator", "lcName"]);
  const funder = nested(data, ["funder.fullName", "funder", "Funder"]);
  const importantDates = [
    ["TRID", nested(data, ["tridDate", "TRID Date"])],
    ["Disclosures", nested(data, ["disclosuresSentDate", "Disclosure Sent Date", "initialDisclosuresSentDate"])],
    ["ITP", nested(data, ["itpSignedDate", "ITP Signed Date"])],
    ["Submitted", nested(data, ["submittedDate", "Submitted Date"])],
    ["CTC", nested(data, ["clearToCloseDate", "Clear To Close Date", "ctcDate"])],
    ["Closing", nested(data, ["closingDate", "Closing Date", "estimatedClosingDate", "Est Closing Date"])],
    ["Funding", nested(data, ["fundingDate", "Fund Date", "estimatedFundingDate", "Est Fund Date", "disbursementDate"])],
    ["Finalized", nested(data, ["loanFinalizedDate", "Loan Finalized Date"])]
  ].filter((item) => item[1]).map((item) => `${item[0]}: ${item[1]}`);
  const trackerNotes = [
    nested(data, ["lenderName", "Lender", "loan.lenderName"]) ? `Lender: ${nested(data, ["lenderName", "Lender", "loan.lenderName"])}` : "",
    nested(data, ["lenderLoanNumber", "Lender Loan Number", "ariveOrInvestorLoanNo"]) ? `Lender loan #: ${nested(data, ["lenderLoanNumber", "Lender Loan Number", "ariveOrInvestorLoanNo"])}` : "",
    nested(data, ["rateLockExpiration", "Lock Expiry Date", "lockExpiryDate"]) ? `Lock expires: ${nested(data, ["rateLockExpiration", "Lock Expiry Date", "lockExpiryDate"])}` : "",
    nested(data, ["appraisalStatus", "Appraisal Status"]) ? `Appraisal: ${nested(data, ["appraisalStatus", "Appraisal Status"])}` : "",
    nested(data, ["titleStatus", "Title Status"]) ? `Title: ${nested(data, ["titleStatus", "Title Status"])}` : "",
    nested(data, ["hoiStatus", "HOI Status"]) ? `HOI: ${nested(data, ["hoiStatus", "HOI Status"])}` : "",
    nested(data, ["conditionCount", "Conditions Count"]) ? `Conditions: ${nested(data, ["conditionCount", "Conditions Count"])}` : "",
    nested(data, ["openTaskCount", "Open Task Count"]) ? `Open tasks: ${nested(data, ["openTaskCount", "Open Task Count"])}` : "",
    ...importantDates,
    nested(data, ["notes", "note", "summary", "description"])
  ].filter(Boolean);

  return {
    ...data,
    id: nested(data, ["ariveLoanId", "Arive Loan ID", "loanId", "loan.id", "id"]),
    fullName: borrowerName,
    firstName,
    lastName,
    email: nested(data, ["borrower.email", "borrowerEmail", "Borrower Email", "email"]),
    phone: nested(data, ["borrower.phone", "borrowerPhone", "Borrower Phone", "phone", "mobile"]),
    type: "loan",
    stage: loanStage,
    source: "ARIVE",
    status: nested(data, ["loanStatus", "Loan Status", "status", "priority"], loanStage),
    value: Number.isFinite(loanAmount) ? loanAmount : 0,
    owner: loanOfficer,
    processor,
    coordinator,
    funder,
    coBorrowerName: `${coFirstName} ${coLastName}`.trim(),
    propertyAddress,
    city,
    state,
    zip,
    notes: trackerNotes.join("; "),
    updatedAt: nested(data, ["updatedAt", "Updated At", "modifiedAt", "lastModified", "created"], new Date().toISOString()),
    raw: data
  };
}

function flattenZillowContact(payload) {
  const data = Array.isArray(payload) ? payload[0] || {} : payload || {};
  const details = data.details || {};
  const quote = data.quote || {};
  const firstName = nested(data, ["sender.firstName", "firstName"]);
  const lastName = nested(data, ["sender.lastName", "lastName"]);
  const propertyValue = nested(data, ["details.propertyValue", "propertyValue", "quote.zillow.propertyValue"]);
  const loanAmount = nested(data, ["details.loanAmount", "loanAmount", "quote.zillow.loanAmount"]);
  const fullPropertyAddress = nested(data, ["details.propertyAddress", "propertyAddress"]);
  const notes = [
    data.source ? `Source: ${data.source}` : "",
    data.type ? `Zillow contact type: ${data.type}` : "",
    details.loanPurpose ? `Loan purpose: ${details.loanPurpose}` : "",
    details.creditScoreLow || details.creditScoreHigh
      ? `Credit score range: ${[details.creditScoreLow, details.creditScoreHigh].filter(Boolean).join("-")}`
      : "",
    quote.rate ? `Quoted rate: ${quote.rate}` : ""
  ].filter(Boolean);

  return {
    ...data,
    id: nested(data, ["id", "contactId", "details.requestId", "requestId"]),
    firstName,
    lastName,
    fullName: `${firstName} ${lastName}`.trim(),
    email: nested(data, ["sender.emailAddress", "sender.email", "email"]),
    phone: nested(data, ["sender.phoneNumber", "sender.phone", "phone"]),
    type: "lead",
    stage: nested(data, ["details.loanPurpose", "type"], "New Zillow contact"),
    source: nested(data, ["source", "brand"], "Zillow"),
    status: nested(data, ["channel"], "New"),
    value: Number(loanAmount || propertyValue || 0),
    owner: [nested(data, ["recipient.firstName"]), nested(data, ["recipient.lastName"])].filter(Boolean).join(" "),
    propertyAddress: fullPropertyAddress || nested(data, ["details.streetAddress", "streetAddress"]),
    streetAddress: nested(data, ["details.streetAddress", "streetAddress"]),
    city: fullPropertyAddress ? "" : nested(data, ["details.city", "city"]),
    state: fullPropertyAddress ? "" : nested(data, ["details.stateAbbreviation", "stateAbbreviation", "state"]),
    zip: fullPropertyAddress ? "" : nested(data, ["details.zipCode", "zipCode", "zip"]),
    notes: nested(data, ["message", "details.message"], notes.join("; ")),
    raw: data
  };
}

function flattenMyhomeIq(payload) {
  const data = Array.isArray(payload) ? payload[0] || {} : payload || {};
  const leadType = String(nested(data, [
    "eventType",
    "event_type",
    "trigger",
    "leadType",
    "lead_type",
    "opportunityType",
    "opportunity_type",
    "type",
    "Type"
  ], "")).trim();
  const lowerLeadType = leadType.toLowerCase();
  const ownerName = nested(data, [
    "property.ownerName",
    "property.owner_name",
    "propertyOwnerName",
    "property_owner_name",
    "Property owner name",
    "ownerName",
    "owner_name",
    "client.name",
    "clientName",
    "client_name",
    "name",
    "fullName"
  ]);
  const firstName = nested(data, ["client.firstName", "client.first_name", "firstName", "first_name"]);
  const lastName = nested(data, ["client.lastName", "client.last_name", "lastName", "last_name"]);
  const email = nested(data, ["client.email", "clientEmail", "client_email", "Client email", "email", "Email"]);
  const phone = nested(data, ["client.phone", "clientPhone", "client_phone", "Client phone number", "phone", "mobile"]);
  const fullAddress = nested(data, [
    "property.fullAddress",
    "property.full_address",
    "propertyFullAddress",
    "property_full_address",
    "Property full address",
    "propertyAddress",
    "property_address",
    "address"
  ]);
  const street = nested(data, ["property.street", "propertyStreet", "property_street", "Property street", "street", "streetAddress"]);
  const city = nested(data, ["property.city", "propertyCity", "property_city", "Property city", "city"]);
  const state = nested(data, ["property.state", "propertyState", "property_state", "Property state", "state"]);
  const zip = nested(data, ["property.zip", "propertyZip", "property_zip", "Property zip", "zip", "zipCode"]);
  const value = Number(nested(data, [
    "property.homeValue",
    "property.home_value",
    "propertyHomeValue",
    "property_home_value",
    "Property home value",
    "homeValue",
    "home_value",
    "estimatedValue",
    "estimated_value",
    "propertyValue",
    "property_value",
    "salePrice",
    "sale_price",
    "Property sale price",
    "loanAmount",
    "loan_amount",
    "Property loan amount",
    "value"
  ], 0));
  const reportUrl = nested(data, ["reportUrl", "report_url", "homeownerReportUrl", "homeowner_report_url", "report.url"]);
  const equity = nested(data, ["equity", "estimatedEquity", "estimated_equity", "property.equity"]);
  const loanRate = nested(data, ["interestRate", "interest_rate", "Property interest rate"]);
  const loanType = nested(data, ["loanType", "loan_type", "Property loan type"]);
  const notes = [
    reportUrl ? `Report: ${reportUrl}` : "",
    equity ? `Estimated equity: ${equity}` : "",
    loanRate ? `Interest rate: ${loanRate}` : "",
    loanType ? `Loan type: ${loanType}` : "",
    nested(data, ["notes", "note", "summary", "description"])
  ].filter(Boolean);

  return {
    ...data,
    id: nested(data, ["id", "recordId", "record_id", "leadId", "lead_id", "reportId", "report_id"]),
    fullName: ownerName || `${firstName} ${lastName}`.trim(),
    firstName,
    lastName,
    email,
    phone,
    type: lowerLeadType.includes("lead") || lowerLeadType.includes("buyer") || lowerLeadType.includes("seller") ? "lead" : "property",
    stage: leadType || nested(data, ["stage", "status"], "myhomeIQ insight"),
    source: nested(data, ["source", "leadSource", "lead_source"], "myhomeIQ"),
    status: nested(data, ["priority", "status", "signal", "signalType", "signal_type"], "New"),
    value: Number.isFinite(value) ? value : 0,
    propertyAddress: fullAddress || street,
    streetAddress: street,
    city,
    state,
    zip,
    notes: notes.join("; "),
    raw: data
  };
}

function normalize(provider, payload) {
  const data = provider === "arive"
    ? flattenAriveLoan(payload)
    : provider === "zillow"
      ? flattenZillowContact(payload)
      : provider === "myhomeiq"
        ? flattenMyhomeIq(payload)
        : Array.isArray(payload) ? payload[0] || {} : payload || {};
  const name = data.name || data.fullName || [data.firstName, data.lastName].filter(Boolean).join(" ") || "Unnamed record";
  const amount = Number(data.value || data.loanAmount || data.homeValue || data.purchasePrice || 0);
  return {
    id: `${provider}-${data.id || data.recordId || crypto.randomUUID()}`,
    provider,
    type: data.type || (provider === "arive" ? "loan" : provider === "myhomeiq" ? "property" : provider === "loanofficerai" ? "opportunity" : "lead"),
    name,
    email: data.email || "",
    phone: data.phone || data.mobile || "",
    stage: data.stage || data.loanStage || data.pipelineStage || "New",
    source: data.source || providers[provider].name,
    status: data.status || data.priority || "New",
    value: Number.isFinite(amount) ? amount : 0,
    owner: data.owner || data.assignedTo || data.loanOfficer || "",
    address: [data.propertyAddress || data.address, data.city, data.state, data.zip].filter(Boolean).join(", "),
    updatedAt: data.updatedAt || data.created || new Date().toISOString(),
    notes: data.notes || data.summary || "",
    raw: data.raw || data
  };
}

function webhookAuthorized(req, url, provider) {
  const token = process.env[`${String(provider || "").toUpperCase()}_WEBHOOK_TOKEN`] || "";
  if (!token) return true;
  if (isAuthenticated(req)) return true;

  const queryToken = url.searchParams.get("token") || url.searchParams.get("secret");
  if (queryToken && safeStringEqual(queryToken, token)) return true;

  const received = req.headers["x-hub-signature-256"] || req.headers["x-signature"];
  if (!received) return false;

  const expected = crypto.createHmac("sha256", token).update(url.pathname).digest("hex");
  const normalized = String(received).replace(/^sha256=/, "");
  if (expected.length !== normalized.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(normalized));
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
:root{--bg:#f5f7f6;--surface:#fff;--soft:#eef3f0;--line:#d8e0dc;--text:#1d2522;--muted:#61706a;--green:#12715b;--blue:#2563eb;--amber:#b45309;--red:#b91c1c;--shadow:0 16px 40px rgba(22,35,30,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}button,input,select,textarea{font:inherit}.app{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}.side{position:sticky;top:0;height:100vh;background:#17211d;color:#f7fbf8;padding:22px}.brand{display:flex;gap:12px;align-items:center;margin-bottom:30px}.mark{display:grid;place-items:center;width:44px;height:44px;border-radius:8px;background:#25443a;font-weight:800}.brand span{display:block;color:#aec3ba;font-size:.84rem;margin-top:2px}.nav{display:grid;gap:6px}.nav a{color:#dbe8e2;text-decoration:none;padding:10px 12px;border-radius:6px}.nav a:first-child,.nav a:hover{background:rgba(255,255,255,.1);color:#fff}.main{width:min(1560px,100%);padding:28px}.top{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:22px}.eyebrow{margin:0 0 6px;color:var(--green);font-size:.78rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}h1{margin:0;font-size:clamp(1.9rem,3vw,2.7rem);line-height:1.08}h2,h3,p{margin-top:0}.subline{margin:8px 0 0;color:var(--muted);max-width:820px;line-height:1.45}button,.button{border:1px solid var(--line);border-radius:6px;min-height:40px;padding:0 14px;background:#fff;color:var(--text);font-weight:750;cursor:pointer}.primary{background:var(--green);color:#fff;border-color:var(--green)}.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin-bottom:18px}.metric,.panel,.connector,.stage,.lead-card,.role-card{background:var(--surface);border:1px solid var(--line);border-radius:8px}.metric{padding:18px;box-shadow:var(--shadow)}.metric span{color:var(--muted);font-size:.9rem}.metric strong{display:block;margin-top:10px;font-size:1.9rem}.grid{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(340px,.75fr);gap:18px;margin-bottom:18px}.panel{padding:18px;box-shadow:var(--shadow)}.panel-head{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:16px}.panel h2{margin:0}.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.input{width:100%;min-height:40px;border:1px solid var(--line);border-radius:6px;background:#fff;color:var(--text);padding:8px 10px}.filters .input{max-width:220px}.funnel-panel{overflow:hidden}.funnel-board{display:grid;grid-template-columns:repeat(7,minmax(220px,1fr));gap:10px;overflow-x:auto;padding-bottom:4px}.stage{display:flex;flex-direction:column;min-height:420px;background:#fbfdfc;box-shadow:none}.stage-head{border-top:4px solid var(--stage);padding:12px 12px 10px}.stage-title{display:flex;justify-content:space-between;gap:10px;align-items:center}.stage-title strong{font-size:.98rem}.stage-count{display:inline-flex;align-items:center;justify-content:center;min-width:28px;height:28px;border-radius:999px;background:var(--soft);font-weight:800}.stage-target{margin:7px 0 0;color:var(--muted);font-size:.8rem;line-height:1.35}.stage-list{display:grid;gap:10px;padding:10px;align-content:start}.lead-card{box-shadow:0 8px 20px rgba(22,35,30,.07);padding:11px}.lead-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.lead-top strong{line-height:1.25}.lead-meta,.lead-contact,.lead-stage,.lead-next{font-size:.82rem;color:var(--muted);line-height:1.35}.lead-meta{display:flex;gap:7px;align-items:center;margin-top:8px}.lead-dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}.lead-stage{margin-top:7px;color:#355149}.lead-contact{margin-top:5px;overflow-wrap:anywhere}.lead-foot{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-top:10px}.lead-value{font-weight:800}.status,.chip,.pill{display:inline-flex;align-items:center;min-height:26px;border-radius:999px;padding:0 9px;background:#e7f2ff;color:#144d8b;font-size:.78rem;font-weight:800}.status.hot,.pill.hot{background:#fee2e2;color:var(--red)}.status.warm,.pill.warm{background:#fff2d7;color:var(--amber)}.empty-stage{color:var(--muted);font-size:.86rem;line-height:1.35;background:#f4f7f5;border:1px dashed #c8d4ce;border-radius:6px;padding:10px}.role-grid{display:grid;gap:10px}.role-card{padding:12px;box-shadow:none}.role-card strong{display:block}.role-card span{display:block;margin-top:4px;color:var(--muted);font-size:.86rem;line-height:1.35}.event{border-left:3px solid var(--green);background:var(--soft);border-radius:6px;padding:10px 12px;margin-bottom:10px}.event span{display:block;color:var(--muted);font-size:.82rem;margin-top:2px}.connectors{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.connector{box-shadow:none;padding:15px}.source{display:flex;gap:10px;align-items:flex-start}.dot{width:12px;height:12px;border-radius:50%;background:var(--green);margin-top:6px}.connector p{color:var(--muted);line-height:1.45;min-height:62px}.chip{background:var(--soft);color:#2d4039;margin:0 6px 6px 0}.good{background:#dff5e9;color:#17603c}.warn{background:#fff2d7;color:#8a4a06}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px}table{width:100%;min-width:940px;border-collapse:collapse;background:#fff}th,td{padding:12px 14px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:#f1f5f3;color:#40514a;font-size:.78rem;text-transform:uppercase}tbody tr:hover{background:#f8fbfa}.name-cell strong,.name-cell span{display:block}.name-cell span{margin-top:2px;color:var(--muted);font-size:.82rem;overflow-wrap:anywhere}.notice{margin-top:14px;border:1px solid #f1d18a;border-radius:8px;background:#fff8e8;color:#6c4305;padding:12px;line-height:1.45}textarea{width:100%;min-height:180px;font-family:Consolas,monospace}.webhook-list code{overflow-wrap:anywhere}.webhook-list p{border:1px solid var(--line);border-radius:6px;padding:10px;background:#fbfdfc}.small-muted{color:var(--muted);font-size:.88rem}
.section-note{margin:8px 0 0;color:var(--muted);line-height:1.45;max-width:760px}.arive-rail{display:grid;grid-template-columns:repeat(11,minmax(138px,1fr));gap:8px;overflow-x:auto;padding-bottom:8px;margin-bottom:16px}.arive-step{border:1px solid var(--line);border-top:4px solid var(--step);border-radius:8px;background:#fbfdfc;padding:10px;min-height:118px}.arive-step strong{display:block;font-size:.88rem}.arive-step span{display:block;color:var(--muted);font-size:.78rem;margin-top:5px;line-height:1.3}.arive-step .stage-count{margin-top:8px}.workflow-columns{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(340px,.9fr);gap:16px}.arive-loans{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.arive-loan{border:1px solid var(--line);border-radius:8px;background:#fff;padding:12px}.arive-loan strong{display:block}.arive-loan span{display:block;color:var(--muted);font-size:.84rem;margin-top:4px;line-height:1.35}.arive-worklist{display:grid;gap:10px}.work-card{border:1px solid var(--line);border-left:4px solid var(--green);border-radius:8px;background:#fff;padding:12px}.work-card strong{display:block;margin-bottom:6px}.work-card ul,.risk-card ul{margin:0;padding-left:18px;color:#40514a;font-size:.86rem;line-height:1.42}.risk-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:16px}.risk-card{border:1px solid #f1d18a;border-radius:8px;background:#fffaf0;padding:12px;color:#6c4305}.risk-card strong{display:block;margin-bottom:5px}.arive-badge{display:inline-flex;align-items:center;min-height:26px;border-radius:999px;background:#e0f2fe;color:#075985;padding:0 9px;font-size:.78rem;font-weight:800}.empty-wide{border:1px dashed #c8d4ce;border-radius:8px;background:#f4f7f5;color:var(--muted);padding:14px;line-height:1.45}
@media(max-width:1280px){.grid,.workflow-columns{grid-template-columns:1fr}.connectors,.metrics,.arive-loans,.risk-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:780px){.app{grid-template-columns:1fr}.side{position:static;height:auto;padding:14px}.brand{margin-bottom:14px}.nav{grid-auto-flow:column;overflow:auto}.main{padding:18px}.metrics,.connectors,.arive-loans,.risk-grid{grid-template-columns:1fr}.top,.panel-head{align-items:flex-start;flex-direction:column}.filters .input{max-width:none}.filters{width:100%}.funnel-board{grid-template-columns:repeat(7,minmax(210px,82vw))}.arive-rail{grid-template-columns:repeat(11,minmax(150px,75vw))}}
</style>
</head>
<body>
<div class="app"><aside class="side"><div class="brand"><div class="mark">8C</div><div><strong>8 Step Close</strong><span>Borrower funnel</span></div></div><nav class="nav"><a href="#overview">Funnel</a><a href="#ariveWorkflow">ARIVE Workflow</a><a href="#systems">Systems</a><a href="#records">Records</a><a href="#webhooks">Webhooks</a></nav></aside>
<main class="main"><header class="top"><div><p class="eyebrow">8 Step Close</p><h1>Borrower Sales Funnel</h1><p class="subline">Track each unique lead or borrower from automated contact, to application, to pre-approval, to disclosures, through the loan cycle, closed, and future-business follow-up.</p></div><div><button id="refresh">Refresh</button> <button id="sync" class="primary">Check Sync</button> <button id="logout">Log Out</button></div></header>
<section id="overview" class="metrics"><article class="metric"><span>Lead nurture</span><strong id="leadNurture">0</strong></article><article class="metric"><span>Application and approval</span><strong id="applicationCount">0</strong></article><article class="metric"><span>Sold and loan cycle</span><strong id="loanCycleCount">0</strong></article><article class="metric"><span>Closed and follow-up</span><strong id="closedCount">0</strong></article><article class="metric"><span>Pipeline value</span><strong id="pipelineValue">$0</strong></article></section>
<section class="grid"><div class="panel funnel-panel"><div class="panel-head"><div><p class="eyebrow">Pipeline</p><h2>Active Borrower Journey</h2></div><div class="filters"><input id="search" class="input" type="search" placeholder="Search leads"><select id="provider" class="input"><option value="all">All sources</option></select><select id="type" class="input"><option value="all">All types</option><option value="lead">Leads</option><option value="loan">Loans</option><option value="contact">Contacts</option><option value="property">Properties</option><option value="opportunity">Opportunities</option></select></div></div><div id="funnelBoard" class="funnel-board"></div></div><div class="panel"><div class="panel-head"><div><p class="eyebrow">How systems work</p><h2>System Roles</h2></div><span id="updated" class="small-muted"></span></div><div id="systemRoles" class="role-grid"></div></div></section>
<section id="ariveWorkflow" class="panel"><div class="panel-head"><div><p class="eyebrow">ARIVE sold to funded</p><h2>Loan Cycle Command Center</h2><p class="section-note">Detailed workflow for files after the borrower commits: Loan Set-up through Funded, Check Received, and Loan Finalized.</p></div><span id="ariveLoanCount" class="arive-badge">0 ARIVE loans</span></div><div id="ariveRail" class="arive-rail"></div><div class="workflow-columns"><div><h3>Active ARIVE loans</h3><div id="ariveLoans" class="arive-loans"></div></div><div><h3>Role checklist</h3><div id="ariveWorklist" class="arive-worklist"></div></div></div><div id="ariveRisks" class="risk-grid"></div></section>
<section class="grid"><div id="systems" class="panel"><div class="panel-head"><div><p class="eyebrow">Data sources</p><h2>Connected Systems</h2></div></div><div id="connectorGrid" class="connectors"></div></div><div class="panel"><div class="panel-head"><div><p class="eyebrow">Activity</p><h2>Recent Events</h2></div></div><div id="events"></div></div></section>
<section id="records" class="panel"><div class="panel-head"><div><p class="eyebrow">Unified view</p><h2>All Records</h2></div><span id="recordCount" class="small-muted"></span></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Funnel stage</th><th>Source</th><th>Type</th><th>System stage</th><th>Status</th><th>Value</th><th>Updated</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<section id="webhooks" class="grid"><div class="panel"><p class="eyebrow">Inbound data</p><h2>Webhook Tester</h2><form id="webhookForm"><p><select id="webhookProvider" class="input"></select></p><p><textarea id="payload" class="input"></textarea></p><button class="primary">Send Test Event</button></form></div><div class="panel"><p class="eyebrow">Setup</p><h2>Webhook URLs</h2><div id="webhookList" class="webhook-list"></div><div class="notice">For Zillow lender contacts, send Zillow the Zillow posting URL. For myhomeIQ, use Zapier buyer and seller lead triggers to post into the myhomeIQ webhook URL with its private token.</div></div></section>
</main></div>
<script>
if(false){
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
}
const fmt=new Intl.NumberFormat("en-US",{style:"currency",currency:"USD",maximumFractionDigits:0});let connectors=[],records=[],recentEvents=[];
const funnelStages=[
  {key:"lead_nurture",label:"Lead nurture",target:"Automated contact strategy",color:"#0f766e"},
  {key:"application",label:"Application",target:"Application started or borrower file building",color:"#2563eb"},
  {key:"preapproved",label:"Pre-approved",target:"Approved and staying engaged until offer",color:"#7c3aed"},
  {key:"disclosures",label:"Disclosures sent",target:"Sold file, disclosures, intent to proceed",color:"#b45309"},
  {key:"loan_cycle",label:"Loan cycle",target:"Processing, underwriting, conditions, closing",color:"#0284c7"},
  {key:"closed",label:"Closed",target:"Closed or funded loan",color:"#16a34a"},
  {key:"post_close",label:"Post-close",target:"Retention, equity alerts, reviews, referrals",color:"#64748b"}
];
const roleCards=[
  ["Lead capture","Zillow, CINC, and myhomeIQ bring new buyer and seller leads into the top of the funnel."],
  ["Automated contact","BNTouch and LoanOfficer.ai keep leads engaged and surface intent signals."],
  ["Application and loans","ARIVE carries applications, pre-approvals, disclosures, processing, and closing milestones."],
  ["Future business","myhomeIQ and BNTouch support homeowner check-ins, equity alerts, reviews, and referrals."]
];
const ariveStages=[
  {key:"loan_setup",label:"Loan Set-up",owner:"LO",color:"#2563eb",exit:"Application, pricing, fees, team, lender registration, and lock verified."},
  {key:"disclosed",label:"Disclosed",owner:"LO",color:"#b45309",exit:"Initial disclosures sent by public link and LO e-sign portion completed."},
  {key:"submitted",label:"Submitted to UW",owner:"Processor",color:"#0284c7",exit:"Clean lender package submitted and ARIVE status/date updated."},
  {key:"conditions",label:"Approved w/ Conditions",owner:"Processor + LC",color:"#7c3aed",exit:"Approval and condition sheets uploaded, LC tasks created, borrower needs active."},
  {key:"resubmitted",label:"Re-Submitted",owner:"Processor",color:"#0f766e",exit:"Conditions uploaded as PTD1 and resubmitted same day or within 24 hours."},
  {key:"ctc",label:"Clear to Close",owner:"Processor + LC",color:"#16a34a",exit:"Closing date confirmed with LO, Processor, borrower, realtors, and title."},
  {key:"docs_out",label:"Docs Out",owner:"Processor",color:"#64748b",exit:"Balanced CD and final documents delivered to title."},
  {key:"docs_signed",label:"Docs Signed",owner:"Funder",color:"#475569",exit:"Status date matches closing date on Final CD."},
  {key:"funded",label:"Funded",owner:"Funder",color:"#15803d",exit:"Funding authorized, final wire breakdown uploaded as PTF."},
  {key:"check_received",label:"Check Received",owner:"Funder",color:"#0e7490",exit:"Purchase/check received and post-closing items tracked."},
  {key:"finalized",label:"Loan Finalized",owner:"Funder",color:"#334155",exit:"Loan purchased by lender and ARIVE moved to Loan Finalized."}
];
const ariveRoleChecklist=[
  ["Loan Officer",["Confirm borrower commitment and expectations.","Review application, product/pricing, loan amount, fees, rate, and lock.","Send disclosures, call/text borrower to e-sign, and support non-response.","Escalate qualification or suspense items with Processor and Manager."]],
  ["Loan Coordinator",["Order title, HOI, WVOE, appraisal, COE, case numbers, and HOA/condo items as applicable.","Keep Client Needs, Tasks, Trackers, and uploaded document labels current daily.","Upload received condition items to ARIVE and lender as PTD1 before funding.","Send required borrower and partner milestone updates."]],
  ["Processor",["Submit the clean lender package and keep ARIVE aligned with lender status.","Upload approvals/conditions, create LC tasks, and resubmit conditions within 24 hours.","Track rate lock, redisclosures, initial CD, title approval, CTC, and Docs Out.","Confirm documents are labeled Initial Submission, PTD1, PTF, or Post Funding.","Prepare final package and assign funding task when ready."]],
  ["Funder",["Confirm final package readiness and Docs Signed date.","Authorize funding, confirm wire breakdown, and upload PTF documents.","Own post-closing conditions and escalate unresolved borrower-needed items after 2 days.","Move ARIVE through Funded, Check Received, and Loan Finalized."]]
];
const ariveRiskRules=[
  ["Borrower non-contact","Over 72 hours without borrower response."],
  ["Closing risk","Closing within 7 days and loan is not Clear to Close."],
  ["Appraisal delay","Appraisal not scheduled within 72 hours."],
  ["Title delay","Title commitment not received within 7 business days."],
  ["HOA delay","HOA documents not received within 7 business days."],
  ["Redisclosure timing","Redisclosure occurs within 7 days of closing."],
  ["Post-closing delay","Post-closing item unresolved after 2 days."]
];
const ariveAdverseRule=["Adverse / withdraw rule",["Loan Set-up or earlier: no action required.","Disclosed or higher: LO tasks Processor with reason; Processor withdraws and clears task."]];
async function api(path,opt={}){const res=await fetch(path,{headers:{"Content-Type":"application/json"},...opt});const data=await res.json();if(!res.ok)throw new Error(data.error||"Request failed");return data}
function $(selector){return document.querySelector(selector)}
function esc(value){const map={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};return String(value??"").replace(/[&<>"']/g,ch=>map[ch])}
function date(v){return new Intl.DateTimeFormat("en-US",{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"}).format(new Date(v))}
function connectorFor(record){return connectors.find(c=>c.id===record.provider)||{id:record.provider,name:record.provider,color:"#64748b"}}
function textFor(record){return [record.stage,record.status,record.type,record.source,record.provider,record.notes].filter(Boolean).join(" ").toLowerCase()}
function stageKey(record){const text=textFor(record);const freshLead=/buyer lead|seller lead|new lead|zillow contact|lead received/.test(text);if((/post.?close|past client|client nurture|homeowner|annual|retention|repeat|referral|equity|home value|likely to move|move signal|rate drop|refi|refinance/.test(text)||(record.provider==="myhomeiq"&&record.type==="property"))&&!freshLead)return"post_close";if(/closed|funded|settled/.test(text))return"closed";if(/processing|underwriting|condition|clear to close|ctc|closing|docs|appraisal|title|submitted|final approval|lock/.test(text))return"loan_cycle";if(/disclosure|intent to proceed|itp|sold|loan setup|loan set-up|contract|accepted offer|purchase agreement/.test(text))return"disclosures";if(/pre.?approved|pre.?approval|pre.?qualified|prequal|approval letter/.test(text)||text.includes("approved"))return"preapproved";if(/application|apply|app complete|1003|borrower|loan app/.test(text)||record.provider==="arive"||record.type==="loan")return"application";return"lead_nurture"}
function stageLabel(key){const stage=funnelStages.find(item=>item.key===key);return stage?stage.label:key}
function nextAction(key){return({lead_nurture:"Keep in automated contact",application:"Complete borrower application",preapproved:"Nurture until offer",disclosures:"Confirm disclosures and intent",loan_cycle:"Watch loan milestones",closed:"Start client-for-life plan",post_close:"Earn repeat and referral business"})[key]||"Review next step"}
function countsByStage(){const counts={};funnelStages.forEach(stage=>counts[stage.key]=0);records.forEach(record=>counts[stageKey(record)]++);return counts}
function statusClass(status){const text=String(status||"").toLowerCase();if(text.includes("hot")||text.includes("high"))return"hot";if(text.includes("warm")||text.includes("watch"))return"warm";return""}
function ariveText(record){return [record.stage,record.status,record.type,record.notes,record.source].filter(Boolean).join(" ").toLowerCase()}
function ariveStageKey(record){const text=ariveText(record);if(/loan finalized|finalized/.test(text))return"finalized";if(/check received|purchased by the lender|purchased by lender/.test(text))return"check_received";if(/loan funded|funded|disbursement/.test(text))return"funded";if(/docs signed|doc signed/.test(text))return"docs_signed";if(/docs out|docs - out|docs – out|doc out|final closing documents/.test(text))return"docs_out";if(/clear to close|ctc/.test(text))return"ctc";if(/re.?submitted|re-submittal|resubmittal/.test(text))return"resubmitted";if(/approved with conditions|approved w\\/conditions|condition/.test(text))return"conditions";if(/submitted to uw|submitted|underwriting|processing|\\buw\\b/.test(text))return"submitted";if(/disclosed|disclosures|initial disclosure/.test(text))return"disclosed";if(/loan setup|loan set-up|sold|registered|locked/.test(text))return"loan_setup";return null}
function isAriveWorkflowRecord(record){return record.provider==="arive"&&Boolean(ariveStageKey(record))}
function ariveOwnerFor(key){const stage=ariveStages.find(item=>item.key===key);return stage?stage.owner:"Team"}
function ariveExitFor(key){const stage=ariveStages.find(item=>item.key===key);return stage?stage.exit:"Review ARIVE file and next task."}
async function load(){const status=await api("/api/status");connectors=status.connectors;recentEvents=status.recentEvents||[];$("#updated").textContent="Updated "+date(status.generatedAt);renderOptions();renderRoles();renderConnectors();renderEvents(recentEvents);await loadRecords()}
function renderMetrics(){const counts=countsByStage();const value=records.reduce((total,record)=>total+Number(record.value||0),0);$("#leadNurture").textContent=counts.lead_nurture||0;$("#applicationCount").textContent=(counts.application||0)+(counts.preapproved||0);$("#loanCycleCount").textContent=(counts.disclosures||0)+(counts.loan_cycle||0);$("#closedCount").textContent=(counts.closed||0)+(counts.post_close||0);$("#pipelineValue").textContent=fmt.format(value)}
function renderOptions(){const p=$("#provider"),w=$("#webhookProvider");const selected=p.value||"all";p.innerHTML='<option value="all">All sources</option>';w.innerHTML='';connectors.forEach(c=>{p.insertAdjacentHTML("beforeend",'<option value="'+esc(c.id)+'">'+esc(c.name)+'</option>');w.insertAdjacentHTML("beforeend",'<option value="'+esc(c.id)+'">'+esc(c.name)+'</option>')});p.value=selected;$("#payload").value=JSON.stringify({firstName:"Casey",lastName:"Williams",email:"casey@example.com",phone:"(555) 016-2204",stage:"New lead",status:"Hot",value:540000,source:"Website"},null,2);$("#webhookList").innerHTML=connectors.map(c=>'<p><strong>'+esc(c.name)+'</strong><br><code>POST '+esc(location.origin+c.webhookPath)+'</code></p>').join("")}
function renderRoles(){$("#systemRoles").innerHTML=roleCards.map(card=>'<article class="role-card"><strong>'+esc(card[0])+'</strong><span>'+esc(card[1])+'</span></article>').join("")}
function renderConnectors(){const grid=$("#connectorGrid");grid.innerHTML=connectors.map(c=>'<article class="connector"><div class="source"><span class="dot" style="background:'+esc(c.color)+'"></span><div><strong>'+esc(c.name)+'</strong><br><span>'+esc(c.category)+'</span></div></div><p>'+esc(c.access)+'</p><span class="chip '+(String(c.status).toLowerCase().includes("ready")?"good":"warn")+'">'+esc(c.status)+'</span><span class="chip">'+esc(c.syncMode)+'</span><p><button data-action="test" data-provider="'+esc(c.id)+'">Test</button> <button data-action="sync" data-provider="'+esc(c.id)+'">Sync</button></p></article>').join("");grid.querySelectorAll("button[data-provider]").forEach(button=>{button.onclick=()=>button.dataset.action==="test"?test(button.dataset.provider):sync(button.dataset.provider)})}
function renderEvents(events){$("#events").innerHTML=(events&&events.length?events:[]).map(e=>'<div class="event"><strong>'+esc(e.message)+'</strong><span>'+esc((connectorFor(e)||{}).name||e.provider)+' - '+date(e.createdAt)+'</span></div>').join("")||'<p class="small-muted">No recent activity yet.</p>'}
function renderFunnel(){const buckets={};funnelStages.forEach(stage=>buckets[stage.key]=[]);records.forEach(record=>buckets[stageKey(record)].push(record));$("#funnelBoard").innerHTML=funnelStages.map(stage=>{const list=buckets[stage.key]||[];const value=list.reduce((total,record)=>total+Number(record.value||0),0);return'<article class="stage" style="--stage:'+stage.color+'"><div class="stage-head"><div class="stage-title"><strong>'+esc(stage.label)+'</strong><span class="stage-count">'+list.length+'</span></div><p class="stage-target">'+esc(stage.target)+'<br>'+fmt.format(value)+'</p></div><div class="stage-list">'+(list.length?list.map(renderLeadCard).join(""):'<div class="empty-stage">No borrowers are sitting here right now.</div>')+'</div></article>'}).join("")}
function renderLeadCard(record){const key=stageKey(record);const connector=connectorFor(record);const contact=[record.email,record.phone].filter(Boolean).join(" - ");return'<article class="lead-card"><div class="lead-top"><strong>'+esc(record.name||"Unnamed record")+'</strong><span class="status '+statusClass(record.status)+'">'+esc(record.status||"New")+'</span></div><div class="lead-meta"><span class="lead-dot" style="background:'+esc(connector.color||"#64748b")+'"></span><span>'+esc(connector.name||record.provider)+'</span></div><div class="lead-stage">'+esc(record.stage||stageLabel(key))+'</div>'+(contact?'<div class="lead-contact">'+esc(contact)+'</div>':"")+'<div class="lead-foot"><span class="lead-value">'+(record.value?fmt.format(record.value):"")+'</span><span class="lead-next">'+esc(nextAction(key))+'</span></div></article>'}
function renderAriveWorkflow(){const workflowRecords=records.filter(isAriveWorkflowRecord).sort((a,b)=>ariveStages.findIndex(s=>s.key===ariveStageKey(a))-ariveStages.findIndex(s=>s.key===ariveStageKey(b)));const counts={};ariveStages.forEach(stage=>counts[stage.key]=0);workflowRecords.forEach(record=>counts[ariveStageKey(record)]++);$("#ariveLoanCount").textContent=workflowRecords.length+" ARIVE loan"+(workflowRecords.length===1?"":"s");$("#ariveRail").innerHTML=ariveStages.map(stage=>'<article class="arive-step" style="--step:'+stage.color+'"><strong>'+esc(stage.label)+'</strong><span>'+esc(stage.owner)+'</span><span>'+esc(stage.exit)+'</span><span class="stage-count">'+(counts[stage.key]||0)+'</span></article>').join("");$("#ariveLoans").innerHTML=workflowRecords.length?workflowRecords.map(record=>{const key=ariveStageKey(record);return'<article class="arive-loan"><strong>'+esc(record.name||"Unnamed loan")+'</strong><span>'+esc(record.stage||stageLabel(stageKey(record)))+'</span><span>Owner: '+esc(ariveOwnerFor(key))+'</span><span>Next: '+esc(ariveExitFor(key))+'</span><span>'+(record.value?fmt.format(record.value):"")+' '+esc(date(record.updatedAt))+'</span></article>'}).join(""):'<div class="empty-wide">No ARIVE loans are currently in the Sold-to-Funded workflow view.</div>';$("#ariveWorklist").innerHTML=ariveRoleChecklist.map(card=>'<article class="work-card"><strong>'+esc(card[0])+'</strong><ul>'+card[1].map(item=>'<li>'+esc(item)+'</li>').join("")+'</ul></article>').join("");$("#ariveRisks").innerHTML=ariveRiskRules.map(rule=>'<article class="risk-card"><strong>'+esc(rule[0])+'</strong><span>'+esc(rule[1])+'</span></article>').join("")+'<article class="risk-card"><strong>'+esc(ariveAdverseRule[0])+'</strong><ul>'+ariveAdverseRule[1].map(item=>'<li>'+esc(item)+'</li>').join("")+'</ul></article>'}
function renderRows(){$("#recordCount").textContent=records.length+" record"+(records.length===1?"":"s")+" shown";$("#rows").innerHTML=records.map(r=>{const connector=connectorFor(r);const key=stageKey(r);return'<tr><td class="name-cell"><strong>'+esc(r.name)+'</strong><span>'+esc([r.email,r.phone].filter(Boolean).join(" - "))+'</span></td><td>'+esc(stageLabel(key))+'</td><td>'+esc(connector.name||r.provider)+'</td><td>'+esc(r.type)+'</td><td>'+esc(r.stage||"")+'</td><td><span class="pill '+statusClass(r.status)+'">'+esc(r.status||"New")+'</span></td><td>'+(r.value?fmt.format(r.value):"")+'</td><td>'+date(r.updatedAt)+'</td></tr>'}).join("")||'<tr><td colspan="8">No records found.</td></tr>'}
async function loadRecords(){const p=$("#provider").value,t=$("#type").value,q=$("#search").value;const data=await api("/api/records?provider="+encodeURIComponent(p)+"&type="+encodeURIComponent(t)+"&q="+encodeURIComponent(q));records=data.records;renderMetrics();renderFunnel();renderAriveWorkflow();renderRows()}
async function test(id){const r=await api("/api/test/"+id,{method:"POST",body:"{}"});alert(r.status+"\\n"+r.detail)}
async function sync(id){await api("/api/sync/"+id,{method:"POST",body:"{}"});await load()}
$("#refresh").onclick=load;$("#sync").onclick=async()=>{for(const c of connectors)await sync(c.id)};$("#logout").onclick=async()=>{await fetch("/api/logout",{method:"POST"});location.href="/login"};$("#provider").onchange=loadRecords;$("#type").onchange=loadRecords;$("#search").oninput=()=>{clearTimeout(window.searchTimer);window.searchTimer=setTimeout(loadRecords,160)};$("#webhookForm").onsubmit=async e=>{e.preventDefault();const id=$("#webhookProvider").value;const r=await api("/api/webhooks/"+id,{method:"POST",body:$("#payload").value});alert(r.warning||"Saved "+r.records.length+" record.");await load()};load();
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
      if (!webhookAuthorized(req, url, provider)) {
        send(res, 401, { error: "Invalid webhook token" });
        return;
      }
      const payload = await readBody(req);
      const record = normalize(provider, payload);
      store.records.unshift(record);
      const item = event(provider, `${providers[provider].name} webhook saved 1 record`);
      store.events.push(item);
      send(res, 202, { accepted: true, stored: true, records: [record], event: item, warning: null });
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
