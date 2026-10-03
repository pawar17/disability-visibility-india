/**
 * Disability Visibility India — petitions and contact backend
 * Cloudflare Worker + D1 (SQLite). Free tier.
 *
 * Public host  api.disability-visibility.com
 *   GET  /summary        counts + public first-name/city list per petition
 *   POST /sign           add a signature (pending until the email link is clicked)
 *   GET  /confirm?t=…    confirm a signature
 *   POST /contact        contact form message
 *
 * Private host admin.disability-visibility.com (email sign-in link for ADMIN_EMAILS; Cloudflare Access also accepted)
 *   GET  /               admin page
 *   GET  /api/data       all signatures and messages
 *   GET  /api/export?type=signatures|messages   CSV download
 *   POST /api/delete     remove a signature or message
 *
 * Secrets (set in the Cloudflare dashboard, never in code):
 *   TURNSTILE_SECRET, RESEND_API_KEY (IP_SALT optional; defaults to the Turnstile secret)
 * Vars (wrangler.toml): SITE_ORIGINS, ACCESS_TEAM, ACCESS_AUD, ADMIN_EMAILS, MAIL_FROM, NOTIFY_EMAIL
 */

const PETITIONS = ["census", "access", "pension", "isl",
  "idea-tactile", "idea-atw", "idea-sunflower", "idea-bme", "idea-signai", "idea-taxi"];
const WHY = ["A parent or family member", "A disabled person", "A teacher or therapist", "A lawyer or researcher",
  "A journalist", "An organisation or company", "Someone who wants to volunteer",
  "Suggesting an organisation or support group", "Suggesting a petition", "Feedback on the site", "Something else"];
const STATES = ["Andaman and Nicobar Islands","Andhra Pradesh","Arunachal Pradesh","Assam","Bihar","Chandigarh","Chhattisgarh",
  "Dadra and Nagar Haveli and Daman and Diu","Delhi","Goa","Gujarat","Haryana","Himachal Pradesh","Jammu and Kashmir","Jharkhand",
  "Karnataka","Kerala","Ladakh","Lakshadweep","Madhya Pradesh","Maharashtra","Manipur","Meghalaya","Mizoram","Nagaland","Odisha",
  "Puducherry","Punjab","Rajasthan","Sikkim","Tamil Nadu","Telangana","Tripura","Uttar Pradesh","Uttarakhand","West Bengal","Outside India"];

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS signatures (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     petition TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL,
     city TEXT NOT NULL, state TEXT NOT NULL,
     show_public INTEGER NOT NULL DEFAULT 0, wants_updates INTEGER NOT NULL DEFAULT 0,
     public_name TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
     token TEXT, ip_hash TEXT, created_at TEXT NOT NULL, confirmed_at TEXT,
     UNIQUE(petition, email))`,
  `CREATE INDEX IF NOT EXISTS sig_token ON signatures(token)`,
  `CREATE INDEX IF NOT EXISTS sig_ip ON signatures(ip_hash, created_at)`,
  `CREATE TABLE IF NOT EXISTS messages (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     name TEXT NOT NULL, email TEXT NOT NULL, writing_as TEXT NOT NULL, message TEXT NOT NULL,
     ip_hash TEXT, created_at TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS msg_email ON messages(email, created_at)`,
  `CREATE TABLE IF NOT EXISTS admin_links (token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS admin_sessions (id_hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS admin_login_attempts (ip_hash TEXT NOT NULL, at TEXT NOT NULL)`,
];
const CACHE_KEY = "https://api.disability-visibility.com/__cache/summary";
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch(SCHEMA.map(s => db.prepare(s)));
  // Added later: lets the signer's own browser check whether they've confirmed (from any device).
  try { await db.prepare("ALTER TABLE signatures ADD COLUMN check_hash TEXT").run(); } catch {}
  try { await db.prepare("CREATE INDEX IF NOT EXISTS sig_check ON signatures(check_hash)").run(); } catch {}
  schemaReady = true;
}

/* ---------- helpers ---------- */
const clean = (v, max) => String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;
const shortName = full => { const p = clean(full, 80).split(" ").filter(Boolean); return p.length ? p[0].slice(0, 24) + (p.length > 1 ? " " + p[p.length - 1][0].toUpperCase() + "." : "") : ""; };
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const now = () => new Date().toISOString();
const hoursAgo = h => new Date(Date.now() - h * 3600e3).toISOString();

async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function token() { const a = new Uint8Array(24); crypto.getRandomValues(a); return [...a].map(x => x.toString(16).padStart(2, "0")).join(""); }

function origins(env) { return String(env.SITE_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean); }
function cors(req, env) {
  const o = req.headers.get("Origin");
  const h = { "Vary": "Origin" };
  if (o && origins(env).includes(o)) {
    h["Access-Control-Allow-Origin"] = o;
    h["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Content-Type";
    h["Access-Control-Max-Age"] = "86400";
  }
  return h;
}
const SEC = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000",
};
function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...SEC, ...extra } });
}
function html(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...SEC, ...extra } });
}

async function readJson(req) {
  if ((req.headers.get("Content-Length") | 0) > 8000) return null;
  const t = await req.text(); if (t.length > 8000) return null;
  try { return JSON.parse(t); } catch { return null; }
}

async function turnstileOk(env, tok, ip) {
  if (!env.TURNSTILE_SECRET) return false;
  if (!tok || typeof tok !== "string" || tok.length > 2048) return false;
  const fd = new FormData(); fd.append("secret", env.TURNSTILE_SECRET); fd.append("response", tok); if (ip) fd.append("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: fd });
    const j = await r.json(); return j.success === true;
  } catch { return false; }
}

async function sendMail(env, to, subject, text) {
  if (!env.RESEND_API_KEY) throw new Error("mail_not_configured");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, text }),
  });
  if (!r.ok) throw new Error("mail_failed " + r.status);
}

/* ---------- public API ---------- */
async function summary(env, ctx, req) {
  const cache = caches.default, key = new Request(CACHE_KEY);
  const hit = await cache.match(key);
  if (hit) return hit;
  const counts = {}, recent = {};
  PETITIONS.forEach(p => { counts[p] = 0; recent[p] = []; });
  const c = await env.DB.prepare("SELECT petition, COUNT(*) n FROM signatures WHERE status='confirmed' GROUP BY petition").all();
  (c.results || []).forEach(r => { if (r.petition in counts) counts[r.petition] = r.n; });
  const pub = await env.DB.prepare(
    `SELECT petition, public_name n, city c, state s, confirmed_at at FROM (
       SELECT *, ROW_NUMBER() OVER (PARTITION BY petition ORDER BY confirmed_at DESC) rn
       FROM signatures WHERE status='confirmed' AND show_public=1) WHERE rn <= 40`).all();
  (pub.results || []).forEach(r => { if (r.petition in recent) recent[r.petition].push({ n: r.n, c: r.c, s: r.s, at: r.at }); });
  const res = json({ ok: true, counts, recent }, 200, { "Cache-Control": "public, max-age=30" });
  ctx.waitUntil(cache.put(key, res.clone()));
  return res;
}

async function sign(req, env, ctx) {
  if (!env.TURNSTILE_SECRET || !env.RESEND_API_KEY) return json({ ok: false, error: "not_ready" }, 503);
  const b = await readJson(req); if (!b) return json({ ok: false, error: "bad_request" }, 400);
  const pet = clean(b.petition, 30), email = clean(b.email, 120).toLowerCase();
  const name = clean(b.name, 80), city = clean(b.city, 60), state = clean(b.state, 60);
  if (!PETITIONS.includes(pet) || name.length < 2 || !city || !STATES.includes(state) || !validEmail(email)) return json({ ok: false, error: "bad_request" }, 400);
  const ip = req.headers.get("CF-Connecting-IP") || "";
  if (!(await turnstileOk(env, b.turnstile, ip))) return json({ ok: false, error: "bot_check" }, 403);
  const ipHash = await sha256((env.IP_SALT || env.TURNSTILE_SECRET || "") + ip);
  const recentFromIp = await env.DB.prepare("SELECT COUNT(*) n FROM signatures WHERE ip_hash=? AND created_at>?").bind(ipHash, hoursAgo(1)).first("n");
  if (recentFromIp >= 15) return json({ ok: false, error: "rate_limited" }, 429);

  const existing = await env.DB.prepare("SELECT id, status, created_at FROM signatures WHERE petition=? AND email=?").bind(pet, email).first();
  if (existing && existing.status === "confirmed") return json({ ok: false, error: "duplicate" }, 409);
  if (existing && existing.created_at > hoursAgo(0.25)) return json({ ok: false, error: "recently_sent" }, 429);

  const t = token(), pub = b.pub === true ? 1 : 0, check = token(), checkHash = await sha256(check);
  if (existing) {
    await env.DB.prepare("UPDATE signatures SET name=?, city=?, state=?, show_public=?, wants_updates=?, public_name=?, token=?, ip_hash=?, created_at=?, check_hash=? WHERE id=?")
      .bind(name, city, state, pub, b.updates === true ? 1 : 0, pub ? shortName(name) : "", t, ipHash, now(), checkHash, existing.id).run();
  } else {
    await env.DB.prepare("INSERT INTO signatures (petition, name, email, city, state, show_public, wants_updates, public_name, status, token, ip_hash, created_at, check_hash) VALUES (?,?,?,?,?,?,?,?, 'pending', ?,?,?,?)")
      .bind(pet, name, email, city, state, pub, b.updates === true ? 1 : 0, pub ? shortName(name) : "", t, ipHash, now(), checkHash).run();
  }
  const link = new URL(req.url).origin + "/confirm?t=" + t;
  try {
    await sendMail(env, email, "Confirm your signature: Disability Visibility India",
      `Hi ${name.split(" ")[0]},\n\nThank you for signing. Please confirm your signature by opening this link:\n${link}\n\nIf you didn't sign, ignore this email and nothing will be counted.\n\nDisability Visibility India\nhttps://disability-visibility.com`);
  } catch (e) {
    return json({ ok: false, error: "mail_failed" }, 502);
  }
  return json({ ok: true, pending: true, check });
}

// Only the browser that signed holds this random value, so nobody can probe other people's emails.
async function status(req, env) {
  const c = clean(new URL(req.url).searchParams.get("c"), 64);
  if (!/^[0-9a-f]{48}$/.test(c)) return json({ ok: false, error: "bad_request" }, 400);
  const r = await env.DB.prepare("SELECT petition, status FROM signatures WHERE check_hash=?").bind(await sha256(c)).first();
  return json({ ok: true, found: !!r, confirmed: !!(r && r.status === "confirmed"), petition: r ? r.petition : null });
}

async function confirm(req, env) {
  const t = clean(new URL(req.url).searchParams.get("t"), 64);
  let msg = "This confirmation link isn’t valid or has already been used.", ok = false, pet = "";
  if (/^[0-9a-f]{48}$/.test(t)) {
    const r = await env.DB.prepare("UPDATE signatures SET status='confirmed', token=NULL, confirmed_at=? WHERE token=? AND status='pending' RETURNING petition").bind(now(), t).first();
    if (r && r.petition) { ok = true; pet = r.petition; msg = "Your signature is confirmed and now counts."; await caches.default.delete(new Request(CACHE_KEY)); }
  }
  const back = "https://disability-visibility.com/" + (pet ? "?signed=" + encodeURIComponent(pet) : "") + "#act";
  return html(page("Signature confirmation", `<h1>${ok ? "Thank you for signing and making your voice count." : "Link not valid"}</h1><p>${esc(msg)}${ok ? " Taking you back to the petition…" : ""}</p><p><a href="${esc(back)}">Back to the petition</a></p>`), ok ? 200 : 400, ok ? { "Refresh": "3; url=" + back } : {});
}

async function contact(req, env, ctx) {
  if (!env.TURNSTILE_SECRET) return json({ ok: false, error: "not_ready" }, 503);
  const b = await readJson(req); if (!b) return json({ ok: false, error: "bad_request" }, 400);
  const name = clean(b.name, 80), email = clean(b.email, 120).toLowerCase(), why = clean(b.why, 60);
  const text = String(b.message == null ? "" : b.message).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, 3000).trim();
  if (!name || !text || !validEmail(email) || !WHY.includes(why)) return json({ ok: false, error: "bad_request" }, 400);
  const ip = req.headers.get("CF-Connecting-IP") || "";
  if (!(await turnstileOk(env, b.turnstile, ip))) return json({ ok: false, error: "bot_check" }, 403);
  const ipHash = await sha256((env.IP_SALT || env.TURNSTILE_SECRET || "") + ip);
  const byEmail = await env.DB.prepare("SELECT COUNT(*) n FROM messages WHERE email=? AND created_at>?").bind(email, hoursAgo(24)).first("n");
  const byIp = await env.DB.prepare("SELECT COUNT(*) n FROM messages WHERE ip_hash=? AND created_at>?").bind(ipHash, hoursAgo(24)).first("n");
  if (byEmail >= 3 || byIp >= 10) return json({ ok: false, error: "rate_limited" }, 429);
  await env.DB.prepare("INSERT INTO messages (name, email, writing_as, message, ip_hash, created_at) VALUES (?,?,?,?,?,?)").bind(name, email, why, text, ipHash, now()).run();
  if (env.NOTIFY_EMAIL && env.RESEND_API_KEY) {
    ctx.waitUntil(sendMail(env, env.NOTIFY_EMAIL, "New message on Disability Visibility India",
      `From: ${name} <${email}>\nWriting as: ${why}\n\n${text}\n\nSee all messages: https://admin.disability-visibility.com`).catch(() => {}));
  }
  return json({ ok: true });
}

/* ---------- admin (Cloudflare Access) ---------- */
let jwks = null, jwksAt = 0;
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
async function accessEmail(req, env) {
  if (!env.ACCESS_TEAM || !env.ACCESS_AUD) return null;
  const jwt = req.headers.get("Cf-Access-Jwt-Assertion");
  if (!jwt) return null;
  const [h, p, s] = jwt.split("."); if (!s) return null;
  let head, pay;
  try { head = JSON.parse(new TextDecoder().decode(b64u(h))); pay = JSON.parse(new TextDecoder().decode(b64u(p))); } catch { return null; }
  if (head.alg !== "RS256") return null;
  if (!jwks || Date.now() - jwksAt > 3600e3) {
    const r = await fetch(`https://${env.ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`);
    jwks = (await r.json()).keys || []; jwksAt = Date.now();
  }
  const jwk = jwks.find(k => k.kid === head.kid); if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64u(s), new TextEncoder().encode(h + "." + p));
  if (!valid) return null;
  const aud = Array.isArray(pay.aud) ? pay.aud : [pay.aud];
  if (!aud.includes(env.ACCESS_AUD)) return null;
  if (pay.iss !== `https://${env.ACCESS_TEAM}.cloudflareaccess.com`) return null;
  if (!pay.exp || pay.exp * 1000 < Date.now()) return null;
  const email = String(pay.email || "").toLowerCase();
  const allowed = String(env.ADMIN_EMAILS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean);
  return allowed.includes(email) ? email : null;
}

const csvCell = v => { let s = String(v == null ? "" : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

/* Email sign-in: a one-time link sent only to addresses in ADMIN_EMAILS. */
const SESSION_COOKIE = "__Host-dvi_admin";
const adminList = env => String(env.ADMIN_EMAILS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean);
function cookie(req, name) {
  const c = req.headers.get("Cookie") || "";
  for (const part of c.split(/;\s*/)) { const i = part.indexOf("="); if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1); }
  return "";
}
async function sessionEmail(req, env) {
  const id = cookie(req, SESSION_COOKIE);
  if (!/^[0-9a-f]{64}$/.test(id)) return null;
  const row = await env.DB.prepare("SELECT email, expires_at FROM admin_sessions WHERE id_hash=?").bind(await sha256(id)).first();
  if (!row || row.expires_at < now()) return null;
  return adminList(env).includes(row.email) ? row.email : null;
}
const LOGIN_CSP = { "Referrer-Policy": "same-origin", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" };
function loginPage(msg) {
  return html(page("Admin sign-in", `<h1>Admin sign-in</h1>${msg ? `<p>${esc(msg)}</p>` : ""}
<form method="post" action="/login" style="display:grid;gap:.6rem;margin-top:1rem">
<label for="e" style="font-weight:600">Email</label>
<input id="e" name="email" type="email" required autocomplete="email" style="font:inherit;padding:.6rem .7rem;border:1px solid #bbb;border-radius:6px">
<button style="font:inherit;font-weight:600;padding:.65rem 1rem;border:0;border-radius:6px;background:#F2C10A;cursor:pointer;justify-self:start">Email me a sign-in link</button>
</form>`), 200, LOGIN_CSP);
}
// Browsers send "Origin: null" for form posts from no-referrer pages, so also accept Sec-Fetch-Site.
const sameOrigin = (req, url) => {
  const o = req.headers.get("Origin"), sfs = req.headers.get("Sec-Fetch-Site");
  if (o && o !== "null") return o === url.origin;
  return sfs === "same-origin";
};

async function adminAuth(req, env, url) {
  const p = url.pathname;
  if (p === "/login" && req.method === "POST") {
    if (!sameOrigin(req, url)) return html(page("Not allowed", "<h1>Not allowed</h1>"), 403);
    const ipHash = await sha256((env.IP_SALT || env.TURNSTILE_SECRET || "") + (req.headers.get("CF-Connecting-IP") || ""));
    const tries = await env.DB.prepare("SELECT COUNT(*) n FROM admin_login_attempts WHERE ip_hash=? AND at>?").bind(ipHash, hoursAgo(1)).first("n");
    if (tries >= 5) return loginPage("Too many attempts. Please wait an hour and try again.");
    await env.DB.prepare("INSERT INTO admin_login_attempts (ip_hash, at) VALUES (?,?)").bind(ipHash, now()).run();
    const fd = await req.formData().catch(() => null);
    const email = clean(fd && fd.get("email"), 120).toLowerCase();
    if (adminList(env).includes(email) && env.RESEND_API_KEY) {
      const t = token() + token().slice(0, 16);
      await env.DB.prepare("INSERT INTO admin_links (token_hash, email, expires_at) VALUES (?,?,?)").bind(await sha256(t), email, new Date(Date.now() + 10 * 60e3).toISOString()).run();
      try { await sendMail(env, email, "Your admin sign-in link", `Open this link within 10 minutes to sign in to the Disability Visibility India admin page:\n${url.origin}/auth?t=${t}\n\nIf you didn't ask for this, ignore this email.`); } catch {}
    }
    return html(page("Check your email", "<h1>Check your email</h1><p>If that address is allowed, a sign-in link is on its way. It works once and expires in 10 minutes.</p>"), 200, LOGIN_CSP);
  }
  if (p === "/auth" && req.method === "GET") {
    // A button step, so email scanners that open links can't use them up.
    const t = clean(url.searchParams.get("t"), 80);
    return html(page("Admin sign-in", `<h1>Sign in</h1><form method="post" action="/auth"><input type="hidden" name="t" value="${esc(t)}"><button style="font:inherit;font-weight:600;padding:.65rem 1rem;border:0;border-radius:6px;background:#F2C10A;cursor:pointer">Sign in to the admin page</button></form>`), 200, LOGIN_CSP);
  }
  if (p === "/auth" && req.method === "POST") {
    if (!sameOrigin(req, url)) return html(page("Not allowed", "<h1>Not allowed</h1>"), 403);
    const fd = await req.formData().catch(() => null);
    const t = clean(fd && fd.get("t"), 80);
    const h = await sha256(t);
    const r = await env.DB.prepare("UPDATE admin_links SET used=1 WHERE token_hash=? AND used=0 AND expires_at>? RETURNING email").bind(h, now()).first();
    if (!r || !adminList(env).includes(r.email)) return loginPage("That link has expired or was already used. Request a new one.");
    const id = token() + token().slice(0, 16);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at<?").bind(now()),
      env.DB.prepare("DELETE FROM admin_links WHERE expires_at<?").bind(now()),
      env.DB.prepare("DELETE FROM admin_login_attempts WHERE at<?").bind(hoursAgo(24)),
      env.DB.prepare("INSERT INTO admin_sessions (id_hash, email, expires_at) VALUES (?,?,?)").bind(await sha256(id), r.email, new Date(Date.now() + 12 * 3600e3).toISOString()),
    ]);
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": `${SESSION_COOKIE}=${id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=43200`, ...SEC } });
  }
  if (p === "/logout" && req.method === "POST") {
    if (!sameOrigin(req, url)) return html(page("Not allowed", "<h1>Not allowed</h1>"), 403);
    const id = cookie(req, SESSION_COOKIE);
    if (id) await env.DB.prepare("DELETE FROM admin_sessions WHERE id_hash=?").bind(await sha256(id)).run();
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`, ...SEC } });
  }
  return null;
}

async function admin(req, env, url) {
  const authRes = await adminAuth(req, env, url);
  if (authRes) return authRes;
  const who = (await sessionEmail(req, env)) || (await accessEmail(req, env));
  const p = url.pathname;
  if (!who) return p === "/" ? loginPage("") : json({ ok: false, error: "signed_out" }, 401);
  if (p === "/" && req.method === "GET") return html(ADMIN_PAGE.replace("{{WHO}}", esc(who)), 200, {
    "Referrer-Policy": "same-origin", "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" });
  if (p === "/api/data" && req.method === "GET") {
    const sigs = await env.DB.prepare("SELECT id, petition, name, email, city, state, show_public, wants_updates, status, created_at, confirmed_at FROM signatures ORDER BY created_at DESC").all();
    const msgs = await env.DB.prepare("SELECT id, name, email, writing_as, message, created_at FROM messages ORDER BY created_at DESC").all();
    return json({ ok: true, signatures: sigs.results || [], messages: msgs.results || [] });
  }
  if (p === "/api/export" && req.method === "GET") {
    const type = url.searchParams.get("type") === "messages" ? "messages" : "signatures";
    const q = type === "messages"
      ? "SELECT created_at, name, email, writing_as, message FROM messages ORDER BY created_at DESC"
      : "SELECT created_at, confirmed_at, status, petition, name, email, city, state, show_public, wants_updates FROM signatures ORDER BY created_at DESC";
    const r = (await env.DB.prepare(q).all()).results || [];
    const cols = r.length ? Object.keys(r[0]) : [];
    const body = [cols.join(","), ...r.map(row => cols.map(c => csvCell(row[c])).join(","))].join("\n");
    return new Response(body, { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="dvi-${type}-${now().slice(0, 10)}.csv"`, "Cache-Control": "no-store", ...SEC } });
  }
  if (p === "/api/delete" && req.method === "POST") {
    if (!sameOrigin(req, url)) return json({ ok: false }, 403);
    const b = await readJson(req); const id = Number(b && b.id);
    const table = b && b.type === "messages" ? "messages" : "signatures";
    if (!Number.isInteger(id)) return json({ ok: false }, 400);
    await env.DB.prepare(`DELETE FROM ${table} WHERE id=?`).bind(id).run();
    await caches.default.delete(new Request(CACHE_KEY));
    return json({ ok: true });
  }
  return json({ ok: false, error: "not_found" }, 404);
}

/* ---------- router ---------- */
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    try {
      await ensureSchema(env.DB);
      if (env.ADMIN_HOST && url.hostname === env.ADMIN_HOST) return await admin(req, env, url);
      const ch = cors(req, env);
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: ch });
      let res;
      if (url.pathname === "/summary" && req.method === "GET") res = await summary(env, ctx, req);
      else if (url.pathname === "/sign" && req.method === "POST") res = await sign(req, env, ctx);
      else if (url.pathname === "/contact" && req.method === "POST") res = await contact(req, env, ctx);
      else if (url.pathname === "/status" && req.method === "GET") res = await status(req, env);
      else if (url.pathname === "/confirm" && req.method === "GET") return await confirm(req, env);
      else if (url.pathname === "/" && req.method === "GET") return Response.redirect("https://disability-visibility.com/", 302);
      else res = json({ ok: false, error: "not_found" }, 404);
      const out = new Response(res.body, res); Object.entries(ch).forEach(([k, v]) => out.headers.set(k, v));
      return out;
    } catch (e) {
      console.error(e && e.stack || e);
      return json({ ok: false, error: "server" }, 500, cors(req, env));
    }
  },
};

/* ---------- pages ---------- */
function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{margin:0;font:18px/1.55 -apple-system,BlinkMacSystemFont,"Helvetica Neue","Segoe UI",Roboto,Arial,sans-serif;color:#111;background:#fff}
header{background:#000;color:#fff;padding:1rem 1.25rem;font-weight:700}main{max-width:34rem;margin:2.5rem auto;padding:0 1.25rem}h1{font-size:1.6rem;margin:0 0 .5rem}a{color:#8A1C14;font-weight:600}</style></head>
<body><header>Disability Visibility India</header><main>${body}</main></body></html>`;
}

const ADMIN_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin · Disability Visibility India</title>
<style>
:root{--f:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue","Segoe UI",Roboto,Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 var(--f);color:#111;background:#fafaf7}
header{background:#000;color:#fff;padding:.9rem 1.25rem;display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
header b{font-size:1.05rem}header span{color:#bbb;font-size:.85rem}
main{max-width:1200px;margin:0 auto;padding:1.5rem 1.25rem 4rem}
h2{font-size:1.2rem;margin:2rem 0 .6rem}
.counts{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:.6rem}
.counts div{background:#fff;border-radius:8px;padding:.7rem .9rem;box-shadow:0 0 0 1px #e6e4dc}
.counts strong{display:block;font-size:1.5rem}.counts small{color:#555}
.bar{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.4rem 0 .8rem}
select,input,button,a.btn{font:inherit;height:2.2rem;border-radius:6px;border:1px solid #ccc;background:#fff;padding:0 .7rem;color:#111}
button,a.btn{cursor:pointer;text-decoration:none;display:inline-flex;align-items:center}a.btn{background:#F2C10A;border-color:#F2C10A;font-weight:600}
.wrap{overflow-x:auto;background:#fff;border-radius:8px;box-shadow:0 0 0 1px #e6e4dc}
table{border-collapse:collapse;width:100%;font-size:.88rem}th,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid #eee;vertical-align:top}
th{background:#f3f2ec;font-weight:600;white-space:nowrap}td.msg{white-space:pre-wrap;min-width:18rem}
.pending{color:#8A1C14;font-weight:600}.del{height:1.8rem;font-size:.8rem;color:#8A1C14;border-color:#e2c3bf}
.muted{color:#666}
</style></head><body>
<header><b>Disability Visibility India · Admin</b><span>Signed in as {{WHO}} <form method="post" action="/logout" style="display:inline"><button style="height:1.8rem;margin-left:.5rem;background:#111;color:#fff;border-color:#444">Sign out</button></form></span></header>
<main>
<h2>Confirmed signatures</h2><div class="counts" id="counts"></div>
<h2>Signatures</h2>
<div class="bar"><select id="fp"><option value="">All petitions</option></select>
<select id="fs"><option value="">Confirmed and pending</option><option value="confirmed">Confirmed only</option><option value="pending">Pending only</option></select>
<input id="q" type="search" placeholder="Search name, email, city"><a class="btn" href="/api/export?type=signatures">Download CSV</a></div>
<div class="wrap"><table><thead><tr><th>Date</th><th>Petition</th><th>Name</th><th>Email</th><th>City</th><th>State</th><th>Status</th><th>Public</th><th>Updates</th><th></th></tr></thead><tbody id="sig"></tbody></table></div>
<h2>Messages</h2>
<div class="bar"><a class="btn" href="/api/export?type=messages">Download CSV</a></div>
<div class="wrap"><table><thead><tr><th>Date</th><th>Name</th><th>Email</th><th>Writing as</th><th>Message</th><th></th></tr></thead><tbody id="msg"></tbody></table></div>
</main>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let D={signatures:[],messages:[]};
async function load(){const r=await fetch("/api/data");if(r.status===401){location.reload();return;}D=await r.json();
 const pets=[...new Set(D.signatures.map(s=>s.petition))].sort();
 const fp=$("#fp"),cur=fp.value;fp.innerHTML='<option value="">All petitions</option>'+pets.map(p=>'<option>'+esc(p)+'</option>').join("");fp.value=cur;draw();}
function draw(){
 const c={};D.signatures.forEach(s=>{if(s.status==="confirmed")c[s.petition]=(c[s.petition]||0)+1});
 const pend=D.signatures.filter(s=>s.status!=="confirmed").length;
 $("#counts").innerHTML=Object.keys(c).sort().map(p=>'<div><strong>'+c[p]+'</strong><small>'+esc(p)+'</small></div>').join("")+'<div><strong>'+pend+'</strong><small>waiting for email confirmation</small></div>';
 const fp=$("#fp").value,fs=$("#fs").value,q=$("#q").value.toLowerCase();
 const rows=D.signatures.filter(s=>(!fp||s.petition===fp)&&(!fs||s.status===fs)&&(!q||(s.name+" "+s.email+" "+s.city).toLowerCase().includes(q)));
 $("#sig").innerHTML=rows.length?rows.map(s=>'<tr><td>'+esc(String(s.created_at).slice(0,10))+'</td><td>'+esc(s.petition)+'</td><td>'+esc(s.name)+'</td><td>'+esc(s.email)+'</td><td>'+esc(s.city)+'</td><td>'+esc(s.state)+'</td><td class="'+(s.status==="confirmed"?"":"pending")+'">'+esc(s.status)+'</td><td>'+(s.show_public?"Yes":"No")+'</td><td>'+(s.wants_updates?"Yes":"No")+'</td><td><button class="del" data-t="signatures" data-id="'+s.id+'">Remove</button></td></tr>').join(""):'<tr><td colspan="10" class="muted">No signatures yet.</td></tr>';
 $("#msg").innerHTML=D.messages.length?D.messages.map(m=>'<tr><td>'+esc(String(m.created_at).slice(0,10))+'</td><td>'+esc(m.name)+'</td><td><a href="mailto:'+esc(m.email)+'">'+esc(m.email)+'</a></td><td>'+esc(m.writing_as)+'</td><td class="msg">'+esc(m.message)+'</td><td><button class="del" data-t="messages" data-id="'+m.id+'">Remove</button></td></tr>').join(""):'<tr><td colspan="6" class="muted">No messages yet.</td></tr>';
}
["#fp","#fs","#q"].forEach(s=>$(s).addEventListener("input",draw));
document.addEventListener("click",async e=>{const b=e.target.closest(".del");if(!b)return;
 if(b.dataset.armed!=="1"){b.dataset.armed="1";b.textContent="Click again to remove";setTimeout(()=>{b.dataset.armed="";b.textContent="Remove"},4000);return;}
 b.disabled=true;await fetch("/api/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:b.dataset.t,id:+b.dataset.id})});load();});
load();
</script></body></html>`;
