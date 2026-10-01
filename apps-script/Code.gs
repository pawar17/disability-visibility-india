/**
 * Disability Visibility India — backend for petitions, pledges and the contact form
 * (Google Apps Script + a Google Sheet you own)
 *
 * Setup (about 10 minutes):
 * 1. Create a new Google Sheet called "DVI Petitions".
 * 2. Extensions > Apps Script. Delete the sample code, paste this file, save.
 * 3. Deploy > New deployment > Web app.  Execute as: Me.  Who has access: Anyone.
 *    Deploy, authorise (it needs your Sheet and permission to send confirmation emails),
 *    and copy the Web app URL ending in /exec.
 * 4. Paste that URL into CONFIG.SHEETS_ENDPOINT near the top of the script in index.html.
 *
 * Security notes
 * - The public page can only call the actions below. Nobody can read the Sheet through
 *   this script: the "summary" action returns counts plus the first name, last initial
 *   and city of signers who chose to be shown. Emails, full names and messages never leave the Sheet.
 * - A signature only counts after the person clicks the link emailed to them.
 * - One signature per email per petition. Messages are capped per email per day.
 * - Only people you share the Sheet with can see it. Keep it unshared.
 */

const PETITIONS = ["census", "access", "pension", "isl", "idea-tactile", "idea-atw", "idea-sunflower", "idea-bme", "idea-signai", "idea-taxi"];
const MAX_MESSAGES_PER_EMAIL_PER_DAY = 3;

function sheet_(name, header) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(name);
  if (!sh) { sh = ss.insertSheet(name); sh.appendRow(header); sh.setFrozenRows(1); }
  return sh;
}
const sigSheet_ = () => sheet_("Signatures", ["timestamp","petition","full_name","email","city","state","show_publicly","wants_updates","public_name","status","token","confirmed_at"]);
const pledgeSheet_ = () => sheet_("Pledges", ["timestamp","amount_inr","public_name"]);
const msgSheet_ = () => sheet_("Messages", ["timestamp","name","email","writing_as","message"]);

function json_(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function clean_(v, max) { return String(v == null ? "" : v).replace(/[\u0000-\u001f]/g, " ").trim().slice(0, max); }
// Stops a value being treated as a formula when the Sheet is opened.
function safe_(v) { return /^[=+\-@]/.test(v) ? "'" + v : v; }
function shortName_(full) {
  const p = clean_(full, 80).split(/\s+/).filter(String);
  return p.length ? p[0].slice(0, 24) + (p.length > 1 ? " " + p[p.length - 1][0].toUpperCase() + "." : "") : "";
}
const validEmail_ = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);

function doGet(e) {
  const action = e.parameter.action || "";
  if (action === "confirm") return confirm_(clean_(e.parameter.t, 64));
  if (action !== "summary") return json_({ ok: false, error: "unknown_action" });

  const cache = CacheService.getScriptCache(), hit = cache.get("summary");
  if (hit) return ContentService.createTextOutput(hit).setMimeType(ContentService.MimeType.JSON);
  const counts = {}, recent = {};
  PETITIONS.forEach(p => { counts[p] = 0; recent[p] = []; });
  const rows = sigSheet_().getDataRange().getValues().slice(1);
  for (let i = rows.length - 1; i >= 0; i--) {
    const r = rows[i], pet = r[1];
    if (!(pet in counts) || r[9] !== "confirmed") continue;
    counts[pet]++;
    if (r[6] === true && recent[pet].length < 40) recent[pet].push({ n: r[8], c: r[4], s: r[5], at: new Date(r[11] || r[0]).toISOString() });
  }
  let pledgeTotal = 0, pledgeCount = 0;
  pledgeSheet_().getDataRange().getValues().slice(1).forEach(r => { pledgeTotal += Number(r[1]) || 0; pledgeCount++; });
  const out = JSON.stringify({ ok: true, counts, recent, pledgeTotal, pledgeCount });
  cache.put("summary", out, 30);
  return ContentService.createTextOutput(out).setMimeType(ContentService.MimeType.JSON);
}

function confirm_(token) {
  const sh = sigSheet_(), rows = sh.getDataRange().getValues();
  let msg = "This confirmation link isn’t valid or has already been used.";
  if (token) for (let i = 1; i < rows.length; i++) {
    if (rows[i][10] === token) {
      if (rows[i][9] !== "confirmed") { sh.getRange(i + 1, 10, 1, 3).setValues([["confirmed", "", new Date()]]); CacheService.getScriptCache().remove("summary"); }
      msg = "Thank you. Your signature is confirmed and now counts.";
      break;
    }
  }
  return HtmlService.createHtmlOutput('<div style="font:18px/1.5 Verdana,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem"><h1 style="font-size:24px">Disability Visibility India</h1><p>' + msg + '</p></div>').setTitle("Signature confirmation");
}

function doPost(e) {
  let b;
  try { b = JSON.parse(e.postData.contents); } catch (err) { return json_({ ok: false, error: "bad_request" }); }
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    if (b.action === "sign") {
      const pet = clean_(b.petition, 20), email = clean_(b.email, 120).toLowerCase();
      const name = clean_(b.name, 80), city = clean_(b.city, 60), state = clean_(b.state, 60);
      if (PETITIONS.indexOf(pet) < 0 || !name || !city || !state || !validEmail_(email)) return json_({ ok: false, error: "bad_request" });
      const sh = sigSheet_();
      if (sh.getDataRange().getValues().some(r => r[1] === pet && String(r[3]).toLowerCase() === email)) return json_({ ok: false, error: "duplicate" });
      const pub = b.pub === true, token = Utilities.getUuid().replace(/-/g, "");
      sh.appendRow([new Date(), pet, safe_(name), safe_(email), safe_(city), safe_(state), pub, b.updates === true, pub ? safe_(shortName_(name)) : "", "pending", token, ""]);
      const link = ScriptApp.getService().getUrl() + "?action=confirm&t=" + token;
      MailApp.sendEmail({ to: email, subject: "Confirm your signature: Disability Visibility India",
        body: "Hi " + name.split(" ")[0] + ",\n\nThank you for signing. Please confirm your signature by opening this link:\n" + link + "\n\nIf you didn't sign, ignore this email and nothing will be counted.\n\nDisability Visibility India" });
      return json_({ ok: true, pending: true });
    }
    if (b.action === "pledge") {
      const amt = Math.round(Number(b.amount));
      if (!(amt >= 10 && amt <= 10000000)) return json_({ ok: false, error: "bad_request" });
      pledgeSheet_().appendRow([new Date(), amt, b.pub === true ? safe_(shortName_(b.name)) : ""]);
      CacheService.getScriptCache().remove("summary");
      return json_({ ok: true });
    }
    if (b.action === "contact") {
      const name = clean_(b.name, 80), email = clean_(b.email, 120).toLowerCase(), why = clean_(b.why, 60);
      const text = String(b.message == null ? "" : b.message).slice(0, 3000).trim();
      if (!name || !text || !validEmail_(email)) return json_({ ok: false, error: "bad_request" });
      const sh = msgSheet_(), dayAgo = Date.now() - 864e5;
      const recent = sh.getDataRange().getValues().slice(1).filter(r => String(r[2]).toLowerCase() === email && new Date(r[0]).getTime() > dayAgo).length;
      if (recent >= MAX_MESSAGES_PER_EMAIL_PER_DAY) return json_({ ok: false, error: "rate_limited" });
      sh.appendRow([new Date(), safe_(name), safe_(email), safe_(why), safe_(text)]);
      return json_({ ok: true });
    }
    return json_({ ok: false, error: "unknown_action" });
  } finally {
    lock.releaseLock();
  }
}
