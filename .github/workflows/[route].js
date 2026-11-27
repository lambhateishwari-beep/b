// The Golden Sip: server part (ONE file). Handles /api/menu, /api/auth and /api/health.
// Put this file in your GitHub repo at:  api/[route].js   (the name has square brackets)
// Shared helpers for The Golden Sip API (Vercel serverless functions).
const crypto = require("crypto");
const { promisify } = require("util");
const pbkdf2 = promisify(crypto.pbkdf2);

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SECRET = process.env.SESSION_SECRET || REDIS_TOKEN || "change-me";

// Original owner login (same hashes that were inside app.js): your CURRENT email/phone + password keep working.
const LEGACY_PW = "6622e7a92227fde47464de4e5b74efd47166f4797305c1af250e3d14ff73a6cb";
const LEGACY_IDS = [
  "957f550879928f79868075e1ad0e8fa183b81b61926c0ecb613a44aedad63333",
  "81d08a0536906dcabaff94c919096752e44522c00fe7b1e0dbd4a99e35a260b2",
];

async function redis(...cmd) {
  if (!REDIS_URL || !REDIS_TOKEN) throw new Error("DB_NOT_CONFIGURED");
  const r = await fetch(REDIS_URL, {
    method: "POST",
    headers: { Authorization: "Bearer " + REDIS_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || "DB_ERROR");
  return j.result;
}

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const slow = async (t) => (await pbkdf2(t, "gs-owner-v1", 150000, 32, "sha256")).toString("hex");

function normId(id) {
  id = String(id || "").trim().toLowerCase();
  return id.includes("@") ? id : id.replace(/\D/g, "").slice(-10);
}

async function checkLogin(id, pw) {
  id = normId(id); pw = String(pw || "");
  if (!id || !pw) return false;
  const idHash = await slow("id:" + id);
  const idOk = LEGACY_IDS.includes(idHash);
  const pwOk = safeEq(await slow("pw:" + pw), LEGACY_PW);
  return idOk && pwOk;
}

// Signed session token (12 hours)
function makeToken() {
  const body = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600 * 1000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function verifyToken(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [body, sig] = t.split(".");
  if (!body || !sig) return false;
  const good = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  if (!safeEq(sig, good)) return false;
  try { return JSON.parse(Buffer.from(body, "base64url").toString()).exp > Date.now(); } catch (_) { return false; }
}

function readBody(req) {
  let b = req.body;
  if (typeof b === "string") { try { b = JSON.parse(b); } catch (_) { b = {}; } }
  return b || {};
}
const clientIp = (req) => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "x";



// ---------- menu ----------
// GET  /api/menu  -> public, returns the live menu saved by the owner (or {} if none saved yet)
// POST /api/menu  -> owner only (Bearer token), saves the full menu

const str = (v, n) => String(v == null ? "" : v).slice(0, n);
const num = (v) => { v = Number(v); return Number.isFinite(v) && v >= 0 ? Math.round(v * 100) / 100 : null; };

function clean(b) {
  if (!b || !Array.isArray(b.items) || !Array.isArray(b.cats)) return null;
  if (b.items.length > 1500 || b.cats.length > 100) return null;
  const cats = [...new Set(b.cats.map((c) => str(c, 40).trim()).filter(Boolean))];
  const items = [];
  for (const i of b.items) {
    const price = num(i.price);
    if (!i || !i.id || !i.name || price === null) continue;
    const o = { id: str(i.id, 40), name: str(i.name, 80), cat: str(i.cat, 40), veg: !!i.veg, price, ok: i.ok !== false, loved: !!i.loved, note: str(i.note, 120) };
    const p10 = num(i.p10); if (p10) o.p10 = p10;
    items.push(o);
  }
  return { cats, items, upi: str(b.upi, 80).trim(), phone: str(b.phone, 25).trim(), updated: new Date().toISOString() };
}

async function menuHandler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try {
    if (req.method === "GET") {
      const raw = await redis("GET", "gs:menu");
      return res.status(200).json(raw ? JSON.parse(raw) : {});
    }
    if (req.method === "POST") {
      if (!verifyToken(req)) return res.status(401).json({ error: "Please sign in again" });
      const m = clean(readBody(req));
      if (!m) return res.status(400).json({ error: "Invalid menu data" });
      await redis("SET", "gs:menu", JSON.stringify(m));
      return res.status(200).json({ ok: true, updated: m.updated });
    }
    res.status(405).json({ error: "Method not allowed" });
  } catch (e) {
    res.status(500).json({ error: e.message === "DB_NOT_CONFIGURED" ? "Database not connected yet (see SETUP.md)" : "Server error" });
  }
}

// ---------- auth ----------
async function authHandler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const b = readBody(req);
  try {
    /* ---- login ---- */
    if (b.action === "login") {
      const k = "gs:tries:" + sha(clientIp(req));
      let tries = 0;
      try { tries = await redis("INCR", k); if (tries === 1) await redis("EXPIRE", k, 900); } catch (_) {}
      if (tries > 10) return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
      if (!(await checkLogin(b.id, b.password))) return res.status(401).json({ error: "Wrong email, phone or password" });
      try { await redis("DEL", k); } catch (_) {}
      return res.status(200).json({ token: makeToken() });
    }

    res.status(400).json({ error: "Unknown action" });
  } catch (e) {
    const msg = (e.message || "") === "DB_NOT_CONFIGURED" ? "Database not connected yet (see SETUP.md)" : "Server error";
    res.status(500).json({ error: msg });
  }
}

// ---------- health ----------
async function healthHandler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try { await redis("PING"); res.status(200).json({ db: true }); }
  catch (e) { res.status(200).json({ db: false, error: e.message === "DB_NOT_CONFIGURED" ? "Live saving is NOT working: database not connected. Follow SETUP.md step 1, then Redeploy." : "Live saving is NOT working: database error." }); }
}

module.exports = async (req, res) => {
  let route = (req.query && req.query.route) || "";
  if (!route) route = String(req.url || "").split("?")[0].split("/").filter(Boolean).pop() || "";
  if (route === "menu") return menuHandler(req, res);
  if (route === "auth") return authHandler(req, res);
  if (route === "health") return healthHandler(req, res);
  res.status(404).json({ error: "Not found" });
};
