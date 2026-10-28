import { Pool } from "@neondatabase/serverless";

const ROLES = new Set(["superadmin", "admin", "operator"]);
const CATEGORIES = new Set(["testimony", "prayer", "bible", "feedback"]);
const SESSION_HOURS = 12;
const ITERATIONS = 600000;
let pool;

function database() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL has not been configured.");
  pool ||= new Pool({ connectionString: process.env.DATABASE_URL });
  return {
    prepare(sql) {
      return {
        values: [],
        bind(...values) { this.values = values; return this; },
        async all() { const result = await pool.query(normalize(sql), this.values); return { results: result.rows }; },
        async first() { const result = await pool.query(normalize(sql), this.values); return result.rows[0] || null; },
        async run() { const result = await pool.query(normalize(sql), this.values); return { meta: { changes: result.rowCount || 0 } }; }
      };
    },
    async batch(statements) { const results = []; for (const statement of statements) results.push(await statement.run()); return results; }
  };
}
function normalize(sql) {
  let index = 0;
  let value = sql.replaceAll(" AS createdAt", ' AS "createdAt"').replace(/\?/g, () => `$${++index}`);
  if (/^\s*INSERT OR IGNORE INTO/i.test(value)) value = value.replace(/INSERT OR IGNORE INTO/i, "INSERT INTO") + " ON CONFLICT DO NOTHING";
  return value;
}
const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", ...headers } });
const now = () => new Date().toISOString();
const validUsername = value => /^[A-Za-z0-9._-]{3,40}$/.test(value);
const hex = bytes => [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
const bytes = value => Uint8Array.from(value.match(/.{1,2}/g) || [], byte => parseInt(byte, 16));
const safeEqual = (a, b) => { if (a.length !== b.length) return false; let result = 0; for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i); return result === 0; };
async function hash(value, salt) { const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(value), "PBKDF2", false, ["deriveBits"]); return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bytes(salt), iterations: ITERATIONS }, key, 256)); }
const randomHex = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const randomToken = () => crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "");
const tokenHash = async token => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
function cookies(request) { return Object.fromEntries((request.headers.get("Cookie") || "").split(";").map(part => part.trim().split(/=(.*)/s)).filter(([key]) => key)); }
const sessionCookie = (token, age) => `cop_session=${token}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${age}`;
const sameOrigin = request => { const origin = request.headers.get("Origin"); return !origin || new URL(origin).host === new URL(request.url).host; };
async function readJson(request) { const payload = await request.json(); if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("JSON body must be an object."); return payload; }
async function activeUser(request, db) { const token = cookies(request).cop_session; return token ? db.prepare("SELECT u.username, u.role FROM sessions s JOIN users u ON u.username = s.username WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1").bind(await tokenHash(token), now()).first() : null; }
async function requireRole(request, db, roles) { const user = await activeUser(request, db); if (!user) return [null, json({ error: "Sign in is required." }, 401)]; if (!roles.includes(user.role)) return [null, json({ error: "Your account cannot access this function." }, 403)]; return [user, null]; }
async function audit(db, username, action, submissionId = null) { await db.prepare("INSERT INTO audit_log(username, action, submission_id, created_at) VALUES (?, ?, ?, ?)").bind(username, action, submissionId, now()).run(); }
async function passkeyMatches(db, role, passkey) { const gate = await db.prepare("SELECT passkey_salt, passkey_hash FROM role_passkeys WHERE role = ?").bind(role).first(); return Boolean(gate && safeEqual(await hash(passkey, gate.passkey_salt), gate.passkey_hash)); }

async function get(request, db, path) {
  if (path === "/api/health") return json({ ok: true });
  if (path === "/api/session") { const user = await activeUser(request, db); return json({ user: user ? { username: user.username, role: user.role } : null }); }
  if (path === "/api/admin/submissions") { const [, error] = await requireRole(request, db, ["superadmin", "admin"]); if (error) return error; return json({ items: (await db.prepare("SELECT id, category, name, message, created_at AS createdAt, status, projection FROM submissions ORDER BY created_at DESC").all()).results }); }
  if (path === "/api/operations/testimonies") { const [, error] = await requireRole(request, db, ["superadmin", "admin", "operator"]); if (error) return error; return json({ items: (await db.prepare("SELECT id, category, name, message, created_at AS createdAt, status, projection FROM submissions WHERE category = 'testimony' AND status = 'approved' AND projection != 'hidden' ORDER BY created_at ASC").all()).results }); }
  if (path === "/api/display/current") return json({ item: await db.prepare("SELECT s.id, s.category, s.message, s.created_at AS createdAt FROM live_state l JOIN submissions s ON s.id = l.current_submission_id WHERE l.id = 1 AND s.category = 'testimony' AND s.status = 'approved' AND s.projection = 'displayed'").first() || null });
  return null;
}

async function post(request, db, path, data) {
  if (path === "/api/submissions") { const category = String(data.category || ""), name = String(data.name || "").trim(), message = String(data.message || "").trim(); if (!CATEGORIES.has(category) || !message || message.length > 2000 || name.length > 60) return json({ error: "Check the category, name, and message length." }, 400); const id = crypto.randomUUID(); await db.prepare("INSERT INTO submissions(id, category, name, message, created_at, status, projection) VALUES (?, ?, ?, ?, ?, 'new', 'waiting')").bind(id, category, name, message, now()).run(); return json({ ok: true, id }, 201); }
  if (path === "/api/auth/login") { const username = String(data.username || "").trim(), password = String(data.password || ""), row = await db.prepare("SELECT username, password_salt, password_hash, role FROM users WHERE username = ? AND active = 1").bind(username).first(); if (!row || !safeEqual(await hash(password, row.password_salt), row.password_hash)) return json({ error: "Username or password is incorrect." }, 401); const token = randomToken(), expires = new Date(Date.now() + SESSION_HOURS * 3600000).toISOString(); await db.prepare("INSERT INTO sessions(token_hash, username, expires_at) VALUES (?, ?, ?)").bind(await tokenHash(token), username, expires).run(); return json({ user: { username: row.username, role: row.role } }, 200, { "Set-Cookie": sessionCookie(token, SESSION_HOURS * 3600) }); }
  if (path === "/api/auth/register") { const role = String(data.role || ""), username = String(data.username || "").trim(), password = String(data.password || ""), passkey = String(data.passkey || ""); if (!ROLES.has(role) || !validUsername(username) || password.length < 12 || !passkey) return json({ error: "Choose a role, use a valid username, and choose a password of at least 12 characters." }, 400); if (!await passkeyMatches(db, role, passkey)) return json({ error: "The passkey is incorrect or account creation has not been configured for this role." }, 403); const salt = randomHex(), result = await db.prepare("INSERT OR IGNORE INTO users(username, password_salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)").bind(username, salt, await hash(password, salt), role, now()).run(); return result.meta.changes ? json({ ok: true, username, role }, 201) : json({ error: "That username already exists." }, 409); }
  if (path === "/api/auth/logout") { const token = cookies(request).cop_session; if (token) await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await tokenHash(token)).run(); return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) }); }
  if (path === "/api/bootstrap") { if (!process.env.BOOTSTRAP_SECRET || String(data.bootstrapSecret || "") !== process.env.BOOTSTRAP_SECRET) return json({ error: "Bootstrap authorization failed." }, 403); const count = await db.prepare("SELECT COUNT(*)::int AS total FROM users").first(); if (count.total) return json({ error: "Bootstrap has already been completed." }, 409); const username = String(data.username || "").trim(), password = String(data.password || ""), passkey = String(data.passkey || ""); if (!validUsername(username) || password.length < 12 || passkey.length < 12) return json({ error: "Use a valid username plus passwords and passkeys of at least 12 characters." }, 400); const ps = randomHex(), ks = randomHex(); await db.batch([db.prepare("INSERT INTO users(username, password_salt, password_hash, role, created_at) VALUES (?, ?, ?, 'superadmin', ?)").bind(username, ps, await hash(password, ps), now()), db.prepare("INSERT INTO role_passkeys(role, passkey_salt, passkey_hash, updated_at) VALUES ('superadmin', ?, ?, ?)").bind(ks, await hash(passkey, ks), now())]); return json({ ok: true, message: "Super admin created. Sign in, then configure other role passkeys." }, 201); }
  if (path === "/api/admin/role-passkeys") { const [user, error] = await requireRole(request, db, ["superadmin"]); if (error) return error; const role = String(data.role || ""), passkey = String(data.passkey || ""); if (!ROLES.has(role) || passkey.length < 12) return json({ error: "Choose a role and a passkey of at least 12 characters." }, 400); const salt = randomHex(); await db.prepare("INSERT INTO role_passkeys(role, passkey_salt, passkey_hash, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(role) DO UPDATE SET passkey_salt = excluded.passkey_salt, passkey_hash = excluded.passkey_hash, updated_at = excluded.updated_at").bind(role, salt, await hash(passkey, salt), now()).run(); await audit(db, user.username, `set_role_passkey:${role}`); return json({ ok: true }); }
  if (path.startsWith("/api/admin/submissions/")) { const [user, error] = await requireRole(request, db, ["superadmin", "admin"]); if (error) return error; const match = path.match(/^\/api\/admin\/submissions\/([^/]+)\/(approve|flag|delete)$/); if (!match) return json({ error: "Admin route not found." }, 404); const [, id, action] = match, exists = await db.prepare("SELECT id FROM submissions WHERE id = ?").bind(id).first(); if (!exists) return json({ error: "Submission not found." }, 404); if (action === "approve") await db.prepare("UPDATE submissions SET status = 'approved', projection = 'queued' WHERE id = ?").bind(id).run(); if (action === "flag") await db.batch([db.prepare("UPDATE submissions SET status = 'flagged', projection = 'waiting' WHERE id = ?").bind(id), db.prepare("UPDATE live_state SET current_submission_id = NULL, changed_at = ? WHERE current_submission_id = ?").bind(now(), id)]); if (action === "delete") await db.prepare("DELETE FROM submissions WHERE id = ?").bind(id).run(); await audit(db, user.username, action, id); return json({ ok: true }); }
  if (path === "/api/operator/current") { const [user, error] = await requireRole(request, db, ["superadmin", "admin", "operator"]); if (error) return error; const id = data.id == null ? null : String(data.id); if (id) { const allowed = await db.prepare("SELECT id FROM submissions WHERE id = ? AND category = 'testimony' AND status = 'approved' AND projection != 'hidden'").bind(id).first(); if (!allowed) return json({ error: "Only approved, visible testimonies can be projected." }, 409); await db.batch([db.prepare("UPDATE submissions SET projection = 'queued' WHERE category = 'testimony' AND status = 'approved' AND projection = 'displayed'"), db.prepare("UPDATE submissions SET projection = 'displayed' WHERE id = ?").bind(id), db.prepare("UPDATE live_state SET current_submission_id = ?, changed_at = ? WHERE id = 1").bind(id, now())]); } else await db.batch([db.prepare("UPDATE submissions SET projection = 'queued' WHERE category = 'testimony' AND status = 'approved' AND projection = 'displayed'"), db.prepare("UPDATE live_state SET current_submission_id = NULL, changed_at = ? WHERE id = 1").bind(now())]); await audit(db, user.username, id ? "display" : "clear_screen", id); return json({ ok: true }); }
  return null;
}

async function app(request) { const path = new URL(request.url).pathname, db = database(); if (request.method === "GET") return await get(request, db, path) || json({ error: "API route not found." }, 404); if (request.method !== "POST") return json({ error: "Method not allowed." }, 405); if (!sameOrigin(request)) return json({ error: "Cross-origin requests are not allowed." }, 403); try { return await post(request, db, path, await readJson(request)) || json({ error: "API route not found." }, 404); } catch (error) { return json({ error: error instanceof Error ? error.message : "Request failed." }, 400); } }

export default async function handler(req, res) { const host = req.headers.host || "localhost"; const headers = new Headers(); for (const [key, value] of Object.entries(req.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value); const body = ["GET", "HEAD"].includes(req.method) ? undefined : typeof req.body === "string" ? req.body : JSON.stringify(req.body || {}); const response = await app(new Request(`https://${host}${req.url}`, { method: req.method, headers, body, duplex: "half" })); res.statusCode = response.status; response.headers.forEach((value, key) => res.setHeader(key, value)); res.end(await response.text()); }
