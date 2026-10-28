CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL CHECK (category IN ('testimony', 'prayer', 'bible', 'feedback')),
  name TEXT NOT NULL DEFAULT '', message TEXT NOT NULL, created_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'flagged', 'approved')),
  projection TEXT NOT NULL DEFAULT 'waiting' CHECK (projection IN ('waiting', 'queued', 'displayed', 'hidden'))
);
CREATE INDEX IF NOT EXISTS submissions_created_idx ON submissions(created_at DESC);
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('superadmin', 'admin', 'operator')),
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_passkeys (
  role TEXT PRIMARY KEY CHECK (role IN ('superadmin', 'admin', 'operator')),
  passkey_salt TEXT NOT NULL, passkey_hash TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, expires_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS audit_log (id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, submission_id TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS live_state (id INTEGER PRIMARY KEY CHECK (id = 1), current_submission_id TEXT REFERENCES submissions(id) ON DELETE SET NULL, changed_at TEXT NOT NULL);
INSERT INTO live_state(id, current_submission_id, changed_at) VALUES (1, NULL, NOW()::text) ON CONFLICT (id) DO NOTHING;
