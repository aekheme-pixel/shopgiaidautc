ALTER TABLE users
ADD COLUMN password_salt TEXT NOT NULL DEFAULT '';

ALTER TABLE users
ADD COLUMN balance INTEGER NOT NULL DEFAULT 0;

ALTER TABLE teams
ADD COLUMN contact_email TEXT;

ALTER TABLE teams
ADD COLUMN player2_email TEXT;

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_expiry
ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_registrations_team
ON registrations(team_id);

CREATE INDEX IF NOT EXISTS idx_registrations_tournament
ON registrations(tournament_id);

CREATE INDEX IF NOT EXISTS idx_payments_registration
ON payments(registration_id);

CREATE INDEX IF NOT EXISTS idx_teams_owner
ON teams(owner_id);
