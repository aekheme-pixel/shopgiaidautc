ALTER TABLE teams ADD COLUMN registrant_name TEXT NOT NULL DEFAULT '';

ALTER TABLE teams ADD COLUMN contact_info TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_registrations_user_tournament
ON registrations(user_id, tournament_id);
