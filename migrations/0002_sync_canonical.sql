
-- ============================================================
-- 0002_sync_canonical.sql
-- Đồng bộ teams với frontend hiện tại.
--
-- KHÔNG tạo app_*
-- KHÔNG sửa users
-- KHÔNG sửa sessions
-- KHÔNG DROP dữ liệu
-- ============================================================

ALTER TABLE teams
ADD COLUMN logo_url TEXT NOT NULL DEFAULT '';

ALTER TABLE teams
ADD COLUMN contact_email TEXT NOT NULL DEFAULT '';

ALTER TABLE teams
ADD COLUMN player2_email TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_registrations_team
ON registrations(team_id);

CREATE INDEX IF NOT EXISTS idx_registrations_tournament
ON registrations(tournament_id);

CREATE INDEX IF NOT EXISTS idx_payments_registration
ON payments(registration_id);

CREATE INDEX IF NOT EXISTS idx_teams_owner
ON teams(owner_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expiry
ON sessions(expires_at);
