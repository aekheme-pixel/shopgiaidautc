-- =========================================================
-- GIẢI ĐẤU TỬ CHIẾN – MÙA 1
-- MIGRATION 0002
--
-- Thêm:
--   users.username
--   users.balance
--   users.password_salt
--
-- Không xóa bảng/dữ liệu cũ.
-- Không tạo app_* tables.
-- =========================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------
-- USERS
-- ---------------------------------------------------------

ALTER TABLE users
ADD COLUMN username TEXT;

ALTER TABLE users
ADD COLUMN balance INTEGER NOT NULL DEFAULT 0;

ALTER TABLE users
ADD COLUMN password_salt TEXT;

-- ---------------------------------------------------------
-- Tạo username cho tài khoản cũ
--
-- Ưu tiên phần trước @ của email.
-- Nếu trùng thì thêm _id.
-- ---------------------------------------------------------

UPDATE users
SET username =
  CASE
    WHEN username IS NOT NULL
         AND trim(username) <> ''
      THEN trim(username)

    ELSE
      CASE
        WHEN (
          SELECT COUNT(*)
          FROM users u2
          WHERE lower(
            substr(
              u2.email,
              1,
              instr(u2.email, '@') - 1
            )
          )
          =
          lower(
            substr(
              users.email,
              1,
              instr(users.email, '@') - 1
            )
          )
        ) = 1
        THEN
          substr(
            email,
            1,
            instr(email, '@') - 1
          )

        ELSE
          substr(
            email,
            1,
            instr(email, '@') - 1
          )
          || '_'
          || id
      END
  END
WHERE username IS NULL
   OR trim(username) = '';

-- ---------------------------------------------------------
-- UNIQUE username
-- ---------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS
idx_users_username_unique
ON users(username);

-- ---------------------------------------------------------
-- INDEX
-- ---------------------------------------------------------

CREATE INDEX IF NOT EXISTS
idx_users_email
ON users(email);

CREATE INDEX IF NOT EXISTS
idx_users_username
ON users(username);

-- ---------------------------------------------------------
-- Session index
-- ---------------------------------------------------------

CREATE INDEX IF NOT EXISTS
idx_sessions_user
ON sessions(user_id);

CREATE INDEX IF NOT EXISTS
idx_sessions_expires
ON sessions(expires_at);

-- ---------------------------------------------------------
-- Registration/payment indexes
-- ---------------------------------------------------------

CREATE INDEX IF NOT EXISTS
idx_registrations_tournament
ON registrations(tournament_id);

CREATE INDEX IF NOT EXISTS
idx_registrations_status
ON registrations(status);

CREATE INDEX IF NOT EXISTS
idx_payments_status
ON payments(status);

CREATE INDEX IF NOT EXISTS
idx_results_team
ON results(team_id);

CREATE INDEX IF NOT EXISTS
idx_results_match
ON results(match_id);

-- ---------------------------------------------------------
-- Audit log index
-- ---------------------------------------------------------

CREATE INDEX IF NOT EXISTS
idx_audit_logs_user
ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS
idx_audit_logs_created
ON audit_logs(created_at);
