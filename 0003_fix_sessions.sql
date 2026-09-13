-- =========================================================
-- GIẢI ĐẤU TỬ CHIẾN – MÙA 1
-- MIGRATION 0003
--
-- Chuẩn hóa sessions về cấu trúc mà index.js sử dụng:
--   token
--   user_id
--   expires_at
--   created_at
--
-- KHÔNG tạo app_sessions.
-- KHÔNG xóa dữ liệu session hiện có.
-- =========================================================

PRAGMA foreign_keys = OFF;

-- ---------------------------------------------------------
-- Tạo bảng sessions chuẩn
-- ---------------------------------------------------------

CREATE TABLE sessions_new (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------
-- Giữ lại session cũ
--
-- id cũ -> token mới
--
-- expires_at:
--   nếu đã là số -> giữ nguyên
--   nếu là ngày giờ TEXT -> chuyển sang Unix milliseconds
-- ---------------------------------------------------------

INSERT INTO sessions_new (
    token,
    user_id,
    expires_at,
    created_at
)
SELECT
    id,
    user_id,
    CASE
        WHEN trim(expires_at) GLOB '[0-9]*'
            THEN CAST(expires_at AS INTEGER)

        ELSE
            CAST(strftime('%s', expires_at) AS INTEGER) * 1000
    END,
    created_at
FROM sessions
WHERE id IS NOT NULL
  AND user_id IS NOT NULL
  AND expires_at IS NOT NULL;

-- ---------------------------------------------------------
-- Thay bảng cũ bằng bảng chuẩn
-- ---------------------------------------------------------

DROP TABLE sessions;

ALTER TABLE sessions_new
RENAME TO sessions;

-- ---------------------------------------------------------
-- Index
-- ---------------------------------------------------------

CREATE INDEX IF NOT EXISTS
idx_sessions_user
ON sessions(user_id);

CREATE INDEX IF NOT EXISTS
idx_sessions_expires
ON sessions(expires_at);

PRAGMA foreign_keys = ON;
