// ============================================================
// CUSTOM 151 - CLOUDFLARE WORKER
// Auth + D1 + Sessions + Tournaments
// Không package ngoài
// Password: Web Crypto PBKDF2
// Tương thích DB hiện tại
// ============================================================

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const SESSION_COOKIE = "session";

// ============================================================
// RESPONSE HELPERS
// ============================================================

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function ok(data = {}) {
  return json({
    success: true,
    ...data
  });
}

function fail(message, status = 400, code = "BAD_REQUEST") {
  return json({
    success: false,
    error: message,
    code
  }, status);
}

// ============================================================
// REQUEST HELPERS
// ============================================================

async function bodyJSON(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

// ============================================================
// RANDOM / BASE64
// ============================================================

function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function base64ToBytes(value) {
  const normalized = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized + "=".repeat((4 - normalized.length % 4) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ============================================================
// CONSTANT-TIME COMPARE
// ============================================================

function safeEqual(a, b) {
  if (!(a instanceof Uint8Array)) {
    a = new Uint8Array(a);
  }

  if (!(b instanceof Uint8Array)) {
    b = new Uint8Array(b);
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

// ============================================================
// PASSWORD HASH
//
// Format:
//
// pbkdf2$100000$SALT$HASH
//
// Salt nằm trong password_hash.
// Không cần password_salt.
// ============================================================

async function derivePassword(password, saltBytes, iterations) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = randomBytes(16);

  const derived = await derivePassword(
    password,
    salt,
    PBKDF2_ITERATIONS
  );

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(derived)
  ].join("$");
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) {
    return false;
  }

  const parts = String(storedHash).split("$");

  if (parts.length !== 4) {
    return false;
  }

  const algorithm = parts[0];
  const iterations = Number(parts[1]);
  const saltString = parts[2];
  const hashString = parts[3];

  if (
    algorithm !== "pbkdf2" ||
    !Number.isFinite(iterations) ||
    iterations < 10000 ||
    !saltString ||
    !hashString
  ) {
    return false;
  }

  try {
    const salt = base64ToBytes(saltString);
    const expected = base64ToBytes(hashString);

    const actual = await derivePassword(
      password,
      salt,
      iterations
    );

    return safeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ============================================================
// COOKIE
// ============================================================

function cookieSerialize(name, value, options = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}`;

  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  if (options.expires) {
    cookie += `; Expires=${options.expires.toUTCString()}`;
  }

  if (options.path) {
    cookie += `; Path=${options.path}`;
  }

  if (options.httpOnly) {
    cookie += "; HttpOnly";
  }

  if (options.secure) {
    cookie += "; Secure";
  }

  if (options.sameSite) {
    cookie += `; SameSite=${options.sameSite}`;
  }

  return cookie;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie");

  if (!header) {
    return null;
  }

  const cookies = header.split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

// ============================================================
// D1 SCHEMA HELPERS
// ============================================================

async function getUserColumns(env) {
  const result = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}

async function getSessionColumns(env) {
  const result = await env.DB
    .prepare("PRAGMA table_info(sessions)")
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}

// ============================================================
// PASSWORD_SALT COMPATIBILITY
//
// Bình thường không cần password_salt.
//
// Nếu DB cũ vẫn có password_salt NOT NULL,
// Worker tự điền salt legacy để INSERT không chết.
// ============================================================

async function usersHasRequiredPasswordSalt(env) {
  const result = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  const row = (result.results || [])
    .find(item => item.name === "password_salt");

  return !!row && Number(row.notnull) === 1;
}

// ============================================================
// SESSION
// ============================================================

async function createSession(env, userId) {
  const columns = await getSessionColumns(env);

  if (
    !columns.has("token") ||
    !columns.has("user_id") ||
    !columns.has("expires_at")
  ) {
    throw new Error(
      "Database sessions không tương thích: cần token, user_id, expires_at"
    );
  }

  const token = bytesToBase64(randomBytes(32));

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (token, user_id, expires_at)
      VALUES (?, ?, ?)
    `)
    .bind(
      token,
      userId,
      expiresAt
    )
    .run();

  return {
    token,
    expiresAt
  };
}

function sessionCookie(token, expiresAt) {
  const expires = new Date(expiresAt * 1000);

  return cookieSerialize(
    SESSION_COOKIE,
    token,
    {
      expires,
      maxAge: SESSION_DAYS * 86400,
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }
  );
}

function clearSessionCookie() {
  return cookieSerialize(
    SESSION_COOKIE,
    "",
    {
      expires: new Date(0),
      maxAge: 0,
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }
  );
}

async function getCurrentUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);

  if (!token) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB
    .prepare(`
      SELECT
        users.id,
        users.email,
        users.role,
        users.created_at,
        sessions.token,
        sessions.expires_at
      FROM sessions
      INNER JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.token = ?
        AND sessions.expires_at > ?
      LIMIT 1
    `)
    .bind(token, now)
    .first();

  if (!row) {
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    role: row.role,
    created_at: row.created_at
  };
}

// ============================================================
// AUDIT
// ============================================================

async function audit(
  env,
  userId,
  action,
  target = null,
  details = null
) {
  try {
    await env.DB
      .prepare(`
        INSERT INTO audit_logs
        (user_id, action, target, details)
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        userId ?? null,
        action,
        target ?? null,
        details
          ? JSON.stringify(details)
          : null
      )
      .run();
  } catch {
    // Audit không được làm request chính thất bại.
  }
}

// ============================================================
// AUTH - REGISTER
// ============================================================

async function register(request, env) {
  const data = await bodyJSON(request);

  if (!data) {
    return fail(
      "Dữ liệu gửi lên không hợp lệ.",
      400,
      "INVALID_JSON"
    );
  }

  const email = cleanEmail(data.email);
  const password = data.password;

  if (!validEmail(email)) {
    return fail(
      "Email không hợp lệ.",
      400,
      "INVALID_EMAIL"
    );
  }

  if (!validPassword(password)) {
    return fail(
      "Mật khẩu phải có ít nhất 8 ký tự.",
      400,
      "WEAK_PASSWORD"
    );
  }

  try {
    const existing = await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE lower(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (existing) {
      return fail(
        "Email này đã được đăng ký.",
        409,
        "EMAIL_EXISTS"
      );
    }

    const passwordHash = await hashPassword(password);

    const columns = await getUserColumns(env);

    if (
      !columns.has("email") ||
      !columns.has("password_hash") ||
      !columns.has("role")
    ) {
      return fail(
        "Database users không đúng cấu trúc yêu cầu.",
        500,
        "INVALID_USERS_SCHEMA"
      );
    }

    // ========================================================
    // Trường hợp DB chuẩn:
    //
    // id
    // email
    // password_hash
    // role
    // created_at
    // ========================================================

    if (
      columns.has("password_salt") &&
      await usersHasRequiredPasswordSalt(env)
    ) {
      // ------------------------------------------------------
      // Tương thích DB cũ có password_salt NOT NULL.
      //
      // Salt trong password_hash vẫn là nguồn chính.
      // Cột legacy chỉ được điền để DB cũ không lỗi.
      // ------------------------------------------------------

      const hashParts = passwordHash.split("$");
      const salt = hashParts[2];

      await env.DB
        .prepare(`
          INSERT INTO users
          (email, password_hash, password_salt, role)
          VALUES (?, ?, ?, ?)
        `)
        .bind(
          email,
          passwordHash,
          salt,
          "USER"
        )
        .run();
    } else {
      // ------------------------------------------------------
      // DB hiện tại theo schema người dùng cung cấp.
      // Không password_salt.
      // ------------------------------------------------------

      await env.DB
        .prepare(`
          INSERT INTO users
          (email, password_hash, role)
          VALUES (?, ?, ?)
        `)
        .bind(
          email,
          passwordHash,
          "USER"
        )
        .run();
    }

    const user = await env.DB
      .prepare(`
        SELECT
          id,
          email,
          role,
          created_at
        FROM users
        WHERE lower(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (!user) {
      return fail(
        "Tạo tài khoản thất bại.",
        500,
        "REGISTER_FAILED"
      );
    }

    await audit(
      env,
      user.id,
      "REGISTER",
      `user:${user.id}`,
      {
        email: user.email
      }
    );

    return ok({
      message: "Tạo tài khoản thành công!",
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        created_at: user.created_at
      }
    });

  } catch (error) {
    const message = String(error?.message || "");

    if (
      message.includes("UNIQUE") ||
      message.includes("unique")
    ) {
      return fail(
        "Email này đã được đăng ký.",
        409,
        "EMAIL_EXISTS"
      );
    }

    return fail(
      `Không thể tạo tài khoản: ${message}`,
      500,
      "REGISTER_DATABASE_ERROR"
    );
  }
}

// ============================================================
// AUTH - LOGIN
// ============================================================

async function login(request, env) {
  const data = await bodyJSON(request);

  if (!data) {
    return fail(
      "Dữ liệu đăng nhập không hợp lệ.",
      400,
      "INVALID_JSON"
    );
  }

  const email = cleanEmail(data.email);
  const password = data.password;

  if (!validEmail(email)) {
    return fail(
      "Email không hợp lệ.",
      400,
      "INVALID_EMAIL"
    );
  }

  if (!password) {
    return fail(
      "Vui lòng nhập mật khẩu.",
      400,
      "PASSWORD_REQUIRED"
    );
  }

  try {
    const columns = await getUserColumns(env);

    if (
      !columns.has("email") ||
      !columns.has("password_hash") ||
      !columns.has("role")
    ) {
      return fail(
        "Database users không đúng cấu trúc.",
        500,
        "INVALID_USERS_SCHEMA"
      );
    }

    const user = await env.DB
      .prepare(`
        SELECT
          id,
          email,
          password_hash,
          role,
          created_at
        FROM users
        WHERE lower(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (!user) {
      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    const valid = await verifyPassword(
      password,
      user.password_hash
    );

    if (!valid) {
      await audit(
        env,
        user.id,
        "LOGIN_FAILED",
        `user:${user.id}`,
        {
          email: user.email
        }
      );

      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    const session = await createSession(
      env,
      user.id
    );

    await audit(
      env,
      user.id,
      "LOGIN",
      `user:${user.id}`,
      {
        email: user.email
      }
    );

    return json(
      {
        success: true,
        message: "Đăng nhập thành công!",
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          created_at: user.created_at
        }
      },
      200,
      {
        "Set-Cookie": sessionCookie(
          session.token,
          session.expiresAt
        )
      }
    );

  } catch (error) {
    return fail(
      `Không thể đăng nhập: ${error?.message || "Lỗi hệ thống"}`,
      500,
      "LOGIN_DATABASE_ERROR"
    );
  }
}

// ============================================================
// AUTH - ME
// ============================================================

async function me(request, env) {
  try {
    const user = await getCurrentUser(
      request,
      env
    );

    if (!user) {
      return ok({
        authenticated: false,
        user: null
      });
    }

    return ok({
      authenticated: true,
      user
    });

  } catch {
    return ok({
      authenticated: false,
      user: null
    });
  }
}

// ============================================================
// AUTH - LOGOUT
// ============================================================

async function logout(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE
  );

  if (token) {
    try {
      const user = await getCurrentUser(
        request,
        env
      );

      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token = ?
        `)
        .bind(token)
        .run();

      if (user) {
        await audit(
          env,
          user.id,
          "LOGOUT",
          `user:${user.id}`
        );
      }
    } catch {
      // Cookie vẫn được xoá kể cả DB logout lỗi.
    }
  }

  return json(
    {
      success: true,
      message: "Đã đăng xuất."
    },
    200,
    {
      "Set-Cookie": clearSessionCookie()
    }
  );
}

// ============================================================
// HEALTH
// ============================================================

async function health(env) {
  try {
    const result = await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return ok({
      worker: "online",
      database:
        result?.ok === 1
          ? "connected"
          : "error",
      site: env.SITE_NAME || "CUSTOM 151"
    });

  } catch (error) {
    return fail(
      error?.message || "Database error",
      500,
      "DATABASE_ERROR"
    );
  }
}

// ============================================================
// TABLES
// ============================================================

async function tables(env) {
  try {
    const result = await env.DB
      .prepare(`
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        ORDER BY name
      `)
      .all();

    return ok({
      tables: result.results || []
    });

  } catch (error) {
    return fail(
      error?.message || "Database error",
      500,
      "DATABASE_ERROR"
    );
  }
}

// ============================================================
// TABLE
// ============================================================

async function table(request, env) {
  const url = new URL(request.url);
  const name = url.searchParams.get("name");

  if (!name) {
    return fail(
      "Thiếu tên bảng.",
      400,
      "MISSING_TABLE"
    );
  }

  if (!/^[A-Za-z0-9_]+$/.test(name)) {
    return fail(
      "Tên bảng không hợp lệ.",
      400,
      "INVALID_TABLE"
    );
  }

  try {
    const result = await env.DB
      .prepare(
        `SELECT * FROM "${name}" LIMIT 100`
      )
      .all();

    return ok({
      table: name,
      rows: result.results || []
    });

  } catch (error) {
    return fail(
      error?.message || "Database error",
      500,
      "DATABASE_ERROR"
    );
  }
}

// ============================================================
// TOURNAMENTS
// ============================================================

async function tournaments(env) {
  try {
    const result = await env.DB
      .prepare(`
        SELECT
          id,
          name,
          fee,
          max_teams,
          status,
          description,
          created_at
        FROM tournaments
        WHERE status = 'OPEN'
        ORDER BY id DESC
      `)
      .all();

    return ok({
      tournaments: result.results || []
    });

  } catch (error) {
    return fail(
      error?.message || "Không thể tải giải đấu.",
      500,
      "TOURNAMENTS_ERROR"
    );
  }
}

// ============================================================
// RANKING
// ============================================================

async function ranking(env) {
  try {
    const result = await env.DB
      .prepare(`
        SELECT
          t.id,
          t.name,
          COALESCE(SUM(r.kills), 0) AS kills,
          COALESCE(SUM(r.points), 0) AS points
        FROM teams t
        LEFT JOIN results r
          ON r.team_id = t.id
        GROUP BY t.id, t.name
        HAVING points > 0 OR kills > 0
        ORDER BY points DESC, kills DESC, t.id ASC
        LIMIT 100
      `)
      .all();

    return ok({
      ranking: result.results || []
    });

  } catch (error) {
    return fail(
      error?.message || "Không thể tải bảng xếp hạng.",
      500,
      "RANKING_ERROR"
    );
  }
}

// ============================================================
// SCHEDULE
// ============================================================

async function schedule(env) {
  try {
    const result = await env.DB
      .prepare(`
        SELECT
          s.id,
          s.slot_time,
          s.group_name,
          s.capacity,
          s.tournament_id,
          t.name AS tournament_name
        FROM slots s
        INNER JOIN tournaments t
          ON t.id = s.tournament_id
        WHERE t.status = 'OPEN'
        ORDER BY s.slot_time ASC, s.id ASC
      `)
      .all();

    return ok({
      slots: result.results || []
    });

  } catch (error) {
    return fail(
      error?.message || "Không thể tải lịch thi đấu.",
      500,
      "SCHEDULE_ERROR"
    );
  }
}

// ============================================================
// API ROUTER
// ============================================================

async function handleAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (path === "/api/health" && method === "GET") {
    return health(env);
  }

  if (path === "/api/tables" && method === "GET") {
    return tables(env);
  }

  if (path === "/api/table" && method === "GET") {
    return table(request, env);
  }

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    return register(request, env);
  }

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    return login(request, env);
  }

  if (
    path === "/api/auth/me" &&
    method === "GET"
  ) {
    return me(request, env);
  }

  if (
    path === "/api/auth/logout" &&
    method === "POST"
  ) {
    return logout(request, env);
  }

  if (
    path === "/api/tournaments" &&
    method === "GET"
  ) {
    return tournaments(env);
  }

  if (
    path === "/api/ranking" &&
    method === "GET"
  ) {
    return ranking(env);
  }

  if (
    path === "/api/schedule" &&
    method === "GET"
  ) {
    return schedule(env);
  }

  return fail(
    "API không tồn tại.",
    404,
    "NOT_FOUND"
  );
}

// ============================================================
// WORKER
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await handleAPI(
          request,
          env
        );
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response(
        "CUSTOM 151",
        {
          headers: {
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );

    } catch (error) {
      console.error(error);

      return fail(
        error?.message ||
          "Lỗi máy chủ không xác định.",
        500,
        "INTERNAL_ERROR"
      );
    }
  }
};
