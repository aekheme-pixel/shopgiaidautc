// ============================================================
// CUSTOM 151 - CLOUDFLARE WORKER + D1
// Auth: PBKDF2 + password_salt
// Session: D1 sessions.token + HttpOnly Cookie
// Compatible with current database
// ============================================================

const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 86400;
const PBKDF2_ITERATIONS = 100000;

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
    throw new Error("Dữ liệu gửi lên không hợp lệ.");
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
    .replace(/=+$/g, "");
}

function base64ToBytes(value) {
  try {
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
  } catch {
    return null;
  }
}

// ============================================================
// PASSWORD HASH
// Compatible with existing password_salt + PBKDF2 SHA-256
// ============================================================

async function derivePassword(password, saltBytes) {
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

  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return new Uint8Array(derived);
}

async function createPasswordHash(password) {
  const salt = randomBytes(16);

  const hash = await derivePassword(password, salt);

  return {
    passwordHash: bytesToBase64(hash),
    passwordSalt: bytesToBase64(salt)
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash || !storedSalt) {
    return false;
  }

  const salt = base64ToBytes(storedSalt);

  if (!salt) {
    return false;
  }

  const calculated = await derivePassword(password, salt);

  const expected = base64ToBytes(storedHash);

  if (!expected || expected.length !== calculated.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < calculated.length; i++) {
    result |= calculated[i] ^ expected[i];
  }

  return result === 0;
}

// ============================================================
// COOKIE HELPERS
// ============================================================

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");

    if (index === -1) continue;

    const key = cookie.slice(0, index).trim();

    if (key !== name) continue;

    return cookie.slice(index + 1).trim();
  }

  return null;
}

function sessionCookie(token, request) {
  const secure =
    new URL(request.url).protocol === "https:"
      ? "; Secure"
      : "";

  return [
    `session=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${SESSION_SECONDS}`,
    secure
  ].filter(Boolean).join("; ");
}

function clearSessionCookie(request) {
  const secure =
    new URL(request.url).protocol === "https:"
      ? "; Secure"
      : "";

  return [
    "session=",
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    secure
  ].filter(Boolean).join("; ");
}

// ============================================================
// DATABASE HELPERS
// ============================================================

async function getUserColumns(env) {
  const result = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}

async function getSession(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  try {
    const now = Math.floor(Date.now() / 1000);

    const session = await env.DB
      .prepare(`
        SELECT
          sessions.token,
          sessions.user_id,
          sessions.expires_at,
          users.id,
          users.email,
          users.role
        FROM sessions
        INNER JOIN users
          ON users.id = sessions.user_id
        WHERE sessions.token = ?
          AND sessions.expires_at > ?
        LIMIT 1
      `)
      .bind(token, now)
      .first();

    if (!session) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

async function createSession(env, userId) {
  const token = bytesToBase64(randomBytes(32));
  const expiresAt =
    Math.floor(Date.now() / 1000) + SESSION_SECONDS;

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
        target,
        details ? JSON.stringify(details) : null
      )
      .run();
  } catch {
    // Audit log không được làm hỏng request chính.
  }
}

// ============================================================
// AUTH - REGISTER
// ============================================================

async function register(request, env) {
  let data;

  try {
    data = await bodyJSON(request);
  } catch {
    return fail(
      "Dữ liệu đăng ký không hợp lệ.",
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
    // --------------------------------------------------------
    // Kiểm tra tài khoản đã tồn tại
    // --------------------------------------------------------

    const existing = await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
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

    // --------------------------------------------------------
    // Hash password
    // --------------------------------------------------------

    const {
      passwordHash,
      passwordSalt
    } = await createPasswordHash(password);

    // --------------------------------------------------------
    // Kiểm tra schema hiện tại
    // --------------------------------------------------------

    const columns = await getUserColumns(env);

    const hasSalt = columns.has("password_salt");
    const hasRole = columns.has("role");

    let result;

    /*
      QUAN TRỌNG:

      Database hiện tại của bạn có role CHECK:

      ('PLAYER', 'ADMIN', 'SUPER_ADMIN')

      nên tài khoản người dùng bình thường phải là PLAYER,
      KHÔNG được insert USER.
    */

    if (hasSalt && hasRole) {
      result = await env.DB
        .prepare(`
          INSERT INTO users
            (email, password_hash, password_salt, role)
          VALUES (?, ?, ?, ?)
        `)
        .bind(
          email,
          passwordHash,
          passwordSalt,
          "PLAYER"
        )
        .run();

    } else if (hasSalt) {
      result = await env.DB
        .prepare(`
          INSERT INTO users
            (email, password_hash, password_salt)
          VALUES (?, ?, ?)
        `)
        .bind(
          email,
          passwordHash,
          passwordSalt
        )
        .run();

    } else if (hasRole) {
      /*
        Trường hợp database cũ không có password_salt.
        Không lý tưởng nhưng vẫn tương thích schema.
      */

      result = await env.DB
        .prepare(`
          INSERT INTO users
            (email, password_hash, role)
          VALUES (?, ?, ?)
        `)
        .bind(
          email,
          passwordHash,
          "PLAYER"
        )
        .run();

    } else {
      result = await env.DB
        .prepare(`
          INSERT INTO users
            (email, password_hash)
          VALUES (?, ?)
        `)
        .bind(
          email,
          passwordHash
        )
        .run();
    }

    const userId = result.meta?.last_row_id;

    await audit(
      env,
      userId,
      "REGISTER",
      "users",
      {
        email
      }
    );

    return ok({
      message: "Tạo tài khoản thành công!",
      user: {
        id: userId,
        email,
        role: "PLAYER"
      }
    });

  } catch (error) {
    const message = String(error?.message || error);

    if (
      message.includes("UNIQUE") ||
      message.includes("users.email")
    ) {
      return fail(
        "Email này đã được đăng ký.",
        409,
        "EMAIL_EXISTS"
      );
    }

    if (message.includes("password_salt")) {
      return fail(
        "Database hiện tại yêu cầu password_salt nhưng cấu trúc users chưa đồng bộ.",
        500,
        "PASSWORD_SALT_SCHEMA"
      );
    }

    if (message.includes("role")) {
      return fail(
        "Role không tương thích với database hiện tại.",
        500,
        "ROLE_SCHEMA"
      );
    }

    return fail(
      "Không thể tạo tài khoản: " + message,
      500,
      "REGISTER_FAILED"
    );
  }
}

// ============================================================
// AUTH - LOGIN
// ============================================================

async function login(request, env) {
  let data;

  try {
    data = await bodyJSON(request);
  } catch {
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

    const hasSalt = columns.has("password_salt");
    const hasRole = columns.has("role");

    const selectSalt = hasSalt
      ? ", password_salt"
      : "";

    const selectRole = hasRole
      ? ", role"
      : "";

    const user = await env.DB
      .prepare(`
        SELECT
          id,
          email,
          password_hash
          ${selectSalt}
          ${selectRole}
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (!user) {
      return fail(
        "Email hoặc mật khẩu không đúng.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    let passwordOK = false;

    if (hasSalt) {
      passwordOK = await verifyPassword(
        password,
        user.password_hash,
        user.password_salt
      );
    }

    if (!passwordOK) {
      await audit(
        env,
        user.id,
        "LOGIN_FAILED",
        "users",
        {
          email
        }
      );

      return fail(
        "Email hoặc mật khẩu không đúng.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    // --------------------------------------------------------
    // Xóa session cũ của user
    // --------------------------------------------------------

    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE user_id = ?
      `)
      .bind(user.id)
      .run();

    // --------------------------------------------------------
    // Tạo session mới
    // --------------------------------------------------------

    const session = await createSession(
      env,
      user.id
    );

    const role = user.role || "PLAYER";

    await audit(
      env,
      user.id,
      "LOGIN",
      "users",
      {
        email
      }
    );

    return ok(
      {
        message: "Đăng nhập thành công!",
        user: {
          id: user.id,
          email: user.email,
          role
        },
        expires_at: session.expiresAt
      },
      200,
      {
        "Set-Cookie": sessionCookie(
          session.token,
          request
        )
      }
    );

  } catch (error) {
    return fail(
      "Không thể đăng nhập: " +
      String(error?.message || error),
      500,
      "LOGIN_FAILED"
    );
  }
}

// ============================================================
// AUTH - ME
// ============================================================

async function me(request, env) {
  const session = await getSession(
    request,
    env
  );

  if (!session) {
    return ok({
      authenticated: false,
      user: null
    });
  }

  return ok({
    authenticated: true,
    user: {
      id: session.id,
      email: session.email,
      role: session.role
    },
    expires_at: session.expires_at
  });
}

// ============================================================
// AUTH - LOGOUT
// ============================================================

async function logout(request, env) {
  const token = getCookie(
    request,
    "session"
  );

  if (token) {
    try {
      const session = await env.DB
        .prepare(`
          SELECT user_id
          FROM sessions
          WHERE token = ?
          LIMIT 1
        `)
        .bind(token)
        .first();

      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token = ?
        `)
        .bind(token)
        .run();

      if (session) {
        await audit(
          env,
          session.user_id,
          "LOGOUT",
          "sessions"
        );
      }
    } catch {
      // Cookie vẫn được xóa phía client.
    }
  }

  return ok(
    {
      message: "Đã đăng xuất."
    },
    200,
    {
      "Set-Cookie": clearSessionCookie(
        request
      )
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
      String(error?.message || error),
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
      String(error?.message || error),
      500,
      "TABLES_FAILED"
    );
  }
}

// ============================================================
// TABLE
// ============================================================

async function table(request, env) {
  const url = new URL(request.url);

  const tableName =
    url.searchParams.get("name");

  if (!tableName) {
    return fail(
      "Thiếu tên bảng.",
      400,
      "MISSING_TABLE"
    );
  }

  if (!/^[A-Za-z0-9_]+$/.test(tableName)) {
    return fail(
      "Tên bảng không hợp lệ.",
      400,
      "INVALID_TABLE"
    );
  }

  try {
    const result = await env.DB
      .prepare(
        `SELECT * FROM "${tableName}" LIMIT 100`
      )
      .all();

    return ok({
      table: tableName,
      rows: result.results || []
    });

  } catch (error) {
    return fail(
      String(error?.message || error),
      500,
      "TABLE_READ_FAILED"
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
      String(error?.message || error),
      500,
      "TOURNAMENTS_FAILED"
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
          teams.id,
          teams.name,
          COALESCE(SUM(results.kills), 0) AS kills,
          COALESCE(SUM(results.points), 0) AS points
        FROM teams
        LEFT JOIN results
          ON results.team_id = teams.id
        GROUP BY
          teams.id,
          teams.name
        ORDER BY
          points DESC,
          kills DESC,
          teams.id ASC
        LIMIT 100
      `)
      .all();

    return ok({
      ranking: result.results || []
    });

  } catch (error) {
    return fail(
      String(error?.message || error),
      500,
      "RANKING_FAILED"
    );
  }
}

// ============================================================
// API ROUTER
// ============================================================

async function handleAPI(request, env) {
  const url = new URL(request.url);

  if (request.method === "GET" &&
      url.pathname === "/api/health") {
    return health(env);
  }

  if (request.method === "GET" &&
      url.pathname === "/api/tables") {
    return tables(env);
  }

  if (request.method === "GET" &&
      url.pathname === "/api/table") {
    return table(request, env);
  }

  // ----------------------------------------------------------
  // AUTH
  // ----------------------------------------------------------

  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/register"
  ) {
    return register(request, env);
  }

  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/login"
  ) {
    return login(request, env);
  }

  if (
    request.method === "GET" &&
    url.pathname === "/api/auth/me"
  ) {
    return me(request, env);
  }

  if (
    request.method === "POST" &&
    url.pathname === "/api/auth/logout"
  ) {
    return logout(request, env);
  }

  // ----------------------------------------------------------
  // PUBLIC DATA
  // ----------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/api/tournaments"
  ) {
    return tournaments(env);
  }

  if (
    request.method === "GET" &&
    url.pathname === "/api/ranking"
  ) {
    return ranking(env);
  }

  return null;
}

// ============================================================
// MAIN WORKER
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        const response = await handleAPI(
          request,
          env
        );

        if (response) {
          return response;
        }

        return fail(
          "API không tồn tại.",
          404,
          "NOT_FOUND"
        );
      }

      // ------------------------------------------------------
      // STATIC WEBSITE
      // ------------------------------------------------------

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
      return fail(
        "Server error: " +
        String(error?.message || error),
        500,
        "SERVER_ERROR"
      );
    }
  }
};
