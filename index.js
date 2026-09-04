// CUSTOM 151
// Cloudflare Worker + D1
// Auth + Sessions + Tournaments + Ranking
// Tương thích DB có password_salt và role CHECK:
// PLAYER / ADMIN / SUPER_ADMIN

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const SESSION_COOKIE = "session";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    try {
      // ================================
      // CORS / OPTIONS
      // ================================

      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders()
        });
      }

      // ================================
      // HEALTH
      // ================================

      if (url.pathname === "/api/health" && method === "GET") {
        return await health(env);
      }

      // ================================
      // AUTH
      // ================================

      if (
        url.pathname === "/api/auth/register" &&
        method === "POST"
      ) {
        return await register(request, env);
      }

      if (
        url.pathname === "/api/auth/login" &&
        method === "POST"
      ) {
        return await login(request, env);
      }

      if (
        url.pathname === "/api/auth/me" &&
        method === "GET"
      ) {
        return await me(request, env);
      }

      if (
        url.pathname === "/api/auth/logout" &&
        method === "POST"
      ) {
        return await logout(request, env);
      }

      // ================================
      // TOURNAMENTS
      // ================================

      if (
        url.pathname === "/api/tournaments" &&
        method === "GET"
      ) {
        return await tournaments(env);
      }

      // ================================
      // RANKING
      // ================================

      if (
        url.pathname === "/api/ranking" &&
        method === "GET"
      ) {
        return await ranking(env);
      }

      // ================================
      // DEBUG DATABASE
      // ================================

      if (
        url.pathname === "/api/tables" &&
        method === "GET"
      ) {
        return await tables(env);
      }

      if (
        url.pathname === "/api/table" &&
        method === "GET"
      ) {
        return await tableData(request, env);
      }

      // ================================
      // STATIC WEBSITE
      // ================================

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response(
        "CUSTOM 151 — Worker đang hoạt động",
        {
          status: 200,
          headers: {
            "content-type": "text/plain; charset=UTF-8"
          }
        }
      );

    } catch (error) {
      console.error(error);

      return json({
        success: false,
        error: error?.message || "Lỗi máy chủ"
      }, 500);
    }
  }
};


// ============================================================
// RESPONSE
// ============================================================

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store",
        ...corsHeaders(),
        ...extraHeaders
      }
    }
  );
}


// ============================================================
// HELPERS
// ============================================================

async function bodyJSON(request) {
  try {
    return await request.json();
  } catch {
    throw new Error("Dữ liệu gửi lên không hợp lệ");
  }
}

function cleanEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 200
  );
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function randomToken(length = 32) {
  return bytesToBase64(randomBytes(length))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}


// ============================================================
// PASSWORD
// ============================================================

async function derivePassword(password, saltBytes) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = randomBytes(32);

  const hash = await derivePassword(
    password,
    salt
  );

  return {
    password_hash: bytesToBase64(hash),
    password_salt: bytesToBase64(salt)
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash) return false;

  // DB cũ bắt buộc password_salt
  if (!storedSalt) return false;

  try {
    const salt = base64ToBytes(storedSalt);

    const calculated = await derivePassword(
      password,
      salt
    );

    const expected = base64ToBytes(storedHash);

    if (calculated.length !== expected.length) {
      return false;
    }

    let result = 0;

    for (let i = 0; i < calculated.length; i++) {
      result |= calculated[i] ^ expected[i];
    }

    return result === 0;

  } catch {
    return false;
  }
}


// ============================================================
// DATABASE SCHEMA COMPATIBILITY
// ============================================================

async function getUserColumns(env) {
  const result = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  return new Set(
    (result.results || []).map(
      row => row.name
    )
  );
}


// ============================================================
// SESSION
// ============================================================

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";

  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

async function createSession(env, userId) {
  const token = randomToken(32);

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

async function getCurrentUser(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE
  );

  if (!token) {
    return null;
  }

  const now =
    Math.floor(Date.now() / 1000);

  const user = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.email,
        u.role,
        u.created_at
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND s.expires_at > ?
      LIMIT 1
    `)
    .bind(token, now)
    .first();

  return user || null;
}

function sessionCookie(token, maxAge) {
  return [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    `Max-Age=${maxAge}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function deleteSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}


// ============================================================
// AUDIT LOG
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
        target,
        details
          ? JSON.stringify(details)
          : null
      )
      .run();
  } catch (error) {
    console.error(
      "Audit error:",
      error
    );
  }
}


// ============================================================
// HEALTH
// ============================================================

async function health(env) {
  try {
    const result = await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return json({
      success: true,
      worker: "online",
      database:
        result?.ok === 1
          ? "connected"
          : "error",
      site:
        env.SITE_NAME ||
        "CUSTOM 151"
    });

  } catch (error) {
    return json({
      success: false,
      worker: "online",
      database: "error",
      error: error.message
    }, 500);
  }
}


// ============================================================
// REGISTER
// ============================================================

async function register(request, env) {
  const data = await bodyJSON(request);

  const email = cleanEmail(
    data.email
  );

  const password = data.password;

  if (!validEmail(email)) {
    return json({
      success: false,
      error: "Email không hợp lệ"
    }, 400);
  }

  if (!validPassword(password)) {
    return json({
      success: false,
      error: "Mật khẩu phải có ít nhất 8 ký tự"
    }, 400);
  }

  // Không cho đăng ký trùng
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
    return json({
      success: false,
      error: "Email này đã được đăng ký"
    }, 409);
  }

  const passwordData =
    await hashPassword(password);

  const columns =
    await getUserColumns(env);

  /*
    QUAN TRỌNG:

    Schema thực tế của DB hiện tại có:
      password_hash
      password_salt
      role CHECK:
      PLAYER / ADMIN / SUPER_ADMIN

    Vì vậy user thường sẽ dùng PLAYER.
    Không dùng USER nữa.
  */

  let result;

  if (
    columns.has("password_salt") &&
    columns.has("role")
  ) {

    result = await env.DB
      .prepare(`
        INSERT INTO users
        (
          email,
          password_hash,
          password_salt,
          role
        )
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        email,
        passwordData.password_hash,
        passwordData.password_salt,
        "PLAYER"
      )
      .run();

  } else if (
    columns.has("password_salt")
  ) {

    result = await env.DB
      .prepare(`
        INSERT INTO users
        (
          email,
          password_hash,
          password_salt
        )
        VALUES (?, ?, ?)
      `)
      .bind(
        email,
        passwordData.password_hash,
        passwordData.password_salt
      )
      .run();

  } else {

    result = await env.DB
      .prepare(`
        INSERT INTO users
        (
          email,
          password_hash
        )
        VALUES (?, ?)
      `)
      .bind(
        email,
        passwordData.password_hash
      )
      .run();
  }

  const userId =
    result.meta?.last_row_id;

  await audit(
    env,
    userId,
    "REGISTER",
    `user:${userId}`,
    {
      email
    }
  );

  // Đăng ký xong tự động đăng nhập
  const session =
    await createSession(
      env,
      userId
    );

  return json(
    {
      success: true,
      message:
        "Tạo tài khoản thành công!",
      user: {
        id: userId,
        email,
        role: "PLAYER"
      }
    },
    201,
    {
      "Set-Cookie": sessionCookie(
        session.token,
        SESSION_DAYS * 86400
      )
    }
  );
}


// ============================================================
// LOGIN
// ============================================================

async function login(request, env) {
  const data = await bodyJSON(request);

  const email = cleanEmail(
    data.email
  );

  const password = data.password;

  if (!validEmail(email)) {
    return json({
      success: false,
      error: "Email không hợp lệ"
    }, 400);
  }

  if (!validPassword(password)) {
    return json({
      success: false,
      error: "Mật khẩu không hợp lệ"
    }, 400);
  }

  const columns =
    await getUserColumns(env);

  const saltColumn =
    columns.has("password_salt")
      ? ", password_salt"
      : "";

  const user = await env.DB
    .prepare(`
      SELECT
        id,
        email,
        password_hash,
        role,
        created_at
        ${saltColumn}
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (!user) {
    return json({
      success: false,
      error:
        "Email hoặc mật khẩu không đúng"
    }, 401);
  }

  const passwordOK =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

  if (!passwordOK) {

    await audit(
      env,
      user.id,
      "LOGIN_FAILED",
      `user:${user.id}`,
      { email }
    );

    return json({
      success: false,
      error:
        "Email hoặc mật khẩu không đúng"
    }, 401);
  }

  const session =
    await createSession(
      env,
      user.id
    );

  await audit(
    env,
    user.id,
    "LOGIN",
    `user:${user.id}`
  );

  return json(
    {
      success: true,
      message:
        "Đăng nhập thành công!",
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        created_at:
          user.created_at
      }
    },
    200,
    {
      "Set-Cookie": sessionCookie(
        session.token,
        SESSION_DAYS * 86400
      )
    }
  );
}


// ============================================================
// ME
// ============================================================

async function me(request, env) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  return json({
    success: true,
    authenticated: !!user,
    user: user || null
  });
}


// ============================================================
// LOGOUT
// ============================================================

async function logout(request, env) {
  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (token) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token = ?
      `)
      .bind(token)
      .run();
  }

  return json(
    {
      success: true,
      message:
        "Đã đăng xuất thành công"
    },
    200,
    {
      "Set-Cookie":
        deleteSessionCookie()
    }
  );
}


// ============================================================
// TOURNAMENTS
// ============================================================

async function tournaments(env) {
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

  return json({
    success: true,
    tournaments:
      result.results || []
  });
}


// ============================================================
// RANKING
// ============================================================

async function ranking(env) {
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
      GROUP BY
        t.id,
        t.name
      ORDER BY
        points DESC,
        kills DESC,
        t.id ASC
      LIMIT 100
    `)
    .all();

  return json({
    success: true,
    ranking:
      result.results || []
  });
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

    return json({
      success: true,
      tables:
        result.results || []
    });

  } catch (error) {
    return json({
      success: false,
      error: error.message
    }, 500);
  }
}


// ============================================================
// TABLE DATA
// ============================================================

async function tableData(request, env) {
  const url =
    new URL(request.url);

  const table =
    url.searchParams.get("name");

  if (!table) {
    return json({
      success: false,
      error: "Thiếu tên bảng"
    }, 400);
  }

  if (!/^[A-Za-z0-9_]+$/.test(table)) {
    return json({
      success: false,
      error:
        "Tên bảng không hợp lệ"
    }, 400);
  }

  try {

    const result =
      await env.DB
        .prepare(
          `SELECT * FROM "${table}" LIMIT 100`
        )
        .all();

    return json({
      success: true,
      table,
      rows:
        result.results || []
    });

  } catch (error) {

    return json({
      success: false,
      error: error.message
    }, 500);
  }
}
