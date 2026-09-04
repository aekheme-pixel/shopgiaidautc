// ============================================================
// CUSTOM 151 — CLOUDFLARE WORKER + D1
// Auth tương thích schema D1 hiện tại
// ============================================================

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const SESSION_BYTES = 32;

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

function ok(data = {}, status = 200) {
  return json(
    {
      success: true,
      ...data
    },
    status
  );
}

function fail(message, status = 400, code = "BAD_REQUEST") {
  return json(
    {
      success: false,
      error: message,
      code
    },
    status
  );
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
  return String(value || "")
    .trim()
    .toLowerCase();
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

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ============================================================
// PASSWORD HASH
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
  const hash = await derivePassword(password, salt);

  return {
    salt: bytesToBase64(salt),
    hash: bytesToBase64(hash)
  };
}

function safeEqual(a, b) {
  const aa = String(a || "");
  const bb = String(b || "");

  if (aa.length !== bb.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < aa.length; i++) {
    result |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  }

  return result === 0;
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash) {
    return false;
  }

  // ----------------------------------------------------------
  // Cách 1:
  // DB có password_salt riêng
  // ----------------------------------------------------------

  if (storedSalt) {
    try {
      const salt = base64ToBytes(storedSalt);
      const hash = await derivePassword(password, salt);
      const calculated = bytesToBase64(hash);

      return safeEqual(calculated, storedHash);
    } catch {
      return false;
    }
  }

  // ----------------------------------------------------------
  // Cách 2:
  // password_hash tự chứa salt
  //
  // pbkdf2$100000$salt$hash
  // ----------------------------------------------------------

  const parts = String(storedHash).split("$");

  if (parts.length === 4 && parts[0] === "pbkdf2") {
    try {
      const iterations = Number(parts[1]);
      const salt = base64ToBytes(parts[2]);
      const expected = parts[3];

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
          salt,
          iterations,
          hash: "SHA-256"
        },
        keyMaterial,
        256
      );

      return safeEqual(
        bytesToBase64(new Uint8Array(bits)),
        expected
      );
    } catch {
      return false;
    }
  }

  return false;
}

// ============================================================
// DB SCHEMA HELPERS
// ============================================================

async function getColumns(env, table) {
  const result = await env.DB
    .prepare(`PRAGMA table_info("${table}")`)
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}

async function getTableSQL(env, table) {
  const row = await env.DB
    .prepare(`
      SELECT sql
      FROM sqlite_master
      WHERE type = 'table'
      AND name = ?
      LIMIT 1
    `)
    .bind(table)
    .first();

  return String(row?.sql || "");
}

// ============================================================
// ROLE COMPATIBILITY
// ============================================================

async function getAllowedRoles(env) {
  const sql = await getTableSQL(env, "users");

  const match = sql.match(
    /role\s+IN\s*\(([^)]*)\)/i
  );

  if (!match) {
    return [];
  }

  return match[1]
    .split(",")
    .map(x => x.trim().replace(/^['"]|['"]$/g, ""))
    .filter(Boolean);
}

async function getDefaultUserRole(env) {
  const roles = await getAllowedRoles(env);

  // Nếu DB cho USER thì ưu tiên USER.
  if (roles.includes("USER")) {
    return "USER";
  }

  // Schema hiện tại của bạn đang có PLAYER.
  if (roles.includes("PLAYER")) {
    return "PLAYER";
  }

  // Nếu không có CHECK hoặc không đọc được.
  if (!roles.length) {
    return "PLAYER";
  }

  // Chọn role đầu tiên hợp lệ.
  return roles[0];
}

function publicRole(role) {
  // Frontend cũ thường coi USER là người dùng thường.
  // DB của bạn có thể dùng PLAYER thay cho USER.
  if (role === "PLAYER") {
    return "USER";
  }

  return role;
}

// ============================================================
// SESSION COMPATIBILITY
// ============================================================

async function getSessionColumns(env) {
  return await getColumns(env, "sessions");
}

async function getSessionTokenColumn(env) {
  const columns = await getSessionColumns(env);

  if (columns.has("token")) {
    return "token";
  }

  if (columns.has("session_token")) {
    return "session_token";
  }

  if (columns.has("sessionToken")) {
    return "sessionToken";
  }

  return null;
}

async function createSession(env, userId) {
  const columns = await getSessionColumns(env);

  const tokenColumn = await getSessionTokenColumn(env);

  if (!tokenColumn) {
    throw new Error(
      "Bảng sessions không có cột token/session_token"
    );
  }

  if (!columns.has("user_id")) {
    throw new Error(
      "Bảng sessions không có cột user_id"
    );
  }

  if (!columns.has("expires_at")) {
    throw new Error(
      "Bảng sessions không có cột expires_at"
    );
  }

  const token = bytesToBase64(
    randomBytes(SESSION_BYTES)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB
    .prepare(`
      INSERT INTO sessions
      ("${tokenColumn}", user_id, expires_at)
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

// ============================================================
// COOKIE
// ============================================================

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  const parts = header.split(";");

  for (const part of parts) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function sessionCookie(token) {
  return [
    `session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

// ============================================================
// CURRENT USER
// ============================================================

async function getCurrentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  const columns = await getSessionColumns(env);
  const tokenColumn = await getSessionTokenColumn(env);

  if (!tokenColumn) {
    return null;
  }

  if (!columns.has("user_id") || !columns.has("expires_at")) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB
    .prepare(`
      SELECT user_id, expires_at
      FROM sessions
      WHERE "${tokenColumn}" = ?
      AND expires_at > ?
      LIMIT 1
    `)
    .bind(token, now)
    .first();

  if (!session) {
    return null;
  }

  const user = await env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(session.user_id)
    .first();

  if (!user) {
    return null;
  }

  return {
    ...user,
    role: publicRole(user.role)
  };
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
    const columns = await getColumns(
      env,
      "audit_logs"
    );

    if (
      !columns.has("user_id") ||
      !columns.has("action")
    ) {
      return;
    }

    await env.DB
      .prepare(`
        INSERT INTO audit_logs
        (user_id, action, target, details)
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        userId || null,
        action,
        target,
        details
          ? JSON.stringify(details)
          : null
      )
      .run();
  } catch {
    // Audit không được phép làm hỏng request chính.
  }
}

// ============================================================
// AUTH — REGISTER
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
    const columns = await getColumns(
      env,
      "users"
    );

    // --------------------------------------------------------
    // Kiểm tra email
    // --------------------------------------------------------

    const exists = await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE lower(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (exists) {
      return fail(
        "Email này đã được đăng ký.",
        409,
        "EMAIL_EXISTS"
      );
    }

    // --------------------------------------------------------
    // Hash password
    // --------------------------------------------------------

    const hashed = await hashPassword(password);

    // --------------------------------------------------------
    // Role tương thích DB
    // --------------------------------------------------------

    const role = await getDefaultUserRole(env);

    // --------------------------------------------------------
    // Tạo INSERT động theo schema thực tế
    // --------------------------------------------------------

    const fields = [];
    const values = [];

    if (columns.has("email")) {
      fields.push("email");
      values.push(email);
    } else {
      return fail(
        "Database users thiếu cột email.",
        500,
        "DB_SCHEMA_ERROR"
      );
    }

    if (columns.has("password_hash")) {
      fields.push("password_hash");
      values.push(hashed.hash);
    } else {
      return fail(
        "Database users thiếu cột password_hash.",
        500,
        "DB_SCHEMA_ERROR"
      );
    }

    // --------------------------------------------------------
    // password_salt:
    //
    // Có cột -> lưu salt riêng.
    //
    // Không có cột -> nhúng salt vào password_hash.
    // --------------------------------------------------------

    let finalPasswordHash = hashed.hash;

    if (columns.has("password_salt")) {
      fields.push("password_salt");
      values.push(hashed.salt);
    } else {
      finalPasswordHash =
        `pbkdf2$${PBKDF2_ITERATIONS}$${hashed.salt}$${hashed.hash}`;

      values[
        fields.indexOf("password_hash")
      ] = finalPasswordHash;
    }

    // --------------------------------------------------------
    // role
    // --------------------------------------------------------

    if (columns.has("role")) {
      fields.push("role");
      values.push(role);
    }

    // --------------------------------------------------------
    // created_at chỉ thêm nếu cần.
    // Nếu DB có DEFAULT thì bỏ qua.
    // --------------------------------------------------------

    const placeholders =
      fields.map(() => "?").join(", ");

    const query = `
      INSERT INTO users
      (${fields.map(x => `"${x}"`).join(", ")})
      VALUES (${placeholders})
    `;

    const result = await env.DB
      .prepare(query)
      .bind(...values)
      .run();

    const userId =
      result.meta?.last_row_id;

    await audit(
      env,
      userId,
      "REGISTER",
      `user:${userId}`,
      { email }
    );

    // --------------------------------------------------------
    // Không tự đăng nhập.
    // User đăng ký xong sẽ được chuyển sang login.
    // --------------------------------------------------------

    return ok(
      {
        message:
          "Tạo tài khoản thành công. Hãy đăng nhập để tiếp tục.",
        user: {
          id: userId,
          email,
          role: publicRole(role)
        }
      },
      201
    );

  } catch (error) {
    const message = String(
      error?.message || error
    );

    console.error(
      "REGISTER ERROR:",
      message
    );

    if (
      /UNIQUE/i.test(message) &&
      /email/i.test(message)
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
      "REGISTER_FAILED"
    );
  }
}

// ============================================================
// AUTH — LOGIN
// ============================================================

async function login(request, env) {
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

  if (!password) {
    return fail(
      "Vui lòng nhập mật khẩu.",
      400,
      "PASSWORD_REQUIRED"
    );
  }

  try {
    const columns = await getColumns(
      env,
      "users"
    );

    const saltColumn =
      columns.has("password_salt")
        ? "password_salt"
        : null;

    const selectFields = [
      "id",
      "email",
      "password_hash",
      "role"
    ];

    if (saltColumn) {
      selectFields.push("password_salt");
    }

    const user = await env.DB
      .prepare(`
        SELECT ${selectFields
          .map(x => `"${x}"`)
          .join(", ")}
        FROM users
        WHERE lower(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (!user) {
      await audit(
        env,
        null,
        "LOGIN_FAILED",
        null,
        { email, reason: "USER_NOT_FOUND" }
      );

      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    const valid = await verifyPassword(
      password,
      user.password_hash,
      saltColumn
        ? user.password_salt
        : null
    );

    if (!valid) {
      await audit(
        env,
        user.id,
        "LOGIN_FAILED",
        `user:${user.id}`,
        { reason: "BAD_PASSWORD" }
      );

      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    // --------------------------------------------------------
    // Session tự tương thích token/session_token
    // --------------------------------------------------------

    const session =
      await createSession(
        env,
        user.id
      );

    await audit(
      env,
      user.id,
      "LOGIN",
      `user:${user.id}`,
      { email: user.email }
    );

    const response = ok({
      message: "Đăng nhập thành công!",
      user: {
        id: user.id,
        email: user.email,
        role: publicRole(user.role)
      }
    });

    response.headers.append(
      "Set-Cookie",
      sessionCookie(session.token)
    );

    return response;

  } catch (error) {
    const message = String(
      error?.message || error
    );

    console.error(
      "LOGIN ERROR:",
      message
    );

    return fail(
      `Không thể đăng nhập: ${message}`,
      500,
      "LOGIN_FAILED"
    );
  }
}

// ============================================================
// AUTH — ME
// ============================================================

async function me(request, env) {
  try {
    const user =
      await getCurrentUser(
        request,
        env
      );

    return ok({
      authenticated: !!user,
      user: user || null
    });
  } catch (error) {
    return fail(
      error.message,
      500,
      "ME_FAILED"
    );
  }
}

// ============================================================
// AUTH — LOGOUT
// ============================================================

async function logout(request, env) {
  try {
    const token =
      getCookie(request, "session");

    if (token) {
      const tokenColumn =
        await getSessionTokenColumn(env);

      if (tokenColumn) {
        await env.DB
          .prepare(`
            DELETE FROM sessions
            WHERE "${tokenColumn}" = ?
          `)
          .bind(token)
          .run();
      }
    }

    const response = ok({
      message: "Đã đăng xuất thành công."
    });

    response.headers.append(
      "Set-Cookie",
      clearSessionCookie()
    );

    return response;

  } catch (error) {
    return fail(
      error.message,
      500,
      "LOGOUT_FAILED"
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

    return ok({
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
    return fail(
      error.message,
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
      tables:
        result.results || []
    });

  } catch (error) {
    return fail(
      error.message,
      500,
      "TABLES_FAILED"
    );
  }
}

// ============================================================
// TABLE DATA
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
      error.message,
      500,
      "TABLE_READ_FAILED"
    );
  }
}

// ============================================================
// TOURNAMENTS — PUBLIC
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
      tournaments:
        result.results || []
    });

  } catch (error) {
    return fail(
      error.message,
      500,
      "TOURNAMENTS_FAILED"
    );
  }
}

// ============================================================
// RANKING — PUBLIC
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
        HAVING
          COALESCE(SUM(r.points), 0) > 0
          OR COALESCE(SUM(r.kills), 0) > 0
        ORDER BY
          points DESC,
          kills DESC,
          t.id ASC
        LIMIT 100
      `)
      .all();

    return ok({
      ranking:
        result.results || []
    });

  } catch (error) {
    return fail(
      error.message,
      500,
      "RANKING_FAILED"
    );
  }
}

// ============================================================
// ROUTER
// ============================================================

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    const method =
      request.method.toUpperCase();

    try {

      // ======================================================
      // HEALTH
      // ======================================================

      if (
        url.pathname === "/api/health" &&
        method === "GET"
      ) {
        return await health(env);
      }

      // ======================================================
      // TABLES
      // ======================================================

      if (
        url.pathname === "/api/tables" &&
        method === "GET"
      ) {
        return await tables(env);
      }

      // ======================================================
      // TABLE
      // ======================================================

      if (
        url.pathname === "/api/table" &&
        method === "GET"
      ) {
        return await table(
          request,
          env
        );
      }

      // ======================================================
      // AUTH REGISTER
      // ======================================================

      if (
        url.pathname === "/api/auth/register" &&
        method === "POST"
      ) {
        return await register(
          request,
          env
        );
      }

      // ======================================================
      // AUTH LOGIN
      // ======================================================

      if (
        url.pathname === "/api/auth/login" &&
        method === "POST"
      ) {
        return await login(
          request,
          env
        );
      }

      // ======================================================
      // AUTH ME
      // ======================================================

      if (
        url.pathname === "/api/auth/me" &&
        method === "GET"
      ) {
        return await me(
          request,
          env
        );
      }

      // ======================================================
      // AUTH LOGOUT
      // ======================================================

      if (
        url.pathname === "/api/auth/logout" &&
        method === "POST"
      ) {
        return await logout(
          request,
          env
        );
      }

      // ======================================================
      // TOURNAMENTS
      // ======================================================

      if (
        url.pathname === "/api/tournaments" &&
        method === "GET"
      ) {
        return await tournaments(env);
      }

      // ======================================================
      // RANKING
      // ======================================================

      if (
        url.pathname === "/api/ranking" &&
        method === "GET"
      ) {
        return await ranking(env);
      }

      // ======================================================
      // WEBSITE / ASSETS
      // ======================================================

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response(
        "CUSTOM 151 — Worker đang hoạt động.",
        {
          status: 200,
          headers: {
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );

    } catch (error) {

      console.error(
        "UNHANDLED ERROR:",
        error
      );

      return fail(
        `Lỗi máy chủ: ${
          error?.message || error
        }`,
        500,
        "INTERNAL_ERROR"
      );
    }
  }
};
