// ============================================================
// CUSTOM 151 - CLOUDFLARE WORKER
// Auth + D1 + Sessions + Tournaments + Ranking
// Không package ngoài - Web Crypto PBKDF2
// Tương thích DB hiện tại:
//   users.password_hash
//   users.password_salt (nếu tồn tại)
//   users.role CHECK khác nhau
//   sessions token/session_token/session_id...
// ============================================================

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const SESSION_COOKIE = "custom151_session";

// ============================================================
// RESPONSE
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

function ok(data = {}, status = 200, headers = {}) {
  return json(
    {
      success: true,
      ...data
    },
    status,
    headers
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
// SAFE SQL IDENTIFIER
// Chỉ dùng cho tên cột lấy trực tiếp từ PRAGMA.
// ============================================================

function quoteIdentifier(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

// ============================================================
// DB SCHEMA DISCOVERY
// ============================================================

async function getTableInfo(env, table) {
  const result = await env.DB
    .prepare(`PRAGMA table_info(${quoteIdentifier(table)})`)
    .all();

  return result.results || [];
}

async function getTableColumns(env, table) {
  const info = await getTableInfo(env, table);
  return new Set(info.map(x => String(x.name)));
}

function firstExisting(columns, names) {
  for (const name of names) {
    if (columns.has(name)) return name;
  }
  return null;
}

// ============================================================
// DETECT USER ROLE CHECK
// ============================================================

async function getAllowedRoles(env) {
  try {
    const row = await env.DB
      .prepare(`
        SELECT sql
        FROM sqlite_master
        WHERE type = 'table'
        AND name = 'users'
        LIMIT 1
      `)
      .first();

    const sql = String(row?.sql || "");

    // Tìm:
    // role IN ('PLAYER','ADMIN','SUPER_ADMIN')
    // hoặc role TEXT ... CHECK...
    const match = sql.match(
      /role\s+IN\s*\(([^)]*)\)/i
    );

    if (match) {
      const values = match[1]
        .split(",")
        .map(x => x.trim().replace(/^['"]|['"]$/g, ""))
        .filter(Boolean);

      if (values.length) return values;
    }

    // DB hiện tại của bạn đang báo CHECK này.
    // PLAYER là role an toàn mặc định cho tài khoản mới.
    return ["PLAYER"];
  } catch {
    return ["PLAYER"];
  }
}

async function getDefaultUserRole(env) {
  const roles = await getAllowedRoles(env);

  if (roles.includes("USER")) return "USER";
  if (roles.includes("PLAYER")) return "PLAYER";

  return roles[0] || "PLAYER";
}

// ============================================================
// CRYPTO HELPERS
// ============================================================

function bytesToBase64(bytes) {
  let binary = "";

  const arr = bytes instanceof Uint8Array
    ? bytes
    : new Uint8Array(bytes);

  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
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

function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomToken(length = 32) {
  return bytesToBase64(randomBytes(length))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

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
  const salt = randomBytes(16);
  const hash = await derivePassword(password, salt);

  return {
    hash: bytesToBase64(hash),
    salt: bytesToBase64(salt)
  };
}

function timingSafeEqual(a, b) {
  if (!a || !b) return false;

  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash) return false;

  // DB hiện tại có password_salt.
  if (storedSalt) {
    try {
      const salt = base64ToBytes(storedSalt);
      const derived = await derivePassword(password, salt);
      const calculated = bytesToBase64(derived);

      return timingSafeEqual(
        calculated,
        String(storedHash)
      );
    } catch {
      return false;
    }
  }

  // Hỗ trợ format:
  // pbkdf2$salt$hash
  const parts = String(storedHash).split("$");

  if (
    parts.length === 3 &&
    parts[0] === "pbkdf2"
  ) {
    try {
      const salt = base64ToBytes(parts[1]);
      const derived = await derivePassword(password, salt);
      const calculated = bytesToBase64(derived);

      return timingSafeEqual(
        calculated,
        parts[2]
      );
    } catch {
      return false;
    }
  }

  return false;
}

// ============================================================
// COOKIE
// ============================================================

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";

  const cookies = {};

  for (const item of header.split(";")) {
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key) {
      cookies[key] = decodeURIComponent(value);
    }
  }

  return cookies;
}

function getSessionCookie(request) {
  const cookies = parseCookies(request);
  return cookies[SESSION_COOKIE] || null;
}

function makeSessionCookie(token) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

// ============================================================
// SESSIONS - TỰ NHẬN DIỆN DB HIỆN TẠI
// ============================================================

async function getSessionSchema(env) {
  const columns = await getTableColumns(env, "sessions");

  const tokenColumn = firstExisting(columns, [
    "token",
    "session_token",
    "sessionToken",
    "session_id",
    "session",
    "key"
  ]);

  const userColumn = firstExisting(columns, [
    "user_id",
    "userid",
    "userId"
  ]);

  const expiresColumn = firstExisting(columns, [
    "expires_at",
    "expires",
    "expiresAt",
    "expiry"
  ]);

  return {
    columns,
    tokenColumn,
    userColumn,
    expiresColumn
  };
}

async function createSession(env, userId) {
  const schema = await getSessionSchema(env);

  const token = randomToken(32);
  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  // DB session đầy đủ
  if (
    schema.tokenColumn &&
    schema.userColumn &&
    schema.expiresColumn
  ) {
    const sql = `
      INSERT INTO sessions
      (${quoteIdentifier(schema.tokenColumn)},
       ${quoteIdentifier(schema.userColumn)},
       ${quoteIdentifier(schema.expiresColumn)})
      VALUES (?, ?, ?)
    `;

    await env.DB
      .prepare(sql)
      .bind(token, userId, expiresAt)
      .run();

    return token;
  }

  // Nếu DB sessions hiện tại không có cấu trúc token,
  // dùng cookie stateless fallback.
  // Cookie vẫn HttpOnly + Secure.
  return `stateless.${userId}.${token}`;
}

async function getSession(env, token) {
  if (!token) return null;

  // Stateless fallback
  if (token.startsWith("stateless.")) {
    const parts = token.split(".");

    if (parts.length !== 3) return null;

    const userId = Number(parts[1]);

    if (!Number.isInteger(userId) || userId <= 0) {
      return null;
    }

    // Stateless token chỉ dùng fallback trong trường hợp
    // sessions không có cột token tương thích.
    return {
      user_id: userId,
      expires_at: Math.floor(Date.now() / 1000) + 60
    };
  }

  const schema = await getSessionSchema(env);

  if (
    !schema.tokenColumn ||
    !schema.userColumn ||
    !schema.expiresColumn
  ) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const sql = `
    SELECT
      ${quoteIdentifier(schema.userColumn)} AS user_id,
      ${quoteIdentifier(schema.expiresColumn)} AS expires_at
    FROM sessions
    WHERE ${quoteIdentifier(schema.tokenColumn)} = ?
      AND ${quoteIdentifier(schema.expiresColumn)} > ?
    LIMIT 1
  `;

  return await env.DB
    .prepare(sql)
    .bind(token, now)
    .first();
}

async function destroySession(env, token) {
  if (!token) return;

  if (token.startsWith("stateless.")) {
    return;
  }

  const schema = await getSessionSchema(env);

  if (!schema.tokenColumn) return;

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE ${quoteIdentifier(schema.tokenColumn)} = ?
    `)
    .bind(token)
    .run();
}

// ============================================================
// USERS
// ============================================================

async function getCurrentUser(request, env) {
  const token = getSessionCookie(request);

  if (!token) return null;

  const session = await getSession(env, token);

  if (!session) return null;

  const columns = await getTableColumns(env, "users");

  const idColumn = firstExisting(columns, [
    "id",
    "user_id"
  ]);

  const emailColumn = firstExisting(columns, [
    "email",
    "username"
  ]);

  const passwordHashColumn = firstExisting(columns, [
    "password_hash",
    "passwordHash"
  ]);

  const roleColumn = firstExisting(columns, [
    "role"
  ]);

  if (!idColumn || !emailColumn) {
    return null;
  }

  const selectParts = [
    `${quoteIdentifier(idColumn)} AS id`,
    `${quoteIdentifier(emailColumn)} AS email`
  ];

  if (roleColumn) {
    selectParts.push(
      `${quoteIdentifier(roleColumn)} AS role`
    );
  }

  if (passwordHashColumn) {
    selectParts.push(
      `${quoteIdentifier(passwordHashColumn)} AS password_hash`
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT ${selectParts.join(", ")}
      FROM users
      WHERE ${quoteIdentifier(idColumn)} = ?
      LIMIT 1
    `)
    .bind(session.user_id)
    .first();

  if (!user) return null;

  return {
    id: user.id,
    email: user.email,
    role: user.role || "PLAYER"
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
    const columns = await getTableColumns(
      env,
      "audit_logs"
    );

    if (!columns.has("user_id")) return;

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
  } catch {
    // Audit không được phép làm hỏng request chính.
  }
}

// ============================================================
// AUTH: REGISTER
// ============================================================

async function register(request, env) {
  const data = await bodyJSON(request);

  if (!data) {
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
    const columns = await getTableColumns(
      env,
      "users"
    );

    const idColumn =
      firstExisting(columns, ["id"]);

    const emailColumn =
      firstExisting(columns, ["email"]);

    const hashColumn =
      firstExisting(columns, [
        "password_hash",
        "passwordHash"
      ]);

    const saltColumn =
      firstExisting(columns, [
        "password_salt",
        "passwordSalt"
      ]);

    const roleColumn =
      firstExisting(columns, ["role"]);

    if (
      !idColumn ||
      !emailColumn ||
      !hashColumn
    ) {
      return fail(
        "Cấu trúc bảng users không tương thích.",
        500,
        "USER_SCHEMA_ERROR"
      );
    }

    // Kiểm tra email trước.
    const existing = await env.DB
      .prepare(`
        SELECT ${quoteIdentifier(idColumn)} AS id
        FROM users
        WHERE LOWER(${quoteIdentifier(emailColumn)}) = ?
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

    const passwordData =
      await hashPassword(password);

    const role = await getDefaultUserRole(env);

    const insertColumns = [
      emailColumn,
      hashColumn
    ];

    const values = [
      email,
      passwordData.hash
    ];

    // DB có password_salt NOT NULL:
    // tự động ghi salt.
    if (saltColumn) {
      insertColumns.push(saltColumn);
      values.push(passwordData.salt);
    }

    if (roleColumn) {
      insertColumns.push(roleColumn);
      values.push(role);
    }

    // Nếu DB có created_at và có default thì
    // không cần truyền vào.
    const placeholders =
      insertColumns.map(() => "?").join(", ");

    await env.DB
      .prepare(`
        INSERT INTO users
        (${insertColumns.map(quoteIdentifier).join(", ")})
        VALUES (${placeholders})
      `)
      .bind(...values)
      .run();

    const newUser = await env.DB
      .prepare(`
        SELECT ${quoteIdentifier(idColumn)} AS id,
               ${quoteIdentifier(emailColumn)} AS email
        FROM users
        WHERE ${quoteIdentifier(emailColumn)} = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    await audit(
      env,
      newUser?.id ?? null,
      "REGISTER",
      "users",
      { email }
    );

    return ok({
      message: "Tạo tài khoản thành công.",
      user: {
        id: newUser?.id ?? null,
        email,
        role
      }
    });
  } catch (error) {
    const message = String(
      error?.message || error
    );

    // UNIQUE email race condition
    if (
      /unique|duplicate/i.test(message)
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
// AUTH: LOGIN
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
    const columns = await getTableColumns(
      env,
      "users"
    );

    const idColumn =
      firstExisting(columns, ["id"]);

    const emailColumn =
      firstExisting(columns, ["email"]);

    const hashColumn =
      firstExisting(columns, [
        "password_hash",
        "passwordHash"
      ]);

    const saltColumn =
      firstExisting(columns, [
        "password_salt",
        "passwordSalt"
      ]);

    const roleColumn =
      firstExisting(columns, ["role"]);

    if (
      !idColumn ||
      !emailColumn ||
      !hashColumn
    ) {
      return fail(
        "Cấu trúc bảng users không tương thích.",
        500,
        "USER_SCHEMA_ERROR"
      );
    }

    const selectParts = [
      `${quoteIdentifier(idColumn)} AS id`,
      `${quoteIdentifier(emailColumn)} AS email`,
      `${quoteIdentifier(hashColumn)} AS password_hash`
    ];

    if (saltColumn) {
      selectParts.push(
        `${quoteIdentifier(saltColumn)} AS password_salt`
      );
    }

    if (roleColumn) {
      selectParts.push(
        `${quoteIdentifier(roleColumn)} AS role`
      );
    }

    const user = await env.DB
      .prepare(`
        SELECT ${selectParts.join(", ")}
        FROM users
        WHERE LOWER(${quoteIdentifier(emailColumn)}) = ?
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

    const passwordOK =
      await verifyPassword(
        password,
        user.password_hash,
        user.password_salt || null
      );

    if (!passwordOK) {
      await audit(
        env,
        user.id,
        "LOGIN_FAILED",
        "users",
        { email }
      );

      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_CREDENTIALS"
      );
    }

    // Xóa session cũ của cookie hiện tại.
    const oldToken =
      getSessionCookie(request);

    if (oldToken) {
      await destroySession(
        env,
        oldToken
      );
    }

    const token =
      await createSession(
        env,
        user.id
      );

    await audit(
      env,
      user.id,
      "LOGIN",
      "users",
      { email }
    );

    return ok(
      {
        message: "Đăng nhập thành công.",
        user: {
          id: user.id,
          email: user.email,
          role: user.role || "PLAYER"
        }
      },
      200,
      {
        "set-cookie":
          makeSessionCookie(token)
      }
    );
  } catch (error) {
    return fail(
      `Không thể đăng nhập: ${error.message}`,
      500,
      "LOGIN_FAILED"
    );
  }
}

// ============================================================
// AUTH: ME
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
      `Không thể kiểm tra phiên đăng nhập: ${error.message}`,
      500,
      "ME_FAILED"
    );
  }
}

// ============================================================
// AUTH: LOGOUT
// ============================================================

async function logout(request, env) {
  try {
    const token =
      getSessionCookie(request);

    if (token) {
      const user =
        await getCurrentUser(
          request,
          env
        );

      await destroySession(
        env,
        token
      );

      if (user) {
        await audit(
          env,
          user.id,
          "LOGOUT",
          "users",
          { email: user.email }
        );
      }
    }

    return ok(
      {
        message: "Đã đăng xuất."
      },
      200,
      {
        "set-cookie":
          clearSessionCookie()
      }
    );
  } catch (error) {
    return fail(
      `Không thể đăng xuất: ${error.message}`,
      500,
      "LOGOUT_FAILED"
    );
  }
}

// ============================================================
// PUBLIC: TOURNAMENTS
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
      `Không thể tải giải đấu: ${error.message}`,
      500,
      "TOURNAMENTS_FAILED"
    );
  }
}

// ============================================================
// PUBLIC: RANKING
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
        ORDER BY points DESC, kills DESC, t.id ASC
        LIMIT 100
      `)
      .all();

    return ok({
      ranking:
        result.results || []
    });
  } catch (error) {
    return fail(
      `Không thể tải bảng xếp hạng: ${error.message}`,
      500,
      "RANKING_FAILED"
    );
  }
}

// ============================================================
// ADMIN CHECK
// ============================================================

async function requireAdmin(request, env) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return {
      ok: false,
      response: fail(
        "Bạn chưa đăng nhập.",
        401,
        "UNAUTHORIZED"
      )
    };
  }

  const role =
    String(user.role || "")
      .toUpperCase();

  if (
    role !== "ADMIN" &&
    role !== "SUPER_ADMIN"
  ) {
    return {
      ok: false,
      response: fail(
        "Bạn không có quyền quản trị.",
        403,
        "FORBIDDEN"
      )
    };
  }

  return {
    ok: true,
    user
  };
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
      `Database error: ${error.message}`,
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

async function tableData(request, env) {
  const url = new URL(request.url);

  const table =
    url.searchParams.get("name");

  if (!table) {
    return fail(
      "Thiếu tên bảng.",
      400,
      "MISSING_TABLE"
    );
  }

  if (!/^[A-Za-z0-9_]+$/.test(table)) {
    return fail(
      "Tên bảng không hợp lệ.",
      400,
      "INVALID_TABLE"
    );
  }

  try {
    const exists = await env.DB
      .prepare(`
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        LIMIT 1
      `)
      .bind(table)
      .first();

    if (!exists) {
      return fail(
        "Bảng không tồn tại.",
        404,
        "TABLE_NOT_FOUND"
      );
    }

    const result = await env.DB
      .prepare(
        `SELECT * FROM ${quoteIdentifier(table)} LIMIT 100`
      )
      .all();

    return ok({
      table,
      rows:
        result.results || []
    });
  } catch (error) {
    return fail(
      error.message,
      500,
      "TABLE_FAILED"
    );
  }
}

// ============================================================
// MAIN ROUTER
// ============================================================

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    const method =
      request.method.toUpperCase();

    try {
      // ------------------------------------------------------
      // CORS / OPTIONS
      // ------------------------------------------------------

      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "access-control-allow-origin":
              url.origin,
            "access-control-allow-methods":
              "GET,POST,OPTIONS",
            "access-control-allow-headers":
              "content-type"
          }
        });
      }

      // ------------------------------------------------------
      // HEALTH
      // ------------------------------------------------------

      if (
        url.pathname === "/api/health" &&
        method === "GET"
      ) {
        return await health(env);
      }

      // ------------------------------------------------------
      // TABLES
      // ------------------------------------------------------

      if (
        url.pathname === "/api/tables" &&
        method === "GET"
      ) {
        return await tables(env);
      }

      // ------------------------------------------------------
      // TABLE
      // ------------------------------------------------------

      if (
        url.pathname === "/api/table" &&
        method === "GET"
      ) {
        return await tableData(
          request,
          env
        );
      }

      // ------------------------------------------------------
      // REGISTER
      // ------------------------------------------------------

      if (
        url.pathname === "/api/auth/register" &&
        method === "POST"
      ) {
        return await register(
          request,
          env
        );
      }

      // ------------------------------------------------------
      // LOGIN
      // ------------------------------------------------------

      if (
        url.pathname === "/api/auth/login" &&
        method === "POST"
      ) {
        return await login(
          request,
          env
        );
      }

      // ------------------------------------------------------
      // ME
      // ------------------------------------------------------

      if (
        url.pathname === "/api/auth/me" &&
        method === "GET"
      ) {
        return await me(
          request,
          env
        );
      }

      // ------------------------------------------------------
      // LOGOUT
      // ------------------------------------------------------

      if (
        url.pathname === "/api/auth/logout" &&
        method === "POST"
      ) {
        return await logout(
          request,
          env
        );
      }

      // ------------------------------------------------------
      // TOURNAMENTS
      // ------------------------------------------------------

      if (
        url.pathname === "/api/tournaments" &&
        method === "GET"
      ) {
        return await tournaments(env);
      }

      // ------------------------------------------------------
      // RANKING
      // ------------------------------------------------------

      if (
        url.pathname === "/api/ranking" &&
        method === "GET"
      ) {
        return await ranking(env);
      }

      // ------------------------------------------------------
      // ADMIN CHECK
      // ------------------------------------------------------

      if (
        url.pathname === "/api/admin/me" &&
        method === "GET"
      ) {
        const auth =
          await requireAdmin(
            request,
            env
          );

        if (!auth.ok) {
          return auth.response;
        }

        return ok({
          user: auth.user
        });
      }

      // ------------------------------------------------------
      // ASSETS
      // ------------------------------------------------------

      if (env.ASSETS) {
        return env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "CUSTOM 151 • Worker Online",
        {
          headers: {
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );
    } catch (error) {
      return fail(
        `Server error: ${error.message}`,
        500,
        "INTERNAL_ERROR"
      );
    }
  }
};
