/*
============================================================
 CUSTOM 151 - CLOUDFLARE WORKER + D1
 AUTH / REGISTER / LOGIN / SESSION / ACCOUNT
============================================================

- Không cần package ngoài
- Không cần password_salt
- Hash password bằng Web Crypto PBKDF2
- Hash có salt riêng nằm bên trong password_hash
- Tương thích users có/không có password_salt
- Tương thích role CHECK khác nhau
- Tương thích sessions token / session_token / session_id...
- Cookie HttpOnly
- Session 7 ngày
============================================================
*/

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const PASSWORD_MIN_LENGTH = 8;
const SESSION_COOKIE = "session";

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
    throw new Error("Dữ liệu gửi lên không hợp lệ.");
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
    password.length >= PASSWORD_MIN_LENGTH
  );
}

// ============================================================
// RANDOM
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
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ============================================================
// PASSWORD HASH - WEB CRYPTO
// ============================================================

async function derivePasswordHash(password, saltBytes, iterations) {
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
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return new Uint8Array(derived);
}

async function hashPassword(password) {
  const salt = randomBytes(16);

  const hash = await derivePasswordHash(
    password,
    salt,
    PBKDF2_ITERATIONS
  );

  /*
    Format:

    pbkdf2$100000$SALT$HASH
  */

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(hash)
  ].join("$");
}

function constantTimeEqual(a, b) {
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

  if (algorithm !== "pbkdf2") {
    return false;
  }

  if (!Number.isInteger(iterations) || iterations <= 0) {
    return false;
  }

  try {
    const salt = base64ToBytes(saltString);
    const expected = base64ToBytes(hashString);

    const actual = await derivePasswordHash(
      password,
      salt,
      iterations
    );

    return constantTimeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ============================================================
// DATABASE SCHEMA DETECTION
// ============================================================

async function getColumns(env, table) {
  const result = await env.DB
    .prepare(
      `
      SELECT
        name,
        type,
        notnull,
        dflt_value,
        pk
      FROM pragma_table_info(?)
      `
    )
    .bind(table)
    .all();

  return result.results || [];
}

async function getTableSQL(env, table) {
  const row = await env.DB
    .prepare(
      `
      SELECT sql
      FROM sqlite_master
      WHERE type = 'table'
      AND name = ?
      LIMIT 1
      `
    )
    .bind(table)
    .first();

  return row?.sql || "";
}

// ============================================================
// USERS SCHEMA
// ============================================================

async function getUsersSchema(env) {
  const columns = await getColumns(env, "users");

  const names = new Set(
    columns.map(c => String(c.name).toLowerCase())
  );

  const emailColumn =
    names.has("email")
      ? "email"
      : null;

  const passwordColumn =
    names.has("password_hash")
      ? "password_hash"
      : names.has("password")
        ? "password"
        : null;

  const roleColumn =
    names.has("role")
      ? "role"
      : null;

  const idColumn =
    names.has("id")
      ? "id"
      : null;

  /*
    password_salt nếu DB cũ còn có cũng được.
    Code KHÔNG dùng nó để verify password.
    Nếu nó là NOT NULL thì register sẽ điền chuỗi rỗng.
  */

  const saltColumn =
    names.has("password_salt")
      ? "password_salt"
      : null;

  return {
    columns,
    names,
    emailColumn,
    passwordColumn,
    roleColumn,
    idColumn,
    saltColumn
  };
}

// ============================================================
// ROLE CHECK COMPATIBILITY
// ============================================================

function extractAllowedRoles(sql) {
  const text = String(sql || "")
    .toUpperCase()
    .replace(/\s+/g, " ");

  const result = new Set();

  /*
    Ví dụ:

    CHECK(role IN ('PLAYER','ADMIN','SUPER_ADMIN'))

    hoặc

    CHECK (role IN ("USER","ADMIN"))
  */

  const matches = text.matchAll(
    /ROLE\s+IN\s*\(([^)]*)\)/g
  );

  for (const match of matches) {
    const inside = match[1];

    const roles = inside.match(
      /['"]([A-Z_]+)['"]/g
    ) || [];

    for (const role of roles) {
      result.add(
        role.replace(/['"]/g, "")
      );
    }
  }

  return result;
}

async function chooseUserRole(env) {
  const sql = await getTableSQL(env, "users");
  const allowed = extractAllowedRoles(sql);

  /*
    Ưu tiên USER vì schema chuẩn của hệ thống.
  */

  if (allowed.size === 0) {
    return "USER";
  }

  if (allowed.has("USER")) {
    return "USER";
  }

  /*
    DB cũ của bạn có CHECK:
    PLAYER / ADMIN / SUPER_ADMIN
  */

  if (allowed.has("PLAYER")) {
    return "PLAYER";
  }

  if (allowed.has("ADMIN")) {
    return "ADMIN";
  }

  if (allowed.has("SUPER_ADMIN")) {
    return "SUPER_ADMIN";
  }

  return [...allowed][0];
}

// ============================================================
// SESSION SCHEMA
// ============================================================

async function getSessionsSchema(env) {
  const columns = await getColumns(env, "sessions");

  const names = new Set(
    columns.map(c => String(c.name).toLowerCase())
  );

  const find = (...candidates) => {
    for (const name of candidates) {
      if (names.has(name)) {
        return name;
      }
    }

    return null;
  };

  return {
    columns,
    tokenColumn: find(
      "token",
      "session_token",
      "session_id",
      "auth_token"
    ),
    userIdColumn: find(
      "user_id",
      "userid",
      "user"
    ),
    expiresColumn: find(
      "expires_at",
      "expires",
      "expired_at"
    )
  };
}

// ============================================================
// COOKIE
// ============================================================

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part
      .slice(0, index)
      .trim();

    const value = part
      .slice(index + 1)
      .trim();

    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function getSessionToken(request) {
  const cookies = parseCookies(request);
  return cookies[SESSION_COOKIE] || null;
}

function sessionCookie(token, maxAge) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${maxAge}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function clearSessionCookie() {
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
// SESSION CREATE
// ============================================================

async function createSession(env, userId) {
  const schema = await getSessionsSchema(env);

  if (
    !schema.tokenColumn ||
    !schema.userIdColumn ||
    !schema.expiresColumn
  ) {
    throw new Error(
      "Bảng sessions hiện tại thiếu cột session cần thiết (token/session_token, user_id hoặc expires_at)."
    );
  }

  const token = bytesToBase64(randomBytes(32));

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  const sql = `
    INSERT INTO sessions
    ("${schema.tokenColumn}", "${schema.userIdColumn}", "${schema.expiresColumn}")
    VALUES (?, ?, ?)
  `;

  await env.DB
    .prepare(sql)
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
// CURRENT USER
// ============================================================

async function getCurrentUser(request, env) {
  const token = getSessionToken(request);

  if (!token) {
    return null;
  }

  const sessionSchema = await getSessionsSchema(env);
  const usersSchema = await getUsersSchema(env);

  if (
    !sessionSchema.tokenColumn ||
    !sessionSchema.userIdColumn ||
    !sessionSchema.expiresColumn ||
    !usersSchema.idColumn
  ) {
    return null;
  }

  const now =
    Math.floor(Date.now() / 1000);

  const sql = `
    SELECT
      u.id,
      u.email,
      ${usersSchema.roleColumn ? `u."${usersSchema.roleColumn}"` : `'USER'`} AS role
    FROM sessions s
    JOIN users u
      ON u."${usersSchema.idColumn}" =
         s."${sessionSchema.userIdColumn}"
    WHERE s."${sessionSchema.tokenColumn}" = ?
      AND s."${sessionSchema.expiresColumn}" > ?
    LIMIT 1
  `;

  return await env.DB
    .prepare(sql)
    .bind(token, now)
    .first();
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
      .prepare(
        `
        INSERT INTO audit_logs
        (user_id, action, target, details)
        VALUES (?, ?, ?, ?)
        `
      )
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
    /*
      Audit không được phép làm hỏng login/register.
    */
  }
}

// ============================================================
// REGISTER
// ============================================================

async function register(request, env) {
  const data = await bodyJSON(request);

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
      `Mật khẩu phải có ít nhất ${PASSWORD_MIN_LENGTH} ký tự.`,
      400,
      "WEAK_PASSWORD"
    );
  }

  const schema = await getUsersSchema(env);

  if (
    !schema.idColumn ||
    !schema.emailColumn ||
    !schema.passwordColumn
  ) {
    return fail(
      "Cấu trúc bảng users không tương thích.",
      500,
      "USERS_SCHEMA_ERROR"
    );
  }

  /*
    Kiểm tra email tồn tại
  */

  const existing = await env.DB
    .prepare(
      `
      SELECT "${schema.idColumn}" AS id
      FROM users
      WHERE LOWER("${schema.emailColumn}") = ?
      LIMIT 1
      `
    )
    .bind(email)
    .first();

  if (existing) {
    return fail(
      "Email này đã được đăng ký.",
      409,
      "EMAIL_EXISTS"
    );
  }

  const passwordHash =
    await hashPassword(password);

  const role =
    schema.roleColumn
      ? await chooseUserRole(env)
      : null;

  /*
    Xây INSERT dựa trên schema thật.

    password_salt:
    - Nếu DB không có -> bỏ qua.
    - Nếu DB có NOT NULL -> ghi chuỗi rỗng.
      Hash thật vẫn nằm trong password_hash.
  */

  const insertColumns = [];
  const insertValues = [];

  insertColumns.push(
    `"${schema.emailColumn}"`
  );

  insertValues.push(email);

  insertColumns.push(
    `"${schema.passwordColumn}"`
  );

  insertValues.push(passwordHash);

  if (schema.roleColumn) {
    insertColumns.push(
      `"${schema.roleColumn}"`
    );

    insertValues.push(role);
  }

  if (schema.saltColumn) {
    const saltInfo =
      schema.columns.find(
        c =>
          String(c.name).toLowerCase() ===
          "password_salt"
      );

    /*
      Không sử dụng salt này.
      Chỉ điền rỗng nếu DB cũ bắt NOT NULL.
    */

    if (saltInfo?.notnull) {
      insertColumns.push(
        `"${schema.saltColumn}"`
      );

      insertValues.push("");
    }
  }

  const placeholders =
    insertValues.map(() => "?").join(", ");

  const sql = `
    INSERT INTO users
    (${insertColumns.join(", ")})
    VALUES (${placeholders})
  `;

  try {
    const result = await env.DB
      .prepare(sql)
      .bind(...insertValues)
      .run();

    const userId =
      result.meta?.last_row_id ?? null;

    await audit(
      env,
      userId,
      "REGISTER",
      "users",
      { email }
    );

    /*
      REGISTER KHÔNG tự login.
      Đăng ký xong frontend sẽ mở form ĐĂNG NHẬP.
    */

    return ok(
      {
        message:
          "Tạo tài khoản thành công. Hãy đăng nhập.",
        user: {
          id: userId,
          email,
          role: role || "USER"
        }
      },
      201
    );
  } catch (error) {
    const message =
      String(error?.message || "");

    /*
      Race-condition UNIQUE
    */

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

    return fail(
      `Không thể tạo tài khoản: ${message}`,
      500,
      "REGISTER_ERROR"
    );
  }
}

// ============================================================
// LOGIN
// ============================================================

async function login(request, env) {
  const data = await bodyJSON(request);

  const email = cleanEmail(data.email);
  const password = data.password;

  if (!validEmail(email)) {
    return fail(
      "Email không hợp lệ.",
      400,
      "INVALID_EMAIL"
    );
  }

  if (
    typeof password !== "string" ||
    !password
  ) {
    return fail(
      "Vui lòng nhập mật khẩu.",
      400,
      "PASSWORD_REQUIRED"
    );
  }

  const schema =
    await getUsersSchema(env);

  if (
    !schema.idColumn ||
    !schema.emailColumn ||
    !schema.passwordColumn
  ) {
    return fail(
      "Cấu trúc bảng users không tương thích.",
      500,
      "USERS_SCHEMA_ERROR"
    );
  }

  const user = await env.DB
    .prepare(
      `
      SELECT
        "${schema.idColumn}" AS id,
        "${schema.emailColumn}" AS email,
        "${schema.passwordColumn}" AS password_hash
        ${
          schema.roleColumn
            ? `, "${schema.roleColumn}" AS role`
            : `, 'USER' AS role`
        }
      FROM users
      WHERE LOWER("${schema.emailColumn}") = ?
      LIMIT 1
      `
    )
    .bind(email)
    .first();

  /*
    Không tiết lộ email có tồn tại hay không.
  */

  if (!user) {
    return fail(
      "Email hoặc mật khẩu không đúng.",
      401,
      "INVALID_CREDENTIALS"
    );
  }

  const passwordOK =
    await verifyPassword(
      password,
      user.password_hash
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
      "Email hoặc mật khẩu không đúng.",
      401,
      "INVALID_CREDENTIALS"
    );
  }

  /*
    Xóa session cũ của chính user
    để tránh tạo quá nhiều session.
  */

  try {
    const sessionSchema =
      await getSessionsSchema(env);

    if (
      sessionSchema.userIdColumn
    ) {
      await env.DB
        .prepare(
          `
          DELETE FROM sessions
          WHERE "${sessionSchema.userIdColumn}" = ?
          `
        )
        .bind(user.id)
        .run();
    }
  } catch {
    /*
      Không chặn login nếu cleanup fail.
    */
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
    "users",
    { email: user.email }
  );

  return ok(
    {
      message: "Đăng nhập thành công.",
      user: {
        id: user.id,
        email: user.email,
        role: user.role || "USER"
      }
    },
    200,
    {
      "set-cookie": sessionCookie(
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

  return ok({
    authenticated: !!user,
    user: user || null
  });
}

// ============================================================
// LOGOUT
// ============================================================

async function logout(request, env) {
  const token =
    getSessionToken(request);

  const user =
    await getCurrentUser(
      request,
      env
    );

  if (token) {
    try {
      const schema =
        await getSessionsSchema(env);

      if (schema.tokenColumn) {
        await env.DB
          .prepare(
            `
            DELETE FROM sessions
            WHERE "${schema.tokenColumn}" = ?
            `
          )
          .bind(token)
          .run();
      }
    } catch {
      /*
        Cookie vẫn được clear.
      */
    }
  }

  if (user) {
    await audit(
      env,
      user.id,
      "LOGOUT",
      "users",
      { email: user.email }
    );
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
}

// ============================================================
// HEALTH
// ============================================================

async function health(env) {
  try {
    const result =
      await env.DB
        .prepare(
          "SELECT 1 AS ok"
        )
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
    const result =
      await env.DB
        .prepare(
          `
          SELECT name
          FROM sqlite_master
          WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
          ORDER BY name
          `
        )
        .all();

    return ok({
      tables:
        result.results || []
    });
  } catch (error) {
    return fail(
      error.message,
      500,
      "TABLES_ERROR"
    );
  }
}

// ============================================================
// TABLE DATA
// ============================================================

async function table(request, env) {
  const url =
    new URL(request.url);

  const tableName =
    url.searchParams.get("name");

  if (!tableName) {
    return fail(
      "Thiếu tên bảng.",
      400,
      "MISSING_TABLE"
    );
  }

  if (
    !/^[A-Za-z0-9_]+$/.test(
      tableName
    )
  ) {
    return fail(
      "Tên bảng không hợp lệ.",
      400,
      "INVALID_TABLE"
    );
  }

  try {
    const result =
      await env.DB
        .prepare(
          `SELECT * FROM "${tableName}" LIMIT 100`
        )
        .all();

    return ok({
      table: tableName,
      rows:
        result.results || []
    });
  } catch (error) {
    return fail(
      error.message,
      500,
      "TABLE_ERROR"
    );
  }
}

// ============================================================
// TOURNAMENTS
// ============================================================

async function tournaments(env) {
  try {
    const result =
      await env.DB
        .prepare(
          `
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
          `
        )
        .all();

    return ok({
      tournaments:
        result.results || []
    });
  } catch (error) {
    return fail(
      error.message,
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
    const result =
      await env.DB
        .prepare(
          `
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
          `
        )
        .all();

    return ok({
      ranking:
        result.results || []
    });
  } catch (error) {
    return fail(
      error.message,
      500,
      "RANKING_ERROR"
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
      // --------------------------
      // HEALTH
      // --------------------------

      if (
        url.pathname === "/api/health" &&
        method === "GET"
      ) {
        return await health(env);
      }

      // --------------------------
      // TABLES
      // --------------------------

      if (
        url.pathname === "/api/tables" &&
        method === "GET"
      ) {
        return await tables(env);
      }

      // --------------------------
      // TABLE
      // --------------------------

      if (
        url.pathname === "/api/table" &&
        method === "GET"
      ) {
        return await table(
          request,
          env
        );
      }

      // --------------------------
      // REGISTER
      // --------------------------

      if (
        url.pathname === "/api/auth/register" &&
        method === "POST"
      ) {
        return await register(
          request,
          env
        );
      }

      // --------------------------
      // LOGIN
      // --------------------------

      if (
        url.pathname === "/api/auth/login" &&
        method === "POST"
      ) {
        return await login(
          request,
          env
        );
      }

      // --------------------------
      // CURRENT ACCOUNT
      // --------------------------

      if (
        url.pathname === "/api/auth/me" &&
        method === "GET"
      ) {
        return await me(
          request,
          env
        );
      }

      // --------------------------
      // LOGOUT
      // --------------------------

      if (
        url.pathname === "/api/auth/logout" &&
        method === "POST"
      ) {
        return await logout(
          request,
          env
        );
      }

      // --------------------------
      // TOURNAMENTS
      // --------------------------

      if (
        url.pathname === "/api/tournaments" &&
        method === "GET"
      ) {
        return await tournaments(
          env
        );
      }

      // --------------------------
      // RANKING
      // --------------------------

      if (
        url.pathname === "/api/ranking" &&
        method === "GET"
      ) {
        return await ranking(
          env
        );
      }

      // --------------------------
      // API 404
      // --------------------------

      if (
        url.pathname.startsWith("/api/")
      ) {
        return fail(
          "API không tồn tại.",
          404,
          "NOT_FOUND"
        );
      }

      // --------------------------
      // STATIC WEBSITE
      // --------------------------

      if (env.ASSETS) {
        return env.ASSETS.fetch(
          request
        );
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
          "Lỗi máy chủ.",
        500,
        "SERVER_ERROR"
      );
    }
  }
};
