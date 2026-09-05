const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const SESSION_COOKIE = "vtt_session";
const SESSION_SECRET_NAME = "SESSION_SECRET";

const encoder = new TextEncoder();

/* =========================================================
   RESPONSE
========================================================= */

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

function fail(message, status = 400, code = "ERROR") {
  return json({
    success: false,
    code,
    message
  }, status);
}

/* =========================================================
   BASIC HELPERS
========================================================= */

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanUsername(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validUsername(username) {
  return (
    username.length >= 3 &&
    username.length <= 40 &&
    /^[\p{L}\p{N}_. -]+$/u.test(username)
  );
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

function randomBytes(size) {
  const bytes = new Uint8Array(size);
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

function safeJsonParse(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

async function bodyJSON(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/* =========================================================
   PASSWORD - CLOUDFLARE WEB CRYPTO
========================================================= */

async function derivePasswordHash(password, salt, iterations = PBKDF2_ITERATIONS) {
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

  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = randomBytes(16);

  const hash = await derivePasswordHash(
    password,
    salt,
    PBKDF2_ITERATIONS
  );

  return {
    hash: bytesToBase64(hash),
    salt: bytesToBase64(salt),
    iterations: PBKDF2_ITERATIONS
  };
}

function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

async function verifyPassword(password, storedHash, storedSalt, iterations = PBKDF2_ITERATIONS) {
  try {
    if (!storedHash || !storedSalt) {
      return false;
    }

    const salt = base64ToBytes(storedSalt);

    let expected;

    /*
      Hỗ trợ cả:
      1. hash base64 thuần
      2. PBKDF2$iterations$salt$hash
      để không làm hỏng account cũ.
    */

    const hashString = String(storedHash);

    if (hashString.startsWith("PBKDF2$")) {
      const parts = hashString.split("$");

      if (parts.length !== 4) {
        return false;
      }

      iterations = Number(parts[1]);

      if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100000) {
        return false;
      }

      expected = base64ToBytes(parts[3]);
    } else {
      expected = base64ToBytes(hashString);
    }

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

/* =========================================================
   DB SCHEMA HELPERS
========================================================= */

async function tableExists(env, tableName) {
  try {
    const result = await env.DB
      .prepare(`
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        LIMIT 1
      `)
      .bind(tableName)
      .first();

    return !!result;
  } catch {
    return false;
  }
}

async function getTableColumns(env, tableName) {
  if (!/^[A-Za-z0-9_]+$/.test(tableName)) {
    return [];
  }

  try {
    const result = await env.DB
      .prepare(`PRAGMA table_info("${tableName}")`)
      .all();

    return result.results || [];
  } catch {
    return [];
  }
}

function columnNames(columns) {
  return new Set(columns.map(c => String(c.name)));
}

function pickColumn(columns, candidates) {
  const names = columnNames(columns);

  for (const candidate of candidates) {
    if (names.has(candidate)) {
      return candidate;
    }
  }

  return null;
}

function isRequiredColumn(column) {
  return Number(column.notnull) === 1 && column.dflt_value == null;
}

function hasColumn(columns, name) {
  return columns.some(c => c.name === name);
}

/* =========================================================
   USERS SCHEMA
========================================================= */

async function getUsersSchema(env) {
  const exists = await tableExists(env, "users");

  if (!exists) {
    throw new Error("Database chưa có bảng users.");
  }

  const columns = await getTableColumns(env, "users");

  if (!columns.length) {
    throw new Error("Không đọc được cấu trúc bảng users.");
  }

  return columns;
}

function resolveUserColumns(columns) {
  return {
    id: pickColumn(columns, [
      "id",
      "user_id"
    ]),

    username: pickColumn(columns, [
      "username",
      "account_name",
      "account",
      "user_name",
      "display_name",
      "name"
    ]),

    email: pickColumn(columns, [
      "email",
      "mail"
    ]),

    passwordHash: pickColumn(columns, [
      "password_hash",
      "password"
    ]),

    passwordSalt: pickColumn(columns, [
      "password_salt",
      "salt"
    ]),

    role: pickColumn(columns, [
      "role",
      "user_role"
    ]),

    balance: pickColumn(columns, [
      "balance",
      "wallet_balance",
      "money",
      "credits"
    ]),

    createdAt: pickColumn(columns, [
      "created_at",
      "created",
      "registered_at"
    ]),

    updatedAt: pickColumn(columns, [
      "updated_at",
      "updated"
    ])
  };
}

/* =========================================================
   SQL INSERT BUILDER
========================================================= */

function quoteIdentifier(name) {
  if (!/^[A-Za-z0-9_]+$/.test(name)) {
    throw new Error("Tên cột không hợp lệ.");
  }

  return `"${name}"`;
}

function buildInsert(table, values) {
  const keys = Object.keys(values);

  const columns = keys.map(quoteIdentifier).join(", ");
  const placeholders = keys.map(() => "?").join(", ");

  return {
    sql: `INSERT INTO ${quoteIdentifier(table)} (${columns}) VALUES (${placeholders})`,
    bindings: keys.map(key => values[key])
  };
}

/* =========================================================
   USER LOOKUP
========================================================= */

async function findUserByEmail(env, email) {
  const columns = await getUsersSchema(env);
  const map = resolveUserColumns(columns);

  if (!map.email) {
    throw new Error("Bảng users không có cột email.");
  }

  const selectColumns = columns
    .map(c => quoteIdentifier(c.name))
    .join(", ");

  const row = await env.DB
    .prepare(`
      SELECT ${selectColumns}
      FROM users
      WHERE lower(${quoteIdentifier(map.email)}) = lower(?)
      LIMIT 1
    `)
    .bind(email)
    .first();

  return {
    row,
    columns,
    map
  };
}

async function findUserById(env, id) {
  const columns = await getUsersSchema(env);
  const map = resolveUserColumns(columns);

  if (!map.id) {
    return {
      row: null,
      columns,
      map
    };
  }

  const selectColumns = columns
    .map(c => quoteIdentifier(c.name))
    .join(", ");

  const row = await env.DB
    .prepare(`
      SELECT ${selectColumns}
      FROM users
      WHERE ${quoteIdentifier(map.id)} = ?
      LIMIT 1
    `)
    .bind(id)
    .first();

  return {
    row,
    columns,
    map
  };
}

/* =========================================================
   SESSION COOKIE - WEB CRYPTO HMAC
========================================================= */

async function getSessionSecret(env) {
  if (env[SESSION_SECRET_NAME]) {
    return String(env[SESSION_SECRET_NAME]);
  }

  /*
    Fallback để project vẫn chạy ngay.
    Khuyến nghị thêm SESSION_SECRET trong Cloudflare Variables.
  */
  if (env.SITE_NAME) {
    return `${env.SITE_NAME}|vua-tu-chien-session-secret`;
  }

  return "vua-tu-chien-session-secret";
}

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value)
  );

  return bytesToBase64(new Uint8Array(signature))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function createSessionCookie(userId, env) {
  const payload = {
    uid: String(userId),
    exp: Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400,
    iat: Math.floor(Date.now() / 1000)
  };

  const body = bytesToBase64(
    encoder.encode(JSON.stringify(payload))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  const secret = await getSessionSecret(env);
  const signature = await hmacSign(body, secret);

  return `${body}.${signature}`;
}

async function verifySessionCookie(cookie, env) {
  try {
    if (!cookie || !cookie.includes(".")) {
      return null;
    }

    const [body, signature] = cookie.split(".");

    if (!body || !signature) {
      return null;
    }

    const secret = await getSessionSecret(env);
    const expected = await hmacSign(body, secret);

    if (expected !== signature) {
      return null;
    }

    const padded = body
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(Math.ceil(body.length / 4) * 4, "=");

    const decoded = new TextDecoder().decode(
      Uint8Array.from(atob(padded), c => c.charCodeAt(0))
    );

    const payload = JSON.parse(decoded);

    if (!payload.uid || !payload.exp) {
      return null;
    }

    if (Number(payload.exp) < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie");

  if (!header) {
    return null;
  }

  const cookies = header.split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function sessionHeader(value, maxAge = SESSION_DAYS * 86400) {
  return {
    "Set-Cookie":
      `${SESSION_COOKIE}=${encodeURIComponent(value)}; ` +
      `Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`
  };
}

function clearSessionHeader() {
  return {
    "Set-Cookie":
      `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
  };
}

/* =========================================================
   CURRENT USER
========================================================= */

async function getCurrentUser(request, env) {
  const cookie = getCookie(request, SESSION_COOKIE);

  if (!cookie) {
    return null;
  }

  const session = await verifySessionCookie(cookie, env);

  if (!session) {
    return null;
  }

  const result = await findUserById(env, session.uid);

  if (!result.row) {
    return null;
  }

  const user = result.row;
  const map = result.map;

  return {
    id: map.id ? user[map.id] : session.uid,
    username: map.username ? user[map.username] : "",
    email: map.email ? user[map.email] : "",
    role: map.role ? user[map.role] : "PLAYER",
    balance: map.balance ? Number(user[map.balance] || 0) : 0
  };
}

/* =========================================================
   OPTIONAL AUDIT
========================================================= */

async function audit(env, action, userId = null, details = null) {
  try {
    const exists = await tableExists(env, "audit_logs");

    if (!exists) {
      return;
    }

    const columns = await getTableColumns(env, "audit_logs");
    const values = {};

    const actionColumn = pickColumn(columns, [
      "action",
      "event",
      "type"
    ]);

    const userColumn = pickColumn(columns, [
      "user_id",
      "userid"
    ]);

    const detailsColumn = pickColumn(columns, [
      "details",
      "metadata",
      "data",
      "description"
    ]);

    const createdColumn = pickColumn(columns, [
      "created_at",
      "created"
    ]);

    if (actionColumn) {
      values[actionColumn] = action;
    }

    if (userColumn && userId != null) {
      values[userColumn] = userId;
    }

    if (detailsColumn) {
      values[detailsColumn] =
        typeof details === "string"
          ? details
          : JSON.stringify(details || {});
    }

    if (createdColumn) {
      values[createdColumn] = new Date().toISOString();
    }

    if (!Object.keys(values).length) {
      return;
    }

    const insert = buildInsert("audit_logs", values);

    await env.DB
      .prepare(insert.sql)
      .bind(...insert.bindings)
      .run();
  } catch {
    /*
      Audit không bao giờ được phép làm
      register/login thất bại.
    */
  }
}

/* =========================================================
   REGISTER
========================================================= */

async function register(request, env) {
  const data = await bodyJSON(request);

  if (!data) {
    return fail("Dữ liệu đăng ký không hợp lệ.", 400, "INVALID_JSON");
  }

  const username = cleanUsername(data.username);
  const email = cleanEmail(data.email);
  const password = String(data.password || "");
  const passwordConfirm = String(
    data.passwordConfirm ??
    data.confirmPassword ??
    data.password_confirmation ??
    ""
  );

  if (!username) {
    return fail("Vui lòng nhập tên tài khoản.", 400, "USERNAME_REQUIRED");
  }

  if (!validUsername(username)) {
    return fail(
      "Tên tài khoản phải từ 3–40 ký tự và chỉ gồm chữ, số, khoảng trắng, dấu . _ -.",
      400,
      "INVALID_USERNAME"
    );
  }

  if (!email || !validEmail(email)) {
    return fail("Email không hợp lệ.", 400, "INVALID_EMAIL");
  }

  if (!validPassword(password)) {
    return fail(
      "Mật khẩu phải có ít nhất 8 ký tự.",
      400,
      "WEAK_PASSWORD"
    );
  }

  if (passwordConfirm && password !== passwordConfirm) {
    return fail(
      "Mật khẩu nhập lại không trùng khớp.",
      400,
      "PASSWORD_MISMATCH"
    );
  }

  let schema;

  try {
    schema = await getUsersSchema(env);
  } catch (error) {
    return fail(error.message, 500, "USERS_SCHEMA_ERROR");
  }

  const map = resolveUserColumns(schema);

  if (!map.email) {
    return fail(
      "Database users chưa có cột email.",
      500,
      "EMAIL_COLUMN_MISSING"
    );
  }

  if (!map.passwordHash) {
    return fail(
      "Database users chưa có cột password_hash/password.",
      500,
      "PASSWORD_HASH_COLUMN_MISSING"
    );
  }

  if (!map.passwordSalt) {
    return fail(
      "Database users bắt buộc password_salt nhưng code không tìm thấy cột này.",
      500,
      "PASSWORD_SALT_COLUMN_MISSING"
    );
  }

  if (!map.username) {
    return fail(
      "Database users chưa có cột tên tài khoản.",
      500,
      "USERNAME_COLUMN_MISSING"
    );
  }

  try {
    /* ---------------------------------------------
       EMAIL EXISTS
    --------------------------------------------- */

    const existingEmail = await env.DB
      .prepare(`
        SELECT ${quoteIdentifier(map.email)}
        FROM users
        WHERE lower(${quoteIdentifier(map.email)}) = lower(?)
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (existingEmail) {
      return fail(
        "Email này đã được đăng ký.",
        409,
        "EMAIL_EXISTS"
      );
    }

    /* ---------------------------------------------
       USERNAME EXISTS
    --------------------------------------------- */

    const existingUsername = await env.DB
      .prepare(`
        SELECT ${quoteIdentifier(map.username)}
        FROM users
        WHERE lower(${quoteIdentifier(map.username)}) = lower(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

    if (existingUsername) {
      return fail(
        "Tên tài khoản này đã tồn tại.",
        409,
        "USERNAME_EXISTS"
      );
    }

    /* ---------------------------------------------
       PASSWORD
    --------------------------------------------- */

    const passwordData = await hashPassword(password);

    const values = {};

    values[map.username] = username;
    values[map.email] = email;
    values[map.passwordHash] = passwordData.hash;
    values[map.passwordSalt] = passwordData.salt;

    /*
      DB hiện tại có CHECK:
      role IN ('PLAYER','ADMIN','SUPER_ADMIN')

      Vì vậy đăng ký người dùng bình thường
      luôn phải là PLAYER.
    */

    if (map.role) {
      values[map.role] = "PLAYER";
    }

    if (map.balance) {
      values[map.balance] = 0;
    }

    if (map.createdAt) {
      values[map.createdAt] = new Date().toISOString();
    }

    if (map.updatedAt) {
      values[map.updatedAt] = new Date().toISOString();
    }

    /*
      Kiểm tra các cột NOT NULL còn lại.
      Chỉ báo lỗi nếu DB thật sự yêu cầu một cột
      mà chúng ta không thể tự điền.
    */

    const supported = new Set(Object.keys(values));

    for (const column of schema) {
      if (
        isRequiredColumn(column) &&
        !supported.has(column.name)
      ) {
        return fail(
          `Database yêu cầu cột "${column.name}" nhưng code chưa có dữ liệu phù hợp.`,
          500,
          "REQUIRED_COLUMN_MISSING"
        );
      }
    }

    const insert = buildInsert("users", values);

    const result = await env.DB
      .prepare(insert.sql)
      .bind(...insert.bindings)
      .run();

    const userId =
      result.meta?.last_row_id ??
      result.meta?.last_rowid ??
      null;

    /*
      Nếu không có id thì tìm lại bằng email.
    */

    let finalUserId = userId;

    if (!finalUserId && map.id) {
      const found = await env.DB
        .prepare(`
          SELECT ${quoteIdentifier(map.id)}
          FROM users
          WHERE lower(${quoteIdentifier(map.email)}) = lower(?)
          LIMIT 1
        `)
        .bind(email)
        .first();

      finalUserId = found?.[map.id] ?? null;
    }

    if (!finalUserId) {
      return ok({
        message: "Tạo tài khoản thành công! Hãy đăng nhập để tiếp tục.",
        authenticated: false
      });
    }

    await audit(
      env,
      "REGISTER",
      finalUserId,
      {
        email
      }
    );

    const session = await createSessionCookie(
      finalUserId,
      env
    );

    const user = await getCurrentUser(
      new Request(request.url, {
        headers: {
          Cookie: `${SESSION_COOKIE}=${session}`
        }
      }),
      env
    );

    return json({
      success: true,
      message: "Tạo tài khoản thành công!",
      authenticated: true,
      user
    }, 201, sessionHeader(session));

  } catch (error) {
    const message = String(error?.message || error);

    if (
      message.includes("UNIQUE") ||
      message.includes("unique")
    ) {
      return fail(
        "Email hoặc tên tài khoản đã tồn tại.",
        409,
        "DUPLICATE"
      );
    }

    return fail(
      `Không thể tạo tài khoản: ${message}`,
      500,
      "REGISTER_FAILED"
    );
  }
}

/* =========================================================
   LOGIN
========================================================= */

async function login(request, env) {
  const data = await bodyJSON(request);

  if (!data) {
    return fail("Dữ liệu đăng nhập không hợp lệ.", 400);
  }

  const email = cleanEmail(data.email);
  const password = String(data.password || "");

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
    const result = await findUserByEmail(env, email);

    if (!result.row) {
      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_LOGIN"
      );
    }

    const user = result.row;
    const map = result.map;

    const storedHash = map.passwordHash
      ? user[map.passwordHash]
      : null;

    const storedSalt = map.passwordSalt
      ? user[map.passwordSalt]
      : null;

    const passwordOK = await verifyPassword(
      password,
      storedHash,
      storedSalt
    );

    if (!passwordOK) {
      await audit(
        env,
        "LOGIN_FAILED",
        map.id ? user[map.id] : null,
        {
          email
        }
      );

      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401,
        "INVALID_LOGIN"
      );
    }

    const userId = map.id
      ? user[map.id]
      : email;

    const session = await createSessionCookie(
      userId,
      env
    );

    await audit(
      env,
      "LOGIN",
      userId,
      {
        email
      }
    );

    return json({
      success: true,
      message: "Đăng nhập thành công!",
      authenticated: true,
      user: {
        id: userId,
        username: map.username ? user[map.username] : "",
        email: map.email ? user[map.email] : email,
        role: map.role ? user[map.role] : "PLAYER",
        balance: map.balance
          ? Number(user[map.balance] || 0)
          : 0
      }
    }, 200, sessionHeader(session));

  } catch (error) {
    return fail(
      `Không thể đăng nhập: ${error.message}`,
      500,
      "LOGIN_FAILED"
    );
  }
}

/* =========================================================
   LOGOUT
========================================================= */

async function logout(request, env) {
  const user = await getCurrentUser(request, env);

  if (user) {
    await audit(
      env,
      "LOGOUT",
      user.id,
      {}
    );
  }

  return json({
    success: true,
    message: "Đã đăng xuất."
  }, 200, clearSessionHeader());
}

/* =========================================================
   PUBLIC TOURNAMENT DATA
========================================================= */

async function getTournamentData(env) {
  const fallback = {
    id: "demo-2vs2",
    name: "Giải 2vs2 chủ nhật tới",
    description: "Giải đấu 2vs2 dành cho các team đăng ký trực tuyến.",
    status: "OPEN",
    slots: 16,
    registered: 0,
    fee: 0
  };

  try {
    const exists = await tableExists(env, "tournaments");

    if (!exists) {
      return fallback;
    }

    const columns = await getTableColumns(env, "tournaments");

    const idColumn = pickColumn(columns, [
      "id",
      "tournament_id"
    ]);

    const nameColumn = pickColumn(columns, [
      "name",
      "title"
    ]);

    const descriptionColumn = pickColumn(columns, [
      "description",
      "details"
    ]);

    const statusColumn = pickColumn(columns, [
      "status"
    ]);

    const feeColumn = pickColumn(columns, [
      "fee",
      "entry_fee",
      "price"
    ]);

    const slotColumn = pickColumn(columns, [
      "slots",
      "max_teams",
      "max_slots",
      "capacity"
    ]);

    if (!nameColumn) {
      return fallback;
    }

    const select = [
      idColumn,
      nameColumn,
      descriptionColumn,
      statusColumn,
      feeColumn,
      slotColumn
    ]
      .filter(Boolean)
      .map(quoteIdentifier)
      .join(", ");

    const row = await env.DB
      .prepare(`
        SELECT ${select}
        FROM tournaments
        ORDER BY rowid DESC
        LIMIT 1
      `)
      .first();

    if (!row) {
      return fallback;
    }

    return {
      id: idColumn ? row[idColumn] : fallback.id,
      name: row[nameColumn] || fallback.name,
      description: descriptionColumn
        ? row[descriptionColumn] || fallback.description
        : fallback.description,
      status: statusColumn
        ? String(row[statusColumn] || "OPEN").toUpperCase()
        : "OPEN",
      slots: slotColumn
        ? Number(row[slotColumn] || fallback.slots)
        : fallback.slots,
      registered: 0,
      fee: feeColumn
        ? Number(row[feeColumn] || 0)
        : 0
    };

  } catch {
    return fallback;
  }
}

/* =========================================================
   RANKING
========================================================= */

async function getRanking(env) {
  try {
    const exists = await tableExists(env, "teams");

    if (!exists) {
      return [];
    }

    const columns = await getTableColumns(env, "teams");

    const id = pickColumn(columns, [
      "id",
      "team_id"
    ]);

    const name = pickColumn(columns, [
      "name",
      "team_name"
    ]);

    const logo = pickColumn(columns, [
      "logo",
      "logo_url"
    ]);

    const points = pickColumn(columns, [
      "points",
      "score"
    ]);

    const wins = pickColumn(columns, [
      "wins",
      "win"
    ]);

    const losses = pickColumn(columns, [
      "losses",
      "loss"
    ]);

    if (!name) {
      return [];
    }

    const select = [
      id,
      name,
      logo,
      points,
      wins,
      losses
    ]
      .filter(Boolean)
      .map(quoteIdentifier)
      .join(", ");

    const order = points
      ? `ORDER BY ${quoteIdentifier(points)} DESC`
      : "ORDER BY rowid ASC";

    const result = await env.DB
      .prepare(`
        SELECT ${select}
        FROM teams
        ${order}
        LIMIT 100
      `)
      .all();

    return (result.results || []).map((row, index) => ({
      rank: index + 1,
      id: id ? row[id] : index + 1,
      name: row[name],
      logo: logo ? row[logo] : "",
      points: points ? Number(row[points] || 0) : 0,
      wins: wins ? Number(row[wins] || 0) : 0,
      losses: losses ? Number(row[losses] || 0) : 0
    }));

  } catch {
    return [];
  }
}

/* =========================================================
   TEAM REGISTER
========================================================= */

async function registerTeam(request, env) {
  const currentUser = await getCurrentUser(request, env);

  if (!currentUser) {
    return fail(
      "Bạn cần đăng nhập để đăng ký team.",
      401,
      "UNAUTHENTICATED"
    );
  }

  const data = await bodyJSON(request);

  if (!data) {
    return fail("Dữ liệu team không hợp lệ.");
  }

  const teamName = cleanUsername(
    data.teamName ||
    data.name
  );

  const teamLogo = String(
    data.logo ||
    data.logoUrl ||
    ""
  ).trim();

  const teamEmail = cleanEmail(
    data.teamEmail ||
    data.email ||
    currentUser.email
  );

  if (!teamName || teamName.length < 2) {
    return fail(
      "Vui lòng nhập tên team.",
      400,
      "TEAM_NAME_REQUIRED"
    );
  }

  try {
    const exists = await tableExists(env, "teams");

    if (!exists) {
      return fail(
        "Database hiện chưa có bảng teams. Phần tài khoản vẫn hoạt động bình thường.",
        503,
        "TEAMS_TABLE_MISSING"
      );
    }

    const columns = await getTableColumns(env, "teams");

    const nameColumn = pickColumn(columns, [
      "name",
      "team_name"
    ]);

    const logoColumn = pickColumn(columns, [
      "logo",
      "logo_url"
    ]);

    const emailColumn = pickColumn(columns, [
      "email",
      "team_email",
      "contact_email"
    ]);

    const ownerColumn = pickColumn(columns, [
      "user_id",
      "owner_id",
      "created_by"
    ]);

    const createdColumn = pickColumn(columns, [
      "created_at",
      "created"
    ]);

    if (!nameColumn) {
      return fail(
        "Bảng teams không có cột tên team.",
        500
      );
    }

    const values = {};

    values[nameColumn] = teamName;

    if (logoColumn) {
      values[logoColumn] = teamLogo;
    }

    if (emailColumn) {
      values[emailColumn] = teamEmail;
    }

    if (ownerColumn) {
      values[ownerColumn] = currentUser.id;
    }

    if (createdColumn) {
      values[createdColumn] = new Date().toISOString();
    }

    const insert = buildInsert("teams", values);

    const result = await env.DB
      .prepare(insert.sql)
      .bind(...insert.bindings)
      .run();

    await audit(
      env,
      "TEAM_REGISTER",
      currentUser.id,
      {
        teamName
      }
    );

    return ok({
      message: "Đăng ký team thành công!",
      team: {
        id: result.meta?.last_row_id || null,
        name: teamName,
        logo: teamLogo,
        email: teamEmail
      }
    });

  } catch (error) {
    return fail(
      `Không thể đăng ký team: ${error.message}`,
      500,
      "TEAM_REGISTER_FAILED"
    );
  }
}

/* =========================================================
   API ROUTER
========================================================= */

async function api(request, env) {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  /* HEALTH */

  if (url.pathname === "/api/health" && method === "GET") {
    try {
      const result = await env.DB
        .prepare("SELECT 1 AS ok")
        .first();

      return ok({
        worker: "online",
        database: result?.ok === 1
          ? "connected"
          : "error",
        site: env.SITE_NAME || "GIẢI ĐẤU TỬ CHIẾN – MÙA 1"
      });

    } catch (error) {
      return fail(
        error.message,
        500,
        "DATABASE_ERROR"
      );
    }
  }

  /* TABLES */

  if (url.pathname === "/api/tables" && method === "GET") {
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
      return fail(error.message, 500);
    }
  }

  /* TABLE */

  if (url.pathname === "/api/table" && method === "GET") {
    const table = url.searchParams.get("name");

    if (!table) {
      return fail("Thiếu tên bảng.", 400);
    }

    if (!/^[A-Za-z0-9_]+$/.test(table)) {
      return fail("Tên bảng không hợp lệ.", 400);
    }

    try {
      const result = await env.DB
        .prepare(`
          SELECT *
          FROM "${table}"
          LIMIT 100
        `)
        .all();

      return ok({
        table,
        rows: result.results || []
      });

    } catch (error) {
      return fail(error.message, 500);
    }
  }

  /* REGISTER */

  if (
    url.pathname === "/api/auth/register" &&
    method === "POST"
  ) {
    return register(request, env);
  }

  /* LOGIN */

  if (
    url.pathname === "/api/auth/login" &&
    method === "POST"
  ) {
    return login(request, env);
  }

  /* ME */

  if (
    url.pathname === "/api/auth/me" &&
    method === "GET"
  ) {
    try {
      const user = await getCurrentUser(
        request,
        env
      );

      return ok({
        authenticated: !!user,
        user: user || null
      });

    } catch {
      return ok({
        authenticated: false,
        user: null
      });
    }
  }

  /* LOGOUT */

  if (
    url.pathname === "/api/auth/logout" &&
    method === "POST"
  ) {
    return logout(request, env);
  }

  /* TOURNAMENT */

  if (
    url.pathname === "/api/tournaments" &&
    method === "GET"
  ) {
    const tournament = await getTournamentData(env);

    return ok({
      tournament
    });
  }

  /* RANKING */

  if (
    url.pathname === "/api/ranking" &&
    method === "GET"
  ) {
    const ranking = await getRanking(env);

    return ok({
      ranking
    });
  }

  /* TEAM REGISTER */

  if (
    url.pathname === "/api/teams/register" &&
    method === "POST"
  ) {
    return registerTeam(request, env);
  }

  return fail(
    "API không tồn tại.",
    404,
    "NOT_FOUND"
  );
}

/* =========================================================
   MAIN WORKER
========================================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env);
      } catch (error) {
        return fail(
          error?.message || "Server error",
          500,
          "SERVER_ERROR"
        );
      }
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "GIẢI ĐẤU TỬ CHIẾN – MÙA 1",
      {
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  }
};
