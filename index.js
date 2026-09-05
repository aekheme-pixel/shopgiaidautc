const SITE_NAME_DEFAULT = "GIẢI ĐẤU TỬ CHIẾN – MÙA 1";

const SESSION_COOKIE = "vtc_session";
const SESSION_DAYS = 7;

const PBKDF2_ITERATIONS = 100000;
const PASSWORD_MIN = 8;

const encoder = new TextEncoder();


// ============================================================
// BASIC HELPERS
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
    code,
    message
  }, status);
}

async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function clean(value) {
  return String(value ?? "").trim();
}

function cleanEmail(value) {
  return clean(value).toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validUsername(username) {
  return /^[A-Za-z0-9_.-]{3,32}$/.test(username);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= PASSWORD_MIN;
}


// ============================================================
// BASE64URL
// ============================================================

function bytesToBase64(bytes) {
  let binary = "";

  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunk)
    );
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

function base64UrlEncode(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized + "=".repeat((4 - normalized.length % 4) % 4);

  return base64ToBytes(padded);
}


// ============================================================
// PASSWORD HASH - PBKDF2
//
// Không dùng password_salt.
// Salt được đóng gói bên trong password_hash:
//
// pbkdf2$100000$SALT$HASH
// ============================================================

async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const key = await crypto.subtle.importKey(
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
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    base64UrlEncode(salt),
    base64UrlEncode(new Uint8Array(bits))
  ].join("$");
}


async function verifyNewPassword(password, storedHash) {
  const parts = String(storedHash || "").split("$");

  if (parts.length !== 4) {
    return false;
  }

  if (parts[0] !== "pbkdf2") {
    return false;
  }

  const iterations = Number(parts[1]);

  if (!Number.isInteger(iterations) || iterations < 10000) {
    return false;
  }

  try {
    const salt = base64UrlDecode(parts[2]);
    const expected = base64UrlDecode(parts[3]);

    const key = await crypto.subtle.importKey(
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
      key,
      expected.length * 8
    );

    return crypto.subtle.timingSafeEqual(
      new Uint8Array(bits),
      expected
    );
  } catch {
    return false;
  }
}


// ============================================================
// LEGACY PASSWORD SUPPORT
//
// Nếu DB cũ từng có password_hash + password_salt,
// login cũ vẫn được thử.
//
// Không ghi password_salt mới.
// ============================================================

async function verifyLegacyPassword(password, passwordHash, passwordSalt) {
  if (!passwordHash) {
    return false;
  }

  if (!passwordSalt) {
    return false;
  }

  try {
    const saltBytes =
      typeof passwordSalt === "string"
        ? base64UrlDecode(passwordSalt)
        : new Uint8Array(passwordSalt);

    const key = await crypto.subtle.importKey(
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
      key,
      256
    );

    const actual = new Uint8Array(bits);

    let expected;

    try {
      expected = base64UrlDecode(passwordHash);
    } catch {
      return false;
    }

    if (expected.length !== actual.length) {
      return false;
    }

    return crypto.subtle.timingSafeEqual(
      actual,
      expected
    );
  } catch {
    return false;
  }
}


// ============================================================
// SESSION - KHÔNG DÙNG BẢNG sessions
//
// Token được ký HMAC.
// Vì vậy không phụ thuộc sessions.token/session_token.
// ============================================================

function getSessionSecret(env) {
  return String(
    env.SESSION_SECRET ||
    `${env.SITE_NAME || SITE_NAME_DEFAULT}::change-this-secret`
  );
}

async function getHmacKey(env) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(getSessionSecret(env)),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}

async function createSessionToken(env, userId) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + SESSION_DAYS * 86400;

  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);

  const payload = [
    String(userId),
    String(now),
    String(exp),
    base64UrlEncode(nonce)
  ].join(".");

  const key = await getHmacKey(env);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return `${payload}.${base64UrlEncode(new Uint8Array(signature))}`;
}

async function verifySessionToken(env, token) {
  if (!token) {
    return null;
  }

  const parts = String(token).split(".");

  if (parts.length !== 5) {
    return null;
  }

  const [
    userId,
    issuedAt,
    expiresAt,
    nonce,
    signature
  ] = parts;

  const exp = Number(expiresAt);

  if (!userId || !Number.isFinite(exp)) {
    return null;
  }

  if (Date.now() / 1000 >= exp) {
    return null;
  }

  const payload = [
    userId,
    issuedAt,
    expiresAt,
    nonce
  ].join(".");

  try {
    const key = await getHmacKey(env);

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(signature),
      encoder.encode(payload)
    );

    if (!valid) {
      return null;
    }

    return {
      userId
    };
  } catch {
    return null;
  }
}

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";

  const cookies = {};

  for (const item of header.split(";")) {
    const index = item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    cookies[key] = value;
  }

  return cookies;
}

function sessionCookie(token) {
  return [
    `${SESSION_COOKIE}=${token}`,
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
// D1 SCHEMA HELPERS
//
// Chỉ đọc schema.
// Không ALTER / CREATE / DROP.
// ============================================================

async function getTableColumns(env, table) {
  if (!/^[A-Za-z0-9_]+$/.test(table)) {
    throw new Error("Tên bảng không hợp lệ");
  }

  const result = await env.DB
    .prepare(`PRAGMA table_info("${table}")`)
    .all();

  return result.results || [];
}

async function tableExists(env, table) {
  const row = await env.DB
    .prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
      AND name = ?
      LIMIT 1
    `)
    .bind(table)
    .first();

  return !!row;
}

function columnNames(columns) {
  return new Set(
    columns.map(column => String(column.name))
  );
}

function findColumn(columns, candidates) {
  const names = columnNames(columns);

  for (const candidate of candidates) {
    if (names.has(candidate)) {
      return candidate;
    }
  }

  return null;
}

function quoteIdentifier(value) {
  if (!/^[A-Za-z0-9_]+$/.test(value)) {
    throw new Error("Identifier không hợp lệ");
  }

  return `"${value}"`;
}


// ============================================================
// USERS
// ============================================================

async function getUsersSchema(env) {
  const columns = await getTableColumns(env, "users");

  if (!columns.length) {
    throw new Error("D1 chưa có bảng users.");
  }

  return {
    columns,
    names: columnNames(columns),

    id: findColumn(columns, [
      "id",
      "user_id"
    ]),

    username: findColumn(columns, [
      "username",
      "user_name",
      "account_name",
      "name"
    ]),

    email: findColumn(columns, [
      "email",
      "email_address"
    ]),

    passwordHash: findColumn(columns, [
      "password_hash",
      "password"
    ]),

    passwordSalt: findColumn(columns, [
      "password_salt"
    ]),

    role: findColumn(columns, [
      "role"
    ]),

    balance: findColumn(columns, [
      "balance",
      "wallet_balance",
      "money"
    ]),

    createdAt: findColumn(columns, [
      "created_at",
      "createdAt",
      "registered_at"
    ])
  };
}


function publicUser(row, schema) {
  if (!row) {
    return null;
  }

  return {
    id: schema.id ? row[schema.id] : null,

    username:
      schema.username
        ? row[schema.username]
        : "",

    email:
      schema.email
        ? row[schema.email]
        : "",

    role:
      schema.role
        ? row[schema.role]
        : "PLAYER",

    balance:
      schema.balance
        ? Number(row[schema.balance] || 0)
        : 0,

    created_at:
      schema.createdAt
        ? row[schema.createdAt]
        : null
  };
}


async function findUserByEmail(env, email) {
  const schema = await getUsersSchema(env);

  if (!schema.email) {
    throw new Error("Bảng users không có cột email.");
  }

  const row = await env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE lower("${schema.email}") = lower(?)
      LIMIT 1
    `)
    .bind(email)
    .first();

  return {
    row,
    schema
  };
}


async function findUserById(env, id) {
  const schema = await getUsersSchema(env);

  if (!schema.id) {
    throw new Error("Bảng users không có cột id.");
  }

  const row = await env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE "${schema.id}" = ?
      LIMIT 1
    `)
    .bind(id)
    .first();

  return {
    row,
    schema
  };
}


// ============================================================
// REGISTER USER
// ============================================================

async function registerUser(env, data) {
  const username = clean(
    data.username ||
    data.accountName ||
    data.account_name
  );

  const email = cleanEmail(data.email);
  const password = String(data.password || "");
  const passwordConfirm = String(
    data.passwordConfirm ||
    data.password_confirm ||
    data.confirmPassword ||
    ""
  );

  if (!username) {
    throw new Error("Vui lòng nhập tên tài khoản.");
  }

  if (!validUsername(username)) {
    throw new Error(
      "Tên tài khoản chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang; dài 3–32 ký tự."
    );
  }

  if (!validEmail(email)) {
    throw new Error("Email không hợp lệ.");
  }

  if (!validPassword(password)) {
    throw new Error(
      `Mật khẩu phải có ít nhất ${PASSWORD_MIN} ký tự.`
    );
  }

  if (password !== passwordConfirm) {
    throw new Error("Mật khẩu nhập lại không khớp.");
  }

  const schema = await getUsersSchema(env);

  if (!schema.email) {
    throw new Error("Bảng users thiếu cột email.");
  }

  if (!schema.passwordHash) {
    throw new Error(
      "Bảng users thiếu cột password_hash. Không thể lưu mật khẩu an toàn."
    );
  }

  const existingEmail = await env.DB
    .prepare(`
      SELECT 1
      FROM users
      WHERE lower("${schema.email}") = lower(?)
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (existingEmail) {
    throw new Error("Email này đã được đăng ký.");
  }

  if (schema.username) {
    const existingUsername = await env.DB
      .prepare(`
        SELECT 1
        FROM users
        WHERE lower("${schema.username}") = lower(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

    if (existingUsername) {
      throw new Error("Tên tài khoản này đã tồn tại.");
    }
  }

  const passwordHash = await hashPassword(password);

  const fields = [];
  const placeholders = [];
  const values = [];

  function addField(column, value) {
    if (!column) {
      return;
    }

    fields.push(quoteIdentifier(column));
    placeholders.push("?");
    values.push(value);
  }

  addField(schema.email, email);

  if (schema.username) {
    addField(schema.username, username);
  }

  addField(schema.passwordHash, passwordHash);

  /*
   * Cố tình KHÔNG thêm password_salt.
   * Salt đã nằm trong password_hash.
   */

  if (schema.role) {
    /*
     * DB hiện tại đã xác nhận PLAYER là role hợp lệ.
     */
    addField(schema.role, "PLAYER");
  }

  if (schema.balance) {
    addField(schema.balance, 0);
  }

  if (schema.createdAt) {
    addField(
      schema.createdAt,
      new Date().toISOString()
    );
  }

  const requiredColumns = schema.columns.filter(
    column =>
      Number(column.notnull) === 1 &&
      column.pk === 0 &&
      column.dflt_value === null
  );

  for (const column of requiredColumns) {
    if (!fields.includes(quoteIdentifier(column.name))) {
      throw new Error(
        `Database yêu cầu cột "${column.name}" nhưng code không tự xác định được giá trị.`
      );
    }
  }

  const result = await env.DB
    .prepare(`
      INSERT INTO users (
        ${fields.join(", ")}
      )
      VALUES (
        ${placeholders.join(", ")}
      )
    `)
    .bind(...values)
    .run();

  const userId =
    result.meta?.last_row_id ??
    result.meta?.last_rowid;

  let row = null;

  if (schema.id && userId !== undefined) {
    row = await env.DB
      .prepare(`
        SELECT *
        FROM users
        WHERE "${schema.id}" = ?
        LIMIT 1
      `)
      .bind(userId)
      .first();
  }

  if (!row) {
    row = await env.DB
      .prepare(`
        SELECT *
        FROM users
        WHERE lower("${schema.email}") = lower(?)
        LIMIT 1
      `)
      .bind(email)
      .first();
  }

  return {
    user: publicUser(row, schema)
  };
}


// ============================================================
// LOGIN
// ============================================================

async function loginUser(env, data) {
  const email = cleanEmail(data.email);
  const password = String(data.password || "");

  if (!validEmail(email)) {
    throw new Error("Email không hợp lệ.");
  }

  if (!password) {
    throw new Error("Vui lòng nhập mật khẩu.");
  }

  const { row, schema } =
    await findUserByEmail(env, email);

  if (!row) {
    throw new Error("Email hoặc mật khẩu không chính xác.");
  }

  const passwordHash =
    schema.passwordHash
      ? row[schema.passwordHash]
      : null;

  const passwordSalt =
    schema.passwordSalt
      ? row[schema.passwordSalt]
      : null;

  let valid = false;

  if (
    typeof passwordHash === "string" &&
    passwordHash.startsWith("pbkdf2$")
  ) {
    valid = await verifyNewPassword(
      password,
      passwordHash
    );
  }

  /*
   * Hỗ trợ tài khoản cũ có password_salt.
   * Không tạo password_salt mới.
   */
  if (!valid && passwordSalt) {
    valid = await verifyLegacyPassword(
      password,
      passwordHash,
      passwordSalt
    );
  }

  if (!valid) {
    throw new Error("Email hoặc mật khẩu không chính xác.");
  }

  if (!schema.id) {
    throw new Error("Bảng users thiếu cột id.");
  }

  const token = await createSessionToken(
    env,
    row[schema.id]
  );

  return {
    user: publicUser(row, schema),
    token
  };
}


// ============================================================
// AUTH ME
// ============================================================

async function getCurrentUser(request, env) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];

  const session =
    await verifySessionToken(env, token);

  if (!session) {
    return null;
  }

  const { row, schema } =
    await findUserById(env, session.userId);

  if (!row) {
    return null;
  }

  return publicUser(row, schema);
}


// ============================================================
// TOURNAMENT HELPERS
// ============================================================

async function getTournamentList(env) {
  if (!(await tableExists(env, "tournaments"))) {
    return [];
  }

  const columns =
    await getTableColumns(env, "tournaments");

  const id = findColumn(columns, ["id", "tournament_id"]);
  const name = findColumn(columns, ["name", "title"]);
  const fee = findColumn(columns, [
    "fee",
    "entry_fee",
    "registration_fee"
  ]);
  const maxTeams = findColumn(columns, [
    "max_teams",
    "max_team",
    "slots",
    "capacity"
  ]);
  const status = findColumn(columns, ["status"]);
  const description = findColumn(columns, [
    "description",
    "details"
  ]);
  const createdAt = findColumn(columns, [
    "created_at",
    "createdAt"
  ]);

  const select = [
    id ? `"${id}" AS id` : `NULL AS id`,
    name ? `"${name}" AS name` : `NULL AS name`,
    fee ? `"${fee}" AS fee` : `0 AS fee`,
    maxTeams
      ? `"${maxTeams}" AS max_teams`
      : `NULL AS max_teams`,
    status
      ? `"${status}" AS status`
      : `'OPEN' AS status`,
    description
      ? `"${description}" AS description`
      : `NULL AS description`,
    createdAt
      ? `"${createdAt}" AS created_at`
      : `NULL AS created_at`
  ];

  let sql = `
    SELECT ${select.join(", ")}
    FROM tournaments
  `;

  if (status) {
    sql += `
      WHERE upper("${status}") IN (
        'OPEN',
        'OPENED',
        'ACTIVE',
        'PUBLISHED'
      )
      OR "${status}" IS NULL
    `;
  }

  sql += `
    ORDER BY
      CASE
        WHEN ${status ? `"${status}"` : `'OPEN'`} = 'OPEN'
        THEN 0
        ELSE 1
      END,
      ${createdAt ? `"${createdAt}" DESC` : `id DESC`}
  `;

  const result =
    await env.DB.prepare(sql).all();

  return result.results || [];
}


// ============================================================
// TOURNAMENT DETAIL
// ============================================================

async function getTournament(env, id) {
  if (!(await tableExists(env, "tournaments"))) {
    return null;
  }

  const columns =
    await getTableColumns(env, "tournaments");

  const idColumn =
    findColumn(columns, ["id", "tournament_id"]);

  if (!idColumn) {
    return null;
  }

  const result =
    await env.DB.prepare(`
      SELECT *
      FROM tournaments
      WHERE "${idColumn}" = ?
      LIMIT 1
    `)
    .bind(id)
    .first();

  return result || null;
}


// ============================================================
// TEAM REGISTRATION
//
// Không tự CREATE TABLE.
// Tự nhận diện teams + registrations nếu DB đã có.
// ============================================================

async function registerTeam(env, request, data) {
  const user = await getCurrentUser(
    request,
    env
  );

  if (!user) {
    throw new Error(
      "Bạn cần đăng nhập trước khi đăng ký team."
    );
  }

  const tournamentId =
    clean(data.tournamentId);

  const teamName =
    clean(data.teamName);

  const logoUrl =
    clean(data.logoUrl);

  const teamEmail =
    cleanEmail(
      data.teamEmail ||
      data.email
    );

  if (!tournamentId) {
    throw new Error("Thiếu giải đấu.");
  }

  if (!teamName) {
    throw new Error("Vui lòng nhập tên team.");
  }

  if (teamName.length < 2 || teamName.length > 60) {
    throw new Error(
      "Tên team phải từ 2 đến 60 ký tự."
    );
  }

  if (!validEmail(teamEmail)) {
    throw new Error("Email team không hợp lệ.");
  }

  const tournament =
    await getTournament(
      env,
      tournamentId
    );

  if (!tournament) {
    throw new Error("Không tìm thấy giải đấu.");
  }

  /*
   * Nếu DB có bảng teams và registrations,
   * code sẽ dùng bảng hiện tại.
   */

  if (!(await tableExists(env, "teams"))) {
    throw new Error(
      "Database hiện tại chưa có bảng teams. Tài khoản vẫn hoạt động bình thường; cần schema team trước khi nhận đăng ký team."
    );
  }

  if (!(await tableExists(env, "registrations"))) {
    throw new Error(
      "Database hiện tại chưa có bảng registrations. Tài khoản vẫn hoạt động bình thường; cần schema registrations trước khi nhận đăng ký team."
    );
  }

  const teamColumns =
    await getTableColumns(env, "teams");

  const regColumns =
    await getTableColumns(env, "registrations");

  const teamId =
    findColumn(teamColumns, [
      "id",
      "team_id"
    ]);

  const teamNameColumn =
    findColumn(teamColumns, [
      "name",
      "team_name"
    ]);

  const teamLogo =
    findColumn(teamColumns, [
      "logo",
      "logo_url",
      "logoUrl"
    ]);

  const teamEmailColumn =
    findColumn(teamColumns, [
      "email",
      "team_email"
    ]);

  const ownerColumn =
    findColumn(teamColumns, [
      "owner_id",
      "user_id",
      "created_by"
    ]);

  if (!teamId || !teamNameColumn) {
    throw new Error(
      "Bảng teams hiện tại không có cấu trúc id/team_id + name/team_name."
    );
  }

  const teamFields = [];
  const teamValues = [];
  const teamPlaceholders = [];

  function addTeam(column, value) {
    if (!column) return;

    teamFields.push(
      quoteIdentifier(column)
    );

    teamValues.push(value);
    teamPlaceholders.push("?");
  }

  addTeam(teamNameColumn, teamName);
  addTeam(teamLogo, logoUrl || null);
  addTeam(teamEmailColumn, teamEmail);
  addTeam(ownerColumn, user.id);

  const teamRequired =
    teamColumns.filter(
      column =>
        Number(column.notnull) === 1 &&
        column.pk === 0 &&
        column.dflt_value === null
    );

  for (const column of teamRequired) {
    if (
      !teamFields.includes(
        quoteIdentifier(column.name)
      )
    ) {
      throw new Error(
        `Bảng teams yêu cầu cột "${column.name}" nhưng chưa xác định được dữ liệu.`
      );
    }
  }

  const teamResult =
    await env.DB
      .prepare(`
        INSERT INTO teams (
          ${teamFields.join(", ")}
        )
        VALUES (
          ${teamPlaceholders.join(", ")}
        )
      `)
      .bind(...teamValues)
      .run();

  const createdTeamId =
    teamResult.meta?.last_row_id;

  const regTournament =
    findColumn(regColumns, [
      "tournament_id"
    ]);

  const regTeam =
    findColumn(regColumns, [
      "team_id"
    ]);

  const regUser =
    findColumn(regColumns, [
      "user_id",
      "owner_id"
    ]);

  const regStatus =
    findColumn(regColumns, [
      "status"
    ]);

  const regCreated =
    findColumn(regColumns, [
      "created_at",
      "registered_at"
    ]);

  if (!regTournament || !regTeam) {
    throw new Error(
      "Bảng registrations thiếu tournament_id hoặc team_id."
    );
  }

  const regFields = [];
  const regValues = [];
  const regPlaceholders = [];

  function addReg(column, value) {
    if (!column) return;

    regFields.push(
      quoteIdentifier(column)
    );

    regValues.push(value);
    regPlaceholders.push("?");
  }

  addReg(regTournament, tournamentId);
  addReg(regTeam, createdTeamId);
  addReg(regUser, user.id);

  if (regStatus) {
    addReg(regStatus, "PENDING_PAYMENT");
  }

  if (regCreated) {
    addReg(
      regCreated,
      new Date().toISOString()
    );
  }

  const regRequired =
    regColumns.filter(
      column =>
        Number(column.notnull) === 1 &&
        column.pk === 0 &&
        column.dflt_value === null
    );

  for (const column of regRequired) {
    if (
      !regFields.includes(
        quoteIdentifier(column.name)
      )
    ) {
      throw new Error(
        `Bảng registrations yêu cầu cột "${column.name}" nhưng chưa xác định được dữ liệu.`
      );
    }
  }

  await env.DB
    .prepare(`
      INSERT INTO registrations (
        ${regFields.join(", ")}
      )
      VALUES (
        ${regPlaceholders.join(", ")}
      )
    `)
    .bind(...regValues)
    .run();

  return {
    teamId: createdTeamId,
    tournamentId,
    status: "PENDING_PAYMENT",
    message:
      "Đăng ký team thành công. Vui lòng hoàn tất thanh toán."
  };
}


// ============================================================
// RANKING
// ============================================================

async function getRanking(env) {
  /*
   * Ưu tiên bảng rankings nếu có.
   * Nếu chưa có thì trả [].
   * Không tự tạo bảng.
   */

  if (!(await tableExists(env, "rankings"))) {
    return [];
  }

  const columns =
    await getTableColumns(env, "rankings");

  const name =
    findColumn(columns, [
      "team_name",
      "name"
    ]);

  const points =
    findColumn(columns, [
      "points",
      "score"
    ]);

  const wins =
    findColumn(columns, [
      "wins",
      "win"
    ]);

  const losses =
    findColumn(columns, [
      "losses",
      "loss"
    ]);

  const position =
    findColumn(columns, [
      "rank",
      "position"
    ]);

  const select = [
    name
      ? `"${name}" AS team_name`
      : `NULL AS team_name`,

    points
      ? `"${points}" AS points`
      : `0 AS points`,

    wins
      ? `"${wins}" AS wins`
      : `0 AS wins`,

    losses
      ? `"${losses}" AS losses`
      : `0 AS losses`,

    position
      ? `"${position}" AS position`
      : `NULL AS position`
  ];

  let sql = `
    SELECT ${select.join(", ")}
    FROM rankings
  `;

  if (points) {
    sql += `
      ORDER BY "${points}" DESC
    `;
  }

  const result =
    await env.DB.prepare(sql).all();

  return result.results || [];
}


// ============================================================
// API ROUTER
// ============================================================

async function handleAPI(request, env) {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const path = url.pathname;

  // ----------------------------------------------------------
  // HEALTH
  // ----------------------------------------------------------

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    try {
      const result =
        await env.DB
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
          SITE_NAME_DEFAULT
      });
    } catch (error) {
      return fail(
        `Database error: ${error.message}`,
        500,
        "DATABASE_ERROR"
      );
    }
  }


  // ----------------------------------------------------------
  // TABLES
  // ----------------------------------------------------------

  if (
    path === "/api/tables" &&
    method === "GET"
  ) {
    try {
      const result =
        await env.DB
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
        error.message,
        500,
        "DATABASE_ERROR"
      );
    }
  }


  // ----------------------------------------------------------
  // TABLE DATA
  // ----------------------------------------------------------

  if (
    path === "/api/table" &&
    method === "GET"
  ) {
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
      const result =
        await env.DB
          .prepare(
            `SELECT * FROM "${table}" LIMIT 100`
          )
          .all();

      return ok({
        table,
        rows: result.results || []
      });
    } catch (error) {
      return fail(
        error.message,
        500,
        "DATABASE_ERROR"
      );
    }
  }


  // ----------------------------------------------------------
  // REGISTER
  // ----------------------------------------------------------

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    try {
      const data =
        await readJSON(request);

      if (!data) {
        return fail(
          "Dữ liệu đăng ký không hợp lệ.",
          400,
          "INVALID_JSON"
        );
      }

      const result =
        await registerUser(
          env,
          data
        );

      const token =
        await createSessionToken(
          env,
          result.user.id
        );

      return ok(
        {
          message:
            "Tạo tài khoản thành công.",
          user: result.user
        },
        201,
        {
          "Set-Cookie":
            sessionCookie(token)
        }
      );
    } catch (error) {
      const message =
        String(error.message || "");

      if (
        /unique|duplicate/i.test(message)
      ) {
        return fail(
          "Email hoặc tên tài khoản đã tồn tại.",
          409,
          "ALREADY_EXISTS"
        );
      }

      return fail(
        message ||
        "Không thể tạo tài khoản.",
        400,
        "REGISTER_FAILED"
      );
    }
  }


  // ----------------------------------------------------------
  // LOGIN
  // ----------------------------------------------------------

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    try {
      const data =
        await readJSON(request);

      if (!data) {
        return fail(
          "Dữ liệu đăng nhập không hợp lệ.",
          400,
          "INVALID_JSON"
        );
      }

      const result =
        await loginUser(
          env,
          data
        );

      return ok(
        {
          message:
            "Đăng nhập thành công.",
          user: result.user
        },
        200,
        {
          "Set-Cookie":
            sessionCookie(
              result.token
            )
        }
      );
    } catch (error) {
      return fail(
        error.message ||
        "Đăng nhập thất bại.",
        401,
        "LOGIN_FAILED"
      );
    }
  }


  // ----------------------------------------------------------
  // ME
  // ----------------------------------------------------------

  if (
    path === "/api/auth/me" &&
    method === "GET"
  ) {
    try {
      const user =
        await getCurrentUser(
          request,
          env
        );

      return ok({
        authenticated: !!user,
        user
      });
    } catch (error) {
      return ok({
        authenticated: false,
        user: null
      });
    }
  }


  // ----------------------------------------------------------
  // LOGOUT
  // ----------------------------------------------------------

  if (
    path === "/api/auth/logout" &&
    method === "POST"
  ) {
    return ok(
      {
        message:
          "Đăng xuất thành công."
      },
      200,
      {
        "Set-Cookie":
          clearSessionCookie()
      }
    );
  }


  // ----------------------------------------------------------
  // TOURNAMENTS
  // ----------------------------------------------------------

  if (
    path === "/api/tournaments" &&
    method === "GET"
  ) {
    try {
      const tournaments =
        await getTournamentList(env);

      return ok({
        tournaments
      });
    } catch (error) {
      return fail(
        error.message,
        500,
        "TOURNAMENT_ERROR"
      );
    }
  }


  // ----------------------------------------------------------
  // TOURNAMENT DETAIL
  // ----------------------------------------------------------

  if (
    path === "/api/tournament" &&
    method === "GET"
  ) {
    const id =
      url.searchParams.get("id");

    if (!id) {
      return fail(
        "Thiếu id giải đấu.",
        400,
        "MISSING_ID"
      );
    }

    try {
      const tournament =
        await getTournament(
          env,
          id
        );

      if (!tournament) {
        return fail(
          "Không tìm thấy giải đấu.",
          404,
          "NOT_FOUND"
        );
      }

      return ok({
        tournament
      });
    } catch (error) {
      return fail(
        error.message,
        500,
        "TOURNAMENT_ERROR"
      );
    }
  }


  // ----------------------------------------------------------
  // REGISTER TEAM
  // ----------------------------------------------------------

  if (
    path === "/api/teams/register" &&
    method === "POST"
  ) {
    try {
      const data =
        await readJSON(request);

      if (!data) {
        return fail(
          "Dữ liệu team không hợp lệ.",
          400,
          "INVALID_JSON"
        );
      }

      const result =
        await registerTeam(
          env,
          request,
          data
        );

      return ok(result);
    } catch (error) {
      return fail(
        error.message ||
        "Không thể đăng ký team.",
        400,
        "TEAM_REGISTER_FAILED"
      );
    }
  }


  // ----------------------------------------------------------
  // RANKING
  // ----------------------------------------------------------

  if (
    path === "/api/ranking" &&
    method === "GET"
  ) {
    try {
      const ranking =
        await getRanking(env);

      return ok({
        ranking
      });
    } catch (error) {
      return fail(
        error.message,
        500,
        "RANKING_ERROR"
      );
    }
  }


  return fail(
    "API không tồn tại.",
    404,
    "NOT_FOUND"
  );
}


// ============================================================
// MAIN WORKER
// ============================================================

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    try {
      if (
        url.pathname.startsWith("/api/")
      ) {
        return await handleAPI(
          request,
          env
        );
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response(
        env.SITE_NAME ||
        SITE_NAME_DEFAULT,
        {
          headers: {
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );
    } catch (error) {
      console.error(error);

      if (
        url.pathname.startsWith("/api/")
      ) {
        return fail(
          "Lỗi máy chủ: " +
          String(error.message || error),
          500,
          "INTERNAL_ERROR"
        );
      }

      return new Response(
        "GIẢI ĐẤU TỬ CHIẾN – MÙA 1",
        {
          status: 500,
          headers: {
            "content-type":
              "text/plain; charset=UTF-8"
          }
        }
      );
    }
  }
};
