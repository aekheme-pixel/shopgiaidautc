const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await api(request, env, url);
      }

      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);

      if (url.pathname.startsWith("/api/")) {
        return json({
          ok: false,
          error: safeError(err)
        }, 500);
      }

      return new Response("Internal Server Error", { status: 500 });
    }
  }
};


/* =========================================================
   BASIC
========================================================= */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function safeError(err) {
  if (!err) return "Unknown error";

  const message = String(err.message || err);

  if (message.includes("D1_ERROR")) return message;
  if (message.includes("SQLITE_")) return message;

  return message;
}

function nowISO() {
  return new Date().toISOString();
}

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);

  return [...data]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function base64(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);

  for (const b of arr) s += String.fromCharCode(b);

  return btoa(s);
}

function fromBase64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);

  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i);
  }

  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}


/* =========================================================
   PASSWORD - WEB CRYPTO
========================================================= */

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
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

  const hash = new Uint8Array(bits);

  return [
    "v1",
    "pbkdf2",
    PBKDF2_ITERATIONS,
    base64(salt),
    base64(hash)
  ].join("$");
}

async function verifyPassword(password, stored) {
  if (!stored) return false;

  stored = String(stored);

  /*
   * New format:
   * v1$pbkdf2$100000$salt$hash
   */
  if (stored.startsWith("v1$pbkdf2$")) {
    const parts = stored.split("$");

    if (parts.length !== 5) return false;

    const iterations = Number(parts[2]);

    if (!Number.isFinite(iterations)) return false;

    /*
     * Never exceed Cloudflare's supported limit.
     */
    if (iterations > 100000) return false;

    const salt = fromBase64(parts[3]);
    const expected = fromBase64(parts[4]);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
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
      256
    );

    return equalBytes(new Uint8Array(bits), expected);
  }

  /*
   * Compatibility with old SHA-256 hashes.
   */
  try {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(password)
    );

    const hex = [...new Uint8Array(digest)]
      .map(x => x.toString(16).padStart(2, "0"))
      .join("");

    if (hex === stored.toLowerCase()) {
      return true;
    }
  } catch {}

  return false;
}


/* =========================================================
   D1 SCHEMA INTROSPECTION
========================================================= */

async function tableInfo(env, table) {
  const result = await env.DB
    .prepare(`PRAGMA table_info("${table.replaceAll('"', '""')}")`)
    .all();

  return result.results || [];
}

async function tableExists(env, table) {
  const rows = await tableInfo(env, table);
  return rows.length > 0;
}

function findColumn(columns, names) {
  const map = new Map(
    columns.map(c => [
      String(c.name).toLowerCase(),
      c.name
    ])
  );

  for (const name of names) {
    const found = map.get(String(name).toLowerCase());

    if (found) return found;
  }

  return null;
}

function hasColumn(columns, name) {
  return !!findColumn(columns, [name]);
}

function q(identifier) {
  return `"${String(identifier).replaceAll('"', '""')}"`;
}

function valuesObject(columns, data) {
  const result = {};

  for (const column of columns) {
    const name = column.name;

    if (
      Object.prototype.hasOwnProperty.call(
        data,
        name
      )
    ) {
      result[name] = data[name];
    }
  }

  return result;
}

async function dynamicInsert(env, table, data) {
  const columns = await tableInfo(env, table);

  if (!columns.length) {
    throw new Error(`D1_ERROR: table ${table} không tồn tại`);
  }

  const obj = valuesObject(columns, data);

  const keys = Object.keys(obj);

  if (!keys.length) {
    throw new Error(`D1_ERROR: không tìm thấy cột phù hợp trong ${table}`);
  }

  const placeholders = keys.map(() => "?").join(", ");

  const sql = `
    INSERT INTO ${q(table)}
    (${keys.map(q).join(", ")})
    VALUES (${placeholders})
  `;

  const result = await env.DB
    .prepare(sql)
    .bind(...keys.map(k => obj[k]))
    .run();

  return result;
}


/* =========================================================
   ROLE COMPATIBILITY
========================================================= */

async function getRoleCandidates(env) {
  try {
    const row = await env.DB
      .prepare(`
        SELECT sql
        FROM sqlite_master
        WHERE type='table'
        AND name='users'
      `)
      .first();

    const sql = String(row?.sql || "");

    const match = sql.match(
      /CHECK\s*\(\s*["'`]?role["'`]?\s+IN\s*\(([^)]+)\)/i
    );

    if (!match) return [];

    const values = [...match[1].matchAll(
      /['"]([^'"]+)['"]/g
    )].map(x => x[1]);

    return values;
  } catch {
    return [];
  }
}

async function getSafePlayerRole(env, usersColumns) {
  const roleColumn = findColumn(
    usersColumns,
    ["role"]
  );

  if (!roleColumn) return null;

  const candidates = await getRoleCandidates(env);

  if (candidates.length) {
    const preferred = [
      "PLAYER",
      "USER",
      "MEMBER",
      "USER_PLAYER"
    ];

    for (const wanted of preferred) {
      const found = candidates.find(
        x => x.toUpperCase() === wanted
      );

      if (found) return found;
    }

    return candidates[0];
  }

  /*
   * If role is NOT required, simply omit it.
   */
  const info = usersColumns.find(
    x => x.name === roleColumn
  );

  if (info && Number(info.notnull) === 0) {
    return null;
  }

  /*
   * Most schemas use PLAYER.
   * This is only reached when no CHECK information
   * is exposed by sqlite_master.
   */
  return "PLAYER";
}


/* =========================================================
   USERS
========================================================= */

async function getUsersSchema(env) {
  const columns = await tableInfo(env, "users");

  if (!columns.length) {
    throw new Error("D1_ERROR: table users không tồn tại");
  }

  return {
    columns,

    id: findColumn(columns, [
      "id",
      "user_id"
    ]),

    username: findColumn(columns, [
      "username",
      "account_name",
      "user_name",
      "name"
    ]),

    email: findColumn(columns, [
      "email",
      "mail"
    ]),

    password: findColumn(columns, [
      "password_hash",
      "password",
      "pass_hash"
    ]),

    role: findColumn(columns, [
      "role"
    ]),

    balance: findColumn(columns, [
      "balance",
      "wallet_balance",
      "money",
      "amount"
    ]),

    created: findColumn(columns, [
      "created_at",
      "created",
      "registered_at"
    ]),

    updated: findColumn(columns, [
      "updated_at",
      "updated"
    ])
  };
}

async function findUserByEmail(env, email) {
  const s = await getUsersSchema(env);

  if (!s.email) {
    throw new Error(
      "D1_ERROR: users không có cột email"
    );
  }

  const row = await env.DB
    .prepare(`
      SELECT *
      FROM ${q("users")}
      WHERE lower(${q(s.email)}) = lower(?)
      LIMIT 1
    `)
    .bind(email)
    .first();

  return row || null;
}

async function findUserById(env, id) {
  const s = await getUsersSchema(env);

  if (!s.id) {
    throw new Error(
      "D1_ERROR: users không có cột id"
    );
  }

  return await env.DB
    .prepare(`
      SELECT *
      FROM ${q("users")}
      WHERE ${q(s.id)} = ?
      LIMIT 1
    `)
    .bind(id)
    .first();
}

function publicUser(user, schema) {
  if (!user) return null;

  return {
    id: schema.id ? user[schema.id] : null,
    username: schema.username
      ? user[schema.username]
      : "",
    email: schema.email
      ? user[schema.email]
      : "",
    role: schema.role
      ? user[schema.role]
      : "PLAYER",
    balance: schema.balance
      ? Number(user[schema.balance] || 0)
      : 0
  };
}


/* =========================================================
   SESSION
========================================================= */

async function getSessionSchema(env) {
  const columns = await tableInfo(env, "sessions");

  if (!columns.length) {
    throw new Error(
      "D1_ERROR: table sessions không tồn tại"
    );
  }

  return {
    columns,

    id: findColumn(columns, [
      "id",
      "session_id"
    ]),

    token: findColumn(columns, [
      "token",
      "session_token",
      "access_token"
    ]),

    userId: findColumn(columns, [
      "user_id",
      "userid",
      "uid"
    ]),

    expires: findColumn(columns, [
      "expires_at",
      "expires",
      "expiry"
    ]),

    created: findColumn(columns, [
      "created_at",
      "created"
    ])
  };
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie");

  if (!header) return null;

  const parts = header.split(";");

  for (const part of parts) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part
      .slice(0, index)
      .trim();

    const value = part
      .slice(index + 1)
      .trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function sessionCookie(token) {
  return [
    `session_token=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "session_token=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

async function createSession(env, userId) {
  const s = await getSessionSchema(env);

  if (!s.token || !s.userId) {
    throw new Error(
      "D1_ERROR: sessions thiếu cột token/session_token hoặc user_id"
    );
  }

  const token = randomToken(32);

  const expires = new Date(
    Date.now() + SESSION_DAYS * 86400000
  ).toISOString();

  const data = {};

  data[s.token] = token;
  data[s.userId] = userId;

  if (s.expires) {
    data[s.expires] = expires;
  }

  if (s.created) {
    data[s.created] = nowISO();
  }

  await dynamicInsert(
    env,
    "sessions",
    data
  );

  return token;
}

async function getCurrentUser(request, env) {
  const token = getCookie(
    request,
    "session_token"
  );

  if (!token) return null;

  const ss = await getSessionSchema(env);

  if (!ss.token || !ss.userId) {
    return null;
  }

  let row;

  if (ss.expires) {
    row = await env.DB
      .prepare(`
        SELECT *
        FROM ${q("sessions")}
        WHERE ${q(ss.token)} = ?
        AND (
          ${q(ss.expires)} IS NULL
          OR ${q(ss.expires)} > ?
        )
        LIMIT 1
      `)
      .bind(token, nowISO())
      .first();
  } else {
    row = await env.DB
      .prepare(`
        SELECT *
        FROM ${q("sessions")}
        WHERE ${q(ss.token)} = ?
        LIMIT 1
      `)
      .bind(token)
      .first();
  }

  if (!row) return null;

  const userId = row[ss.userId];

  if (userId === undefined || userId === null) {
    return null;
  }

  const user = await findUserById(
    env,
    userId
  );

  if (!user) return null;

  const schema = await getUsersSchema(env);

  return {
    raw: user,
    user: publicUser(user, schema),
    token
  };
}

async function deleteCurrentSession(request, env) {
  const token = getCookie(
    request,
    "session_token"
  );

  if (!token) return;

  const ss = await getSessionSchema(env);

  if (!ss.token) return;

  await env.DB
    .prepare(`
      DELETE FROM ${q("sessions")}
      WHERE ${q(ss.token)} = ?
    `)
    .bind(token)
    .run();
}


/* =========================================================
   REQUEST BODY
========================================================= */

async function body(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function cleanEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function cleanUsername(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}


/* =========================================================
   AUTH REGISTER
========================================================= */

async function register(request, env) {
  const data = await body(request);

  const username = cleanUsername(
    data.username
  );

  const email = cleanEmail(
    data.email
  );

  const password = String(
    data.password || ""
  );

  const passwordConfirm = String(
    data.password_confirm ??
    data.passwordConfirm ??
    ""
  );

  if (username.length < 3) {
    return json({
      ok: false,
      error: "Tên tài khoản phải có ít nhất 3 ký tự."
    }, 400);
  }

  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
    return json({
      ok: false,
      error: "Tên tài khoản chỉ được dùng chữ, số, _, . hoặc -."
    }, 400);
  }

  if (!email || !email.includes("@")) {
    return json({
      ok: false,
      error: "Email không hợp lệ."
    }, 400);
  }

  if (password.length < 6) {
    return json({
      ok: false,
      error: "Mật khẩu phải có ít nhất 6 ký tự."
    }, 400);
  }

  if (password !== passwordConfirm) {
    return json({
      ok: false,
      error: "Mật khẩu nhập lại không khớp."
    }, 400);
  }

  const schema = await getUsersSchema(env);

  if (!schema.email || !schema.password) {
    throw new Error(
      "D1_ERROR: users thiếu cột email hoặc password/password_hash"
    );
  }

  if (schema.username) {
    const existingUsername = await env.DB
      .prepare(`
        SELECT ${q(schema.id || schema.email)}
        FROM ${q("users")}
        WHERE lower(${q(schema.username)}) = lower(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

    if (existingUsername) {
      return json({
        ok: false,
        error: "Tên tài khoản đã tồn tại."
      }, 409);
    }
  }

  const existingEmail = await findUserByEmail(
    env,
    email
  );

  if (existingEmail) {
    return json({
      ok: false,
      error: "Email này đã được đăng ký."
    }, 409);
  }

  const passwordHash = await hashPassword(
    password
  );

  const insert = {};

  if (schema.username) {
    insert[schema.username] = username;
  }

  insert[schema.email] = email;
  insert[schema.password] = passwordHash;

  if (schema.role) {
    const role = await getSafePlayerRole(
      env,
      schema.columns
    );

    if (role !== null) {
      insert[schema.role] = role;
    }
  }

  if (schema.balance) {
    insert[schema.balance] = 0;
  }

  if (schema.created) {
    insert[schema.created] = nowISO();
  }

  if (schema.updated) {
    insert[schema.updated] = nowISO();
  }

  try {
    await dynamicInsert(
      env,
      "users",
      insert
    );
  } catch (err) {
    const message = safeError(err);

    if (
      message.includes("UNIQUE") ||
      message.includes("unique")
    ) {
      return json({
        ok: false,
        error: "Email hoặc tên tài khoản đã tồn tại."
      }, 409);
    }

    throw err;
  }

  const createdUser = await findUserByEmail(
    env,
    email
  );

  if (!createdUser) {
    throw new Error(
      "Tạo tài khoản thành công nhưng không đọc lại được user."
    );
  }

  const userId = schema.id
    ? createdUser[schema.id]
    : null;

  if (userId === null || userId === undefined) {
    throw new Error(
      "users không có ID hợp lệ để tạo session."
    );
  }

  const token = await createSession(
    env,
    userId
  );

  return json(
    {
      ok: true,
      message: "Tạo tài khoản thành công.",
      user: publicUser(
        createdUser,
        schema
      )
    },
    201,
    {
      "Set-Cookie": sessionCookie(token)
    }
  );
}


/* =========================================================
   AUTH LOGIN
========================================================= */

async function login(request, env) {
  const data = await body(request);

  const email = cleanEmail(
    data.email
  );

  const password = String(
    data.password || ""
  );

  if (!email || !password) {
    return json({
      ok: false,
      error: "Vui lòng nhập email và mật khẩu."
    }, 400);
  }

  const schema = await getUsersSchema(env);

  const user = await findUserByEmail(
    env,
    email
  );

  if (!user) {
    return json({
      ok: false,
      error: "Email hoặc mật khẩu không đúng."
    }, 401);
  }

  const storedPassword = user[
    schema.password
  ];

  const valid = await verifyPassword(
    password,
    storedPassword
  );

  if (!valid) {
    return json({
      ok: false,
      error: "Email hoặc mật khẩu không đúng."
    }, 401);
  }

  const userId = schema.id
    ? user[schema.id]
    : null;

  if (userId === null || userId === undefined) {
    throw new Error(
      "users không có ID hợp lệ."
    );
  }

  /*
   * Xoá session cũ cùng user để tránh session rác.
   */
  try {
    const ss = await getSessionSchema(env);

    if (ss.userId) {
      await env.DB
        .prepare(`
          DELETE FROM ${q("sessions")}
          WHERE ${q(ss.userId)} = ?
        `)
        .bind(userId)
        .run();
    }
  } catch {}

  const token = await createSession(
    env,
    userId
  );

  return json(
    {
      ok: true,
      message: "Đăng nhập thành công.",
      user: publicUser(user, schema)
    },
    200,
    {
      "Set-Cookie": sessionCookie(token)
    }
  );
}


/* =========================================================
   SETTINGS
========================================================= */

async function settingsMap(env) {
  if (!(await tableExists(env, "settings"))) {
    return {};
  }

  const columns = await tableInfo(
    env,
    "settings"
  );

  const keyColumn = findColumn(
    columns,
    [
      "key",
      "setting_key",
      "name"
    ]
  );

  const valueColumn = findColumn(
    columns,
    [
      "value",
      "setting_value",
      "content"
    ]
  );

  if (!keyColumn || !valueColumn) {
    return {};
  }

  const rows = await env.DB
    .prepare(`
      SELECT
        ${q(keyColumn)} AS k,
        ${q(valueColumn)} AS v
      FROM ${q("settings")}
    `)
    .all();

  const result = {};

  for (const row of rows.results || []) {
    result[String(row.k)] = row.v;
  }

  return result;
}


/* =========================================================
   TOURNAMENT
========================================================= */

async function tournaments(env) {
  if (!(await tableExists(env, "tournaments"))) {
    return [];
  }

  const columns = await tableInfo(
    env,
    "tournaments"
  );

  const id = findColumn(columns, [
    "id",
    "tournament_id"
  ]);

  const name = findColumn(columns, [
    "name",
    "title",
    "tournament_name"
  ]);

  const description = findColumn(columns, [
    "description",
    "details",
    "content"
  ]);

  const start = findColumn(columns, [
    "start_at",
    "starts_at",
    "date",
    "scheduled_at"
  ]);

  const status = findColumn(columns, [
    "status",
    "state"
  ]);

  const maxTeams = findColumn(columns, [
    "max_teams",
    "max_team",
    "capacity",
    "slots"
  ]);

  const fee = findColumn(columns, [
    "entry_fee",
    "fee",
    "registration_fee",
    "price"
  ]);

  const rows = await env.DB
    .prepare(`
      SELECT *
      FROM ${q("tournaments")}
      ORDER BY ${
        start
          ? q(start)
          : q(id || columns[0].name)
      } ASC
    `)
    .all();

  return (rows.results || []).map(row => ({
    id: id ? row[id] : null,
    name: name
      ? row[name]
      : "Giải đấu",
    description: description
      ? row[description]
      : "",
    start_at: start
      ? row[start]
      : null,
    status: status
      ? row[status]
      : "OPEN",
    max_teams: maxTeams
      ? Number(row[maxTeams] || 0)
      : 0,
    entry_fee: fee
      ? Number(row[fee] || 0)
      : 0
  }));
}


/* =========================================================
   TEAMS
========================================================= */

async function registerTeam(request, env) {
  const current = await getCurrentUser(
    request,
    env
  );

  if (!current) {
    return json({
      ok: false,
      error: "Bạn cần đăng nhập."
    }, 401);
  }

  const data = await body(request);

  const tournamentId = data.tournament_id;

  const teamName = cleanUsername(
    data.team_name
  );

  const teamEmail = cleanEmail(
    data.team_email
  );

  const logo = String(
    data.logo || ""
  ).trim();

  if (!tournamentId) {
    return json({
      ok: false,
      error: "Thiếu giải đấu."
    }, 400);
  }

  if (teamName.length < 2) {
    return json({
      ok: false,
      error: "Tên team không hợp lệ."
    }, 400);
  }

  if (!teamEmail || !teamEmail.includes("@")) {
    return json({
      ok: false,
      error: "Gmail của team không hợp lệ."
    }, 400);
  }

  if (!(await tableExists(env, "teams"))) {
    throw new Error(
      "D1_ERROR: database hiện tại chưa có bảng teams."
    );
  }

  if (!(await tableExists(
    env,
    "registrations"
  ))) {
    throw new Error(
      "D1_ERROR: database hiện tại chưa có bảng registrations."
    );
  }

  const teamColumns = await tableInfo(
    env,
    "teams"
  );

  const teamIdColumn = findColumn(
    teamColumns,
    [
      "id",
      "team_id"
    ]
  );

  const teamNameColumn = findColumn(
    teamColumns,
    [
      "name",
      "team_name"
    ]
  );

  const teamEmailColumn = findColumn(
    teamColumns,
    [
      "email",
      "team_email",
      "gmail"
    ]
  );

  const teamLogoColumn = findColumn(
    teamColumns,
    [
      "logo",
      "logo_url",
      "avatar"
    ]
  );

  const teamOwnerColumn = findColumn(
    teamColumns,
    [
      "user_id",
      "owner_id",
      "created_by"
    ]
  );

  const createdColumn = findColumn(
    teamColumns,
    [
      "created_at",
      "created"
    ]
  );

  if (!teamNameColumn) {
    throw new Error(
      "D1_ERROR: teams không có cột tên team."
    );
  }

  const teamInsert = {};

  teamInsert[teamNameColumn] = teamName;

  if (teamEmailColumn) {
    teamInsert[teamEmailColumn] = teamEmail;
  }

  if (teamLogoColumn) {
    teamInsert[teamLogoColumn] = logo;
  }

  if (teamOwnerColumn) {
    teamInsert[teamOwnerColumn] =
      current.user.id;
  }

  if (createdColumn) {
    teamInsert[createdColumn] =
      nowISO();
  }

  await dynamicInsert(
    env,
    "teams",
    teamInsert
  );

  let team = null;

  if (teamIdColumn) {
    team = await env.DB
      .prepare(`
        SELECT *
        FROM ${q("teams")}
        WHERE ${q(teamNameColumn)} = ?
        ORDER BY ${
          createdColumn
            ? q(createdColumn)
            : q(teamIdColumn)
        } DESC
        LIMIT 1
      `)
      .bind(teamName)
      .first();
  }

  const registrationColumns =
    await tableInfo(
      env,
      "registrations"
    );

  const registration = {};

  const rTournament = findColumn(
    registrationColumns,
    [
      "tournament_id",
      "tournament"
    ]
  );

  const rTeam = findColumn(
    registrationColumns,
    [
      "team_id",
      "team"
    ]
  );

  const rUser = findColumn(
    registrationColumns,
    [
      "user_id",
      "owner_id"
    ]
  );

  const rStatus = findColumn(
    registrationColumns,
    [
      "status",
      "state"
    ]
  );

  const rCreated = findColumn(
    registrationColumns,
    [
      "created_at",
      "created"
    ]
  );

  if (rTournament) {
    registration[rTournament] =
      tournamentId;
  }

  if (rTeam && team && teamIdColumn) {
    registration[rTeam] =
      team[teamIdColumn];
  }

  if (rUser) {
    registration[rUser] =
      current.user.id;
  }

  if (rStatus) {
    registration[rStatus] =
      "PENDING_PAYMENT";
  }

  if (rCreated) {
    registration[rCreated] =
      nowISO();
  }

  await dynamicInsert(
    env,
    "registrations",
    registration
  );

  return json({
    ok: true,
    message:
      "Đăng ký team thành công. Vui lòng thanh toán phí tham dự.",
    team: team
      ? {
          id: teamIdColumn
            ? team[teamIdColumn]
            : null,
          name: teamName,
          email: teamEmail,
          logo
        }
      : {
          id: null,
          name: teamName,
          email: teamEmail,
          logo
        }
  });
}


/* =========================================================
   PAYMENT
========================================================= */

async function createPayment(request, env) {
  const current = await getCurrentUser(
    request,
    env
  );

  if (!current) {
    return json({
      ok: false,
      error: "Bạn cần đăng nhập."
    }, 401);
  }

  if (!(await tableExists(
    env,
    "payments"
  ))) {
    throw new Error(
      "D1_ERROR: database hiện tại chưa có bảng payments."
    );
  }

  const data = await body(request);

  const registrationId =
    data.registration_id || null;

  const amount = Number(
    data.amount || 0
  );

  const transferCode = String(
    data.transfer_code || ""
  ).trim();

  const columns = await tableInfo(
    env,
    "payments"
  );

  const insert = {};

  const cRegistration = findColumn(
    columns,
    [
      "registration_id",
      "registration"
    ]
  );

  const cUser = findColumn(
    columns,
    [
      "user_id",
      "payer_id"
    ]
  );

  const cAmount = findColumn(
    columns,
    [
      "amount",
      "money",
      "payment_amount"
    ]
  );

  const cStatus = findColumn(
    columns,
    [
      "status",
      "state"
    ]
  );

  const cCode = findColumn(
    columns,
    [
      "transfer_code",
      "transaction_code",
      "content",
      "reference"
    ]
  );

  const cCreated = findColumn(
    columns,
    [
      "created_at",
      "created"
    ]
  );

  if (cRegistration && registrationId) {
    insert[cRegistration] =
      registrationId;
  }

  if (cUser) {
    insert[cUser] =
      current.user.id;
  }

  if (cAmount) {
    insert[cAmount] =
      amount;
  }

  if (cStatus) {
    insert[cStatus] =
      "PENDING";
  }

  if (cCode) {
    insert[cCode] =
      transferCode;
  }

  if (cCreated) {
    insert[cCreated] =
      nowISO();
  }

  await dynamicInsert(
    env,
    "payments",
    insert
  );

  return json({
    ok: true,
    message:
      "Đã ghi nhận yêu cầu thanh toán. Trạng thái hiện tại: PENDING."
  });
}


/* =========================================================
   RANKING
========================================================= */

async function ranking(env) {
  if (!(await tableExists(
    env,
    "teams"
  ))) {
    return [];
  }

  const columns = await tableInfo(
    env,
    "teams"
  );

  const id = findColumn(columns, [
    "id",
    "team_id"
  ]);

  const name = findColumn(columns, [
    "name",
    "team_name"
  ]);

  const logo = findColumn(columns, [
    "logo",
    "logo_url",
    "avatar"
  ]);

  const points = findColumn(columns, [
    "points",
    "score",
    "ranking_points"
  ]);

  const wins = findColumn(columns, [
    "wins",
    "win"
  ]);

  const losses = findColumn(columns, [
    "losses",
    "loss"
  ]);

  if (!name) return [];

  const rows = await env.DB
    .prepare(`
      SELECT *
      FROM ${q("teams")}
      ORDER BY ${
        points
          ? q(points)
          : q(id || columns[0].name)
      } DESC
      LIMIT 50
    `)
    .all();

  return (rows.results || []).map(
    (row, index) => ({
      rank: index + 1,
      id: id
        ? row[id]
        : null,
      name: row[name],
      logo: logo
        ? row[logo]
        : "",
      points: points
        ? Number(row[points] || 0)
        : 0,
      wins: wins
        ? Number(row[wins] || 0)
        : 0,
      losses: losses
        ? Number(row[losses] || 0)
        : 0
    })
  );
}


/* =========================================================
   API
========================================================= */

async function api(request, env, url) {
  const method = request.method.toUpperCase();

  if (
    method === "OPTIONS"
  ) {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods":
          "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type"
      }
    });
  }

  /*
   * Health
   */
  if (
    url.pathname === "/api/health" &&
    method === "GET"
  ) {
    const settings =
      await settingsMap(env);

    return json({
      ok: true,
      site:
        env.SITE_NAME ||
        settings.tournament_name ||
        "GIẢI ĐẤU VUA TỬ CHIẾN – MÙA 1",
      time: nowISO()
    });
  }

  /*
   * Current account
   */
  if (
    url.pathname === "/api/auth/me" &&
    method === "GET"
  ) {
    const current =
      await getCurrentUser(
        request,
        env
      );

    return json({
      ok: true,
      logged_in: !!current,
      user: current
        ? current.user
        : null
    });
  }

  /*
   * Register
   */
  if (
    url.pathname === "/api/auth/register" &&
    method === "POST"
  ) {
    return await register(
      request,
      env
    );
  }

  /*
   * Login
   */
  if (
    url.pathname === "/api/auth/login" &&
    method === "POST"
  ) {
    return await login(
      request,
      env
    );
  }

  /*
   * Logout
   */
  if (
    url.pathname === "/api/auth/logout" &&
    method === "POST"
  ) {
    await deleteCurrentSession(
      request,
      env
    );

    return json(
      {
        ok: true,
        message: "Đã đăng xuất."
      },
      200,
      {
        "Set-Cookie":
          clearSessionCookie()
      }
    );
  }

  /*
   * Tournament
   */
  if (
    url.pathname === "/api/tournaments" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      tournaments:
        await tournaments(env)
    });
  }

  /*
   * Settings / bank
   */
  if (
    url.pathname === "/api/settings" &&
    method === "GET"
  ) {
    const settings =
      await settingsMap(env);

    return json({
      ok: true,
      settings
    });
  }

  /*
   * Register team
   */
  if (
    url.pathname === "/api/teams/register" &&
    method === "POST"
  ) {
    return await registerTeam(
      request,
      env
    );
  }

  /*
   * Payment
   */
  if (
    url.pathname === "/api/payments" &&
    method === "POST"
  ) {
    return await createPayment(
      request,
      env
    );
  }

  /*
   * Ranking
   */
  if (
    url.pathname === "/api/ranking" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      ranking:
        await ranking(env)
    });
  }

  return json({
    ok: false,
    error: "API endpoint không tồn tại."
  }, 404);
}
