// ============================================================
// GIẢI ĐẤU TỬ CHIẾN MÙA 1
// Cloudflare Worker + D1
// Auth dùng Web Crypto - không cần package
// Tương thích DB cũ/mới:
// - password_hash
// - password_salt nếu DB bắt buộc
// - role PLAYER / ADMIN / SUPER_ADMIN
// - sessions token/session_token
// - audit_logs có hoặc không có
// ============================================================

const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

const jsonHeaders = {
  "content-type": "application/json; charset=UTF-8",
  "cache-control": "no-store"
};

// ============================================================
// RESPONSE
// ============================================================

function ok(data = {}, status = 200) {
  return new Response(
    JSON.stringify({
      success: true,
      ...data
    }),
    {
      status,
      headers: jsonHeaders
    }
  );
}

function fail(message, status = 400, extra = {}) {
  return new Response(
    JSON.stringify({
      success: false,
      error: message,
      ...extra
    }),
    {
      status,
      headers: jsonHeaders
    }
  );
}

// ============================================================
// BODY
// ============================================================

async function bodyJSON(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

// ============================================================
// STRING
// ============================================================

function clean(value) {
  return String(value ?? "").trim();
}

function emailClean(value) {
  return clean(value).toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,30}$/.test(username);
}

// ============================================================
// BASE64
// ============================================================

function bytesToBase64(bytes) {
  let binary = "";

  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, Math.min(i + chunk, bytes.length))
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

// ============================================================
// RANDOM
// ============================================================

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return bytesToBase64(data)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// ============================================================
// PASSWORD
//
// SHA-256 + random salt.
// Nếu DB có password_salt NOT NULL:
//    lưu salt.
// Nếu DB không có password_salt:
//    chỉ lưu hash.
// ============================================================

async function sha256(text) {
  const encoded = new TextEncoder().encode(text);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoded
  );

  return bytesToBase64(new Uint8Array(digest));
}

async function hashPassword(password, salt) {
  return await sha256(`${salt}:${password}`);
}

async function createPassword(password) {
  const salt = randomToken(16);
  const hash = await hashPassword(password, salt);

  return {
    hash,
    salt
  };
}

async function verifyPassword(password, storedHash, storedSalt = "") {
  // Trường hợp DB có salt
  if (storedSalt) {
    const hash = await hashPassword(password, storedSalt);

    return timingSafeEqual(
      hash,
      String(storedHash)
    );
  }

  // Trường hợp DB cũ chỉ có password_hash
  const directHash = await sha256(password);

  return timingSafeEqual(
    directHash,
    String(storedHash)
  );
}

function timingSafeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));

  if (x.length !== y.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < x.length; i++) {
    result |= x[i] ^ y[i];
  }

  return result === 0;
}

// ============================================================
// DB SCHEMA
// ============================================================

async function getTableColumns(env, table) {
  try {
    const result = await env.DB
      .prepare(`PRAGMA table_info("${table}")`)
      .all();

    return result.results || [];
  } catch {
    return [];
  }
}

async function hasTable(env, table) {
  try {
    const result = await env.DB
      .prepare(`
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        LIMIT 1
      `)
      .bind(table)
      .first();

    return !!result;
  } catch {
    return false;
  }
}

function columnMap(columns) {
  const map = {};

  for (const c of columns) {
    map[c.name] = c;
  }

  return map;
}

// ============================================================
// USERS
// ============================================================

async function getUsersColumns(env) {
  return await getTableColumns(env, "users");
}

async function findUserByEmail(env, email) {
  const columns = await getUsersColumns(env);

  if (!columns.length) {
    throw new Error("Bảng users không tồn tại.");
  }

  const names = columns.map(x => x.name);

  const select = [
    "id",
    names.includes("email") ? "email" : "NULL AS email",
    names.includes("password_hash")
      ? "password_hash"
      : "NULL AS password_hash",
    names.includes("password_salt")
      ? "password_salt"
      : "NULL AS password_salt",
    names.includes("role")
      ? "role"
      : "NULL AS role",
    names.includes("username")
      ? "username"
      : names.includes("name")
        ? "name AS username"
        : "NULL AS username",
    names.includes("balance")
      ? "balance"
      : names.includes("wallet")
        ? "wallet AS balance"
        : "0 AS balance",
    names.includes("created_at")
      ? "created_at"
      : "NULL AS created_at"
  ];

  return await env.DB
    .prepare(`
      SELECT ${select.join(", ")}
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();
}

// ============================================================
// REGISTER
// ============================================================

async function registerUser(env, data) {
  const username = clean(
    data.username ||
    data.account_name ||
    data.name
  );

  const email = emailClean(data.email);
  const password = String(data.password || "");

  if (!validUsername(username)) {
    throw new Error(
      "Tên tài khoản phải từ 3-30 ký tự và chỉ gồm chữ, số, dấu chấm, gạch ngang hoặc gạch dưới."
    );
  }

  if (!validEmail(email)) {
    throw new Error("Email không hợp lệ.");
  }

  if (password.length < 8) {
    throw new Error("Mật khẩu phải có ít nhất 8 ký tự.");
  }

  const columns = await getUsersColumns(env);

  if (!columns.length) {
    throw new Error("Bảng users không tồn tại trong D1.");
  }

  const map = columnMap(columns);

  // Kiểm tra email
  const oldEmail = await env.DB
    .prepare(`
      SELECT id
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (oldEmail) {
    throw new Error("Email này đã được đăng ký.");
  }

  // Nếu DB có username/name thì kiểm tra
  if (map.username || map.name) {
    const usernameColumn = map.username
      ? "username"
      : "name";

    const oldUsername = await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE ${usernameColumn} = ?
        LIMIT 1
      `)
      .bind(username)
      .first();

    if (oldUsername) {
      throw new Error("Tên tài khoản này đã tồn tại.");
    }
  }

  const password = await createPassword(password);

  // ----------------------------------------------------------
  // QUAN TRỌNG:
  //
  // DB thực tế của bạn đang CHECK role:
  // ('PLAYER','ADMIN','SUPER_ADMIN')
  //
  // Vì vậy USER sẽ lỗi.
  //
  // Tài khoản đăng ký bình thường = PLAYER.
  // ----------------------------------------------------------

  const insertColumns = [];
  const values = [];

  function add(column, value) {
    if (map[column]) {
      insertColumns.push(column);
      values.push(value);
    }
  }

  add("email", email);
  add("password_hash", password.hash);

  // DB cũ có password_salt NOT NULL -> phải điền.
  if (map.password_salt) {
    add("password_salt", password.salt);
  }

  if (map.username) {
    add("username", username);
  } else if (map.name) {
    add("name", username);
  }

  if (map.role) {
    // tương thích CHECK constraint thực tế
    add("role", "PLAYER");
  }

  if (map.balance) {
    add("balance", 0);
  } else if (map.wallet) {
    add("wallet", 0);
  }

  // Không insert created_at nếu DB đã có DEFAULT.
  // Nếu NOT NULL nhưng không DEFAULT thì xử lý.
  if (
    map.created_at &&
    map.created_at.notnull === 1 &&
    map.created_at.dflt_value == null
  ) {
    add("created_at", new Date().toISOString());
  }

  if (!insertColumns.length) {
    throw new Error("Không xác định được cấu trúc bảng users.");
  }

  const placeholders = insertColumns
    .map(() => "?")
    .join(", ");

  try {
    const result = await env.DB
      .prepare(`
        INSERT INTO users
        (${insertColumns.join(", ")})
        VALUES
        (${placeholders})
      `)
      .bind(...values)
      .run();

    const userId =
      result.meta?.last_row_id ||
      result.meta?.last_rowid;

    // Audit KHÔNG được làm hỏng đăng ký
    await safeAudit(
      env,
      userId || null,
      "REGISTER",
      "users",
      {
        username,
        email
      }
    );

    return {
      id: userId,
      username,
      email,
      role: "PLAYER",
      balance: 0
    };

  } catch (error) {
    const message = String(error?.message || error);

    if (/UNIQUE/i.test(message)) {
      throw new Error("Email hoặc tên tài khoản đã tồn tại.");
    }

    if (/password_salt/i.test(message)) {
      throw new Error(
        "DB đang yêu cầu password_salt. Code đã hỗ trợ password_salt, hãy kiểm tra cấu trúc bảng users."
      );
    }

    if (/role.*CHECK/i.test(message)) {
      throw new Error(
        "DB đang giới hạn role. Tài khoản thường phải dùng PLAYER."
      );
    }

    throw error;
  }
}

// ============================================================
// SESSION COLUMN COMPATIBILITY
// ============================================================

async function getSessionInfo(env) {
  const columns = await getTableColumns(env, "sessions");

  if (!columns.length) {
    throw new Error("Bảng sessions không tồn tại.");
  }

  const names = columns.map(x => x.name);

  let tokenColumn = null;

  if (names.includes("token")) {
    tokenColumn = "token";
  } else if (names.includes("session_token")) {
    tokenColumn = "session_token";
  } else if (names.includes("session_id")) {
    tokenColumn = "session_id";
  }

  if (!tokenColumn) {
    throw new Error(
      "Không tìm thấy cột token/session_token trong bảng sessions."
    );
  }

  const userColumn = names.includes("user_id")
    ? "user_id"
    : names.includes("userid")
      ? "userid"
      : null;

  const expiresColumn = names.includes("expires_at")
    ? "expires_at"
    : names.includes("expires")
      ? "expires"
      : null;

  if (!userColumn || !expiresColumn) {
    throw new Error(
      "Bảng sessions thiếu user_id hoặc expires_at."
    );
  }

  return {
    columns,
    names,
    tokenColumn,
    userColumn,
    expiresColumn
  };
}

// ============================================================
// COOKIE
// ============================================================

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function sessionCookie(token, maxAge = SESSION_SECONDS) {
  return [
    `session=${encodeURIComponent(token)}`,
    `Max-Age=${maxAge}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "session=",
    "Max-Age=0",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

// ============================================================
// CREATE SESSION
// ============================================================

async function createSession(env, userId) {
  const info = await getSessionInfo(env);

  const token = randomToken(32);

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_SECONDS;

  const columns = [];
  const values = [];

  columns.push(info.tokenColumn);
  values.push(token);

  columns.push(info.userColumn);
  values.push(userId);

  columns.push(info.expiresColumn);
  values.push(expiresAt);

  const placeholders = columns.map(() => "?").join(", ");

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (${columns.join(", ")})
      VALUES
      (${placeholders})
    `)
    .bind(...values)
    .run();

  return token;
}

// ============================================================
// CURRENT USER
// ============================================================

async function getCurrentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  try {
    const info = await getSessionInfo(env);

    const now = Math.floor(Date.now() / 1000);

    const row = await env.DB
      .prepare(`
        SELECT
          s.${info.userColumn} AS user_id
        FROM sessions s
        WHERE s.${info.tokenColumn} = ?
          AND s.${info.expiresColumn} > ?
        LIMIT 1
      `)
      .bind(token, now)
      .first();

    if (!row?.user_id) {
      return null;
    }

    const user = await env.DB
      .prepare(`
        SELECT *
        FROM users
        WHERE id = ?
        LIMIT 1
      `)
      .bind(row.user_id)
      .first();

    if (!user) {
      return null;
    }

    const username =
      user.username ||
      user.name ||
      user.account_name ||
      user.email?.split("@")[0] ||
      "Tài khoản";

    const balance =
      Number(
        user.balance ??
        user.wallet ??
        0
      ) || 0;

    return {
      id: user.id,
      username,
      email: user.email,
      role: user.role || "PLAYER",
      balance
    };

  } catch {
    return null;
  }
}

// ============================================================
// LOGOUT
// ============================================================

async function logout(request, env) {
  const token = getCookie(request, "session");

  if (token) {
    try {
      const info = await getSessionInfo(env);

      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE ${info.tokenColumn} = ?
        `)
        .bind(token)
        .run();

    } catch {
      // Không để logout crash
    }
  }

  return new Response(
    JSON.stringify({
      success: true,
      message: "Đã đăng xuất."
    }),
    {
      status: 200,
      headers: {
        ...jsonHeaders,
        "Set-Cookie": clearSessionCookie()
      }
    }
  );
}

// ============================================================
// AUDIT
// ============================================================

async function safeAudit(
  env,
  userId,
  action,
  target = null,
  details = null
) {
  try {
    const exists = await hasTable(env, "audit_logs");

    if (!exists) {
      return;
    }

    const columns = await getTableColumns(
      env,
      "audit_logs"
    );

    const names = columns.map(x => x.name);

    if (
      !names.includes("action")
    ) {
      return;
    }

    const insertColumns = [];
    const values = [];

    if (names.includes("user_id")) {
      insertColumns.push("user_id");
      values.push(userId);
    }

    insertColumns.push("action");
    values.push(action);

    if (names.includes("target")) {
      insertColumns.push("target");
      values.push(target);
    }

    if (names.includes("details")) {
      insertColumns.push("details");
      values.push(
        details == null
          ? null
          : JSON.stringify(details)
      );
    }

    if (names.includes("created_at")) {
      const created = columns.find(
        x => x.name === "created_at"
      );

      if (
        created.notnull === 1 &&
        created.dflt_value == null
      ) {
        insertColumns.push("created_at");
        values.push(
          new Date().toISOString()
        );
      }
    }

    const placeholders =
      insertColumns.map(() => "?").join(", ");

    await env.DB
      .prepare(`
        INSERT INTO audit_logs
        (${insertColumns.join(", ")})
        VALUES
        (${placeholders})
      `)
      .bind(...values)
      .run();

  } catch {
    // Audit log chỉ là phụ.
    // Tuyệt đối không làm REGISTER / LOGIN thất bại.
  }
}

// ============================================================
// AUTH REGISTER
// ============================================================

async function handleRegister(request, env) {
  const data = await bodyJSON(request);

  try {
    const user = await registerUser(env, data);

    return ok({
      message: "Tạo tài khoản thành công!",
      user
    });

  } catch (error) {
    return fail(
      `Không thể tạo tài khoản: ${error.message}`,
      400
    );
  }
}

// ============================================================
// AUTH LOGIN
// ============================================================

async function handleLogin(request, env) {
  const data = await bodyJSON(request);

  const email = emailClean(data.email);
  const password = String(data.password || "");

  if (!validEmail(email)) {
    return fail("Email không hợp lệ.", 400);
  }

  if (!password) {
    return fail("Vui lòng nhập mật khẩu.", 400);
  }

  try {
    const user = await findUserByEmail(
      env,
      email
    );

    if (!user) {
      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401
      );
    }

    const valid = await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

    if (!valid) {
      await safeAudit(
        env,
        user.id,
        "LOGIN_FAILED",
        "users",
        { email }
      );

      return fail(
        "Email hoặc mật khẩu không chính xác.",
        401
      );
    }

    const token = await createSession(
      env,
      user.id
    );

    const username =
      user.username ||
      user.email.split("@")[0];

    const balance =
      Number(user.balance || 0);

    const role =
      user.role || "PLAYER";

    await safeAudit(
      env,
      user.id,
      "LOGIN",
      "users",
      { email }
    );

    return new Response(
      JSON.stringify({
        success: true,
        message: "Đăng nhập thành công!",
        user: {
          id: user.id,
          username,
          email: user.email,
          role,
          balance
        }
      }),
      {
        status: 200,
        headers: {
          ...jsonHeaders,
          "Set-Cookie": sessionCookie(token)
        }
      }
    );

  } catch (error) {
    return fail(
      `Không thể đăng nhập: ${error.message}`,
      500
    );
  }
}

// ============================================================
// AUTH ME
// ============================================================

async function handleMe(request, env) {
  const user =
    await getCurrentUser(request, env);

  return ok({
    authenticated: !!user,
    user
  });
}

// ============================================================
// TOURNAMENTS
// ============================================================

async function handleTournaments(env) {
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
      `Không thể tải giải đấu: ${error.message}`,
      500
    );
  }
}

// ============================================================
// RANKING
// ============================================================

async function handleRanking(env) {
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
        ORDER BY points DESC, kills DESC
        LIMIT 100
      `)
      .all();

    return ok({
      ranking: result.results || []
    });

  } catch (error) {
    return fail(
      `Không thể tải bảng xếp hạng: ${error.message}`,
      500
    );
  }
}

// ============================================================
// SLOTS
// ============================================================

async function handleSlots(env, tournamentId) {
  if (!tournamentId) {
    return fail("Thiếu tournament_id.", 400);
  }

  try {
    const result = await env.DB
      .prepare(`
        SELECT
          s.id,
          s.tournament_id,
          s.slot_time,
          s.group_name,
          s.capacity,
          COUNT(r.id) AS registered
        FROM slots s
        LEFT JOIN registrations r
          ON r.slot_id = s.id
          AND r.status != 'CANCELLED'
        WHERE s.tournament_id = ?
        GROUP BY
          s.id,
          s.tournament_id,
          s.slot_time,
          s.group_name,
          s.capacity
        ORDER BY s.slot_time ASC
      `)
      .bind(tournamentId)
      .all();

    return ok({
      slots: result.results || []
    });

  } catch (error) {
    return fail(
      `Không thể tải khung giờ: ${error.message}`,
      500
    );
  }
}

// ============================================================
// TEAM REGISTER
// ============================================================

async function handleTeamRegister(request, env) {
  const user =
    await getCurrentUser(request, env);

  if (!user) {
    return fail(
      "Bạn cần đăng nhập trước.",
      401
    );
  }

  const data = await bodyJSON(request);

  const name = clean(data.name);
  const tag = clean(data.tag);
  const logoUrl = clean(
    data.logo_url ||
    data.logoUrl
  );

  if (name.length < 2) {
    return fail(
      "Tên đội phải có ít nhất 2 ký tự.",
      400
    );
  }

  try {
    const result = await env.DB
      .prepare(`
        INSERT INTO teams
        (
          owner_id,
          name,
          tag,
          logo_url,
          status
        )
        VALUES
        (?, ?, ?, ?, 'PENDING')
      `)
      .bind(
        user.id,
        name,
        tag || null,
        logoUrl || null
      )
      .run();

    const teamId =
      result.meta?.last_row_id;

    await safeAudit(
      env,
      user.id,
      "CREATE_TEAM",
      `teams:${teamId}`,
      { name, tag }
    );

    return ok({
      message: "Tạo đội thành công!",
      team: {
        id: teamId,
        name,
        tag,
        logo_url: logoUrl,
        status: "PENDING"
      }
    });

  } catch (error) {
    return fail(
      `Không thể tạo đội: ${error.message}`,
      400
    );
  }
}

// ============================================================
// REGISTRATION
// ============================================================

async function handleRegistration(request, env) {
  const user =
    await getCurrentUser(request, env);

  if (!user) {
    return fail(
      "Bạn cần đăng nhập trước.",
      401
    );
  }

  const data = await bodyJSON(request);

  const teamId =
    Number(data.team_id);

  const tournamentId =
    Number(data.tournament_id);

  const slotId =
    data.slot_id
      ? Number(data.slot_id)
      : null;

  if (!teamId || !tournamentId) {
    return fail(
      "Thiếu thông tin đội hoặc giải đấu.",
      400
    );
  }

  try {
    const team = await env.DB
      .prepare(`
        SELECT *
        FROM teams
        WHERE id = ?
          AND owner_id = ?
        LIMIT 1
      `)
      .bind(teamId, user.id)
      .first();

    if (!team) {
      return fail(
        "Đội không tồn tại hoặc bạn không phải chủ đội.",
        403
      );
    }

    const tournament = await env.DB
      .prepare(`
        SELECT *
        FROM tournaments
        WHERE id = ?
          AND status = 'OPEN'
        LIMIT 1
      `)
      .bind(tournamentId)
      .first();

    if (!tournament) {
      return fail(
        "Giải đấu không tồn tại hoặc đã đóng đăng ký.",
        400
      );
    }

    if (slotId) {
      const slot = await env.DB
        .prepare(`
          SELECT *
          FROM slots
          WHERE id = ?
            AND tournament_id = ?
          LIMIT 1
        `)
        .bind(slotId, tournamentId)
        .first();

      if (!slot) {
        return fail(
          "Khung giờ không hợp lệ.",
          400
        );
      }
    }

    const existed = await env.DB
      .prepare(`
        SELECT id
        FROM registrations
        WHERE team_id = ?
          AND tournament_id = ?
          AND status != 'CANCELLED'
        LIMIT 1
      `)
      .bind(teamId, tournamentId)
      .first();

    if (existed) {
      return fail(
        "Đội này đã đăng ký giải đấu.",
        409
      );
    }

    const orderCode =
      "TD1-" +
      Date.now().toString(36).toUpperCase() +
      "-" +
      randomToken(4).toUpperCase();

    const amount =
      Number(tournament.fee || 0);

    const result = await env.DB
      .prepare(`
        INSERT INTO registrations
        (
          team_id,
          tournament_id,
          slot_id,
          order_code,
          amount,
          status
        )
        VALUES
        (?, ?, ?, ?, ?, 'AWAITING_PAYMENT')
      `)
      .bind(
        teamId,
        tournamentId,
        slotId,
        orderCode,
        amount
      )
      .run();

    const registrationId =
      result.meta?.last_row_id;

    await safeAudit(
      env,
      user.id,
      "REGISTER_TOURNAMENT",
      `registrations:${registrationId}`,
      {
        teamId,
        tournamentId,
        slotId,
        orderCode,
        amount
      }
    );

    return ok({
      message:
        "Đăng ký giải thành công, chờ thanh toán.",
      registration: {
        id: registrationId,
        order_code: orderCode,
        amount,
        status: "AWAITING_PAYMENT"
      }
    });

  } catch (error) {
    return fail(
      `Đăng ký thất bại: ${error.message}`,
      400
    );
  }
}

// ============================================================
// CONFIG PAYMENT
// ============================================================

function paymentConfig(env) {
  return {
    bankId:
      env.BANK_ID ||
      "MB",

    accountNo:
      env.BANK_ACCOUNT ||
      "",

    accountName:
      env.BANK_NAME ||
      "",

    template:
      env.BANK_QR_TEMPLATE ||
      "compact2"
  };
}

// ============================================================
// MY REGISTRATIONS
// ============================================================

async function handleMyRegistrations(request, env) {
  const user =
    await getCurrentUser(request, env);

  if (!user) {
    return fail(
      "Bạn cần đăng nhập.",
      401
    );
  }

  try {
    const result = await env.DB
      .prepare(`
        SELECT
          r.id,
          r.order_code,
          r.amount,
          r.status,
          r.created_at,
          t.name AS team_name,
          tr.name AS tournament_name,
          s.slot_time,
          s.group_name
        FROM registrations r
        JOIN teams t
          ON t.id = r.team_id
        JOIN tournaments tr
          ON tr.id = r.tournament_id
        LEFT JOIN slots s
          ON s.id = r.slot_id
        WHERE t.owner_id = ?
        ORDER BY r.id DESC
        LIMIT 50
      `)
      .bind(user.id)
      .all();

    return ok({
      registrations:
        result.results || []
    });

  } catch (error) {
    return fail(
      `Không thể tải đăng ký: ${error.message}`,
      500
    );
  }
}

// ============================================================
// API ROUTER
// ============================================================

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

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
          "Giải Đấu Tử Chiến Mùa 1"
      });

    } catch (error) {
      return fail(
        error.message,
        500
      );
    }
  }

  // ----------------------------------------------------------
  // AUTH REGISTER
  // ----------------------------------------------------------

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    return await handleRegister(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // AUTH LOGIN
  // ----------------------------------------------------------

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    return await handleLogin(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // AUTH ME
  // ----------------------------------------------------------

  if (
    path === "/api/auth/me" &&
    method === "GET"
  ) {
    return await handleMe(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // AUTH LOGOUT
  // ----------------------------------------------------------

  if (
    path === "/api/auth/logout" &&
    method === "POST"
  ) {
    return await logout(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // TOURNAMENTS
  // ----------------------------------------------------------

  if (
    path === "/api/tournaments" &&
    method === "GET"
  ) {
    return await handleTournaments(
      env
    );
  }

  // ----------------------------------------------------------
  // SLOTS
  // ----------------------------------------------------------

  if (
    path === "/api/slots" &&
    method === "GET"
  ) {
    return await handleSlots(
      env,
      Number(
        url.searchParams.get(
          "tournament_id"
        )
      )
    );
  }

  // ----------------------------------------------------------
  // RANKING
  // ----------------------------------------------------------

  if (
    path === "/api/ranking" &&
    method === "GET"
  ) {
    return await handleRanking(
      env
    );
  }

  // ----------------------------------------------------------
  // CREATE TEAM
  // ----------------------------------------------------------

  if (
    path === "/api/teams" &&
    method === "POST"
  ) {
    return await handleTeamRegister(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // REGISTER TOURNAMENT
  // ----------------------------------------------------------

  if (
    path === "/api/registrations" &&
    method === "POST"
  ) {
    return await handleRegistration(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // MY REGISTRATIONS
  // ----------------------------------------------------------

  if (
    path === "/api/my-registrations" &&
    method === "GET"
  ) {
    return await handleMyRegistrations(
      request,
      env
    );
  }

  // ----------------------------------------------------------
  // PAYMENT CONFIG
  // ----------------------------------------------------------

  if (
    path === "/api/payment/config" &&
    method === "GET"
  ) {
    return ok({
      payment:
        paymentConfig(env)
    });
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
        tables:
          result.results || []
      });

    } catch (error) {
      return fail(
        error.message,
        500
      );
    }
  }

  // ----------------------------------------------------------
  // TABLE
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
        400
      );
    }

    if (
      !/^[A-Za-z0-9_]+$/.test(table)
    ) {
      return fail(
        "Tên bảng không hợp lệ.",
        400
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
        rows:
          result.results || []
      });

    } catch (error) {
      return fail(
        error.message,
        500
      );
    }
  }

  return fail(
    "API không tồn tại.",
    404
  );
}

// ============================================================
// WORKER
// ============================================================

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    // API
    if (
      url.pathname.startsWith("/api/")
    ) {
      try {
        return await api(
          request,
          env
        );
      } catch (error) {
        return fail(
          error?.message ||
            "Server error.",
          500
        );
      }
    }

    // WEBSITE
    if (env.ASSETS) {
      return env.ASSETS.fetch(
        request
      );
    }

    return new Response(
      "GIẢI ĐẤU TỬ CHIẾN MÙA 1",
      {
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  }
};
