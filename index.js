const PBKDF2_ITERATIONS = 100000;
const SESSION_DAYS = 30;

const jsonHeaders = {
  "content-type": "application/json; charset=UTF-8",
  "cache-control": "no-store"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: jsonHeaders
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  if (!hex || typeof hex !== "string" || hex.length % 2 !== 0) {
    return null;
  }

  const out = new Uint8Array(hex.length / 2);

  for (let i = 0; i < out.length; i++) {
    const value = parseInt(hex.slice(i * 2, i * 2 + 2), 16);

    if (Number.isNaN(value)) {
      return null;
    }

    out[i] = value;
  }

  return out;
}

function base64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function hashPassword(password, saltBytes) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
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

  return bytesToHex(new Uint8Array(derived));
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function verifyPassword(password, hash, salt) {
  const saltBytes = hexToBytes(salt);

  if (!saltBytes) {
    return false;
  }

  const calculated = await hashPassword(password, saltBytes);

  return constantTimeEqual(
    calculated.toLowerCase(),
    String(hash || "").toLowerCase()
  );
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function ensureAuthSchema(env) {
  // Kiểm tra users hiện tại
  const columns = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  const names = new Set(
    (columns.results || []).map(x => x.name)
  );

  // Nếu DB cũ chưa có password_salt thì tự thêm.
  if (!names.has("password_salt")) {
    await env.DB
      .prepare("ALTER TABLE users ADD COLUMN password_salt TEXT")
      .run();
  }

  // Sessions phải tồn tại theo schema người dùng đang dùng.
  await env.DB
    .prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
      )
    `)
    .run();

  await env.DB
    .prepare(`
      CREATE INDEX IF NOT EXISTS idx_sessions_expiry
      ON sessions(expires_at)
    `)
    .run();
}

async function createSession(env, userId) {
  const token = base64Url(randomBytes(32));
  const expiresAt =
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;

  await env.DB
    .prepare(`
      INSERT INTO sessions (
        token,
        user_id,
        expires_at
      )
      VALUES (?, ?, ?)
    `)
    .bind(token, userId, expiresAt)
    .run();

  return {
    token,
    expiresAt
  };
}

async function getSessionUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(
    /(?:^|;\s*)session_token=([^;]+)/
  );

  if (!match) {
    return null;
  }

  const token = decodeURIComponent(match[1]);

  if (!token) {
    return null;
  }

  const row = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.email,
        u.role,
        u.created_at,
        s.expires_at
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
      LIMIT 1
    `)
    .bind(token)
    .first();

  if (!row) {
    return null;
  }

  if (Number(row.expires_at) <= Date.now()) {
    await env.DB
      .prepare("DELETE FROM sessions WHERE token = ?")
      .bind(token)
      .run();

    return null;
  }

  return {
    id: row.id,
    email: row.email,
    role: row.role,
    created_at: row.created_at
  };
}

function sessionCookie(token, maxAge) {
  return [
    `session_token=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${maxAge}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "session_token=",
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

async function register(request, env) {
  const body = await readJson(request);

  const email = normalizeEmail(body?.email);
  const password = body?.password;

  if (!email || !validEmail(email)) {
    return json({
      success: false,
      error: "EMAIL_INVALID",
      message: "Email không hợp lệ."
    }, 400);
  }

  if (!validPassword(password)) {
    return json({
      success: false,
      error: "PASSWORD_TOO_SHORT",
      message: "Mật khẩu phải có ít nhất 8 ký tự."
    }, 400);
  }

  try {
    await ensureAuthSchema(env);

    const existed = await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (existed) {
      return json({
        success: false,
        error: "EMAIL_EXISTS",
        message: "Email này đã được đăng ký."
      }, 409);
    }

    const saltBytes = randomBytes(16);
    const salt = bytesToHex(saltBytes);

    const passwordHash =
      await hashPassword(password, saltBytes);

    /*
      role luôn dùng USER.
      Không dùng PLAYER ở bảng users.
      PLAYER chỉ là role của team_members.
    */

    const result = await env.DB
      .prepare(`
        INSERT INTO users (
          email,
          password_hash,
          password_salt,
          role
        )
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        email,
        passwordHash,
        salt,
        "USER"
      )
      .run();

    return json({
      success: true,
      message: "Tạo tài khoản thành công.",
      user: {
        id: result.meta?.last_row_id,
        email,
        role: "USER"
      }
    }, 201);

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return json({
      success: false,
      error: "REGISTER_ERROR",
      message: error.message || "Không thể tạo tài khoản."
    }, 500);
  }
}

async function login(request, env) {
  const body = await readJson(request);

  const email = normalizeEmail(body?.email);
  const password = body?.password;

  if (!email || !password) {
    return json({
      success: false,
      error: "MISSING_LOGIN",
      message: "Vui lòng nhập email và mật khẩu."
    }, 400);
  }

  try {
    await ensureAuthSchema(env);

    const user = await env.DB
      .prepare(`
        SELECT
          id,
          email,
          password_hash,
          password_salt,
          role,
          created_at
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    /*
      Không tiết lộ email có tồn tại hay không.
    */
    if (!user) {
      return json({
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Email hoặc mật khẩu không đúng."
      }, 401);
    }

    /*
      Nếu tài khoản cũ chưa có salt thì không đoán hash.
      Trả lỗi rõ ràng thay vì làm login sai âm thầm.
    */
    if (!user.password_salt) {
      return json({
        success: false,
        error: "PASSWORD_SALT_MISSING",
        message:
          "Tài khoản này chưa có password_salt. " +
          "Hãy đăng ký một tài khoản mới để sử dụng hệ thống xác thực mới."
      }, 401);
    }

    const valid = await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

    if (!valid) {
      return json({
        success: false,
        error: "INVALID_CREDENTIALS",
        message: "Email hoặc mật khẩu không đúng."
      }, 401);
    }

    /*
      Xóa session cũ đã hết hạn.
    */
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE expires_at <= ?
      `)
      .bind(Date.now())
      .run();

    /*
      Xóa session cũ của user này.
      Tránh tồn quá nhiều token.
    */
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE user_id = ?
      `)
      .bind(user.id)
      .run();

    const session = await createSession(
      env,
      user.id
    );

    return new Response(
      JSON.stringify({
        success: true,
        message: "Đăng nhập thành công.",
        user: {
          id: user.id,
          email: user.email,
          role: user.role || "USER",
          created_at: user.created_at
        }
      }),
      {
        status: 200,
        headers: {
          ...jsonHeaders,
          "Set-Cookie": sessionCookie(
            session.token,
            SESSION_DAYS * 24 * 60 * 60
          )
        }
      }
    );

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return json({
      success: false,
      error: "LOGIN_ERROR",
      message: error.message || "Không thể đăng nhập."
    }, 500);
  }
}

async function logout(request, env) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(
    /(?:^|;\s*)session_token=([^;]+)/
  );

  if (match) {
    const token = decodeURIComponent(match[1]);

    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token = ?
      `)
      .bind(token)
      .run();
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

async function me(request, env) {
  try {
    await ensureAuthSchema(env);

    const user = await getSessionUser(
      request,
      env
    );

    return json({
      success: true,
      authenticated: !!user,
      user
    });

  } catch (error) {
    return json({
      success: false,
      authenticated: false,
      user: null,
      message: error.message
    }, 500);
  }
}

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

    return json({
      success: true,
      tournaments: result.results || []
    });

  } catch (error) {
    return json({
      success: false,
      error: "TOURNAMENT_ERROR",
      message: error.message
    }, 500);
  }
}

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
      tables: result.results || []
    });

  } catch (error) {
    return json({
      success: false,
      message: error.message
    }, 500);
  }
}

async function tableData(url, env) {
  const table = url.searchParams.get("name");

  if (!table) {
    return json({
      success: false,
      message: "Thiếu tên bảng."
    }, 400);
  }

  if (!/^[A-Za-z0-9_]+$/.test(table)) {
    return json({
      success: false,
      message: "Tên bảng không hợp lệ."
    }, 400);
  }

  try {
    const result = await env.DB
      .prepare(`SELECT * FROM "${table}" LIMIT 100`)
      .all();

    return json({
      success: true,
      table,
      rows: result.results || []
    });

  } catch (error) {
    return json({
      success: false,
      message: error.message
    }, 500);
  }
}

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
      site: env.SITE_NAME || "CUSTOM 151"
    });

  } catch (error) {
    return json({
      success: false,
      worker: "online",
      database: "error",
      message: error.message
    }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /*
      API
    */
    if (url.pathname === "/api/health") {
      return health(env);
    }

    if (url.pathname === "/api/tables") {
      return tables(env);
    }

    if (url.pathname === "/api/table") {
      return tableData(url, env);
    }

    if (url.pathname === "/api/tournaments") {
      return tournaments(env);
    }

    if (url.pathname === "/api/auth/register") {
      if (request.method !== "POST") {
        return json({
          success: false,
          message: "Method không được hỗ trợ."
        }, 405);
      }

      return register(request, env);
    }

    if (url.pathname === "/api/auth/login") {
      if (request.method !== "POST") {
        return json({
          success: false,
          message: "Method không được hỗ trợ."
        }, 405);
      }

      return login(request, env);
    }

    if (url.pathname === "/api/auth/logout") {
      if (request.method !== "POST") {
        return json({
          success: false,
          message: "Method không được hỗ trợ."
        }, 405);
      }

      return logout(request, env);
    }

    if (url.pathname === "/api/auth/me") {
      return me(request, env);
    }

    /*
      Website
    */
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "CUSTOM 151 • Worker online",
      {
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  }
};
