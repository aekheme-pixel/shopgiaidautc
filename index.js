// ============================================================
// CUSTOM 151 - Cloudflare Worker
// D1 + Register + Login + Session + Tournaments
// ============================================================

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      ...headers
    }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}

function makeToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);

  return Array.from(data)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ------------------------------------------------------------
// Password hashing
// ------------------------------------------------------------

async function hashPassword(password) {
  const encoder = new TextEncoder();

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const key = await crypto.subtle.importKey(
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
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  const hash = new Uint8Array(bits);

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    toBase64(salt),
    toBase64(hash)
  ].join("$");
}

async function verifyPassword(password, stored) {
  try {
    const parts = stored.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const [algorithm, iterationsString, saltBase64, hashBase64] = parts;

    if (algorithm !== "pbkdf2") {
      return false;
    }

    const iterations = Number(iterationsString);

    if (!Number.isInteger(iterations) || iterations < 10000) {
      return false;
    }

    const salt = fromBase64(saltBase64);
    const originalHash = fromBase64(hashBase64);

    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
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
        salt,
        iterations,
        hash: "SHA-256"
      },
      key,
      originalHash.length * 8
    );

    const newHash = new Uint8Array(bits);

    if (newHash.length !== originalHash.length) {
      return false;
    }

    let result = 0;

    for (let i = 0; i < newHash.length; i++) {
      result |= newHash[i] ^ originalHash[i];
    }

    return result === 0;

  } catch (error) {
    return false;
  }
}

// ------------------------------------------------------------
// Authentication
// ------------------------------------------------------------

async function register(request, env) {
  if (request.method !== "POST") {
    return json(
      {
        success: false,
        error: "Method không hợp lệ"
      },
      405
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Dữ liệu gửi lên không hợp lệ"
      },
      400
    );
  }

  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!email) {
    return json(
      {
        success: false,
        error: "Vui lòng nhập email"
      },
      400
    );
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json(
      {
        success: false,
        error: "Email không hợp lệ"
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        success: false,
        error: "Mật khẩu phải có ít nhất 8 ký tự"
      },
      400
    );
  }

  try {
    const existing = await env.DB
      .prepare(
        "SELECT id FROM users WHERE email = ? LIMIT 1"
      )
      .bind(email)
      .first();

    if (existing) {
      return json(
        {
          success: false,
          error: "Email này đã được đăng ký"
        },
        409
      );
    }

    const passwordHash = await hashPassword(password);

    const result = await env.DB
      .prepare(`
        INSERT INTO users (
          email,
          password_hash,
          role
        )
        VALUES (?, ?, 'USER')
      `)
      .bind(email, passwordHash)
      .run();

    if (!result.success) {
      throw new Error("Không thể tạo tài khoản");
    }

    return json({
      success: true,
      message: "Tạo tài khoản thành công"
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return json(
      {
        success: false,
        error: error.message || "Không thể tạo tài khoản"
      },
      500
    );
  }
}

async function login(request, env) {
  if (request.method !== "POST") {
    return json(
      {
        success: false,
        error: "Method không hợp lệ"
      },
      405
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Dữ liệu gửi lên không hợp lệ"
      },
      400
    );
  }

  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!email || !password) {
    return json(
      {
        success: false,
        error: "Vui lòng nhập email và mật khẩu"
      },
      400
    );
  }

  try {
    const user = await env.DB
      .prepare(`
        SELECT
          id,
          email,
          password_hash,
          role
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (!user) {
      return json(
        {
          success: false,
          error: "Email hoặc mật khẩu không đúng"
        },
        401
      );
    }

    const valid = await verifyPassword(
      password,
      user.password_hash
    );

    if (!valid) {
      return json(
        {
          success: false,
          error: "Email hoặc mật khẩu không đúng"
        },
        401
      );
    }

    const token = makeToken(32);

    const expiresAt =
      Math.floor(Date.now() / 1000) +
      SESSION_DAYS * 24 * 60 * 60;

    await env.DB
      .prepare(`
        INSERT INTO sessions (
          token,
          user_id,
          expires_at
        )
        VALUES (?, ?, ?)
      `)
      .bind(
        token,
        user.id,
        expiresAt
      )
      .run();

    const cookie = [
      `session=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
    ].join("; ");

    return json(
      {
        success: true,
        message: "Đăng nhập thành công",
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        }
      },
      200,
      {
        "Set-Cookie": cookie
      }
    );

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return json(
      {
        success: false,
        error: error.message || "Không thể đăng nhập"
      },
      500
    );
  }
}

async function currentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return json({
      success: true,
      authenticated: false,
      user: null
    });
  }

  try {
    const session = await env.DB
      .prepare(`
        SELECT
          s.token,
          s.expires_at,
          u.id,
          u.email,
          u.role
        FROM sessions s
        JOIN users u
          ON u.id = s.user_id
        WHERE s.token = ?
        LIMIT 1
      `)
      .bind(token)
      .first();

    if (!session) {
      return json({
        success: true,
        authenticated: false,
        user: null
      });
    }

    const now = Math.floor(Date.now() / 1000);

    if (session.expires_at <= now) {
      await env.DB
        .prepare("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .run();

      return json({
        success: true,
        authenticated: false,
        user: null
      });
    }

    return json({
      success: true,
      authenticated: true,
      user: {
        id: session.id,
        email: session.email,
        role: session.role
      }
    });

  } catch (error) {
    return json(
      {
        success: false,
        error: error.message
      },
      500
    );
  }
}

async function logout(request, env) {
  const token = getCookie(request, "session");

  if (token) {
    try {
      await env.DB
        .prepare("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .run();
    } catch (error) {
      console.error("LOGOUT ERROR:", error);
    }
  }

  return json(
    {
      success: true,
      message: "Đã đăng xuất"
    },
    200,
    {
      "Set-Cookie":
        "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    }
  );
}

// ------------------------------------------------------------
// Tournaments
// ------------------------------------------------------------

async function tournaments(request, env) {
  if (request.method !== "GET") {
    return json(
      {
        success: false,
        error: "Method không hợp lệ"
      },
      405
    );
  }

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
    console.error("TOURNAMENT ERROR:", error);

    return json(
      {
        success: false,
        error: error.message
      },
      500
    );
  }
}

// ------------------------------------------------------------
// Main Worker
// ------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // HEALTH
    // =========================

    if (url.pathname === "/api/health") {
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
        return json(
          {
            success: false,
            worker: "online",
            database: "error",
            message: error.message
          },
          500
        );
      }
    }

    // =========================
    // REGISTER
    // =========================

    if (url.pathname === "/api/auth/register") {
      return register(request, env);
    }

    // =========================
    // LOGIN
    // =========================

    if (url.pathname === "/api/auth/login") {
      return login(request, env);
    }

    // =========================
    // CURRENT USER
    // =========================

    if (url.pathname === "/api/auth/me") {
      return currentUser(request, env);
    }

    // =========================
    // LOGOUT
    // =========================

    if (url.pathname === "/api/auth/logout") {
      return logout(request, env);
    }

    // =========================
    // TOURNAMENTS
    // =========================

    if (url.pathname === "/api/tournaments") {
      return tournaments(request, env);
    }

    // =========================
    // TABLE LIST
    // =========================

    if (url.pathname === "/api/tables") {
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
        return json(
          {
            success: false,
            message: error.message
          },
          500
        );
      }
    }

    // =========================
    // TABLE DATA
    // =========================

    if (url.pathname === "/api/table") {
      const table = url.searchParams.get("name");

      if (!table) {
        return json(
          {
            success: false,
            message: "Thiếu tên bảng"
          },
          400
        );
      }

      if (!/^[A-Za-z0-9_]+$/.test(table)) {
        return json(
          {
            success: false,
            message: "Tên bảng không hợp lệ"
          },
          400
        );
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
        return json(
          {
            success: false,
            message: error.message
          },
          500
        );
      }
    }

    // =========================
    // CLEAN EXPIRED SESSIONS
    // =========================

    // Không bắt buộc nhưng giúp dọn session cũ.
    if (
      request.method === "GET" &&
      url.pathname === "/api/cleanup"
    ) {
      try {
        await env.DB
          .prepare(
            "DELETE FROM sessions WHERE expires_at <= ?"
          )
          .bind(Math.floor(Date.now() / 1000))
          .run();

        return json({
          success: true
        });

      } catch (error) {
        return json(
          {
            success: false,
            error: error.message
          },
          500
        );
      }
    }

    // =========================
    // WEBSITE
    // =========================

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "GIẢI ĐẤU VUA TỬ CHIẾN – MÙA 1",
      {
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  }
};
