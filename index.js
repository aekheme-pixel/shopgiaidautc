// ============================================================
// CUSTOM 151 - CLOUDFLARE WORKER + D1
// Auth + Teams + Tournaments + Registrations + Ranking
// Compatible with users.password_salt if it exists in D1
// ============================================================

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const SESSION_COOKIE = "session";


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

function ok(data = {}) {
  return json({
    success: true,
    ...data
  });
}

function fail(message, status = 400, code = "BAD_REQUEST") {
  return json({
    success: false,
    error: message,
    code
  }, status);
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

function cleanText(value, max = 255) {
  return String(value || "")
    .trim()
    .slice(0, max);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128;
}


// ============================================================
// BASE64 HELPERS
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
  const binary = atob(String(value));

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}


// ============================================================
// RANDOM TOKEN
// ============================================================

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);

  return bytesToBase64(data)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
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
  const salt = new Uint8Array(16);

  crypto.getRandomValues(salt);

  const hash = await derivePassword(password, salt);

  return {
    salt: bytesToBase64(salt),
    hash: bytesToBase64(hash)
  };
}


function safeEqual(a, b) {
  if (!(a instanceof Uint8Array)) {
    a = new TextEncoder().encode(String(a));
  }

  if (!(b instanceof Uint8Array)) {
    b = new TextEncoder().encode(String(b));
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


async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash) {
    return false;
  }

  try {
    // --------------------------------------------------------
    // New format:
    // pbkdf2$100000$SALT$HASH
    // --------------------------------------------------------

    if (String(storedHash).startsWith("pbkdf2$")) {
      const parts = String(storedHash).split("$");

      if (parts.length !== 4) {
        return false;
      }

      const iterations = Number(parts[1]);

      if (!Number.isFinite(iterations)) {
        return false;
      }

      const salt = base64ToBytes(parts[2]);
      const expected = base64ToBytes(parts[3]);

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
        expected.length * 8
      );

      return safeEqual(
        new Uint8Array(bits),
        expected
      );
    }

    // --------------------------------------------------------
    // Legacy compatibility:
    // password_hash + password_salt
    // --------------------------------------------------------

    if (!storedSalt) {
      return false;
    }

    const salt = base64ToBytes(storedSalt);

    const actual = await derivePassword(
      password,
      salt
    );

    let expected;

    try {
      expected = base64ToBytes(storedHash);
    } catch {
      return false;
    }

    return safeEqual(actual, expected);

  } catch {
    return false;
  }
}


// ============================================================
// USERS SCHEMA COMPATIBILITY
// ============================================================

async function getUserColumns(env) {
  const result = await env.DB
    .prepare("PRAGMA table_info(users)")
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}


// ============================================================
// COOKIE HELPERS
// ============================================================

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  const cookies = header.split(";");

  for (const item of cookies) {
    const index = item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (key === name) {
      return value;
    }
  }

  return null;
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
// SESSION
// ============================================================

async function createSession(env, userId) {
  const token = randomToken(32);

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

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
      userId,
      expiresAt
    )
    .run();

  return token;
}


async function getCurrentUser(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE
  );

  if (!token) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const result = await env.DB
    .prepare(`
      SELECT
        users.id,
        users.email,
        users.role,
        users.created_at
      FROM sessions
      INNER JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.token = ?
        AND sessions.expires_at > ?
      LIMIT 1
    `)
    .bind(
      token,
      now
    )
    .first();

  return result || null;
}


async function requireUser(request, env) {
  const user = await getCurrentUser(
    request,
    env
  );

  if (!user) {
    return {
      error: fail(
        "Bạn chưa đăng nhập.",
        401,
        "UNAUTHORIZED"
      )
    };
  }

  return {
    user
  };
}


async function requireAdmin(request, env) {
  const auth = await requireUser(
    request,
    env
  );

  if (auth.error) {
    return auth;
  }

  if (auth.user.role !== "ADMIN") {
    return {
      error: fail(
        "Bạn không có quyền quản trị.",
        403,
        "FORBIDDEN"
      )
    };
  }

  return auth;
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
    await env.DB
      .prepare(`
        INSERT INTO audit_logs (
          user_id,
          action,
          target,
          details
        )
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        userId || null,
        action,
        target || null,
        details
          ? JSON.stringify(details)
          : null
      )
      .run();
  } catch {
    // Audit must never break the main request.
  }
}


// ============================================================
// ROUTER
// ============================================================

export default {

  async fetch(request, env) {

    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    try {

      // ======================================================
      // HEALTH
      // ======================================================

      if (
        url.pathname === "/api/health" &&
        method === "GET"
      ) {

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
            error.message,
            500,
            "DATABASE_ERROR"
          );
        }
      }


      // ======================================================
      // AUTH: REGISTER
      // ======================================================

      if (
        url.pathname === "/api/auth/register" &&
        method === "POST"
      ) {

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

        const exists = await env.DB
          .prepare(`
            SELECT id
            FROM users
            WHERE email = ?
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

        const columns =
          await getUserColumns(env);

        const passwordData =
          await hashPassword(password);

        // ----------------------------------------------------
        // HỖ TRỢ CẢ DATABASE:
        //
        // users(
        //   email,
        //   password_hash,
        //   password_salt,
        //   role,
        //   ...
        // )
        //
        // và schema không có password_salt.
        // ----------------------------------------------------

        if (columns.has("password_salt")) {

          await env.DB
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
              passwordData.hash,
              passwordData.salt,
              "USER"
            )
            .run();

        } else {

          // Nếu DB không có password_salt,
          // lưu cả salt bên trong password_hash.
          const combinedHash =
            `pbkdf2$${PBKDF2_ITERATIONS}$${passwordData.salt}$${passwordData.hash}`;

          await env.DB
            .prepare(`
              INSERT INTO users (
                email,
                password_hash,
                role
              )
              VALUES (?, ?, ?)
            `)
            .bind(
              email,
              combinedHash,
              "USER"
            )
            .run();
        }

        const user = await env.DB
          .prepare(`
            SELECT
              id,
              email,
              role,
              created_at
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(email)
          .first();

        await audit(
          env,
          user?.id,
          "REGISTER",
          "users",
          { email }
        );

        return ok({
          message:
            "Tạo tài khoản thành công!",
          user
        });
      }


      // ======================================================
      // AUTH: LOGIN
      // ======================================================

      if (
        url.pathname === "/api/auth/login" &&
        method === "POST"
      ) {

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

        const user = await env.DB
          .prepare(`
            SELECT *
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(email)
          .first();

        if (!user) {
          return fail(
            "Email hoặc mật khẩu không đúng.",
            401,
            "INVALID_CREDENTIALS"
          );
        }

        const valid =
          await verifyPassword(
            password,
            user.password_hash,
            user.password_salt
          );

        if (!valid) {

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

        return json(
          {
            success: true,
            message:
              "Đăng nhập thành công!",
            user: {
              id: user.id,
              email: user.email,
              role: user.role,
              created_at: user.created_at
            }
          },
          200,
          {
            "Set-Cookie":
              sessionCookie(token)
          }
        );
      }


      // ======================================================
      // AUTH: ME
      // ======================================================

      if (
        url.pathname === "/api/auth/me" &&
        method === "GET"
      ) {

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


      // ======================================================
      // AUTH: LOGOUT
      // ======================================================

      if (
        url.pathname === "/api/auth/logout" &&
        method === "POST"
      ) {

        const token =
          getCookie(
            request,
            SESSION_COOKIE
          );

        if (token) {

          try {
            await env.DB
              .prepare(`
                DELETE FROM sessions
                WHERE token = ?
              `)
              .bind(token)
              .run();
          } catch {}
        }

        return json(
          {
            success: true,
            message:
              "Đã đăng xuất."
          },
          200,
          {
            "Set-Cookie":
              clearSessionCookie()
          }
        );
      }


      // ======================================================
      // TOURNAMENTS
      // ======================================================

      if (
        url.pathname === "/api/tournaments" &&
        method === "GET"
      ) {

        const result =
          await env.DB
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
      }


      // ======================================================
      // TOURNAMENT DETAIL
      // ======================================================

      const tournamentMatch =
        url.pathname.match(
          /^\/api\/tournaments\/(\d+)$/
        );

      if (
        tournamentMatch &&
        method === "GET"
      ) {

        const tournamentId =
          Number(tournamentMatch[1]);

        const tournament =
          await env.DB
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
              WHERE id = ?
              LIMIT 1
            `)
            .bind(tournamentId)
            .first();

        if (!tournament) {
          return fail(
            "Không tìm thấy giải đấu.",
            404,
            "TOURNAMENT_NOT_FOUND"
          );
        }

        const slots =
          await env.DB
            .prepare(`
              SELECT
                s.id,
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
                s.slot_time,
                s.group_name,
                s.capacity
              ORDER BY s.slot_time
            `)
            .bind(tournamentId)
            .all();

        return ok({
          tournament,
          slots:
            slots.results || []
        });
      }


      // ======================================================
      // RANKING
      // ======================================================

      if (
        url.pathname === "/api/ranking" &&
        method === "GET"
      ) {

        const result =
          await env.DB
            .prepare(`
              SELECT
                t.id,
                t.name,
                COALESCE(
                  SUM(r.kills),
                  0
                ) AS kills,
                COALESCE(
                  SUM(r.points),
                  0
                ) AS points
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

        return ok({
          ranking:
            result.results || []
        });
      }


      // ======================================================
      // CURRENT USER TEAMS
      // ======================================================

      if (
        url.pathname === "/api/teams" &&
        method === "GET"
      ) {

        const auth =
          await requireUser(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

        const result =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                tag,
                logo_url,
                status,
                created_at
              FROM teams
              WHERE owner_id = ?
              ORDER BY id DESC
            `)
            .bind(auth.user.id)
            .all();

        return ok({
          teams:
            result.results || []
        });
      }


      // ======================================================
      // CREATE TEAM
      // ======================================================

      if (
        url.pathname === "/api/teams" &&
        method === "POST"
      ) {

        const auth =
          await requireUser(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

        const data =
          await bodyJSON(request);

        if (!data) {
          return fail(
            "Dữ liệu đội không hợp lệ.",
            400,
            "INVALID_JSON"
          );
        }

        const name =
          cleanText(data.name, 80);

        const tag =
          cleanText(data.tag, 20);

        const logoUrl =
          cleanText(data.logo_url, 500);

        if (!name) {
          return fail(
            "Vui lòng nhập tên đội.",
            400,
            "TEAM_NAME_REQUIRED"
          );
        }

        const result =
          await env.DB
            .prepare(`
              INSERT INTO teams (
                owner_id,
                name,
                tag,
                logo_url,
                status
              )
              VALUES (?, ?, ?, ?, 'PENDING')
            `)
            .bind(
              auth.user.id,
              name,
              tag || null,
              logoUrl || null
            )
            .run();

        const teamId =
          result.meta?.last_row_id;

        await audit(
          env,
          auth.user.id,
          "CREATE_TEAM",
          `teams:${teamId}`,
          {
            name,
            tag
          }
        );

        return ok({
          message:
            "Tạo đội thành công! Đội đang chờ duyệt.",
          team: {
            id: teamId,
            name,
            tag,
            status: "PENDING"
          }
        });
      }


      // ======================================================
      // TEAM DETAIL
      // ======================================================

      const teamMatch =
        url.pathname.match(
          /^\/api\/teams\/(\d+)$/
        );

      if (
        teamMatch &&
        method === "GET"
      ) {

        const auth =
          await requireUser(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

        const teamId =
          Number(teamMatch[1]);

        const team =
          await env.DB
            .prepare(`
              SELECT
                t.id,
                t.name,
                t.tag,
                t.logo_url,
                t.status,
                t.created_at
              FROM teams t
              WHERE t.id = ?
                AND t.owner_id = ?
              LIMIT 1
            `)
            .bind(
              teamId,
              auth.user.id
            )
            .first();

        if (!team) {
          return fail(
            "Không tìm thấy đội.",
            404,
            "TEAM_NOT_FOUND"
          );
        }

        const members =
          await env.DB
            .prepare(`
              SELECT
                id,
                game_name,
                uid,
                role
              FROM team_members
              WHERE team_id = ?
              ORDER BY id
            `)
            .bind(teamId)
            .all();

        return ok({
          team,
          members:
            members.results || []
        });
      }


      // ======================================================
      // REGISTER TEAM TO TOURNAMENT
      // ======================================================

      if (
        url.pathname === "/api/registrations" &&
        method === "POST"
      ) {

        const auth =
          await requireUser(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

        const data =
          await bodyJSON(request);

        if (!data) {
          return fail(
            "Dữ liệu đăng ký không hợp lệ.",
            400,
            "INVALID_JSON"
          );
        }

        const teamId =
          Number(data.team_id);

        const tournamentId =
          Number(data.tournament_id);

        const slotId =
          data.slot_id
            ? Number(data.slot_id)
            : null;

        if (
          !Number.isInteger(teamId) ||
          !Number.isInteger(tournamentId)
        ) {
          return fail(
            "Thông tin đội hoặc giải không hợp lệ.",
            400,
            "INVALID_REGISTRATION"
          );
        }

        const team =
          await env.DB
            .prepare(`
              SELECT *
              FROM teams
              WHERE id = ?
                AND owner_id = ?
              LIMIT 1
            `)
            .bind(
              teamId,
              auth.user.id
            )
            .first();

        if (!team) {
          return fail(
            "Đội không tồn tại hoặc không thuộc tài khoản của bạn.",
            403,
            "TEAM_FORBIDDEN"
          );
        }

        const tournament =
          await env.DB
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
            404,
            "TOURNAMENT_CLOSED"
          );
        }

        // Kiểm tra đăng ký trùng
        const duplicate =
          await env.DB
            .prepare(`
              SELECT id
              FROM registrations
              WHERE team_id = ?
                AND tournament_id = ?
                AND status != 'CANCELLED'
              LIMIT 1
            `)
            .bind(
              teamId,
              tournamentId
            )
            .first();

        if (duplicate) {
          return fail(
            "Đội này đã đăng ký giải.",
            409,
            "ALREADY_REGISTERED"
          );
        }

        // Kiểm tra slot
        if (slotId) {

          const slot =
            await env.DB
              .prepare(`
                SELECT *
                FROM slots
                WHERE id = ?
                  AND tournament_id = ?
                LIMIT 1
              `)
              .bind(
                slotId,
                tournamentId
              )
              .first();

          if (!slot) {
            return fail(
              "Khung giờ không hợp lệ.",
              400,
              "INVALID_SLOT"
            );
          }

          const count =
            await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM registrations
                WHERE slot_id = ?
                  AND status != 'CANCELLED'
              `)
              .bind(slotId)
              .first();

          if (
            Number(count?.total || 0) >=
            Number(slot.capacity)
          ) {
            return fail(
              "Khung giờ này đã đủ đội.",
              409,
              "SLOT_FULL"
            );
          }
        }

        const orderCode =
          `C151-${Date.now().toString(36).toUpperCase()}-${randomToken(5).toUpperCase()}`;

        const amount =
          Number(tournament.fee || 0);

        const result =
          await env.DB
            .prepare(`
              INSERT INTO registrations (
                team_id,
                tournament_id,
                slot_id,
                order_code,
                amount,
                status
              )
              VALUES (?, ?, ?, ?, ?, 'AWAITING_PAYMENT')
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

        await audit(
          env,
          auth.user.id,
          "REGISTER_TEAM",
          `registrations:${registrationId}`,
          {
            teamId,
            tournamentId,
            slotId,
            orderCode
          }
        );

        return ok({
          message:
            "Đăng ký đội thành công!",
          registration: {
            id: registrationId,
            order_code: orderCode,
            amount,
            status:
              "AWAITING_PAYMENT"
          }
        });
      }


      // ======================================================
      // USER REGISTRATIONS
      // ======================================================

      if (
        url.pathname === "/api/registrations/me" &&
        method === "GET"
      ) {

        const auth =
          await requireUser(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

        const result =
          await env.DB
            .prepare(`
              SELECT
                r.id,
                r.order_code,
                r.amount,
                r.status,
                r.created_at,
                t.name AS team_name,
                t.tag AS team_tag,
                tr.name AS tournament_name,
                s.slot_time,
                s.group_name
              FROM registrations r
              INNER JOIN teams t
                ON t.id = r.team_id
              INNER JOIN tournaments tr
                ON tr.id = r.tournament_id
              LEFT JOIN slots s
                ON s.id = r.slot_id
              WHERE t.owner_id = ?
              ORDER BY r.id DESC
            `)
            .bind(auth.user.id)
            .all();

        return ok({
          registrations:
            result.results || []
        });
      }


      // ======================================================
      // ADMIN TABLE LIST
      // ======================================================

      if (
        url.pathname === "/api/tables" &&
        method === "GET"
      ) {

        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

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
      }


      // ======================================================
      // ADMIN TABLE DATA
      // ======================================================

      if (
        url.pathname === "/api/table" &&
        method === "GET"
      ) {

        const auth =
          await requireAdmin(
            request,
            env
          );

        if (auth.error) {
          return auth.error;
        }

        const table =
          url.searchParams.get("name");

        if (!table) {
          return fail(
            "Thiếu tên bảng.",
            400,
            "MISSING_TABLE"
          );
        }

        if (
          !/^[A-Za-z0-9_]+$/.test(table)
        ) {
          return fail(
            "Tên bảng không hợp lệ.",
            400,
            "INVALID_TABLE"
          );
        }

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
      }


      // ======================================================
      // STATIC WEBSITE
      // ======================================================

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response(
        "CUSTOM 151 - Worker đang hoạt động.",
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
