// ============================================================
// GIẢI ĐẤU TỬ CHIẾN MÙA 1
// Cloudflare Worker + D1
// Auth: Web Crypto PBKDF2
// Compatible with current DB:
// users, teams, team_members, tournaments, slots,
// registrations, payments, matches, results,
// sessions, audit_logs
// ============================================================

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;

// ============================================================
// RESPONSE
// ============================================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store"
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
    return {};
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function cleanText(value, max = 200) {
  return String(value || "").trim().slice(0, max);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

// ============================================================
// RANDOM
// ============================================================

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

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

function randomToken(bytes = 32) {
  return bytesToBase64(randomBytes(bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// ============================================================
// PASSWORD
// Format:
// v1$PBKDF2$iterations$salt$hash
//
// Salt được lưu ngay trong password_hash.
// Không cần password_salt.
// ============================================================

async function hashPassword(password) {
  const salt = randomBytes(16);

  const keyMaterial = await crypto.subtle.importKey(
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
    keyMaterial,
    256
  );

  const hash = new Uint8Array(bits);

  return [
    "v1",
    "PBKDF2",
    String(PBKDF2_ITERATIONS),
    bytesToBase64(salt),
    bytesToBase64(hash)
  ].join("$");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 5) {
      return false;
    }

    const [
      version,
      algorithm,
      iterationString,
      salt64,
      hash64
    ] = parts;

    if (version !== "v1") return false;
    if (algorithm !== "PBKDF2") return false;

    const iterations = Number(iterationString);

    if (!Number.isFinite(iterations) || iterations < 10000) {
      return false;
    }

    const salt = base64ToBytes(salt64);
    const expected = base64ToBytes(hash64);

    const keyMaterial = await crypto.subtle.importKey(
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
      keyMaterial,
      expected.length * 8
    );

    const actual = new Uint8Array(bits);

    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ============================================================
// COOKIE
// ============================================================

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";

  const cookies = header.split(";");

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");

    if (index === -1) continue;

    const key = cookie.slice(0, index).trim();

    if (key !== name) continue;

    return decodeURIComponent(
      cookie.slice(index + 1).trim()
    );
  }

  return null;
}

function sessionCookie(token, maxAge) {
  return [
    `session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
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
// SESSION
// ============================================================

async function createSession(env, userId) {
  const token = randomToken(32);

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (token, user_id, expires_at)
      VALUES (?, ?, ?)
    `)
    .bind(token, userId, expiresAt)
    .run();

  return {
    token,
    expiresAt
  };
}

async function getCurrentUser(request, env) {
  const token = getCookie(request, "session");

  if (!token) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.email,
        u.role,
        u.created_at,
        s.token,
        s.expires_at
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND s.expires_at > ?
      LIMIT 1
    `)
    .bind(token, now)
    .first();

  if (!row) {
    return null;
  }

  return row;
}

// ============================================================
// ACCOUNT NAME
//
// Current DB does not contain users.username.
// Therefore we store the requested account name in audit_logs
// without changing the current database schema.
//
// If later you add users.username, backend can be upgraded.
// ============================================================

async function saveAccountName(env, userId, username) {
  const details = JSON.stringify({
    username: cleanText(username, 50)
  });

  await env.DB
    .prepare(`
      INSERT INTO audit_logs
      (user_id, action, target, details)
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      userId,
      "PROFILE_NAME_SET",
      `user:${userId}`,
      details
    )
    .run();
}

async function getAccountName(env, user) {
  try {
    const row = await env.DB
      .prepare(`
        SELECT details
        FROM audit_logs
        WHERE user_id = ?
          AND action = 'PROFILE_NAME_SET'
        ORDER BY id DESC
        LIMIT 1
      `)
      .bind(user.id)
      .first();

    if (row?.details) {
      try {
        const data = JSON.parse(row.details);

        if (data.username) {
          return String(data.username);
        }
      } catch {}
    }
  } catch {}

  const fallback =
    String(user.email || "")
      .split("@")[0]
      .slice(0, 50);

  return fallback || "Người chơi";
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
    // Audit không được làm hỏng request chính.
  }
}

// ============================================================
// USER RESPONSE
// ============================================================

async function publicUser(env, user) {
  if (!user) return null;

  const username = await getAccountName(env, user);

  return {
    id: user.id,
    email: user.email,
    role: user.role,
    username,
    balance: 0,
    created_at: user.created_at
  };
}

// ============================================================
// DATABASE HELPERS
// ============================================================

async function getUserColumns(env) {
  const result = await env.DB
    .prepare(`PRAGMA table_info(users)`)
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}

async function roleForRegistration(env) {
  const columns = await getUserColumns(env);

  // Current DB may have CHECK:
  // role IN ('PLAYER','ADMIN','SUPER_ADMIN')
  //
  // PLAYER is the safe public-user role.
  if (columns.has("role")) {
    return "PLAYER";
  }

  return null;
}

// ============================================================
// API ROUTER
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ========================================================
    // CORS / OPTIONS
    // ========================================================

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": url.origin,
          "access-control-allow-methods":
            "GET,POST,PUT,DELETE,OPTIONS",
          "access-control-allow-headers":
            "Content-Type",
          "access-control-allow-credentials": "true"
        }
      });
    }

    // ========================================================
    // HEALTH
    // ========================================================

    if (
      url.pathname === "/api/health" &&
      request.method === "GET"
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
          site:
            env.SITE_NAME ||
            "Giải Đấu Tử Chiến Mùa 1"
        });
      } catch (error) {
        return fail(
          error.message,
          500,
          "DATABASE_ERROR"
        );
      }
    }

    // ========================================================
    // TABLES
    // ========================================================

    if (
      url.pathname === "/api/tables" &&
      request.method === "GET"
    ) {
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
        return fail(
          error.message,
          500,
          "DATABASE_ERROR"
        );
      }
    }

    // ========================================================
    // AUTH: ME
    // ========================================================

    if (
      url.pathname === "/api/auth/me" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return ok({
            authenticated: false,
            user: null
          });
        }

        return ok({
          authenticated: true,
          user: await publicUser(env, user)
        });
      } catch (error) {
        return fail(
          error.message,
          500,
          "AUTH_ERROR"
        );
      }
    }

    // ========================================================
    // AUTH: REGISTER
    // ========================================================

    if (
      url.pathname === "/api/auth/register" &&
      request.method === "POST"
    ) {
      try {
        const data = await bodyJSON(request);

        const username = cleanText(
          data.username ||
          data.accountName ||
          "",
          50
        );

        const email = cleanEmail(data.email);
        const password = data.password;
        const passwordConfirm =
          data.password_confirm ??
          data.passwordConfirm ??
          "";

        if (username.length < 3) {
          return fail(
            "Tên tài khoản phải có ít nhất 3 ký tự.",
            400,
            "INVALID_USERNAME"
          );
        }

        if (!/^[A-Za-z0-9_.-]+$/.test(username)) {
          return fail(
            "Tên tài khoản chỉ được dùng chữ, số, dấu chấm, gạch ngang hoặc gạch dưới.",
            400,
            "INVALID_USERNAME"
          );
        }

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

        if (password !== passwordConfirm) {
          return fail(
            "Mật khẩu nhập lại không khớp.",
            400,
            "PASSWORD_MISMATCH"
          );
        }

        const existing = await env.DB
          .prepare(`
            SELECT id
            FROM users
            WHERE lower(email) = ?
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

        // Check account name from audit logs.
        const existingName = await env.DB
          .prepare(`
            SELECT user_id
            FROM audit_logs
            WHERE action = 'PROFILE_NAME_SET'
              AND json_extract(details, '$.username') = ?
            LIMIT 1
          `)
          .bind(username)
          .first();

        if (existingName) {
          return fail(
            "Tên tài khoản này đã được sử dụng.",
            409,
            "USERNAME_EXISTS"
          );
        }

        const passwordHash =
          await hashPassword(password);

        const role =
          await roleForRegistration(env);

        if (!role) {
          return fail(
            "Database users hiện không có cấu trúc role tương thích.",
            500,
            "ROLE_SCHEMA_ERROR"
          );
        }

        // QUAN TRỌNG:
        // Không dùng USER vì DB hiện tại của bạn có
        // CHECK role IN ('PLAYER','ADMIN','SUPER_ADMIN')
        const result = await env.DB
          .prepare(`
            INSERT INTO users
            (email, password_hash, role)
            VALUES (?, ?, ?)
          `)
          .bind(
            email,
            passwordHash,
            role
          )
          .run();

        const userId =
          result.meta?.last_row_id;

        if (!userId) {
          throw new Error(
            "Không lấy được ID tài khoản sau khi tạo."
          );
        }

        await saveAccountName(
          env,
          userId,
          username
        );

        await audit(
          env,
          userId,
          "REGISTER",
          `user:${userId}`,
          {
            email,
            username
          }
        );

        return ok({
          message:
            "Tạo tài khoản thành công!",
          user: {
            id: userId,
            username,
            email,
            role
          }
        });
      } catch (error) {
        console.error("REGISTER ERROR:", error);

        return fail(
          "Không thể tạo tài khoản: " +
          error.message,
          500,
          "REGISTER_ERROR"
        );
      }
    }

    // ========================================================
    // AUTH: LOGIN
    // ========================================================

    if (
      url.pathname === "/api/auth/login" &&
      request.method === "POST"
    ) {
      try {
        const data = await bodyJSON(request);

        const email = cleanEmail(data.email);
        const password =
          typeof data.password === "string"
            ? data.password
            : "";

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
            SELECT
              id,
              email,
              password_hash,
              role,
              created_at
            FROM users
            WHERE lower(email) = ?
            LIMIT 1
          `)
          .bind(email)
          .first();

        if (!user) {
          return fail(
            "Email hoặc mật khẩu không đúng.",
            401,
            "INVALID_LOGIN"
          );
        }

        const valid =
          await verifyPassword(
            password,
            user.password_hash
          );

        if (!valid) {
          await audit(
            env,
            user.id,
            "LOGIN_FAILED",
            `user:${user.id}`,
            { email }
          );

          return fail(
            "Email hoặc mật khẩu không đúng.",
            401,
            "INVALID_LOGIN"
          );
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
          `user:${user.id}`,
          { email }
        );

        const publicUserData =
          await publicUser(env, user);

        return new Response(
          JSON.stringify({
            success: true,
            message: "Đăng nhập thành công!",
            user: publicUserData
          }),
          {
            status: 200,
            headers: {
              "content-type":
                "application/json; charset=UTF-8",
              "cache-control":
                "no-store",
              "set-cookie":
                sessionCookie(
                  session.token,
                  SESSION_DAYS * 86400
                )
            }
          }
        );
      } catch (error) {
        console.error("LOGIN ERROR:", error);

        return fail(
          "Không thể đăng nhập: " +
          error.message,
          500,
          "LOGIN_ERROR"
        );
      }
    }

    // ========================================================
    // AUTH: LOGOUT
    // ========================================================

    if (
      url.pathname === "/api/auth/logout" &&
      request.method === "POST"
    ) {
      try {
        const token =
          getCookie(request, "session");

        if (token) {
          const user =
            await getCurrentUser(
              request,
              env
            );

          await env.DB
            .prepare(`
              DELETE FROM sessions
              WHERE token = ?
            `)
            .bind(token)
            .run();

          if (user) {
            await audit(
              env,
              user.id,
              "LOGOUT",
              `user:${user.id}`
            );
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
              "content-type":
                "application/json; charset=UTF-8",
              "cache-control":
                "no-store",
              "set-cookie":
                clearSessionCookie()
            }
          }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({
            success: false,
            error: error.message
          }),
          {
            status: 500,
            headers: {
              "content-type":
                "application/json; charset=UTF-8",
              "set-cookie":
                clearSessionCookie()
            }
          }
        );
      }
    }

    // ========================================================
    // TOURNAMENTS
    // ========================================================

    if (
      url.pathname === "/api/tournaments" &&
      request.method === "GET"
    ) {
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
          "TOURNAMENT_ERROR"
        );
      }
    }

    // ========================================================
    // SLOTS
    // ========================================================

    if (
      url.pathname === "/api/slots" &&
      request.method === "GET"
    ) {
      try {
        const tournamentId =
          Number(
            url.searchParams.get(
              "tournament_id"
            )
          );

        if (!tournamentId) {
          return fail(
            "Thiếu tournament_id.",
            400
          );
        }

        const result = await env.DB
          .prepare(`
            SELECT
              s.id,
              s.tournament_id,
              s.slot_time,
              s.group_name,
              s.capacity,
              COUNT(
                CASE
                  WHEN r.status != 'CANCELLED'
                  THEN r.id
                END
              ) AS used_slots
            FROM slots s
            LEFT JOIN registrations r
              ON r.slot_id = s.id
            WHERE s.tournament_id = ?
            GROUP BY s.id
            ORDER BY s.slot_time
          `)
          .bind(tournamentId)
          .all();

        return ok({
          slots: (result.results || []).map(
            slot => ({
              ...slot,
              used_slots:
                Number(slot.used_slots || 0),
              remaining:
                Math.max(
                  0,
                  Number(slot.capacity || 0) -
                  Number(slot.used_slots || 0)
                )
            })
          )
        });
      } catch (error) {
        return fail(
          error.message,
          500,
          "SLOT_ERROR"
        );
      }
    }

    // ========================================================
    // REGISTER TEAM
    // ========================================================

    if (
      url.pathname === "/api/registrations" &&
      request.method === "POST"
    ) {
      try {
        const user =
          await getCurrentUser(
            request,
            env
          );

        if (!user) {
          return fail(
            "Bạn cần đăng nhập trước.",
            401,
            "UNAUTHORIZED"
          );
        }

        const data =
          await bodyJSON(request);

        const tournamentId =
          Number(data.tournament_id);

        const slotId =
          data.slot_id
            ? Number(data.slot_id)
            : null;

        const teamName =
          cleanText(data.team_name, 80);

        const teamTag =
          cleanText(data.team_tag, 20);

        const logoUrl =
          cleanText(data.logo_url, 500);

        const contactEmail =
          cleanEmail(
            data.contact_email ||
            user.email
          );

        const members =
          Array.isArray(data.members)
            ? data.members
            : [];

        if (!tournamentId) {
          return fail(
            "Vui lòng chọn giải đấu.",
            400
          );
        }

        if (!teamName) {
          return fail(
            "Vui lòng nhập tên team.",
            400
          );
        }

        if (!validEmail(contactEmail)) {
          return fail(
            "Gmail liên hệ không hợp lệ.",
            400
          );
        }

        if (members.length < 2) {
          return fail(
            "Giải 2vs2 cần tối thiểu 2 thành viên.",
            400
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
            "TOURNAMENT_NOT_FOUND"
          );
        }

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
            Number(slot.capacity || 0)
          ) {
            return fail(
              "Khung giờ này đã hết slot.",
              409,
              "SLOT_FULL"
            );
          }
        }

        const existingTeam =
          await env.DB
            .prepare(`
              SELECT id
              FROM teams
              WHERE owner_id = ?
                AND lower(name) = ?
              LIMIT 1
            `)
            .bind(
              user.id,
              teamName.toLowerCase()
            )
            .first();

        let teamId =
          existingTeam?.id || null;

        if (!teamId) {
          const teamResult =
            await env.DB
              .prepare(`
                INSERT INTO teams
                (owner_id, name, tag, logo_url, status)
                VALUES (?, ?, ?, ?, 'PENDING')
              `)
              .bind(
                user.id,
                teamName,
                teamTag || null,
                logoUrl || null
              )
              .run();

          teamId =
            teamResult.meta?.last_row_id;
        }

        if (!teamId) {
          throw new Error(
            "Không tạo được team."
          );
        }

        // Thêm members.
        // Tránh duplicate trong cùng team.
        for (const member of members) {
          const gameName =
            cleanText(
              member.game_name ||
              member.gameName,
              80
            );

          const uid =
            cleanText(
              member.uid,
              80
            );

          const role =
            cleanText(
              member.role || "PLAYER",
              20
            );

          if (!gameName || !uid) {
            continue;
          }

          const exists =
            await env.DB
              .prepare(`
                SELECT id
                FROM team_members
                WHERE team_id = ?
                  AND uid = ?
                LIMIT 1
              `)
              .bind(
                teamId,
                uid
              )
              .first();

          if (!exists) {
            await env.DB
              .prepare(`
                INSERT INTO team_members
                (team_id, game_name, uid, role)
                VALUES (?, ?, ?, ?)
              `)
              .bind(
                teamId,
                gameName,
                uid,
                role
              )
              .run();
          }
        }

        const amount =
          Number(tournament.fee || 0);

        const orderCode =
          "TD1-" +
          Date.now().toString(36).toUpperCase() +
          "-" +
          randomToken(4)
            .toUpperCase();

        const registrationResult =
          await env.DB
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
          registrationResult.meta?.last_row_id;

        if (!registrationId) {
          throw new Error(
            "Không tạo được đơn đăng ký."
          );
        }

        // Payment record
        const paymentResult =
          await env.DB
            .prepare(`
              INSERT INTO payments
              (
                registration_id,
                gateway,
                external_id,
                amount,
                status,
                raw_json
              )
              VALUES (?, 'BANK', ?, ?, 'PENDING', ?)
            `)
            .bind(
              registrationId,
              orderCode,
              amount,
              JSON.stringify({
                contact_email:
                  contactEmail,
                created_by:
                  user.id
              })
            )
            .run();

        const paymentId =
          paymentResult.meta?.last_row_id;

        await audit(
          env,
          user.id,
          "CREATE_REGISTRATION",
          `registration:${registrationId}`,
          {
            teamId,
            tournamentId,
            slotId,
            orderCode,
            amount
          }
        );

        // VietQR configuration:
        // env.BANK_ID
        // env.BANK_ACCOUNT
        // env.BANK_NAME
        //
        // Nếu chưa cấu hình, frontend vẫn hiển thị
        // mã đơn + hướng dẫn.
        let qrUrl = null;

        if (
          env.BANK_ID &&
          env.BANK_ACCOUNT &&
          env.BANK_NAME &&
          amount > 0
        ) {
          const addInfo =
            encodeURIComponent(
              orderCode
            );

          qrUrl =
            `https://img.vietqr.io/image/` +
            `${encodeURIComponent(env.BANK_ID)}-` +
            `${encodeURIComponent(env.BANK_ACCOUNT)}-compact2.png` +
            `?amount=${encodeURIComponent(amount)}` +
            `&addInfo=${addInfo}` +
            `&accountName=${encodeURIComponent(env.BANK_NAME)}`;
        }

        return ok({
          message:
            "Tạo đăng ký đội thành công.",
          registration: {
            id: registrationId,
            team_id: teamId,
            tournament_id: tournamentId,
            slot_id: slotId,
            order_code: orderCode,
            amount,
            status:
              "AWAITING_PAYMENT"
          },
          payment: {
            id: paymentId,
            status: "PENDING",
            qr_url: qrUrl
          }
        });
      } catch (error) {
        console.error(
          "REGISTRATION ERROR:",
          error
        );

        return fail(
          "Không thể tạo đăng ký: " +
          error.message,
          500,
          "REGISTRATION_ERROR"
        );
      }
    }

    // ========================================================
    // MY REGISTRATIONS
    // ========================================================

    if (
      url.pathname === "/api/my-registrations" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getCurrentUser(
            request,
            env
          );

        if (!user) {
          return fail(
            "Bạn cần đăng nhập.",
            401,
            "UNAUTHORIZED"
          );
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
                t.name AS tournament_name,
                t.description AS tournament_description,
                tm.name AS team_name,
                p.status AS payment_status
              FROM registrations r
              JOIN teams tm
                ON tm.id = r.team_id
              JOIN tournaments t
                ON t.id = r.tournament_id
              LEFT JOIN payments p
                ON p.registration_id = r.id
              WHERE tm.owner_id = ?
              ORDER BY r.id DESC
            `)
            .bind(user.id)
            .all();

        return ok({
          registrations:
            result.results || []
        });
      } catch (error) {
        return fail(
          error.message,
          500,
          "REGISTRATION_ERROR"
        );
      }
    }

    // ========================================================
    // PAYMENT STATUS
    // ========================================================

    if (
      url.pathname === "/api/payment/status" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getCurrentUser(
            request,
            env
          );

        if (!user) {
          return fail(
            "Bạn cần đăng nhập.",
            401,
            "UNAUTHORIZED"
          );
        }

        const orderCode =
          cleanText(
            url.searchParams.get(
              "order_code"
            ),
            100
          );

        if (!orderCode) {
          return fail(
            "Thiếu mã đơn."
          );
        }

        const row =
          await env.DB
            .prepare(`
              SELECT
                r.id,
                r.order_code,
                r.amount,
                r.status AS registration_status,
                p.status AS payment_status,
                p.gateway,
                p.external_id,
                p.created_at
              FROM registrations r
              JOIN teams tm
                ON tm.id = r.team_id
              LEFT JOIN payments p
                ON p.registration_id = r.id
              WHERE r.order_code = ?
                AND tm.owner_id = ?
              LIMIT 1
            `)
            .bind(
              orderCode,
              user.id
            )
            .first();

        if (!row) {
          return fail(
            "Không tìm thấy đơn.",
            404,
            "ORDER_NOT_FOUND"
          );
        }

        return ok({
          payment: row
        });
      } catch (error) {
        return fail(
          error.message,
          500,
          "PAYMENT_ERROR"
        );
      }
    }

    // ========================================================
    // PAYMENT WEBHOOK
    //
    // Dùng cho ngân hàng/cổng thanh toán.
    //
    // Header:
    // x-payment-secret
    //
    // Body:
    // {
    //   order_code,
    //   amount,
    //   external_id,
    //   status
    // }
    // ========================================================

    if (
      url.pathname ===
        "/api/payment/webhook" &&
      request.method === "POST"
    ) {
      try {
        const secret =
          request.headers.get(
            "x-payment-secret"
          );

        if (
          env.PAYMENT_WEBHOOK_SECRET &&
          secret !==
            env.PAYMENT_WEBHOOK_SECRET
        ) {
          return fail(
            "Webhook không hợp lệ.",
            401,
            "INVALID_WEBHOOK"
          );
        }

        const data =
          await bodyJSON(request);

        const orderCode =
          cleanText(
            data.order_code ||
            data.orderCode,
            100
          );

        const amount =
          Number(data.amount || 0);

        const externalId =
          cleanText(
            data.external_id ||
            data.externalId ||
            "",
            200
          );

        const incomingStatus =
          String(
            data.status || "PAID"
          ).toUpperCase();

        if (!orderCode) {
          return fail(
            "Thiếu order_code."
          );
        }

        const registration =
          await env.DB
            .prepare(`
              SELECT *
              FROM registrations
              WHERE order_code = ?
              LIMIT 1
            `)
            .bind(orderCode)
            .first();

        if (!registration) {
          return fail(
            "Không tìm thấy đơn.",
            404
          );
        }

        if (
          amount &&
          amount !==
            Number(registration.amount)
        ) {
          return fail(
            "Số tiền thanh toán không khớp.",
            400,
            "AMOUNT_MISMATCH"
          );
        }

        const paid =
          incomingStatus === "PAID" ||
          incomingStatus === "SUCCESS" ||
          incomingStatus === "COMPLETED";

        const paymentStatus =
          paid
            ? "PAID"
            : incomingStatus === "FAILED"
              ? "FAILED"
              : "PENDING";

        const registrationStatus =
          paid
            ? "PAID"
            : incomingStatus === "FAILED"
              ? "CANCELLED"
              : "AWAITING_PAYMENT";

        await env.DB
          .prepare(`
            UPDATE payments
            SET
              status = ?,
              external_id = ?,
              raw_json = ?
            WHERE registration_id = ?
          `)
          .bind(
            paymentStatus,
            externalId || null,
            JSON.stringify(data),
            registration.id
          )
          .run();

        await env.DB
          .prepare(`
            UPDATE registrations
            SET status = ?
            WHERE id = ?
          `)
          .bind(
            registrationStatus,
            registration.id
          )
          .run();

        await audit(
          env,
          null,
          "PAYMENT_WEBHOOK",
          `registration:${registration.id}`,
          {
            orderCode,
            amount,
            paymentStatus,
            externalId
          }
        );

        return ok({
          message:
            paid
              ? "Thanh toán đã được xác nhận."
              : "Đã cập nhật trạng thái thanh toán.",
          order_code: orderCode,
          payment_status:
            paymentStatus,
          registration_status:
            registrationStatus
        });
      } catch (error) {
        return fail(
          error.message,
          500,
          "PAYMENT_WEBHOOK_ERROR"
        );
      }
    }

    // ========================================================
    // RANKING
    // ========================================================

    if (
      url.pathname === "/api/ranking" &&
      request.method === "GET"
    ) {
      try {
        const result =
          await env.DB
            .prepare(`
              SELECT
                tm.id AS team_id,
                tm.name AS team_name,
                COALESCE(
                  SUM(res.kills),
                  0
                ) AS kills,
                COALESCE(
                  SUM(res.points),
                  0
                ) AS points
              FROM teams tm
              JOIN results res
                ON res.team_id = tm.id
              GROUP BY
                tm.id,
                tm.name
              ORDER BY
                points DESC,
                kills DESC,
                tm.id ASC
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
          "RANKING_ERROR"
        );
      }
    }

    // ========================================================
    // TABLE API
    // ========================================================

    if (
      url.pathname === "/api/table" &&
      request.method === "GET"
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

      if (
        !/^[A-Za-z0-9_]+$/.test(table)
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
          500,
          "DATABASE_ERROR"
        );
      }
    }

    // ========================================================
    // WEBSITE ASSETS
    // ========================================================

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
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
