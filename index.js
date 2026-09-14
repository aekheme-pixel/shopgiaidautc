/**
 * ============================================================
 * GIẢI ĐẤU TỬ CHIẾN – MÙA 1
 * Cloudflare Worker + D1 + Web Crypto
 * ============================================================
 *
 * DATABASE THỰC TẾ:
 *
 * users:
 *   id
 *   email
 *   password_hash
 *   password_salt
 *   role
 *   status
 *   created_at
 *
 * teams:
 *   id
 *   name
 *   tag
 *   owner_id
 *   status
 *   created_at
 *   logo_url
 *   contact_email
 *   player2_email
 *
 * team_members:
 *   id
 *   team_id
 *   user_id
 *   game_uid
 *   nickname
 *
 * tournaments:
 *   id
 *   name
 *   description
 *   fee
 *   max_teams
 *   status
 *   created_at
 *
 * registrations:
 *   id
 *   order_code
 *   tournament_id
 *   team_id
 *   user_id
 *   amount
 *   status
 *   created_at
 *   updated_at
 *   reviewed_at
 *   reviewed_by
 *
 * payments:
 *   transaction_id
 *
 * sessions:
 *   id
 *   user_id
 *   expires_at
 *   created_at
 *
 * matches:
 *   id
 *   tournament_id
 *   slot_id
 *   room_id
 *   room_password
 *   start_at
 *   status
 *
 * results:
 *   id
 *   match_id
 *   team_id
 *   placement
 *   kills
 *   points
 *
 * KHÔNG DÙNG app_*
 * ============================================================
 */

const SESSION_COOKIE = "vtc_session";

const SESSION_TTL_MS =
  30 * 24 * 60 * 60 * 1000;

const PBKDF2_ITERATIONS = 100000;
const TEAM_ENTRY_FEE = 30000;

/* ============================================================
   RESPONSE HELPERS
   ============================================================ */

function json(data, status = 200, headers = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=utf-8",
        "cache-control": "no-store",
        ...headers,
      },
    }
  );
}

function text(data, status = 200, headers = {}) {
  return new Response(data, {
    status,
    headers: {
      "content-type":
        "text/plain; charset=utf-8",
      ...headers,
    },
  });
}

/* ============================================================
   ENCODING
   ============================================================ */

function base64url(bytes) {
  let binary = "";
  const chunk = 0x8000;

  for (
    let i = 0;
    i < bytes.length;
    i += chunk
  ) {
    binary += String.fromCharCode(
      ...bytes.subarray(
        i,
        i + chunk
      )
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(value) {
  const input = String(value || "");

  const padded =
    input
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(
        Math.ceil(input.length / 4) * 4,
        "="
      );

  const binary = atob(padded);

  const bytes =
    new Uint8Array(
      binary.length
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}

/* ============================================================
   RANDOM
   ============================================================ */

function randomToken(size = 32) {
  const bytes =
    new Uint8Array(size);

  crypto.getRandomValues(bytes);

  return base64url(bytes);
}

/* ============================================================
   CONSTANT-TIME COMPARE
   ============================================================ */

function safeEqual(a, b) {
  const left =
    new TextEncoder().encode(
      String(a ?? "")
    );

  const right =
    new TextEncoder().encode(
      String(b ?? "")
    );

  if (
    left.length !==
    right.length
  ) {
    return false;
  }

  let result = 0;

  for (
    let i = 0;
    i < left.length;
    i++
  ) {
    result |=
      left[i] ^ right[i];
  }

  return result === 0;
}

/* ============================================================
   SEPAY HMAC SHA-256
   ============================================================ */

async function hmacSha256Hex(
  secret,
  message
) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        secret
      ),
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(
        message
      )
    );

  return [
    ...new Uint8Array(
      signature
    ),
  ]
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}

/* ============================================================
   PASSWORD HASH
   ============================================================ */

async function derivePassword(
  password,
  salt
) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        password
      ),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations:
          PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      key,
      256
    );

  return new Uint8Array(bits);
}

async function makePassword(
  password
) {
  const salt =
    new Uint8Array(16);

  crypto.getRandomValues(salt);

  const hash =
    await derivePassword(
      password,
      salt
    );

  return {
    salt: base64url(salt),
    hash: base64url(hash),
  };
}

async function checkPassword(
  password,
  saltText,
  hashText
) {
  try {
    const salt =
      fromBase64url(saltText);

    const expected =
      fromBase64url(hashText);

    const actual =
      await derivePassword(
        password,
        salt
      );

    return safeEqual(
      actual,
      expected
    );
  } catch {
    return false;
  }
}

/* ============================================================
   COOKIES
   ============================================================ */

function cookies(request) {
  const result = {};

  const header =
    request.headers.get(
      "cookie"
    ) || "";

  for (
    const part of header.split(";")
  ) {
    const index =
      part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      part
        .slice(0, index)
        .trim();

    const value =
      part
        .slice(index + 1)
        .trim();

    if (key) {
      try {
        result[key] =
          decodeURIComponent(
            value
          );
      } catch {
        result[key] = value;
      }
    }
  }

  return result;
}

function setSessionCookie(
  token
) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${Math.floor(
      SESSION_TTL_MS / 1000
    )}`,
  ].join("; ");
}

function deleteSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

/* ============================================================
   INPUT
   ============================================================ */

async function bodyJson(request) {
  try {
    return await request.json();
  } catch {
    throw new Error(
      "Dữ liệu gửi lên không hợp lệ."
    );
  }
}

function email(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    value
  );
}

function positiveNumber(value, fallback = 0) {
  const n = Number(value);

  return Number.isFinite(n)
    ? n
    : fallback;
}

function cleanString(
  value,
  max = 500
) {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}

/* ============================================================
   USER
   ============================================================ */

function publicUser(user) {
  return {
    id: Number(user.id),
    email: user.email,

    role:
      user.role ||
      "PLAYER",

    balance: Number(
      user.balance || 0
    ),

    createdAt:
      user.created_at ||
      null,
  };
}

/* ============================================================
   SESSION
   ============================================================ */

async function currentSession(
  request,
  env
) {
  const token =
    cookies(request)[
      SESSION_COOKIE
    ];

  if (!token) {
    return null;
  }

  const now =
    Date.now();

  try {
    const row =
      await env.DB
        .prepare(`
          SELECT
            s.id,
            s.user_id,
            s.expires_at,

            u.id AS uid,
            u.email,
            u.password_hash,
            u.password_salt,
            u.role,
            u.status,
            u.created_at

          FROM sessions s

          JOIN users u
            ON u.id = s.user_id

          WHERE
            s.id = ?
            AND CAST(
              s.expires_at AS INTEGER
            ) > ?

          LIMIT 1
        `)
        .bind(
          token,
          now
        )
        .first();

    if (!row) {
      return null;
    }

    if (
      row.status &&
      row.status !== "ACTIVE"
    ) {
      return null;
    }

    return {
      token,

      user: {
        id: row.uid,

        email:
          row.email,

        role:
          row.role ||
          "PLAYER",

        balance: 0,

        created_at:
          row.created_at,
      },
    };
  } catch {
    return null;
  }
}

async function createSession(
  env,
  userId
) {
  const token =
    randomToken(32);

  const expires =
    Date.now() +
    SESSION_TTL_MS;

  await env.DB
    .prepare(`
      INSERT INTO sessions
        (
          id,
          user_id,
          expires_at
        )
      VALUES
        (?, ?, ?)
    `)
    .bind(
      token,
      userId,
      expires
    )
    .run();

  return token;
}

/* ============================================================
   ADMIN AUTHORIZATION
   ============================================================ */

function isAdminRole(role) {
  return (
    role === "ADMIN" ||
    role === "SUPER_ADMIN"
  );
}

async function requireAdmin(
  request,
  env
) {
  const session =
    await currentSession(
      request,
      env
    );

  if (!session) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          error:
            "Bạn chưa đăng nhập.",
        },
        401
      ),
    };
  }

  if (
    !isAdminRole(
      session.user.role
    )
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          error:
            "Bạn không có quyền truy cập trang quản trị.",
        },
        403
      ),
    };
  }

  return {
    ok: true,
    session,
  };
}

/* ============================================================
   AUDIT
   ============================================================ */

async function writeAudit(
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
          (
            user_id,
            action,
            target,
            details
          )
        VALUES
          (?, ?, ?, ?)
      `)
      .bind(
        userId ?? null,
        action,
        target,
        details == null
          ? null
          : JSON.stringify(
              details
            )
      )
      .run();
  } catch {
    /*
     * Audit log không được
     * làm hỏng thao tác chính.
     */
  }
}

/* ============================================================
   HEALTH
   ============================================================ */

async function health(env) {
  try {
    await env.DB
      .prepare(
        "SELECT 1 AS ok"
      )
      .first();

    return json({
      ok: true,
      service:
        "vua-tu-chien-mua1",
      database: true,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        database: false,
        error:
          error?.message ||
          "D1 error",
      },
      500
    );
  }
}

/* ============================================================
   REGISTER
   ============================================================ */

async function register(
  request,
  env
) {
  const data =
    await bodyJson(request);

  /*
   * FORM CHÍNH THỨC:
   *
   * email
   * password
   * confirmPassword
   *
   * KHÔNG username.
   */

  const userEmail =
    email(data.email);

  const password =
    String(
      data.password || ""
    );

  const confirmPassword =
    String(
      data.confirmPassword ??
      ""
    );

  if (
    !validEmail(
      userEmail
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Email không hợp lệ.",
      },
      400
    );
  }

  if (
    password.length < 6
  ) {
    return json(
      {
        ok: false,
        error:
          "Mật khẩu phải có ít nhất 6 ký tự.",
      },
      400
    );
  }

  if (
    password !==
    confirmPassword
  ) {
    return json(
      {
        ok: false,
        error:
          "Mật khẩu nhập lại không khớp.",
      },
      400
    );
  }

  const existed =
    await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(userEmail)
      .first();

  if (existed) {
    return json(
      {
        ok: false,
        error:
          "Email này đã được đăng ký.",
      },
      409
    );
  }

  const passwordData =
    await makePassword(
      password
    );

  let userId;

  try {
    const result =
      await env.DB
        .prepare(`
          INSERT INTO users
            (
              email,
              password_hash,
              password_salt,
              role,
              status
            )
          VALUES
            (?, ?, ?, 'PLAYER', 'ACTIVE')
        `)
        .bind(
          userEmail,
          passwordData.hash,
          passwordData.salt
        )
        .run();

    userId =
      result.meta
        ?.last_row_id;

    if (!userId) {
      const created =
        await env.DB
          .prepare(`
            SELECT id
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(
            userEmail
          )
          .first();

      userId =
        created?.id;
    }
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể tạo tài khoản: " +
          (
            error?.message ||
            "D1 error"
          ),
      },
      500
    );
  }

  if (!userId) {
    return json(
      {
        ok: false,
        error:
          "Tạo tài khoản thất bại.",
      },
      500
    );
  }

  let token;

  try {
    token =
      await createSession(
        env,
        userId
      );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Tài khoản đã tạo nhưng không tạo được phiên đăng nhập: " +
          (
            error?.message ||
            "session error"
          ),
      },
      500
    );
  }

  const user =
    await env.DB
      .prepare(`
        SELECT
          id,
          email,
          role,
          status,
          created_at
        FROM users
        WHERE id = ?
        LIMIT 1
      `)
      .bind(userId)
      .first();

  await writeAudit(
    env,
    userId,
    "REGISTER",
    `user:${userId}`
  );

  return json(
    {
      ok: true,
      message:
        "Tạo tài khoản thành công.",
      user:
        publicUser(user),
    },
    201,
    {
      "set-cookie":
        setSessionCookie(
          token
        ),
    }
  );
}

/* ============================================================
   LOGIN
   ============================================================ */

async function login(
  request,
  env
) {
  const data =
    await bodyJson(request);

  const userEmail =
    email(data.email);

  const password =
    String(
      data.password || ""
    );

  if (
    !validEmail(
      userEmail
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Email không hợp lệ.",
      },
      400
    );
  }

  if (!password) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập mật khẩu.",
      },
      400
    );
  }

  const user =
    await env.DB
      .prepare(`
        SELECT
          id,
          email,
          password_hash,
          password_salt,
          role,
          status,
          created_at
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(userEmail)
      .first();

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Email hoặc mật khẩu không đúng.",
      },
      401
    );
  }

  if (
    user.status &&
    user.status !== "ACTIVE"
  ) {
    return json(
      {
        ok: false,
        error:
          "Tài khoản hiện không hoạt động.",
      },
      403
    );
  }

  const valid =
    await checkPassword(
      password,
      user.password_salt,
      user.password_hash
    );

  if (!valid) {
    return json(
      {
        ok: false,
        error:
          "Email hoặc mật khẩu không đúng.",
      },
      401
    );
  }

  const token =
    await createSession(
      env,
      user.id
    );

  await writeAudit(
    env,
    user.id,
    "LOGIN",
    `user:${user.id}`
  );

  return json(
    {
      ok: true,
      message:
        "Đăng nhập thành công.",
      user:
        publicUser(user),
    },
    200,
    {
      "set-cookie":
        setSessionCookie(
          token
        ),
    }
  );
}

/* ============================================================
   LOGOUT
   ============================================================ */

async function logout(
  request,
  env
) {
  const token =
    cookies(request)[
      SESSION_COOKIE
    ];

  if (token) {
    try {
      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE id = ?
        `)
        .bind(token)
        .run();
    } catch {}
  }

  return json(
    {
      ok: true,
      message:
        "Đã đăng xuất.",
    },
    200,
    {
      "set-cookie":
        deleteSessionCookie(),
    }
  );
}

/* ============================================================
   ME
   ============================================================ */

async function me(
  request,
  env
) {
  const session =
    await currentSession(
      request,
      env
    );

  if (!session) {
    return json({
      ok: true,
      authenticated: false,
      user: null,
    });
  }

  return json({
    ok: true,
    authenticated: true,
    user:
      publicUser(
        session.user
      ),
  });
}

/* ============================================================
   SESSION CLEANUP
   ============================================================ */

async function cleanupSessions(env) {
  try {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE CAST(expires_at AS INTEGER) <= ?
      `)
      .bind(Date.now())
      .run();
  } catch {}
}

/* ============================================================
   BANK CONFIG
   ============================================================ */

function bankConfig(env) {
  return {
    name:
      env.BANK_NAME ||
      "MB BANK",

    account:
      env.BANK_ACCOUNT ||
      "0977049795",

    owner:
      env.BANK_OWNER ||
      "Đinh Hồng Hạnh",
  };
}

/* ============================================================
   OPEN TOURNAMENT
   ============================================================ */

async function getOpenTournament(env) {
  return await env.DB
    .prepare(`
      SELECT
        id,
        name,
        description,
        fee,
        max_teams,
        status,
        created_at
      FROM tournaments
      WHERE status = 'OPEN'
      ORDER BY id DESC
      LIMIT 1
    `)
    .first();
}

/* ============================================================
   PUBLIC TOURNAMENT
   ============================================================ */

async function tournament(
  request,
  env
) {
  const t =
    await getOpenTournament(
      env
    );

  const bank =
    bankConfig(env);

  if (!t) {
    return json({
      ok: true,
      tournament: {
        id: null,
        name:
          "Chưa có giải đấu",
        description:
          "Hiện chưa có giải đấu đang mở.",
        registered: 0,
        slots: 0,
        remaining: 0,

        entryFee:
          TEAM_ENTRY_FEE,

        status: "CLOSED",
        statusText:
          "CHƯA MỞ",

        bank,
      },
    });
  }

  const registered =
    Number(
      t.registered || 0
    );

  const slots =
    Number(
      t.max_teams || 0
    );

  const remaining =
    Math.max(
      slots - registered,
      0
    );

  const status =
    remaining > 0
      ? "OPEN"
      : "FULL";

  return json({
    ok: true,

    tournament: {
      id: t.id,
      name: t.name,
      description:
        t.description || "",

      registered,
      slots,
      remaining,

      entryFee:
        TEAM_ENTRY_FEE,

      status,

      statusText:
        status === "OPEN"
          ? "CÒN SLOT"
          : "HẾT SLOT",

      bank,
    },
  });
}

/* ============================================================
   TEAM REGISTER
   ============================================================ */

async function teamRegister(
  request,
  env
) {
  const session =
    await currentSession(
      request,
      env
    );

  if (!session) {
    return json(
      {
        ok: false,
        error:
          "Bạn cần đăng nhập trước khi đăng ký team.",
      },
      401
    );
  }

  const body =
    await bodyJson(request);

  const teamName =
    cleanString(
      body.teamName,
      60
    );

  const logoUrl =
    cleanString(
      body.logoUrl,
      180000
    );

  const registrantName =
    cleanString(
      body.registrantName,
      100
    );

  const contactInfo =
    cleanString(
      body.contactInfo,
      200
    );

  if (
    teamName.length < 2
  ) {
    return json(
      {
        ok: false,
        error:
          "Tên team phải có ít nhất 2 ký tự.",
      },
      400
    );
  }

  if (
    !registrantName
  ) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập tên người đăng ký.",
      },
      400
    );
  }

  if (
    !contactInfo
  ) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập thông tin liên hệ Zalo/Facebook.",
      },
      400
    );
  }

  if (
    logoUrl &&
    !/^data:image\/(?:png|jpe?g|webp);base64,/i.test(
      logoUrl
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Logo không đúng định dạng ảnh.",
      },
      400
    );
  }

  if (
    logoUrl.length > 180000
  ) {
    return json(
      {
        ok: false,
        error:
          "Logo quá lớn.",
      },
      400
    );
  }

  const t =
    await getOpenTournament(
      env
    );

  if (!t) {
    return json(
      {
        ok: false,
        error:
          "Hiện chưa có giải đấu đang mở.",
      },
      400
    );
  }

  const countRow =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS count
        FROM registrations
        WHERE tournament_id = ?
          AND status NOT IN (
            'CANCELLED',
            'REJECTED'
          )
      `)
      .bind(t.id)
      .first();

  const registered =
    Number(
      countRow?.count || 0
    );

  const maxTeams =
    Number(
      t.max_teams || 0
    );

  if (
    maxTeams > 0 &&
    registered >= maxTeams
  ) {
    return json(
      {
        ok: false,
        error:
          "Giải đấu đã hết slot.",
      },
      409
    );
  }

  const duplicate =
    await env.DB
      .prepare(`
        SELECT r.id
        FROM registrations r
        JOIN teams tm
          ON tm.id = r.team_id
        WHERE r.tournament_id = ?
          AND tm.owner_id = ?
          AND r.status NOT IN (
            'CANCELLED',
            'REJECTED'
          )
        LIMIT 1
      `)
      .bind(
        t.id,
        session.user.id
      )
      .first();

  if (duplicate) {
    return json(
      {
        ok: false,
        error:
          "Bạn đã có team đăng ký giải này rồi.",
      },
      409
    );
  }

  const orderCode =
    (
      "VTC" +
      Date.now().toString(36) +
      randomToken(4)
        .replace(
          /[^A-Za-z0-9]/g,
          ""
        )
    )
      .toUpperCase()
      .slice(0, 30);

  const amount =
    TEAM_ENTRY_FEE;

  let teamId;
  let registrationId;

  try {
    const teamResult =
      await env.DB
        .prepare(`
          INSERT INTO teams
            (
              name,
              tag,
              owner_id,
              status,
              logo_url,
              contact_email,
              player2_email,
              registrant_name,
              contact_info
            )
          VALUES
            (?, '', ?, 'PENDING_PAYMENT', ?, '', '', ?, ?)
        `)
        .bind(
          teamName,
          session.user.id,
          logoUrl,
          registrantName,
          contactInfo
        )
        .run();

    teamId =
      teamResult.meta
        ?.last_row_id;

    if (!teamId) {
      const createdTeam =
        await env.DB
          .prepare(`
            SELECT id
            FROM teams
            WHERE owner_id = ?
              AND name = ?
            ORDER BY id DESC
            LIMIT 1
          `)
          .bind(
            session.user.id,
            teamName
          )
          .first();

      teamId =
        createdTeam?.id;
    }

    if (!teamId) {
      throw new Error(
        "Không tạo được team."
      );
    }

    await env.DB
      .prepare(`
        INSERT INTO team_members
          (
            team_id,
            user_id,
            game_uid,
            nickname
          )
        VALUES
          (?, ?, '', ?)
      `)
      .bind(
        teamId,
        session.user.id,
        registrantName
      )
      .run();

    const registrationResult =
      await env.DB
        .prepare(`
          INSERT INTO registrations
            (
              order_code,
              tournament_id,
              team_id,
              user_id,
              amount,
              status
            )
          VALUES
            (?, ?, ?, ?, ?, 'AWAITING_PAYMENT')
        `)
        .bind(
          orderCode,
          t.id,
          teamId,
          session.user.id,
          amount
        )
        .run();

    registrationId =
      registrationResult.meta
        ?.last_row_id;

    if (!registrationId) {
      const createdRegistration =
        await env.DB
          .prepare(`
            SELECT id
            FROM registrations
            WHERE order_code = ?
            LIMIT 1
          `)
          .bind(
            orderCode
          )
          .first();

      registrationId =
        createdRegistration?.id;
    }

    if (!registrationId) {
      throw new Error(
        "Không tạo được đơn đăng ký."
      );
    }

    await env.DB
      .prepare(`
        INSERT INTO payments
          (
            registration_id,
            gateway,
            transaction_id,
            amount,
            status,
            raw_json
          )
        VALUES
          (?, 'BANK', '', ?, 'PENDING', ?)
      `)
      .bind(
        registrationId,
        amount,
        JSON.stringify({
          orderCode,
          bank:
            bankConfig(env),
        })
      )
      .run();

    await writeAudit(
      env,
      session.user.id,
      "TEAM_REGISTER",
      `team:${teamId}`,
      {
        registrationId,
        orderCode,
        amount,
      }
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể tạo đăng ký team: " +
          (
            error?.message ||
            "D1 error"
          ),
      },
      500
    );
  }

  return json(
    {
      ok: true,

      message:
        "Đăng ký team thành công. Vui lòng thanh toán 30.000đ.",

      team: {
        id:
          Number(teamId),
        name:
          teamName,
        logoUrl:
          logoUrl || "",
        registrantName:
          registrantName,
        contactInfo:
          contactInfo,
        status:
          "PENDING_PAYMENT",
      },

      registration: {
        id:
          Number(
            registrationId
          ),
        orderCode,
        amount,
        status:
          "AWAITING_PAYMENT",
      },

      bank:
        bankConfig(env),
    }
  );
}

/* ============================================================
   TEAM ME
   ============================================================ */

async function teamMe(
  request,
  env
) {
  const session =
    await currentSession(
      request,
      env
    );

  if (!session) {
    return json({
      ok: true,
      authenticated: false,
      hasTeam: false,
    });
  }

  const row =
    await env.DB
      .prepare(`
        SELECT
          r.id AS registration_id,
          r.order_code,
          r.amount,
          r.status AS registration_status,
          r.created_at,
          r.updated_at,

          tm.id AS team_id,
          tm.name AS team_name,
          tm.tag AS team_tag,
          tm.status AS team_status,
          tm.logo_url,
          tm.registrant_name,
          tm.contact_info,

          t.id AS tournament_id,
          t.name AS tournament_name,
          t.description AS tournament_description

        FROM registrations r

        JOIN teams tm
          ON tm.id = r.team_id

        JOIN tournaments t
          ON t.id = r.tournament_id

        WHERE
          r.user_id = ?
          AND r.status NOT IN (
            'CANCELLED',
            'REJECTED'
          )

        ORDER BY
          r.id DESC

        LIMIT 1
      `)
      .bind(
        session.user.id
      )
      .first();

  if (!row) {
    return json({
      ok: true,
      authenticated: true,
      hasTeam: false,
    });
  }

  return json({
    ok: true,
    authenticated: true,
    hasTeam: true,

    registration: {
      id:
        Number(
          row.registration_id
        ),

      orderCode:
        row.order_code,

      amount:
        Number(
          row.amount || 0
        ),

      status:
        row.registration_status,

      createdAt:
        row.created_at ||
        null,

      updatedAt:
        row.updated_at ||
        null,
    },

    team: {
      id:
        Number(
          row.team_id
        ),

      name:
        row.team_name,

      tag:
        row.team_tag || "",

      status:
        row.team_status,

      logoUrl:
        row.logo_url || "",

      registrantName:
        row.registrant_name ||
        "",

      contactInfo:
        row.contact_info ||
        "",
    },

    tournament: {
      id:
        Number(
          row.tournament_id
        ),

      name:
        row.tournament_name,

      description:
        row.tournament_description ||
        "",
    },

    schedule: null,
  });
}

/* ============================================================
   PAYMENT CONFIRM
   ============================================================ */

async function teamPaymentConfirm(
  request,
  env
) {
  const session =
    await currentSession(
      request,
      env
    );

  if (!session) {
    return json(
      {
        ok: false,
        error:
          "Bạn chưa đăng nhập.",
      },
      401
    );
  }

  const row =
    await env.DB
      .prepare(`
        SELECT
          id,
          status
        FROM registrations
        WHERE user_id = ?
          AND status IN (
            'AWAITING_PAYMENT',
            'PAYMENT_PENDING_CONFIRMATION'
          )
        ORDER BY id DESC
        LIMIT 1
      `)
      .bind(
        session.user.id
      )
      .first();

  if (!row) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy đơn đăng ký đang chờ thanh toán.",
      },
      404
    );
  }

  await env.DB
    .prepare(`
      UPDATE registrations
      SET
        status =
          'PAYMENT_PENDING_CONFIRMATION',
        updated_at =
          CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(row.id)
    .run();

  await writeAudit(
    env,
    session.user.id,
    "PAYMENT_CONFIRM",
    `registration:${row.id}`,
    {}
  );

  return json({
    ok: true,

    registration: {
      id:
        Number(row.id),

      status:
        "PAYMENT_PENDING_CONFIRMATION",
    },
  });
}
  const name =
    cleanString(
      data.name,
      150
    );

  const description =
    cleanString(
      data.description,
      2000
    );

  const fee =
    Math.max(
      0,
      Math.floor(
        positiveNumber(
          data.fee,
          0
        )
      )
    );

  const maxTeams =
    Math.max(
      1,
      Math.floor(
        positiveNumber(
          data.maxTeams ??
            data.max_teams,
          48
        )
      )
    );

  const status =
    ["OPEN", "CLOSED"].includes(
      String(
        data.status ||
          "OPEN"
      ).toUpperCase()
    )
      ? String(
          data.status ||
            "OPEN"
        ).toUpperCase()
      : "OPEN";

  if (!name) {
    return json(
      {
        ok: false,
        error:
          "Tên giải đấu không được để trống.",
      },
      400
    );
  }

  try {
    const result =
      await env.DB
        .prepare(`
          INSERT INTO tournaments
            (
              name,
              description,
              fee,
              max_teams,
              status
            )
          VALUES
            (?, ?, ?, ?, ?)
        `)
        .bind(
          name,
          description,
          fee,
          maxTeams,
          status
        )
        .run();

    const id =
      result.meta
        ?.last_row_id;

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_CREATE_TOURNAMENT",
      id
        ? `tournament:${id}`
        : null,
      {
        name,
        fee,
        maxTeams,
        status,
      }
    );

    return json(
      {
        ok: true,
        message:
          "Đã tạo giải đấu.",

        tournament: {
          id:
            Number(id || 0),
          name,
          description,
          fee,
          maxTeams,
          status,
        },
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không thể tạo giải đấu.",
      },
      500
    );
  }

/* ============================================================
   ADMIN: UPDATE TOURNAMENT
   ============================================================ */

async function adminUpdateTournament(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const data =
    await bodyJson(request);

  const id =
    Number(
      data.id
    );

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "ID giải đấu không hợp lệ.",
      },
      400
    );
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT *
        FROM tournaments
        WHERE id = ?
        LIMIT 1
      `)
      .bind(id)
      .first();

  if (!existing) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy giải đấu.",
      },
      404
    );
  }

  const name =
    cleanString(
      data.name ??
        existing.name,
      150
    );

  const description =
    cleanString(
      data.description ??
        existing.description ??
        "",
      2000
    );

  const fee =
    Math.max(
      0,
      Math.floor(
        positiveNumber(
          data.fee,
          Number(
            existing.fee || 0
          )
        )
      )
    );

  const maxTeams =
    Math.max(
      1,
      Math.floor(
        positiveNumber(
          data.maxTeams ??
            data.max_teams,
          Number(
            existing.max_teams ||
              48
          )
        )
      )
    );

  const status =
    String(
      data.status ??
        existing.status ??
        "OPEN"
    ).toUpperCase();

  if (
    ![
      "OPEN",
      "CLOSED",
    ].includes(status)
  ) {
    return json(
      {
        ok: false,
        error:
          "Trạng thái giải đấu không hợp lệ.",
      },
      400
    );
  }

  try {
    await env.DB
      .prepare(`
        UPDATE tournaments
        SET
          name = ?,
          description = ?,
          fee = ?,
          max_teams = ?,
          status = ?
        WHERE id = ?
      `)
      .bind(
        name,
        description,
        fee,
        maxTeams,
        status,
        id
      )
      .run();

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_UPDATE_TOURNAMENT",
      `tournament:${id}`,
      {
        name,
        fee,
        maxTeams,
        status,
      }
    );

    return json({
      ok: true,
      message:
        "Đã cập nhật giải đấu.",

      tournament: {
        id,
        name,
        description,
        fee,
        maxTeams,
        status,
      },
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không thể cập nhật giải đấu.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: SCHEDULES
   ============================================================ */

async function adminSchedules(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const url =
    new URL(
      request.url
    );

  const tournamentId =
    Number(
      url.searchParams.get(
        "tournamentId"
      ) ||
        url.searchParams.get(
          "tournament_id"
        ) ||
        0
    );

  if (
    !Number.isInteger(
      tournamentId
    ) ||
    tournamentId <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Thiếu tournamentId.",
      },
      400
    );
  }

  try {
    const result =
      await env.DB
        .prepare(`
          SELECT
            m.id,
            m.tournament_id,
            m.slot_id,
            m.room_id,
            m.room_password,
            m.start_at,
            m.status,

            s.slot_time,
            s.group_name

          FROM matches m

          LEFT JOIN slots s
            ON s.id =
               m.slot_id

          WHERE
            m.tournament_id = ?

          ORDER BY
            CASE
              WHEN m.start_at IS NULL
              THEN 1
              ELSE 0
            END,
            m.start_at ASC,
            m.id ASC
        `)
        .bind(
          tournamentId
        )
        .all();

    return json({
      ok: true,

      schedules:
        (
          result.results ||
          []
        ).map(
          row => ({
            id:
              Number(row.id),

            tournamentId:
              Number(
                row.tournament_id
              ),

            slotId:
              row.slot_id == null
                ? null
                : Number(
                    row.slot_id
                  ),

            roomId:
              row.room_id ||
              "",

            roomPassword:
              row.room_password ||
              "",

            startAt:
              row.start_at ||
              null,

            status:
              row.status ||
              "SCHEDULED",

            slotTime:
              row.slot_time ||
              null,

            groupName:
              row.group_name ||
              "",
          })
        ),
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không lấy được lịch thi đấu.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: CREATE SCHEDULE
   ============================================================ */

async function adminCreateSchedule(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const data =
    await bodyJson(request);

  const tournamentId =
    Number(
      data.tournamentId ??
        data.tournament_id
    );

  const slotId =
    data.slotId ??
    data.slot_id;

  const normalizedSlotId =
    slotId == null ||
    slotId === ""
      ? null
      : Number(
          slotId
        );

  const roomId =
    cleanString(
      data.roomId ??
        data.room_id,
      100
    );

  const roomPassword =
    cleanString(
      data.roomPassword ??
        data.room_password,
      100
    );

  const startAt =
    data.startAt ??
    data.start_at ??
    null;

  const status =
    cleanString(
      data.status ||
        "SCHEDULED",
      50
    );

  if (
    !Number.isInteger(
      tournamentId
    ) ||
    tournamentId <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Tournament ID không hợp lệ.",
      },
      400
    );
  }

  if (
    normalizedSlotId !== null &&
    (
      !Number.isInteger(
        normalizedSlotId
      ) ||
      normalizedSlotId <= 0
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Slot ID không hợp lệ.",
      },
      400
    );
  }

  const tournamentExists =
    await env.DB
      .prepare(`
        SELECT id
        FROM tournaments
        WHERE id = ?
        LIMIT 1
      `)
      .bind(
        tournamentId
      )
      .first();

  if (!tournamentExists) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy giải đấu.",
      },
      404
    );
  }

  try {
    const result =
      await env.DB
        .prepare(`
          INSERT INTO matches
            (
              tournament_id,
              slot_id,
              room_id,
              room_password,
              start_at,
              status
            )
          VALUES
            (?, ?, ?, ?, ?, ?)
        `)
        .bind(
          tournamentId,
          normalizedSlotId,
          roomId,
          roomPassword,
          startAt,
          status
        )
        .run();

    const id =
      result.meta
        ?.last_row_id;

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_CREATE_SCHEDULE",
      id
        ? `match:${id}`
        : null,
      {
        tournamentId,
        slotId:
          normalizedSlotId,
        roomId,
        startAt,
        status,
      }
    );

    return json(
      {
        ok: true,

        message:
          "Đã tạo lịch thi đấu.",

        schedule: {
          id:
            Number(id || 0),

          tournamentId,

          slotId:
            normalizedSlotId,

          roomId,

          roomPassword,

          startAt,

          status,
        },
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không thể tạo lịch thi đấu.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: UPDATE SCHEDULE
   ============================================================ */

async function adminUpdateSchedule(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const data =
    await bodyJson(request);

  const id =
    Number(
      data.id
    );

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "ID lịch thi đấu không hợp lệ.",
      },
      400
    );
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT *
        FROM matches
        WHERE id = ?
        LIMIT 1
      `)
      .bind(id)
      .first();

  if (!existing) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy lịch thi đấu.",
      },
      404
    );
  }

  const tournamentId =
    Number(
      data.tournamentId ??
        data.tournament_id ??
        existing.tournament_id
    );

  const slotValue =
    data.slotId ??
    data.slot_id ??
    existing.slot_id;

  const slotId =
    slotValue == null ||
    slotValue === ""
      ? null
      : Number(
          slotValue
        );

  const roomId =
    cleanString(
      data.roomId ??
        data.room_id ??
        existing.room_id ??
        "",
      100
    );

  const roomPassword =
    cleanString(
      data.roomPassword ??
        data.room_password ??
        existing.room_password ??
        "",
      100
    );

  const startAt =
    data.startAt ??
    data.start_at ??
    existing.start_at ??
    null;

  const status =
    cleanString(
      data.status ??
        existing.status ??
        "SCHEDULED",
      50
    );

  if (
    !Number.isInteger(
      tournamentId
    ) ||
    tournamentId <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Tournament ID không hợp lệ.",
      },
      400
    );
  }

  if (
    slotId !== null &&
    (
      !Number.isInteger(
        slotId
      ) ||
      slotId <= 0
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Slot ID không hợp lệ.",
      },
      400
    );
  }

  try {
    await env.DB
      .prepare(`
        UPDATE matches
        SET
          tournament_id = ?,
          slot_id = ?,
          room_id = ?,
          room_password = ?,
          start_at = ?,
          status = ?
        WHERE id = ?
      `)
      .bind(
        tournamentId,
        slotId,
        roomId,
        roomPassword,
        startAt,
        status,
        id
      )
      .run();

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_UPDATE_SCHEDULE",
      `match:${id}`,
      {
        tournamentId,
        slotId,
        roomId,
        startAt,
        status,
      }
    );

    return json({
      ok: true,

      message:
        "Đã cập nhật lịch thi đấu.",

      schedule: {
        id,
        tournamentId,
        slotId,
        roomId,
        roomPassword,
        startAt,
        status,
      },
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không thể cập nhật lịch thi đấu.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: DELETE SCHEDULE
   ============================================================ */

async function adminDeleteSchedule(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const data =
    await bodyJson(request);

  const id =
    Number(
      data.id
    );

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "ID lịch thi đấu không hợp lệ.",
      },
      400
    );
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM matches
        WHERE id = ?
        LIMIT 1
      `)
      .bind(id)
      .first();

  if (!existing) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy lịch thi đấu.",
      },
      404
    );
  }

  try {
    await env.DB
      .prepare(`
        DELETE FROM matches
        WHERE id = ?
      `)
      .bind(id)
      .run();

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_DELETE_SCHEDULE",
      `match:${id}`,
      {}
    );

    return json({
      ok: true,

      message:
        "Đã xóa lịch thi đấu.",
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không thể xóa lịch thi đấu.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: TEAMS
   ============================================================ */

async function adminTeams(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const url =
    new URL(
      request.url
    );

  const tournamentId =
    Number(
      url.searchParams.get(
        "tournamentId"
      ) ||
        url.searchParams.get(
          "tournament_id"
        ) ||
        0
    );

  try {
    let result;

    if (
      tournamentId > 0
    ) {
      result =
        await env.DB
          .prepare(`
            SELECT
              tm.id,
              tm.name,
              tm.tag,
              tm.owner_id,
              tm.status,
              tm.logo_url,
              tm.contact_email,
              tm.player2_email,
              tm.registrant_name,
              tm.contact_info,
              tm.created_at,

              u.email AS owner_email,

              r.id AS registration_id,
              r.order_code,
              r.amount,
              r.status AS registration_status,
              r.created_at AS registration_created_at

            FROM teams tm

            JOIN users u
              ON u.id =
                 tm.owner_id

            LEFT JOIN registrations r
              ON r.team_id =
                 tm.id
              AND r.tournament_id = ?

            ORDER BY
              tm.id DESC

            LIMIT 500
          `)
          .bind(
            tournamentId
          )
          .all();
    } else {
      result =
        await env.DB
          .prepare(`
            SELECT
              tm.id,
              tm.name,
              tm.tag,
              tm.owner_id,
              tm.status,
              tm.logo_url,
              tm.contact_email,
              tm.player2_email,
              tm.registrant_name,
              tm.contact_info,
              tm.created_at,

              u.email AS owner_email,

              r.id AS registration_id,
              r.order_code,
              r.amount,
              r.status AS registration_status,
              r.tournament_id,
              r.created_at AS registration_created_at

            FROM teams tm

            JOIN users u
              ON u.id =
                 tm.owner_id

            LEFT JOIN registrations r
              ON r.team_id =
                 tm.id

            ORDER BY
              tm.id DESC

            LIMIT 500
          `)
          .all();
    }

    return json({
      ok: true,

      teams:
        (
          result.results ||
          []
        ).map(
          row => ({
            id:
              Number(row.id),

            name:
              row.name,

            tag:
              row.tag ||
              "",

            ownerId:
              Number(
                row.owner_id
              ),

            ownerEmail:
              row.owner_email ||
              "",

            status:
              row.status,

            logoUrl:
              row.logo_url ||
              "",

            contactEmail:
              row.contact_email ||
              "",

            player2Email:
              row.player2_email ||
              "",

            registrantName:
              row.registrant_name ||
              "",

            contactInfo:
              row.contact_info ||
              "",

            registration:
              row.registration_id
                ? {
                    id:
                      Number(
                        row.registration_id
                      ),

                    orderCode:
                      row.order_code ||
                      "",

                    amount:
                      Number(
                        row.amount ||
                        0
                      ),

                    status:
                      row.registration_status ||
                      "",

                    tournamentId:
                      row.tournament_id
                        ? Number(
                            row.tournament_id
                          )
                        : tournamentId ||
                          null,

                    createdAt:
                      row.registration_created_at ||
                      null,
                  }
                : null,

            createdAt:
              row.created_at ||
              null,
          })
        ),
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không lấy được danh sách team.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: RANKING
   ============================================================ */

async function adminRanking(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const url =
    new URL(
      request.url
    );

  const tournamentId =
    Number(
      url.searchParams.get(
        "tournamentId"
      ) ||
        url.searchParams.get(
          "tournament_id"
        ) ||
        0
    );

  if (
    !Number.isInteger(
      tournamentId
    ) ||
    tournamentId <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Thiếu tournamentId.",
      },
      400
    );
  }

  try {
    const result =
      await env.DB
        .prepare(`
          SELECT
            tm.id AS team_id,
            tm.name AS team_name,
            tm.tag,
            tm.logo_url,

            COALESCE(
              SUM(
                CASE
                  WHEN m.tournament_id = ?
                  THEN COALESCE(
                    r.points,
                    0
                  )
                  ELSE 0
                END
              ),
              0
            ) AS points,

            COALESCE(
              SUM(
                CASE
                  WHEN m.tournament_id = ?
                  THEN COALESCE(
                    r.kills,
                    0
                  )
                  ELSE 0
                END
              ),
              0
            ) AS kills

          FROM teams tm

          JOIN registrations reg
            ON reg.team_id =
               tm.id
            AND reg.tournament_id = ?

          LEFT JOIN results r
            ON r.team_id =
               tm.id

          LEFT JOIN matches m
            ON m.id =
               r.match_id

          WHERE
            reg.status IN (
              'PAID',
              'CONFIRMED',
              'APPROVED'
            )

          GROUP BY
            tm.id,
            tm.name,
            tm.tag,
            tm.logo_url

          ORDER BY
            points DESC,
            kills DESC,
            tm.id ASC
        `)
        .bind(
          tournamentId,
          tournamentId,
          tournamentId
        )
        .all();

    return json({
      ok: true,

      ranking:
        (
          result.results ||
          []
        ).map(
          (row, index) => ({
            rank:
              index + 1,

            teamId:
              Number(
                row.team_id
              ),

            teamName:
              row.team_name,

            tag:
              row.tag ||
              "",

            logoUrl:
              row.logo_url ||
              "",

            points:
              Number(
                row.points ||
                0
              ),

            kills:
              Number(
                row.kills ||
                0
              ),
          })
        ),
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không lấy được bảng xếp hạng.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: RANKING MATCH
   ============================================================ */

async function getAdminRankingMatch(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const url =
    new URL(
      request.url
    );

  const matchId =
    Number(
      url.searchParams.get(
        "matchId"
      ) ||
        url.searchParams.get(
          "match_id"
        ) ||
        0
    );

  if (
    !Number.isInteger(
      matchId
    ) ||
    matchId <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Thiếu matchId.",
      },
      400
    );
  }

  try {
    const match =
      await env.DB
        .prepare(`
          SELECT
            id,
            tournament_id,
            slot_id,
            room_id,
            room_password,
            start_at,
            status
          FROM matches
          WHERE id = ?
          LIMIT 1
        `)
        .bind(
          matchId
        )
        .first();

    if (!match) {
      return json(
        {
          ok: false,
          error:
            "Không tìm thấy trận đấu.",
        },
        404
      );
    }

    const result =
      await env.DB
        .prepare(`
          SELECT
            tm.id AS team_id,
            tm.name AS team_name,
            tm.tag,
            tm.logo_url,

            COALESCE(
              res.placement,
              0
            ) AS placement,

            COALESCE(
              res.kills,
              0
            ) AS kills,

            COALESCE(
              res.points,
              0
            ) AS points

          FROM teams tm

          JOIN registrations reg
            ON reg.team_id =
               tm.id
            AND reg.tournament_id = ?

          LEFT JOIN results res
            ON res.team_id =
               tm.id
            AND res.match_id = ?

          WHERE
            reg.status IN (
              'PAID',
              'CONFIRMED',
              'APPROVED'
            )

          ORDER BY
            CASE
              WHEN res.placement IS NULL
              THEN 999999
              ELSE res.placement
            END,
            tm.id ASC
        `)
        .bind(
          match.tournament_id,
          matchId
        )
        .all();

    return json({
      ok: true,

      match: {
        id:
          Number(match.id),

        tournamentId:
          Number(
            match.tournament_id
          ),

        slotId:
          match.slot_id == null
            ? null
            : Number(
                match.slot_id
              ),

        roomId:
          match.room_id ||
          "",

        roomPassword:
          match.room_password ||
          "",

        startAt:
          match.start_at ||
          null,

        status:
          match.status ||
          "",
      },

      teams:
        (
          result.results ||
          []
        ).map(
          row => ({
            teamId:
              Number(
                row.team_id
              ),

            teamName:
              row.team_name,

            tag:
              row.tag ||
              "",

            logoUrl:
              row.logo_url ||
              "",

            placement:
              Number(
                row.placement ||
                0
              ),

            kills:
              Number(
                row.kills ||
                0
              ),

            points:
              Number(
                row.points ||
                0
              ),
          })
        ),
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          error?.message ||
          "Không lấy được dữ liệu trận đấu.",
      },
      500
    );
  }
}
/* ============================================================
   ADMIN: CREATE ADMIN ACCOUNT
   ============================================================ */

async function adminCreateAdmin(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const data =
    await bodyJson(request);

  const newEmail =
    email(data.email);

  const password =
    String(
      data.password ||
      ""
    );

  if (
    !validEmail(
      newEmail
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Email admin không hợp lệ.",
      },
      400
    );
  }

  if (
    password.length < 6
  ) {
    return json(
      {
        ok: false,
        error:
          "Mật khẩu admin phải có ít nhất 6 ký tự.",
      },
      400
    );
  }

  const exists =
    await env.DB
      .prepare(`
        SELECT
          id,
          role
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(
        newEmail
      )
      .first();

  if (exists) {
    return json(
      {
        ok: false,
        error:
          "Email này đã tồn tại.",
      },
      409
    );
  }

  const passwordData =
    await makePassword(
      password
    );

  try {
    const result =
      await env.DB
        .prepare(`
          INSERT INTO users
            (
              email,
              password_hash,
              password_salt,
              role,
              status
            )
          VALUES
            (?, ?, ?, 'ADMIN', 'ACTIVE')
        `)
        .bind(
          newEmail,
          passwordData.hash,
          passwordData.salt
        )
        .run();

    const userId =
      result.meta
        ?.last_row_id;

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_CREATE_ADMIN",
      userId
        ? `user:${userId}`
        : null,
      {
        email:
          newEmail,
      }
    );

    return json(
      {
        ok: true,

        message:
          "Đã tạo tài khoản admin.",

        userId:
          userId ||
          null,
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể tạo admin: " +
          (
            error?.message ||
            "D1 error"
          ),
      },
      500
    );
  }
}

/* ============================================================
   ADMIN API ROUTER
   ============================================================ */

async function adminApi(
  request,
  env
) {
  const url =
    new URL(
      request.url
    );

  const path =
    url.pathname;

  const method =
    request.method
      .toUpperCase();

  /*
   * ADMIN ME
   */

  if (
    path ===
      "/api/admin/me" &&
    method === "GET"
  ) {
    return adminMe(
      request,
      env
    );
  }

  /*
   * TOURNAMENTS
   */

  if (
    path ===
      "/api/admin/tournaments" &&
    method === "GET"
  ) {
    return adminTournaments(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/tournaments" &&
    method === "POST"
  ) {
    return adminCreateTournament(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/tournaments" &&
    method === "PUT"
  ) {
    return adminUpdateTournament(
      request,
      env
    );
  }

  /*
   * SCHEDULES
   */

  if (
    path ===
      "/api/admin/schedules" &&
    method === "GET"
  ) {
    return adminSchedules(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "POST"
  ) {
    return adminCreateSchedule(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "PUT"
  ) {
    return adminUpdateSchedule(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "DELETE"
  ) {
    return adminDeleteSchedule(
      request,
      env
    );
  }

  /*
   * TEAMS
   */

  if (
    path ===
      "/api/admin/teams" &&
    method === "GET"
  ) {
    return adminTeams(
      request,
      env
    );
  }

  /*
   * RANKING
   */

  if (
    path ===
      "/api/admin/ranking" &&
    method === "GET"
  ) {
    return adminRanking(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/ranking/match" &&
    method === "GET"
  ) {
    const tournamentId =
      Number(
        url.searchParams.get(
          "tournamentId"
        )
      );

    if (
      !Number.isInteger(
        tournamentId
      ) ||
      tournamentId <= 0
    ) {
      return json(
        {
          ok: false,
          error:
            "Thiếu tournamentId.",
        },
        400
      );
    }

    try {
      const matchId =
        await getAdminRankingMatch(
          env,
          tournamentId
        );

      if (!matchId) {
        return json(
          {
            ok: false,
            error:
              "Không tạo được bảng BXH.",
          },
          500
        );
      }

      return json({
        ok: true,
        matchId,
      });
    } catch (error) {
      return json(
        {
          ok: false,
          error:
            error?.message ||
            "Không lấy được bảng BXH.",
        },
        500
      );
    }
  }

  if (
    path ===
      "/api/admin/ranking" &&
    method === "POST"
  ) {
    return adminSaveRanking(
      request,
      env
    );
  }

  /*
   * CREATE ADMIN
   */

  if (
    path ===
      "/api/admin/create-admin" &&
    method === "POST"
  ) {
    return adminCreateAdmin(
      request,
      env
    );
  }

  return json(
    {
      ok: false,
      error:
        "Admin API không tồn tại.",
    },
    404
  );
}

/* ============================================================
   PUBLIC API ROUTER
   ============================================================ */

async function api(
  request,
  env
) {
  const url =
    new URL(
      request.url
    );

  const path =
    url.pathname;

  const method =
    request.method
      .toUpperCase();

  /*
   * HEALTH
   */

  if (
    path ===
      "/api/health" &&
    method === "GET"
  ) {
    return health(env);
  }

  /*
   * AUTH REGISTER
   */

  if (
    path ===
      "/api/auth/register" &&
    method === "POST"
  ) {
    return register(
      request,
      env
    );
  }

  /*
   * AUTH LOGIN
   */

  if (
    path ===
      "/api/auth/login" &&
    method === "POST"
  ) {
    return login(
      request,
      env
    );
  }

  /*
   * AUTH LOGOUT
   */

  if (
    path ===
      "/api/auth/logout" &&
    method === "POST"
  ) {
    return logout(
      request,
      env
    );
  }

  /*
   * AUTH ME
   */

  if (
    path ===
      "/api/auth/me" &&
    method === "GET"
  ) {
    return me(
      request,
      env
    );
  }

  /*
   * TOURNAMENT
   */

  if (
    path ===
      "/api/tournament" &&
    method === "GET"
  ) {
    return tournament(
      request,
      env
    );
  }

  /*
   * TEAM REGISTER
   */

  if (
    path ===
      "/api/team/register" &&
    method === "POST"
  ) {
    return teamRegister(
      request,
      env
    );
  }

  /*
   * TEAM ME
   */

  if (
    path ===
      "/api/team/me" &&
    method === "GET"
  ) {
    return teamMe(
      request,
      env
    );
  }

  /*
   * PAYMENT CONFIRM
   */

  if (
    path ===
      "/api/team/payment-confirm" &&
    method === "POST"
  ) {
    return teamPaymentConfirm(
      request,
      env
    );
  }

  /*
   * RANKING
   */

  if (
    path ===
      "/api/ranking" &&
    method === "GET"
  ) {
    return ranking(
      request,
      env
    );
  }

  /*
   * SEPAY WEBHOOK
   */

  if (
    path ===
      "/api/payment/webhook" &&
    method === "POST"
  ) {
    return paymentWebhook(
      request,
      env
    );
  }

  /*
   * ADMIN API
   */

  if (
    path.startsWith(
      "/api/admin/"
    )
  ) {
    return adminApi(
      request,
      env
    );
  }

  return json(
    {
      ok: false,
      error:
        "API không tồn tại.",
    },
    404
  );
}

/* ============================================================
   FETCH
   ============================================================ */

export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    const url =
      new URL(
        request.url
      );

    /*
     * API
     */

    if (
      url.pathname.startsWith(
        "/api/"
      )
    ) {
      return api(
        request,
        env
      );
    }

    /*
     * STATIC ASSETS
     */

    if (
      env.ASSETS
    ) {
      return env.ASSETS.fetch(
        request
      );
    }

    return new Response(
      "GIẢI ĐẤU VUA TỬ CHIẾN – MÙA 1",
      {
        status: 200,
        headers: {
          "content-type":
            "text/plain; charset=utf-8",
        },
      }
    );
  },

  async scheduled(
    event,
    env,
    ctx
  ) {
    ctx.waitUntil(
      cleanupSessions(env)
    );
  },
};
    );

    return json({
      ok: true,

      message:
        "Đã cập nhật BXH.",

      teamId,

      points,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể cập nhật BXH: " +
          (
            error?.message ||
            "D1 error"
          ),
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: CREATE ADMIN ACCOUNT
   ============================================================ */

async function adminCreateAdmin(
  request,
  env
) {
  const auth =
    await requireAdmin(
      request,
      env
    );

  if (!auth.ok) {
    return auth.response;
  }

  const data =
    await bodyJson(request);

  const newEmail =
    email(data.email);

  const password =
    String(
      data.password ||
      ""
    );

  if (
    !validEmail(
      newEmail
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Email admin không hợp lệ.",
      },
      400
    );
  }

  if (
    password.length < 6
  ) {
    return json(
      {
        ok: false,
        error:
          "Mật khẩu admin phải có ít nhất 6 ký tự.",
      },
      400
    );
  }

  const exists =
    await env.DB
      .prepare(`
        SELECT
          id,
          role
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(
        newEmail
      )
      .first();

  if (exists) {
    return json(
      {
        ok: false,
        error:
          exists.role === "ADMIN" ||
          exists.role === "SUPER_ADMIN"
            ? "Tài khoản này đã là admin."
            : "Email này đã tồn tại trong hệ thống.",
      },
      409
    );
  }

  try {
    const passwordData =
      await makePassword(
        password
      );

    const result =
      await env.DB
        .prepare(`
          INSERT INTO users
            (
              email,
              password_hash,
              password_salt,
              role,
              status
            )
          VALUES
            (?, ?, ?, 'ADMIN', 'ACTIVE')
        `)
        .bind(
          newEmail,
          passwordData.hash,
          passwordData.salt
        )
        .run();

    const userId =
      result.meta
        ?.last_row_id;

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_CREATE_ADMIN",
      userId
        ? `user:${userId}`
        : null,
      {
        email:
          newEmail,
      }
    );

    return json(
      {
        ok: true,
        message:
          "Đã tạo tài khoản admin.",
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể tạo admin: " +
          (
            error?.message ||
            "D1 error"
          ),
      },
      500
    );
  }
}

/* ============================================================
   ADMIN ROUTER
   ============================================================ */

async function adminApi(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname;

  const method =
    request.method
      .toUpperCase();

  if (
    path ===
      "/api/admin/me" &&
    method === "GET"
  ) {
    return adminMe(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/tournaments" &&
    method === "GET"
  ) {
    return adminTournaments(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/tournaments" &&
    method === "POST"
  ) {
    return adminCreateTournament(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/tournaments" &&
    method === "PUT"
  ) {
    return adminUpdateTournament(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "GET"
  ) {
    return adminSchedules(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "POST"
  ) {
    return adminCreateSchedule(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "PUT"
  ) {
    return adminUpdateSchedule(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/schedules" &&
    method === "DELETE"
  ) {
    return adminDeleteSchedule(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/teams" &&
    method === "GET"
  ) {
    return adminTeams(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/ranking" &&
    method === "GET"
  ) {
    return adminRanking(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/ranking" &&
    method === "POST"
  ) {
    return adminSaveRanking(
      request,
      env
    );
  }

  if (
    path ===
      "/api/admin/admins" &&
    method === "POST"
  ) {
    return adminCreateAdmin(
      request,
      env
    );
  }

  return json(
    {
      ok: false,
      error:
        "Admin API không tồn tại.",
    },
    404
  );
}

/* ============================================================
   CLEAN EXPIRED SESSIONS
   ============================================================ */

async function cleanupSessions(
  env
) {
  try {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE
          CAST(
            expires_at AS INTEGER
          ) <= ?
      `)
      .bind(
        Date.now()
      )
      .run();
  } catch {
    // Không ảnh hưởng request.
  }
}

/* ============================================================
   MAIN API ROUTER
   ============================================================ */

async function api(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname;

  const method =
    request.method
      .toUpperCase();

  /*
   * ADMIN API
   */

  if (
    path.startsWith(
      "/api/admin/"
    )
  ) {
    return adminApi(
      request,
      env
    );
  }

  /*
   * HEALTH
   */

  if (
    path ===
      "/api/health" &&
    method === "GET"
  ) {
    return health(env);
  }

  /*
   * AUTH
   */

  if (
    path ===
      "/api/auth/register" &&
    method === "POST"
  ) {
    return register(
      request,
      env
    );
  }

  if (
    path ===
      "/api/auth/login" &&
    method === "POST"
  ) {
    return login(
      request,
      env
    );
  }

  if (
    path ===
      "/api/auth/logout" &&
    method === "POST"
  ) {
    return logout(
      request,
      env
    );
  }

  if (
    path ===
      "/api/auth/me" &&
    method === "GET"
  ) {
    return me(
      request,
      env
    );
  }

  /*
   * PUBLIC TOURNAMENT
   */

  if (
    path ===
      "/api/tournament" &&
    method === "GET"
  ) {
    return tournament(
      request,
      env
    );
  }

  /*
   * PUBLIC TEAM REGISTER
   */

  if (
    path ===
      "/api/team/register" &&
    method === "POST"
  ) {
    return teamRegister(
      request,
      env
    );
  }

  if (
    path ===
      "/api/team/me" &&
    method === "GET"
  ) {
    return teamMe(
      request,
      env
    );
  }

  if (
    path ===
      "/api/team/payment-confirm" &&
    method === "POST"
  ) {
    return teamPaymentConfirm(
      request,
      env
    );
  }

  /*
   * PUBLIC RANKING
   */

  if (
    path ===
      "/api/ranking" &&
    method === "GET"
  ) {
    return ranking(
      request,
      env
    );
  }

  /*
   * PAYMENT WEBHOOK
   */

  if (
    path ===
      "/api/payment/webhook" &&
    method === "POST"
  ) {
    return paymentWebhook(
      request,
      env
    );
  }

  return json(
    {
      ok: false,
      error:
        "API không tồn tại.",
    },
    404
  );
}

/* ============================================================
   WORKER
   ============================================================ */

export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    const url =
      new URL(request.url);

    /*
     * API
     */

    if (
      url.pathname.startsWith(
        "/api/"
      )
    ) {
      /*
       * Cleanup session nhẹ,
       * không chặn request.
       */

      if (
        ctx?.waitUntil
      ) {
        ctx.waitUntil(
          cleanupSessions(
            env
          )
        );
      }

      return api(
        request,
        env
      );
    }

    /*
     * ADMIN PAGE
     *
     * /admin
     * sẽ mở:
     * public/admin.html
     *
     * Quyền admin vẫn được
     * kiểm tra ở API server-side.
     */

    if (
      url.pathname ===
        "/admin" ||
      url.pathname ===
        "/admin/"
    ) {
      if (env.ASSETS) {
        const adminUrl =
          new URL(
            "/admin.html",
            request.url
          );

        return env.ASSETS.fetch(
          new Request(
            adminUrl.toString(),
            request
          )
        );
      }

      return text(
        "Không tìm thấy trang Admin.",
        404
      );
    }

    /*
     * PUBLIC FILES
     *
     * public/index.html
     * public/admin.html
     * ...
     */

    if (env.ASSETS) {
      return env.ASSETS.fetch(
        request
      );
    }

    return text(
      "GIẢI ĐẤU TỬ CHIẾN – MÙA 1"
    );
  },
      /*
     * PUBLIC FILES
     *
     * public/index.html
     * public/admin.html
     * ...
     */

    if (env.ASSETS) {
      return env.ASSETS.fetch(
        request
      );
    }

    return text(
      "GIẢI ĐẤU TỬ CHIẾN – MÙA 1"
    );
  },
};
