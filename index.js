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

/*
 * PHÍ THAM GIA CHÍNH THỨC
 * 30.000 VNĐ
 */
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
   HEALTH – SEPAY
   ============================================================
   Chỉ kiểm tra Worker có nhìn thấy Secret hay không.
   KHÔNG BAO GIỜ trả Secret Key ra response.
   ============================================================ */

async function sepayHealth(env) {
  const configured =
    typeof env.SEPAY_WEBHOOK_SECRET ===
      "string" &&
    env.SEPAY_WEBHOOK_SECRET.trim()
      .length > 0;

  const bankConfigured =
    typeof env.SEPAY_BANK_ACCOUNT ===
      "string" &&
    env.SEPAY_BANK_ACCOUNT.trim()
      .length > 0;

  return json({
    ok: true,

    service:
      "vua-tu-chien-mua1",

    sepaySecretConfigured:
      configured,

    sepayBankAccountConfigured:
      bankConfigured,

    note:
      "Chỉ kiểm tra trạng thái cấu hình, không trả về Secret Key.",
  });
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
    ) ||
    !password
  ) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập đúng email và mật khẩu.",
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
      .bind(
        userEmail
      )
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

  let token;

  try {
    token =
      await createSession(
        env,
        user.id
      );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể tạo phiên đăng nhập: " +
          (
            error?.message ||
            "D1 error"
          ),
      },
      500
    );
  }

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
      const session =
        await env.DB
          .prepare(`
            SELECT user_id
            FROM sessions
            WHERE id = ?
            LIMIT 1
          `)
          .bind(token)
          .first();

      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE id = ?
        `)
        .bind(token)
        .run();

      if (
        session?.user_id
      ) {
        await writeAudit(
          env,
          session.user_id,
          "LOGOUT",
          `user:${session.user_id}`
        );
      }
    } catch {
      // Không làm logout thất bại.
    }
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
   TOURNAMENT
   ============================================================ */

async function getTournament(
  env
) {
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
      ORDER BY id ASC
      LIMIT 1
    `)
    .first();
}

async function tournament(
  request,
  env
) {
  const t =
    await getTournament(
      env
    );

  const bank = {
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

        entryFee: 0,

        status:
          "CLOSED",

        statusText:
          "CHƯA MỞ",

        schedule: [],

        bank,
      },
    });
  }

  const count =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS total
        FROM registrations
        WHERE
          tournament_id = ?
          AND status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
          )
      `)
      .bind(t.id)
      .first();

  const registered =
    Number(
      count?.total || 0
    );

  const maxTeams =
    Number(
      t.max_teams || 48
    );

  const remaining =
    Math.max(
      maxTeams -
        registered,
      0
    );

  let schedule = [];

  try {
    const scheduleResult =
      await env.DB
        .prepare(`
          SELECT
            m.id,
            m.start_at,
            m.room_id,
            m.status,
            m.slot_id,
            s.slot_time,
            s.group_name

          FROM matches m

          LEFT JOIN slots s
            ON s.id = m.slot_id

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

          LIMIT 50
        `)
        .bind(t.id)
        .all();

    schedule =
      (
        scheduleResult.results ||
        []
      ).map(
        row => ({
          id:
            Number(row.id),

          startAt:
            row.start_at ||
            null,

          roomId:
            row.room_id ||
            "",

          status:
            row.status ||
            "SCHEDULED",

          slotId:
            row.slot_id == null
              ? null
              : Number(
                  row.slot_id
                ),

          slotTime:
            row.slot_time ||
            null,

          groupName:
            row.group_name ||
            "",
        })
      );
  } catch {
    schedule = [];
  }

  return json({
    ok: true,

    tournament: {
      id: t.id,

      name:
        t.name,

      description:
        t.description ||
        "",

      registered,

      slots:
        maxTeams,

      remaining,

      entryFee:
        TEAM_ENTRY_FEE,

      status:
        remaining > 0
          ? "OPEN"
          : "FULL",

      statusText:
        remaining > 0
          ? "CÒN SLOT"
          : "HẾT SLOT",

      schedule,

      bank,
    },
  });
}

/* ============================================================
   TEAM REGISTER
   ============================================================ */

async function teamRegister(request, env) {
  const session = await currentSession(request, env);

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

  const data = await bodyJson(request);

  const teamName =
    cleanString(
      data.teamName,
      60
    );

  const logoUrl =
    cleanString(
      data.logoUrl,
      180000
    );

  const registrantName =
    cleanString(
      data.registrantName,
      80
    );

  const contactInfo =
    cleanString(
      data.contactInfo,
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

  if (!registrantName) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập tên người đăng ký.",
      },
      400
    );
  }

  if (!contactInfo) {
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
    !/^data:image\/(png|jpeg|jpg|webp);base64,/i.test(
      logoUrl
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Logo team không đúng định dạng.",
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
          "Logo quá lớn. Vui lòng chọn ảnh nhỏ hơn.",
      },
      400
    );
  }

  const t =
    await getTournament(
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

  /*
   * CHỈ TEAM ĐÃ THANH TOÁN MỚI CHIẾM SLOT.
   *
   * Các đơn:
   * AWAITING_PAYMENT
   * PAYMENT_PENDING_CONFIRMATION
   * ... chưa thanh toán
   *
   * không làm đầy slot.
   */

  const count =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS total
        FROM registrations
        WHERE
          tournament_id = ?
          AND status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
          )
      `)
      .bind(
        t.id
      )
      .first();

  const registered =
    Number(
      count?.total || 0
    );

  if (
    registered >=
    Number(
      t.max_teams || 48
    )
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

  /*
   * Một tài khoản không tạo
   * nhiều đơn đang hoạt động
   * cho cùng giải.
   */

  const duplicate =
    await env.DB
      .prepare(`
        SELECT
          id
        FROM registrations
        WHERE
          tournament_id = ?
          AND user_id = ?
          AND status NOT IN (
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
          "Tài khoản này đã đăng ký team cho giải đấu.",
      },
      409
    );
  }

  /*
   * Mã thanh toán.
   */

  const orderCode =
    "VTC" +
    Date.now()
      .toString(36)
      .toUpperCase() +
    randomToken(5)
      .toUpperCase();

  /*
   * Luôn cố định 30.000đ
   * cho người chơi.
   */

  const amount =
    TEAM_ENTRY_FEE;

  let teamId;
  let registrationId;

  try {
    /*
     * Tạo team ở trạng thái
     * chờ thanh toán.
     */

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
  (
    ?,
    ?,
    ?,
    'ACTIVE',
    ?,
    ?,
    '',
    ?,
    ?
  )
        `)
.bind(
  teamName,
  teamName,
  session.user.id,
  logoUrl,
  session.user.email,
  registrantName,
  contactInfo
)
        .run();

    teamId =
      teamResult.meta
        ?.last_row_id;

    if (!teamId) {
      const team =
        await env.DB
          .prepare(`
            SELECT
              id
            FROM teams
            WHERE
              owner_id = ?
              AND name = ?
            ORDER BY
              id DESC
            LIMIT 1
          `)
          .bind(
            session.user.id,
            teamName
          )
          .first();

      teamId =
        team?.id;
    }

    if (!teamId) {
      throw new Error(
        "Không tạo được team."
      );
    }

    /*
     * Thêm chủ team vào
     * team_members.
     */

    await env.DB
      .prepare(`
        INSERT OR IGNORE INTO team_members
          (
            team_id,
            user_id,
            game_uid,
            nickname
          )
        VALUES
          (?, ?, ?, ?)
      `)
      .bind(
        teamId,
        session.user.id,
        "",
        registrantName
      )
      .run();

    /*
     * Tạo registration.
     */

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
            (
              ?,
              ?,
              ?,
              ?,
              ?,
              'AWAITING_PAYMENT'
            )
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
      const reg =
        await env.DB
          .prepare(`
            SELECT
              id
            FROM registrations
            WHERE
              order_code = ?
            LIMIT 1
          `)
          .bind(
            orderCode
          )
          .first();

      registrationId =
        reg?.id;
    }

    if (!registrationId) {
      throw new Error(
        "Không tạo được đơn đăng ký."
      );
    }

    /*
     * Tạo payment chờ ngân hàng.
     */

await env.DB
  .prepare(`
    INSERT INTO payments
      (
        registration_id,
        transaction_id,
        amount,
        description,
        status
      )
    VALUES
      (
        ?,
        '',
        ?,
        ?,
        'PENDING'
      )
  `)
  .bind(
    registrationId,
    amount,
    `BANK_QR ${orderCode}`
  )
  .run();

    await writeAudit(
      env,
      session.user.id,
      "TEAM_REGISTER",
      `registration:${registrationId}`,
      {
        teamId,
        tournamentId:
          t.id,
        orderCode,
        amount,
      }
    );

    return json(
      {
        ok: true,

        message:
          `Đăng ký thành công. Mã thanh toán: ${orderCode}.`,

        registration: {
          id:
            Number(
              registrationId
            ),

          teamId:
            Number(teamId),

          tournamentId:
            Number(t.id),

          orderCode,

          amount,

          status:
            "AWAITING_PAYMENT",
        },

        team: {
          id:
            Number(teamId),

          name:
            teamName,

          logoUrl,

          registrantName,

          contactInfo,

          status:
            "PENDING_PAYMENT",
        },

        bank: {
          name:
            env.BANK_NAME ||
            "MB BANK",

          account:
            env.BANK_ACCOUNT ||
            "0977049795",

          owner:
            env.BANK_OWNER ||
            "Đinh Hồng Hạnh",
        },
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể đăng ký team: " +
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
          ON tm.id =
             r.team_id

        JOIN tournaments t
          ON t.id =
             r.tournament_id

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
        row.team_tag ||
        "",

      status:
        row.team_status,

      logoUrl:
        row.logo_url ||
        "",

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
   TEAM PAYMENT CONFIRM
   ============================================================ */

async function teamPaymentConfirm(request, env) {
  const session = await currentSession(request, env);

  if (!session) {
    return json(
      {
        ok: false,
        error: "Bạn chưa đăng nhập."
      },
      401
    );
  }

  const row = await env.DB
    .prepare(`
      SELECT
        r.id,
        r.order_code,
        r.status
      FROM registrations r
      WHERE
        r.user_id = ?
        AND r.status = 'AWAITING_PAYMENT'
      ORDER BY r.id DESC
      LIMIT 1
    `)
    .bind(session.user.id)
    .first();

  if (!row) {
    return json(
      {
        ok: false,
        error: "Không tìm thấy đơn đăng ký đang chờ thanh toán."
      },
      404
    );
  }

  /*
    Không đổi registrations.status.
    Giữ AWAITING_PAYMENT để tương thích schema hiện tại.

    Chỉ đánh dấu rằng người dùng đã bấm
    "XÁC NHẬN ĐÃ CHUYỂN KHOẢN".
  */

  await env.DB
    .prepare(`
      UPDATE payments
      SET
        description = ?,
        status = 'PENDING'
      WHERE registration_id = ?
    `)
    .bind(
      `BANK_QR ${row.order_code} | USER_CONFIRMED`,
      row.id
    )
    .run();

  await writeAudit(
    env,
    session.user.id,
    "PAYMENT_CONFIRM",
    `registration:${row.id}`,
    {
      orderCode: row.order_code
    }
  );

  return json({
    ok: true,
    registration: {
      id: Number(row.id),
      orderCode: row.order_code,
      status: "PAYMENT_PENDING_CONFIRMATION"
    }
  });
}

/* ============================================================
   PUBLIC RANKING
   ============================================================ */

async function ranking(
  request,
  env
) {
  const t =
    await getTournament(
      env
    );

  if (!t) {
    return json({
      ok: true,
      ranking: [],
    });
  }

  const result =
    await env.DB
      .prepare(`
        SELECT
          tm.id AS team_id,
          tm.name AS team_name,
          tm.logo_url,

          COALESCE(
            SUM(
              CASE
                WHEN r.points IS NOT NULL
                THEN r.points
                ELSE 0
              END
            ),
            0
          ) AS points

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
          AND m.tournament_id = ?

        WHERE
          reg.status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
          )

          AND (
            r.id IS NULL
            OR m.id IS NOT NULL
          )

        GROUP BY
          tm.id,
          tm.name,
          tm.logo_url

        ORDER BY
          points DESC,
          tm.id ASC

        LIMIT 100
      `)
      .bind(
        t.id,
        t.id
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

          logoUrl:
            row.logo_url ||
            "",

          teamName:
            row.team_name,

          points:
            Number(
              row.points ||
              0
            ),
        })
      ),
  });
}

/* ============================================================
   PAYMENT WEBHOOK – SEPAY HMAC
   ============================================================ */

async function paymentWebhook(
  request,
  env
) {
  try {
    const configured =
      env.SEPAY_WEBHOOK_SECRET;

    if (!configured) {
      return json(
        {
          ok: false,
          error:
            "SEPAY_WEBHOOK_SECRET chưa được cấu hình."
        },
        503
      );
    }

    const signatureHeader =
      request.headers.get(
        "X-SePay-Signature"
      ) || "";

    const timestampHeader =
      request.headers.get(
        "X-SePay-Timestamp"
      ) || "";

    if (
      !signatureHeader ||
      !timestampHeader
    ) {
      return json(
        {
          ok: false,
          error:
            "Thiếu chữ ký hoặc timestamp của SePay."
        },
        401
      );
    }

    const timestamp =
      Number(
        timestampHeader
      );

    if (
      !Number.isInteger(
        timestamp
      )
    ) {
      return json(
        {
          ok: false,
          error:
            "Timestamp của SePay không hợp lệ."
        },
        401
      );
    }

    const nowSeconds =
      Math.floor(
        Date.now() / 1000
      );

    if (
      Math.abs(
        nowSeconds -
          timestamp
      ) > 300
    ) {
      return json(
        {
          ok: false,
          error:
            "Webhook đã hết hạn hoặc timestamp không hợp lệ."
        },
        401
      );
    }

    /*
     * Lấy RAW BODY trước khi JSON.parse.
     */
    const rawBody =
      await request.text();

    const expectedSignature =
      "sha256=" +
      await hmacSha256Hex(
        configured,
        `${timestamp}.${rawBody}`
      );

    if (
      !safeEqual(
        signatureHeader,
        expectedSignature
      )
    ) {
      return json(
        {
          ok: false,
          error:
            "Chữ ký SePay không hợp lệ."
        },
        401
      );
    }

    let data;

    try {
      data =
        JSON.parse(
          rawBody
        );
    } catch {
      return json(
        {
          ok: false,
          error:
            "Payload SePay không phải JSON hợp lệ."
        },
        400
      );
    }

    /*
     * ==========================================================
     * SEPAY TEST / GỬI THỬ
     * ==========================================================
     */

    const transactionId =
      String(
        data.id ?? ""
      ).trim();

    if (
      transactionId === "0"
    ) {
return json({
  ok: true,
  success: true,
  test: true,
  message:
    "Đã nhận webhook test từ SePay. Không phát sinh giao dịch thật."
});
    }

    /*
     * ==========================================================
     * CHỈ NHẬN TIỀN VÀO
     * ==========================================================
     */

    if (
      String(
        data.transferType ||
        ""
      ).toLowerCase() !==
      "in"
    ) {
      return json(
        {
          ok: false,
          error:
            "Webhook không phải giao dịch tiền vào."
        },
        400
      );
    }

    /*
     * ==========================================================
     * LẤY SỐ TIỀN
     * ==========================================================
     */

    const amount =
      Number(
        data.transferAmount ??
        data.amount ??
        data.transfer_amount ??
        0
      );

    /*
     * ==========================================================
     * LẤY MÃ ĐĂNG KÝ
     * ==========================================================
     */

    const codeFromPayload =
      String(
        data.code ||
        ""
      ).trim();

    const content =
      String(
        data.content ||
        ""
      ).trim();

    const codeFromContent =
      (
        content.match(
          /VTC[A-Z0-9_-]+/i
        ) || []
      )[0] || "";

    const orderCode =
      (
        codeFromPayload ||
        codeFromContent
      )
        .trim()
        .toUpperCase();

    if (
      !orderCode ||
      amount <= 0 ||
      !transactionId
    ) {
      return json(
        {
          ok: false,
          error:
            "Thiếu mã đăng ký, số tiền hoặc mã giao dịch SePay.",
          orderCode,
          amount,
          transactionId
        },
        400
      );
    }

    /*
     * ==========================================================
     * KIỂM TRA TÀI KHOẢN NHẬN
     * ==========================================================
     */

    if (
      env.SEPAY_BANK_ACCOUNT
    ) {
      const receivedAccount =
        String(
          data.accountNumber ||
          ""
        ).trim();

      const configuredAccount =
        String(
          env.SEPAY_BANK_ACCOUNT
        ).trim();

      if (
        receivedAccount &&
        receivedAccount !==
          configuredAccount
      ) {
        return json(
          {
            ok: false,
            error:
              "Giao dịch không đến từ tài khoản ngân hàng đã cấu hình."
          },
          400
        );
      }
    }

    /*
     * ==========================================================
     * TÌM REGISTRATION
     * ==========================================================
     */

    const registration =
      await env.DB
        .prepare(`
          SELECT
            id,
            team_id,
            tournament_id,
            user_id,
            amount,
            status,
            order_code
          FROM registrations
          WHERE
            order_code = ?
          LIMIT 1
        `)
        .bind(
          orderCode
        )
        .first();

    if (!registration) {
      return json(
        {
          ok: false,
          error:
            "Không tìm thấy mã đăng ký.",
          orderCode
        },
        404
      );
    }

    /*
     * ==========================================================
     * NẾU ĐÃ PAID THÌ KHÔNG XỬ LÝ LẠI
     * ==========================================================
     */

    if (
      String(
        registration.status
      ).toUpperCase() ===
      "PAID"
    ) {
return json({
  ok: true,
  success: true,
  message:
    "Đơn đăng ký đã được xác nhận thanh toán.",
        registrationId:
          Number(
            registration.id
          ),
        status:
          "PAID"
      });
    }

    /*
     * ==========================================================
     * KIỂM TRA SỐ TIỀN
     * ==========================================================
     */

    const required =
      Number(
        registration.amount ||
        0
      );

    if (
      amount <
      required
    ) {
      return json(
        {
          ok: false,
          error:
            `Số tiền thanh toán chưa đủ. Cần ${required}, nhận ${amount}.`,
          required,
          received:
            amount
        },
        400
      );
    }

    /*
     * ==========================================================
     * KIỂM TRA TRANSACTION ĐÃ TỒN TẠI CHƯA
     * ==========================================================
     *
     * Không dùng gateway vì bảng payments
     * thực tế của bạn KHÔNG có cột gateway.
     */

    const existed =
      await env.DB
        .prepare(`
          SELECT
            id,
            registration_id
          FROM payments
          WHERE
            transaction_id = ?
          LIMIT 1
        `)
        .bind(
          transactionId
        )
        .first();

    if (existed) {
return json({
  ok: true,
  success: true,
  message:
    "Giao dịch SePay đã được xử lý trước đó.",
        registrationId:
          Number(
            registration.id
          ),
        status:
          "PAID"
      });
    }

    /*
     * ==========================================================
     * CẬP NHẬT PAYMENT ĐÃ ĐƯỢC TẠO KHI ĐĂNG KÝ
     * ==========================================================
     *
     * payments hiện tại của bạn có:
     *
     * id
     * registration_id
     * transaction_id
     * amount
     * description
     * status
     * created_at
     * reviewed_at
     * reviewed_by
     *
     * Vì vậy không INSERT gateway/raw_json.
     */

    const payment =
      await env.DB
        .prepare(`
          SELECT
            id
          FROM payments
          WHERE
            registration_id = ?
          ORDER BY
            id DESC
          LIMIT 1
        `)
        .bind(
          registration.id
        )
        .first();

    if (payment) {
      await env.DB
        .prepare(`
          UPDATE payments
          SET
            transaction_id = ?,
            amount = ?,
            description = ?,
            status = 'SUCCESS',
            reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(
          transactionId,
          amount,
          `SEPAY ${orderCode}`,
          payment.id
        )
        .run();
    } else {
      /*
       * Trường hợp đặc biệt nếu payment
       * chưa tồn tại thì tạo mới theo
       * đúng schema thực tế.
       */

      await env.DB
        .prepare(`
          INSERT INTO payments
            (
              registration_id,
              transaction_id,
              amount,
              description,
              status
            )
          VALUES
            (?, ?, ?, ?, 'SUCCESS')
        `)
        .bind(
          registration.id,
          transactionId,
          amount,
          `SEPAY ${orderCode}`
        )
        .run();
    }

    /*
     * ==========================================================
     * ĐÁNH DẤU ĐĂNG KÝ ĐÃ THANH TOÁN
     * ==========================================================
     */

    await env.DB
      .prepare(`
        UPDATE registrations
        SET
          status = 'PAID',
          updated_at = CURRENT_TIMESTAMP,
          reviewed_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        registration.id
      )
      .run();

    /*
     * ==========================================================
     * KÍCH HOẠT TEAM
     * ==========================================================
     */

    await env.DB
      .prepare(`
        UPDATE teams
        SET
          status = 'ACTIVE'
        WHERE id = ?
      `)
      .bind(
        registration.team_id
      )
      .run();

    /*
     * ==========================================================
     * AUDIT LOG
     * ==========================================================
     */

    await writeAudit(
      env,
      registration.user_id,
      "SEPAY_PAYMENT_SUCCESS",
      `registration:${registration.id}`,
      {
        transactionId,
        amount,
        orderCode,
        teamId:
          registration.team_id,
        tournamentId:
          registration.tournament_id
      }
    );

    /*
     * ==========================================================
     * THÀNH CÔNG
     * ==========================================================
     */

return json({
  ok: true,
  success: true,
  message:
    "Đã xác nhận thanh toán.",
  registrationId:
    Number(
      registration.id
    ),
  orderCode,
  amount,
  status:
    "PAID"
});

  } catch (error) {

    /*
     * Không để Worker chết trắng.
     * Trả lỗi D1 cụ thể để dễ kiểm tra.
     */

    return json(
      {
        ok: false,
        error:
          "Lỗi xử lý webhook SePay: " +
          (
            error?.message ||
            "D1 error"
          )
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: ME
   ============================================================ */

async function adminMe(
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

  return json({
    ok: true,
    authenticated: true,

    admin:
      publicUser(
        auth.session.user
      ),
  });
}

/* ============================================================
   ADMIN: TOURNAMENT LIST
   ============================================================ */

async function adminTournaments(
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

  try {
    const result =
      await env.DB
        .prepare(`
          SELECT
            t.id,
            t.name,
            t.description,
            t.fee,
            t.max_teams,
            t.status,
            t.created_at,

            (
              SELECT COUNT(*)
              FROM registrations r
              WHERE
                r.tournament_id =
                  t.id
                AND r.status NOT IN (
                  'CANCELLED',
                  'REJECTED'
                )
            ) AS registered

          FROM tournaments t

          ORDER BY
            t.id DESC

          LIMIT 100
        `)
        .all();

    return json({
      ok: true,

      tournaments:
        (
          result.results ||
          []
        ).map(
          row => ({
            id:
              Number(row.id),

            name:
              row.name,

            description:
              row.description ||
              "",

            fee:
              Number(
                row.fee || 0
              ),

            maxTeams:
              Number(
                row.max_teams ||
                0
              ),

            status:
              row.status,

            registered:
              Number(
                row.registered ||
                0
              ),

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
          "Không lấy được danh sách giải đấu.",
      },
      500
    );
  }
}

/* ============================================================
   ADMIN: CREATE TOURNAMENT
   ============================================================ */

async function adminCreateTournament(
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
          data.maxTeams,
          48
        )
      )
    );

  const status =
    String(
      data.status ||
      "OPEN"
    )
      .trim()
      .toUpperCase();

  if (
    name.length < 2
  ) {
    return json(
      {
        ok: false,
        error:
          "Tên giải đấu phải có ít nhất 2 ký tự.",
      },
      400
    );
  }

  if (
    ![
      "OPEN",
      "CLOSED",
      "DRAFT"
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

    const tournamentId =
      result.meta
        ?.last_row_id;

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_CREATE_TOURNAMENT",
      tournamentId
        ? `tournament:${tournamentId}`
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
          "Tạo giải đấu thành công.",

        tournamentId:
          tournamentId ||
          null,
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể tạo giải đấu: " +
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

  const url =
    new URL(request.url);

  const id =
    Number(
      url.searchParams.get(
        "id"
      )
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

  const data =
    await bodyJson(request);

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
          data.maxTeams,
          48
        )
      )
    );

  const status =
    String(
      data.status ||
      "OPEN"
    )
      .trim()
      .toUpperCase();

  if (
    name.length < 2
  ) {
    return json(
      {
        ok: false,
        error:
          "Tên giải đấu không hợp lệ.",
      },
      400
    );
  }

  if (
    ![
      "OPEN",
      "CLOSED",
      "DRAFT"
    ].includes(status)
  ) {
    return json(
      {
        ok: false,
        error:
          "Trạng thái không hợp lệ.",
      },
      400
    );
  }

  try {
    const result =
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

    if (
      !result.meta?.changes
    ) {
      return json(
        {
          ok: false,
          error:
            "Không tìm thấy giải đấu.",
        },
        404
      );
    }

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
   ADMIN: SCHEDULE LIST
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
    new URL(request.url);

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
            s.group_name,
            s.capacity

          FROM matches m

          LEFT JOIN slots s
            ON s.id = m.slot_id

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

            capacity:
              row.capacity == null
                ? null
                : Number(
                    row.capacity
                  ),
          })
        ),
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không lấy được lịch thi đấu: " +
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
      data.tournamentId
    );

  const slotIdRaw =
    data.slotId;

  const slotId =
    slotIdRaw === "" ||
    slotIdRaw == null
      ? null
      : Number(
          slotIdRaw
        );

  const roomId =
    cleanString(
      data.roomId,
      100
    );

  const roomPassword =
    cleanString(
      data.roomPassword,
      200
    );

  const startAt =
    cleanString(
      data.startAt,
      100
    );

  const status =
    String(
      data.status ||
      "SCHEDULED"
    )
      .trim()
      .toUpperCase();

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
          "Giải đấu không hợp lệ.",
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
          "Slot không hợp lệ.",
      },
      400
    );
  }

  if (!startAt) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng chọn thời gian thi đấu.",
      },
      400
    );
  }

  const tournamentExists =
    await env.DB
      .prepare(`
        SELECT
          id
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

  if (slotId !== null) {
    const slot =
      await env.DB
        .prepare(`
          SELECT
            id
          FROM slots
          WHERE
            id = ?
            AND tournament_id = ?
          LIMIT 1
        `)
        .bind(
          slotId,
          tournamentId
        )
        .first();

    if (!slot) {
      return json(
        {
          ok: false,
          error:
            "Slot không thuộc giải đấu này.",
        },
        400
      );
    }
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
          slotId,
          roomId,
          roomPassword,
          startAt,
          status
        )
        .run();

    const matchId =
      result.meta
        ?.last_row_id;

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_CREATE_SCHEDULE",
      matchId
        ? `match:${matchId}`
        : null,
      {
        tournamentId,
        startAt,
        roomId,
        status,
      }
    );

    return json(
      {
        ok: true,
        message:
          "Đã thêm lịch thi đấu.",
        matchId:
          matchId ||
          null,
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể thêm lịch: " +
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

  const url =
    new URL(request.url);

  const id =
    Number(
      url.searchParams.get(
        "id"
      )
    );

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "ID lịch không hợp lệ.",
      },
      400
    );
  }

  const data =
    await bodyJson(request);

  const slotIdRaw =
    data.slotId;

  const slotId =
    slotIdRaw === "" ||
    slotIdRaw == null
      ? null
      : Number(
          slotIdRaw
        );

  const roomId =
    cleanString(
      data.roomId,
      100
    );

  const roomPassword =
    cleanString(
      data.roomPassword,
      200
    );

  const startAt =
    cleanString(
      data.startAt,
      100
    );

  const status =
    String(
      data.status ||
      "SCHEDULED"
    )
      .trim()
      .toUpperCase();

  if (!startAt) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng chọn thời gian.",
      },
      400
    );
  }

  try {
    const existing =
      await env.DB
        .prepare(`
          SELECT
            id,
            tournament_id
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
            "Không tìm thấy lịch.",
        },
        404
      );
    }

    if (slotId !== null) {
      const slot =
        await env.DB
          .prepare(`
            SELECT
              id
            FROM slots
            WHERE
              id = ?
              AND tournament_id = ?
            LIMIT 1
          `)
          .bind(
            slotId,
            existing.tournament_id
          )
          .first();

      if (!slot) {
        return json(
          {
            ok: false,
            error:
              "Slot không thuộc giải đấu.",
          },
          400
        );
      }
    }

    await env.DB
      .prepare(`
        UPDATE matches
        SET
          slot_id = ?,
          room_id = ?,
          room_password = ?,
          start_at = ?,
          status = ?
        WHERE id = ?
      `)
      .bind(
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
      `match:${id}`
    );

    return json({
      ok: true,
      message:
        "Đã cập nhật lịch thi đấu.",
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không thể cập nhật lịch: " +
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

  const url =
    new URL(request.url);

  const id =
    Number(
      url.searchParams.get(
        "id"
      )
    );

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "ID lịch không hợp lệ.",
      },
      400
    );
  }

  try {
    const result =
      await env.DB
        .prepare(`
          DELETE FROM matches
          WHERE id = ?
        `)
        .bind(id)
        .run();

    if (
      !result.meta?.changes
    ) {
      return json(
        {
          ok: false,
          error:
            "Không tìm thấy lịch.",
        },
        404
      );
    }

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_DELETE_SCHEDULE",
      `match:${id}`
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
          "Không thể xóa lịch: " +
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
   ADMIN: REGISTERED TEAMS
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
    new URL(request.url);

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
    const result =
      await env.DB
        .prepare(`
          SELECT
            t.id,
            t.name,
            t.tag,
            t.logo_url,
            t.contact_email,
            t.player2_email,
            t.owner_id,
            t.status,

            u.email AS owner_email,

            r.id AS registration_id,
            r.order_code,
            r.amount,
            r.status AS registration_status

          FROM registrations r

          JOIN teams t
            ON t.id = r.team_id

          LEFT JOIN users u
            ON u.id = t.owner_id

          WHERE
            r.tournament_id = ?

          ORDER BY
            r.id DESC

          LIMIT 200
        `)
        .bind(
          tournamentId
        )
        .all();

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

            logoUrl:
              row.logo_url ||
              "",

            contactEmail:
              row.contact_email ||
              "",

            player2Email:
              row.player2_email ||
              "",

            ownerEmail:
              row.owner_email ||
              "",

            registrationId:
              Number(
                row.registration_id
              ),

            orderCode:
              row.order_code,

            amount:
              Number(
                row.amount ||
                0
              ),

            registrationStatus:
              row.registration_status,

            teamStatus:
              row.status,
          })
        ),
    });
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          "Không lấy được danh sách team: " +
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
   ADMIN: RANKING LIST
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
    new URL(request.url);

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
    const result =
      await env.DB
        .prepare(`
          SELECT
            t.id AS team_id,
            t.name AS team_name,
            t.logo_url,

            COALESCE(
              SUM(
                CASE
                  WHEN r.points IS NOT NULL
                  THEN r.points
                  ELSE 0
                END
              ),
              0
            ) AS points

          FROM teams t

          JOIN registrations reg
            ON reg.team_id = t.id
            AND reg.tournament_id = ?

          LEFT JOIN results r
            ON r.team_id = t.id

          LEFT JOIN matches m
            ON m.id = r.match_id
            AND m.tournament_id = ?

          WHERE
            reg.status IN (
              'PAID',
              'CONFIRMED',
              'APPROVED'
            )

            AND (
              r.id IS NULL
              OR m.id IS NOT NULL
            )

          GROUP BY
            t.id,
            t.name,
            t.logo_url

          ORDER BY
            points DESC,
            t.id ASC

          LIMIT 100
        `)
        .bind(
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

            logoUrl:
              row.logo_url ||
              "",

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
          "Không lấy được BXH: " +
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
   ADMIN: FIND/CREATE RANKING MATCH
   ============================================================ */

async function getAdminRankingMatch(
  env,
  tournamentId
) {
  const existing =
    await env.DB
      .prepare(`
        SELECT
          id
        FROM matches
        WHERE
          tournament_id = ?
          AND status = 'RANKING'
          AND room_id = 'ADMIN_RANKING'
        ORDER BY id ASC
        LIMIT 1
      `)
      .bind(
        tournamentId
      )
      .first();

  if (existing?.id) {
    return Number(
      existing.id
    );
  }

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
          (
            ?,
            NULL,
            'ADMIN_RANKING',
            '',
            ?,
            'RANKING'
          )
      `)
      .bind(
        tournamentId,
        new Date().toISOString()
      )
      .run();

  const id =
    result.meta
      ?.last_row_id;

  if (id) {
    return Number(id);
  }

  const retry =
    await env.DB
      .prepare(`
        SELECT
          id
        FROM matches
        WHERE
          tournament_id = ?
          AND status = 'RANKING'
          AND room_id = 'ADMIN_RANKING'
        ORDER BY
          id ASC
        LIMIT 1
      `)
      .bind(
        tournamentId
      )
      .first();

  return retry?.id
    ? Number(retry.id)
    : null;
}

/* ============================================================
   ADMIN: SAVE RANKING
   ============================================================ */

async function adminSaveRanking(
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
      data.tournamentId
    );

  const teamId =
    Number(
      data.teamId
    );

  const points =
    Math.max(
      0,
      Math.floor(
        positiveNumber(
          data.points,
          0
        )
      )
    );

  const placement =
    Math.max(
      0,
      Math.floor(
        positiveNumber(
          data.placement,
          0
        )
      )
    );

  const kills =
    Math.max(
      0,
      Math.floor(
        positiveNumber(
          data.kills,
          0
        )
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
          "Giải đấu không hợp lệ.",
      },
      400
    );
  }

  if (
    !Number.isInteger(
      teamId
    ) ||
    teamId <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Team không hợp lệ.",
      },
      400
    );
  }

  const registration =
    await env.DB
      .prepare(`
        SELECT
          r.id,
          r.status
        FROM registrations r
        WHERE
          r.tournament_id = ?
          AND r.team_id = ?
          AND r.status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
          )
        LIMIT 1
      `)
      .bind(
        tournamentId,
        teamId
      )
      .first();

  if (!registration) {
    return json(
      {
        ok: false,
        error:
          "Team chưa có đăng ký thanh toán hợp lệ cho giải này.",
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
      throw new Error(
        "Không tạo được bảng BXH."
      );
    }

    await env.DB
      .prepare(`
        DELETE FROM results
        WHERE
          match_id = ?
          AND team_id = ?
      `)
      .bind(
        matchId,
        teamId
      )
      .run();

    await env.DB
      .prepare(`
        INSERT INTO results
          (
            match_id,
            team_id,
            placement,
            kills,
            points
          )
        VALUES
          (?, ?, ?, ?, ?)
      `)
      .bind(
        matchId,
        teamId,
        placement,
        kills,
        points
      )
      .run();

    await writeAudit(
      env,
      auth.session.user.id,
      "ADMIN_SAVE_RANKING",
      `team:${teamId}`,
      {
        tournamentId,
        teamId,
        points,
        placement,
        kills,
      }
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
   * HEALTH – SEPAY
   *
   * Dùng endpoint này để kiểm tra
   * Secret có thực sự được inject
   * vào Worker hay chưa.
   */

  if (
    path ===
      "/api/health/sepay" &&
    method === "GET"
  ) {
    return sepayHealth(env);
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
};
