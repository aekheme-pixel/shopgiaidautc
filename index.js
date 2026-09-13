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
 *   dùng transaction_id theo DB hiện tại
 *
 * sessions:
 *   id
 *   user_id
 *   expires_at
 *   created_at
 *
 * KHÔNG DÙNG app_*
 * ============================================================
 */

const SESSION_COOKIE = "vtc_session";
const SESSION_TTL_MS =
  30 * 24 * 60 * 60 * 1000;

const PBKDF2_ITERATIONS = 100000;

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
    new Uint8Array(binary.length);

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
      result[key] =
        decodeURIComponent(
          value
        );
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

    /*
     * DB hiện tại chưa bắt buộc có balance.
     * Frontend vẫn nhận được số dư = 0.
     */
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
        email: row.email,
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
  /*
   * Chỉ dùng các cột chắc chắn
   * có trong DB hiện tại.
   */

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
      "068686862",

    owner:
      env.BANK_OWNER ||
      "Dang Gia Khanh",
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
        status: "CLOSED",
        statusText:
          "CHƯA MỞ",
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
        Number(
          t.fee || 0
        ),

      status:
        remaining > 0
          ? "OPEN"
          : "FULL",

      statusText:
        remaining > 0
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

  const data =
    await bodyJson(request);

  const teamName =
    String(
      data.teamName || ""
    ).trim();

  const logoUrl =
    String(
      data.logoUrl || ""
    ).trim();

  const contactEmail =
    email(
      data.contactEmail ||
      session.user.email
    );

  const player2Email =
    email(
      data.player2Email ||
      ""
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
    teamName.length > 60
  ) {
    return json(
      {
        ok: false,
        error:
          "Tên team tối đa 60 ký tự.",
      },
      400
    );
  }

  if (
    !validEmail(
      contactEmail
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Email liên hệ không hợp lệ.",
      },
      400
    );
  }

  if (
    player2Email &&
    !validEmail(
      player2Email
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Email thành viên 2 không hợp lệ.",
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

  const count =
    await env.DB
      .prepare(`
        SELECT COUNT(*) AS total
        FROM registrations
        WHERE
          tournament_id = ?
          AND status NOT IN (
            'CANCELLED',
            'REJECTED'
          )
      `)
      .bind(t.id)
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
   * Mỗi tài khoản chỉ đăng ký
   * một team cho một giải.
   */

  const duplicate =
    await env.DB
      .prepare(`
        SELECT id
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

  const orderCode =
    "VTC" +
    Date.now().toString(36)
      .toUpperCase() +
    randomToken(5)
      .toUpperCase();

  const amount =
    Number(
      t.fee || 0
    );

  let teamId;
  let registrationId;

  try {
    /*
     * teams sau migration:
     * logo_url
     * contact_email
     * player2_email
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
              player2_email
            )
          VALUES
            (
              ?,
              NULL,
              ?,
              'ACTIVE',
              ?,
              ?,
              ?
            )
        `)
        .bind(
          teamName,
          session.user.id,
          logoUrl,
          contactEmail,
          player2Email
        )
        .run();

    teamId =
      teamResult.meta
        ?.last_row_id;

    if (!teamId) {
      const team =
        await env.DB
          .prepare(`
            SELECT id
            FROM teams
            WHERE
              owner_id = ?
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
        team?.id;
    }

    /*
     * team_members schema hiện tại:
     *
     * team_id
     * user_id
     * game_uid
     * nickname
     *
     * Chủ team được thêm tự động.
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
        teamName
      )
      .run();

    /*
     * Nếu email thành viên 2
     * đã có tài khoản trên hệ thống,
     * tự liên kết tài khoản đó.
     *
     * Nếu chưa có tài khoản:
     * vẫn lưu email ở teams.player2_email.
     */

    if (
      player2Email &&
      player2Email !==
        session.user.email
    ) {
      const player2 =
        await env.DB
          .prepare(`
            SELECT id
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(
            player2Email
          )
          .first();

      if (player2?.id) {
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
            player2.id,
            "",
            player2Email
          )
          .run();
      }
    }

    /*
     * registrations schema hiện tại
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
        reg?.id;
    }

    /*
     * payments:
     *
     * DB hiện tại có transaction_id.
     *
     * Ta tạo payment PENDING trước.
     */

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
          (
            ?,
            'BANK',
            ?,
            ?,
            'PENDING',
            ?
          )
      `)
      .bind(
        registrationId,
        orderCode,
        amount,
        JSON.stringify({
          type:
            "BANK_QR",
          orderCode,
          createdAt:
            new Date().toISOString(),
        })
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
          amount > 0
            ? `Đăng ký thành công. Mã thanh toán: ${orderCode}.`
            : `Đăng ký team thành công. Mã đăng ký: ${orderCode}.`,

        registration: {
          id:
            registrationId,
          teamId,
          tournamentId:
            t.id,
          orderCode,
          amount,
          status:
            "AWAITING_PAYMENT",
        },

        bank: {
          name:
            env.BANK_NAME ||
            "MB BANK",

          account:
            env.BANK_ACCOUNT ||
            "068686862",

          owner:
            env.BANK_OWNER ||
            "Dang Gia Khanh",
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
   RANKING
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

  /*
   * Chỉ tính team đã thanh toán.
   */

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

        LEFT JOIN results r
          ON r.team_id =
             tm.id

        WHERE
          reg.tournament_id = ?

          AND reg.status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
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
      .bind(t.id)
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
   PAYMENT WEBHOOK
   ============================================================ */

async function paymentWebhook(
  request,
  env
) {
  const configured =
    env.PAYMENT_WEBHOOK_SECRET;

  if (!configured) {
    return json(
      {
        ok: false,
        error:
          "PAYMENT_WEBHOOK_SECRET chưa được cấu hình.",
      },
      503
    );
  }

  const data =
    await bodyJson(request);

  const secret =
    String(
      data.secret || ""
    );

  if (
    !safeEqual(
      secret,
      configured
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Webhook secret không hợp lệ.",
      },
      401
    );
  }

  const orderCode =
    String(
      data.orderCode ||
      data.order_code ||
      data.content ||
      ""
    ).trim();

  const amount =
    Number(
      data.amount ||
      data.transferAmount ||
      data.transfer_amount ||
      0
    );

  const transactionId =
    String(
      data.transactionId ||
      data.transaction_id ||
      data.externalId ||
      data.external_id ||
      orderCode
    ).trim();

  if (
    !orderCode ||
    amount <= 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Thiếu mã đăng ký hoặc số tiền.",
      },
      400
    );
  }

  const registration =
    await env.DB
      .prepare(`
        SELECT
          id,
          team_id,
          tournament_id,
          amount,
          status
        FROM registrations
        WHERE order_code = ?
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
      },
      404
    );
  }

  const required =
    Number(
      registration.amount ||
      0
    );

  if (
    amount < required
  ) {
    return json(
      {
        ok: false,
        error:
          "Số tiền thanh toán chưa đủ.",
      },
      400
    );
  }

  /*
   * Chống xử lý giao dịch trùng.
   */

  const existed =
    await env.DB
      .prepare(`
        SELECT id
        FROM payments
        WHERE transaction_id = ?
        LIMIT 1
      `)
      .bind(
        transactionId
      )
      .first();

  if (existed) {
    return json({
      ok: true,
      message:
        "Giao dịch đã được xử lý.",
    });
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
        (
          ?,
          'BANK',
          ?,
          ?,
          'SUCCESS',
          ?
        )
    `)
    .bind(
      registration.id,
      transactionId,
      amount,
      JSON.stringify(data)
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE registrations
      SET
        status = 'PAID',
        updated_at =
          CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(
      registration.id
    )
    .run();

  /*
   * Team thanh toán thành công
   * chuyển sang ACTIVE.
   */

  await env.DB
    .prepare(`
      UPDATE teams
      SET status = 'ACTIVE'
      WHERE id = ?
    `)
    .bind(
      registration.team_id
    )
    .run();

  return json({
    ok: true,
    message:
      "Đã xác nhận thanh toán.",
    registrationId:
      registration.id,
    status:
      "PAID",
  });
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
   ROUTER
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

  if (
    path ===
      "/api/health" &&
    method === "GET"
  ) {
    return health(env);
  }

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
      "/api/ranking" &&
    method === "GET"
  ) {
    return ranking(
      request,
      env
    );
  }

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
     * Các file public:
     * public/index.html
     * public/...
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
