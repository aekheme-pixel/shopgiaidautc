/**
 * =========================================================
 * GIẢI ĐẤU TỬ CHIẾN – MÙA 1
 *
 * Cloudflare Worker
 * Cloudflare D1
 * Web Crypto
 *
 * DATABASE:
 *   users
 *   teams
 *   team_members
 *   tournaments
 *   slots
 *   registrations
 *   payments
 *   matches
 *   results
 *   sessions
 *   audit_logs
 *
 * KHÔNG sử dụng:
 *   app_sessions
 *   app_teams
 *   app_tournaments
 * =========================================================
 */

const PBKDF2_ITERATIONS = 100000;

const SESSION_TTL_SECONDS =
  60 * 60 * 24 * 30;

const SESSION_COOKIE =
  "vtc_session";

const JSON_HEADERS = {
  "content-type":
    "application/json; charset=utf-8",

  "cache-control":
    "no-store",
};

/* =========================================================
   WORKER
========================================================= */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    try {
      if (
        url.pathname.startsWith("/api/")
      ) {
        return await api(
          request,
          env,
          url
        );
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "Assets chưa được cấu hình.",
        {
          status: 500,
        }
      );
    } catch (error) {
      console.error(
        "WORKER ERROR:",
        error
      );

      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        return json(
          {
            ok: false,
            error: safeError(error),
          },
          500,
          null,
          request
        );
      }

      return new Response(
        "Internal Server Error",
        {
          status: 500,
        }
      );
    }
  },
};

/* =========================================================
   API ROUTER
========================================================= */

async function api(
  request,
  env,
  url
) {
  const method =
    request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers:
        corsHeaders(request),
    });
  }

  if (
    url.pathname ===
      "/api/health" &&
    method === "GET"
  ) {
    return json(
      {
        ok: true,

        site:
          env.SITE_NAME ||
          "GIẢI ĐẤU TỬ CHIẾN – MÙA 1",
      },
      200,
      null,
      request
    );
  }

  if (
    url.pathname ===
      "/api/auth/register" &&
    method === "POST"
  ) {
    return handleRegister(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/auth/login" &&
    method === "POST"
  ) {
    return handleLogin(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/auth/logout" &&
    method === "POST"
  ) {
    return handleLogout(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/auth/me" &&
    method === "GET"
  ) {
    return handleMe(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/tournament" &&
    method === "GET"
  ) {
    return handleTournament(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/team/register" &&
    method === "POST"
  ) {
    return handleTeamRegister(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/ranking" &&
    method === "GET"
  ) {
    return handleRanking(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/api/payment/webhook" &&
    method === "POST"
  ) {
    return handlePaymentWebhook(
      request,
      env
    );
  }

  return json(
    {
      ok: false,
      error: "API không tồn tại.",
    },
    404,
    null,
    request
  );
}

/* =========================================================
   REGISTER
========================================================= */

async function handleRegister(
  request,
  env
) {
  if (!env.DB) {
    return json(
      {
        ok: false,
        error:
          "D1 DB chưa được cấu hình.",
      },
      500,
      null,
      request
    );
  }

  const data =
    await readJson(request);

  const username =
    normalizeUsername(
      data.username ??
        data.accountName ??
        data.userName
    );

  const email =
    normalizeEmail(
      data.email
    );

  const password =
    String(
      data.password || ""
    );

  const confirmPassword =
    String(
      data.confirmPassword ??
        data.passwordConfirm ??
        data.confirm ??
        ""
    );

  /* -------------------------------------------------------
     Validate username
  ------------------------------------------------------- */

  if (
    !isUsername(username)
  ) {
    return json(
      {
        ok: false,
        error:
          "Tên tài khoản phải từ 3–30 ký tự, chỉ gồm chữ, số, dấu gạch dưới.",
      },
      400,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Validate email
  ------------------------------------------------------- */

  if (!isEmail(email)) {
    return json(
      {
        ok: false,
        error:
          "Email không hợp lệ.",
      },
      400,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Validate password
  ------------------------------------------------------- */

  if (
    password.length < 6
  ) {
    return json(
      {
        ok: false,
        error:
          "Mật khẩu phải có ít nhất 6 ký tự.",
      },
      400,
      null,
      request
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
      400,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Check username
  ------------------------------------------------------- */

  const usernameExists =
    await env.DB
      .prepare(
        `SELECT id
         FROM users
         WHERE lower(username) = lower(?)
         LIMIT 1`
      )
      .bind(username)
      .first();

  if (usernameExists) {
    return json(
      {
        ok: false,
        error:
          "Tên tài khoản này đã tồn tại.",
      },
      409,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Check email
  ------------------------------------------------------- */

  const emailExists =
    await env.DB
      .prepare(
        `SELECT id
         FROM users
         WHERE lower(email) = lower(?)
         LIMIT 1`
      )
      .bind(email)
      .first();

  if (emailExists) {
    return json(
      {
        ok: false,
        error:
          "Email này đã được đăng ký.",
      },
      409,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Password hash
  ------------------------------------------------------- */

  const salt =
    randomBytes(16);

  const hash =
    await hashPassword(
      password,
      salt,
      PBKDF2_ITERATIONS
    );

  const passwordHash =
    bytesToB64Url(hash);

  const passwordSalt =
    bytesToB64Url(salt);

  /* -------------------------------------------------------
     Role
  ------------------------------------------------------- */

  const role =
    chooseDefaultRole();

  /* -------------------------------------------------------
     INSERT
  ------------------------------------------------------- */

  let result;

  try {
    result =
      await env.DB
        .prepare(
          `INSERT INTO users
           (
             username,
             email,
             password_hash,
             password_salt,
             role,
             balance,
             created_at
           )
           VALUES (?, ?, ?, ?, ?, 0, ?)`
        )
        .bind(
          username,
          email,
          passwordHash,
          passwordSalt,
          role,
          new Date().toISOString()
        )
        .run();
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "Không thể tạo tài khoản: " +
          safeError(error),
      },
      500,
      null,
      request
    );
  }

  const user =
    await findUserById(
      env.DB,
      result.meta?.last_row_id
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Tạo tài khoản thành công nhưng không đọc lại được tài khoản.",
      },
      500,
      null,
      request
    );
  }

  await writeAudit(
    env.DB,
    user.id,
    "REGISTER",
    "users",
    "Tạo tài khoản mới"
  );

  const session =
    await createSession(
      env.DB,
      user
    );

  return json(
    {
      ok: true,

      message:
        "Tạo tài khoản thành công.",

      user:
        publicUser(user),
    },
    200,
    session.cookie,
    request
  );
}

/* =========================================================
   LOGIN
========================================================= */

async function handleLogin(
  request,
  env
) {
  if (!env.DB) {
    return json(
      {
        ok: false,
        error:
          "D1 DB chưa được cấu hình.",
      },
      500,
      null,
      request
    );
  }

  const data =
    await readJson(request);

  const email =
    normalizeEmail(
      data.email
    );

  const password =
    String(
      data.password || ""
    );

  if (
    !isEmail(email) ||
    !password
  ) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập đúng email và mật khẩu.",
      },
      400,
      null,
      request
    );
  }

  const user =
    await findUserByEmail(
      env.DB,
      email
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Email hoặc mật khẩu không đúng.",
      },
      401,
      null,
      request
    );
  }

  const valid =
    await verifyStoredPassword(
      user,
      password
    );

  if (!valid) {
    return json(
      {
        ok: false,
        error:
          "Email hoặc mật khẩu không đúng.",
      },
      401,
      null,
      request
    );
  }

  const session =
    await createSession(
      env.DB,
      user
    );

  await writeAudit(
    env.DB,
    user.id,
    "LOGIN",
    "sessions",
    "Đăng nhập"
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
    session.cookie,
    request
  );
}

/* =========================================================
   LOGOUT
========================================================= */

async function handleLogout(
  request,
  env
) {
  if (!env.DB) {
    return json(
      {
        ok: false,
        error:
          "D1 DB chưa được cấu hình.",
      },
      500,
      null,
      request
    );
  }

  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (token) {
    await env.DB
      .prepare(
        `DELETE FROM sessions
         WHERE token = ?`
      )
      .bind(token)
      .run()
      .catch(() => {});
  }

  return json(
    {
      ok: true,
      message:
        "Đã đăng xuất.",
    },
    200,
    deleteCookieHeader(),
    request
  );
}

/* =========================================================
   CURRENT USER
========================================================= */

async function handleMe(
  request,
  env
) {
  if (!env.DB) {
    return json(
      {
        ok: false,
        error:
          "D1 DB chưa được cấu hình.",
      },
      500,
      null,
      request
    );
  }

  const user =
    await getCurrentUser(
      request,
      env.DB
    );

  if (!user) {
    return json(
      {
        ok: true,

        authenticated:
          false,

        user: null,
      },
      200,
      null,
      request
    );
  }

  return json(
    {
      ok: true,

      authenticated:
        true,

      user:
        publicUser(user),
    },
    200,
    null,
    request
  );
}

/* =========================================================
   USER
========================================================= */

async function findUserById(
  db,
  id
) {
  if (
    id === null ||
    id === undefined
  ) {
    return null;
  }

  const row =
    await db
      .prepare(
        `SELECT *
         FROM users
         WHERE id = ?
         LIMIT 1`
      )
      .bind(Number(id))
      .first();

  return row
    ? normalizeUserRow(row)
    : null;
}

async function findUserByEmail(
  db,
  email
) {
  const row =
    await db
      .prepare(
        `SELECT *
         FROM users
         WHERE lower(email) =
               lower(?)
         LIMIT 1`
      )
      .bind(email)
      .first();

  return row
    ? normalizeUserRow(row)
    : null;
}

function normalizeUserRow(
  row
) {
  return {
    id:
      Number(row.id),

    username:
      String(
        row.username || ""
      ),

    email:
      String(
        row.email || ""
      ),

    passwordHash:
      String(
        row.password_hash || ""
      ),

    passwordSalt:
      String(
        row.password_salt || ""
      ),

    role:
      String(
        row.role || "USER"
      ),

    balance:
      Number(
        row.balance || 0
      ),

    createdAt:
      row.created_at || null,
  };
}

function publicUser(user) {
  return {
    id:
      user.id,

    username:
      user.username,

    email:
      user.email,

    role:
      user.role,

    balance:
      Number.isFinite(
        user.balance
      )
        ? user.balance
        : 0,
  };
}

/* =========================================================
   PASSWORD
========================================================= */

async function hashPassword(
  password,
  salt,
  iterations
) {
  const encoder =
    new TextEncoder();

  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      {
        name: "PBKDF2",
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",

        salt,

        iterations,

        hash: "SHA-256",
      },
      key,
      256
    );

  return new Uint8Array(bits);
}

async function verifyStoredPassword(
  user,
  password
) {
  /*
   * -------------------------------------------------------
   * Format mới:
   *
   * password_hash = base64url(hash)
   * password_salt = base64url(salt)
   * -------------------------------------------------------
   */

  if (
    user.passwordSalt &&
    user.passwordHash
  ) {
    const salt =
      b64UrlToBytes(
        user.passwordSalt
      );

    const expected =
      b64UrlToBytes(
        user.passwordHash
      );

    if (
      salt.length &&
      expected.length
    ) {
      const actual =
        await hashPassword(
          password,
          salt,
          PBKDF2_ITERATIONS
        );

      return timingSafeEqual(
        actual,
        expected
      );
    }
  }

  /*
   * -------------------------------------------------------
   * Hỗ trợ format cũ:
   *
   * pbkdf2$100000$salt$hash
   * -------------------------------------------------------
   */

  const stored =
    user.passwordHash;

  if (
    stored.startsWith(
      "pbkdf2$"
    )
  ) {
    const parts =
      stored.split("$");

    if (
      parts.length === 4
    ) {
      const iterations =
        Number(parts[1]);

      const salt =
        b64UrlToBytes(
          parts[2]
        );

      const expected =
        b64UrlToBytes(
          parts[3]
        );

      if (
        iterations > 0 &&
        iterations <=
          PBKDF2_ITERATIONS &&
        salt.length &&
        expected.length
      ) {
        const actual =
          await hashPassword(
            password,
            salt,
            iterations
          );

        return timingSafeEqual(
          actual,
          expected
        );
      }
    }
  }

  return false;
}

/* =========================================================
   SESSION
========================================================= */

async function createSession(
  db,
  user
) {
  /*
   * sessions.token là PRIMARY KEY
   * theo 0001.
   *
   * Vì vậy không cần token_hash.
   */

  const token =
    bytesToB64Url(
      randomBytes(32)
    );

  const expiresAt =
    Math.floor(
      Date.now() / 1000
    ) +
    SESSION_TTL_SECONDS;

  await db
    .prepare(
      `INSERT INTO sessions
       (
         token,
         user_id,
         expires_at
       )
       VALUES (?, ?, ?)`
    )
    .bind(
      token,
      user.id,
      expiresAt
    )
    .run();

  return {
    token,

    cookie:
      sessionCookie(token),
  };
}

async function getCurrentUser(
  request,
  db
) {
  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (!token) {
    return null;
  }

  const now =
    Math.floor(
      Date.now() / 1000
    );

  /*
   * Xóa session hết hạn.
   */

  await db
    .prepare(
      `DELETE FROM sessions
       WHERE expires_at <= ?`
    )
    .bind(now)
    .run()
    .catch(() => {});

  const session =
    await db
      .prepare(
        `SELECT
           token,
           user_id,
           expires_at
         FROM sessions
         WHERE token = ?
         LIMIT 1`
      )
      .bind(token)
      .first();

  if (!session) {
    return null;
  }

  if (
    Number(
      session.expires_at
    ) <= now
  ) {
    await db
      .prepare(
        `DELETE FROM sessions
         WHERE token = ?`
      )
      .bind(token)
      .run()
      .catch(() => {});

    return null;
  }

  return findUserById(
    db,
    session.user_id
  );
}

/* =========================================================
   TOURNAMENT
========================================================= */

async function handleTournament(
  request,
  env
) {
  const tournament =
    await getOrCreateTournament(
      env
    );

  if (!tournament) {
    return json(
      {
        ok: false,
        error:
          "Chưa có giải đấu.",
      },
      500,
      null,
      request
    );
  }

  const count =
    await env.DB
      .prepare(
        `SELECT COUNT(*) AS count
         FROM registrations
         WHERE tournament_id = ?
         AND status IN
           (
             'AWAITING_PAYMENT',
             'PAID',
             'CONFIRMED'
           )`
      )
      .bind(
        tournament.id
      )
      .first();

  const registered =
    Number(
      count?.count || 0
    );

  const maxTeams =
    Number(
      tournament.max_teams || 48
    );

  return json(
    {
      ok: true,

      tournament: {
        id:
          Number(
            tournament.id
          ),

        name:
          tournament.name,

        description:
          tournament.description ||
          "",

        fee:
          Number(
            tournament.fee || 0
          ),

        maxTeams,

        registered,

        remaining:
          Math.max(
            0,
            maxTeams -
              registered
          ),

        status:
          registered >=
          maxTeams
            ? "FULL"
            : tournament.status,

        statusText:
          registered >=
          maxTeams
            ? "ĐÃ ĐỦ SLOT"
            : "CÒN SLOT",

        bank: {
          name:
            env.BANK_NAME || "",

          account:
            env.BANK_ACCOUNT || "",

          owner:
            env.BANK_OWNER || "",
        },
      },
    },
    200,
    null,
    request
  );
}

async function getOrCreateTournament(
  env
) {
  let tournament =
    await env.DB
      .prepare(
        `SELECT *
         FROM tournaments
         ORDER BY id ASC
         LIMIT 1`
      )
      .first();

  if (tournament) {
    return tournament;
  }

  const fee =
    Number(
      env.ENTRY_FEE || 0
    );

  await env.DB
    .prepare(
      `INSERT INTO tournaments
       (
         name,
         fee,
         max_teams,
         status,
         description
       )
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(
      "Giải Tử Chiến Mùa 1",
      fee,
      48,
      "OPEN",
      "Giải đấu Tử Chiến Mùa 1."
    )
    .run();

  tournament =
    await env.DB
      .prepare(
        `SELECT *
         FROM tournaments
         ORDER BY id ASC
         LIMIT 1`
      )
      .first();

  return tournament;
}

/* =========================================================
   TEAM REGISTER
========================================================= */

async function handleTeamRegister(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env.DB
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Bạn cần đăng nhập trước.",
      },
      401,
      null,
      request
    );
  }

  const data =
    await readJson(request);

  const teamName =
    String(
      data.teamName ||
        data.name ||
        ""
    ).trim();

  const tag =
    String(
      data.tag || ""
    ).trim();

  const logoUrl =
    String(
      data.logoUrl || ""
    ).trim();

  const contactEmail =
    normalizeEmail(
      data.contactEmail ||
        user.email
    );

  const player2Email =
    normalizeEmail(
      data.player2Email ||
        ""
    );

  if (
    teamName.length < 2 ||
    teamName.length > 60
  ) {
    return json(
      {
        ok: false,
        error:
          "Tên team phải từ 2–60 ký tự.",
      },
      400,
      null,
      request
    );
  }

  if (!isEmail(contactEmail)) {
    return json(
      {
        ok: false,
        error:
          "Email liên hệ không hợp lệ.",
      },
      400,
      null,
      request
    );
  }

  if (
    player2Email &&
    !isEmail(player2Email)
  ) {
    return json(
      {
        ok: false,
        error:
          "Email thành viên 2 không hợp lệ.",
      },
      400,
      null,
      request
    );
  }

  const tournament =
    await getOrCreateTournament(
      env
    );

  if (!tournament) {
    return json(
      {
        ok: false,
        error:
          "Chưa có giải đấu.",
      },
      500,
      null,
      request
    );
  }

  if (
    String(
      tournament.status
    ).toUpperCase() !==
      "OPEN"
  ) {
    return json(
      {
        ok: false,
        error:
          "Giải đấu hiện không mở đăng ký.",
      },
      409,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Count registrations
  ------------------------------------------------------- */

  const count =
    await env.DB
      .prepare(
        `SELECT COUNT(*) AS count
         FROM registrations
         WHERE tournament_id = ?
         AND status IN
           (
             'AWAITING_PAYMENT',
             'PAID',
             'CONFIRMED'
           )`
      )
      .bind(
        tournament.id
      )
      .first();

  const registered =
    Number(
      count?.count || 0
    );

  const maxTeams =
    Number(
      tournament.max_teams ||
        48
    );

  if (
    registered >= maxTeams
  ) {
    return json(
      {
        ok: false,
        error:
          "Giải đã đủ slot.",
      },
      409,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     User đã có team trong giải?
  ------------------------------------------------------- */

  const duplicate =
    await env.DB
      .prepare(
        `SELECT
           r.id
         FROM registrations r
         INNER JOIN teams t
           ON t.id = r.team_id
         WHERE
           r.tournament_id = ?
           AND t.owner_id = ?
         AND r.status NOT IN
           ('CANCELLED', 'FAILED')
         LIMIT 1`
      )
      .bind(
        tournament.id,
        user.id
      )
      .first();

  if (duplicate) {
    return json(
      {
        ok: false,
        error:
          "Bạn đã đăng ký team cho giải này rồi.",
      },
      409,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     INSERT TEAM
  ------------------------------------------------------- */

  let teamId;

  try {
    const teamResult =
      await env.DB
        .prepare(
          `INSERT INTO teams
           (
             owner_id,
             name,
             tag,
             logo_url,
             status
           )
           VALUES (?, ?, ?, ?, 'PENDING')`
        )
        .bind(
          user.id,
          teamName,
          tag || null,
          logoUrl || null
        )
        .run();

    teamId =
      Number(
        teamResult.meta
          ?.last_row_id
      );
  } catch (error) {
    console.error(
      "TEAM INSERT ERROR:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "Không thể tạo team: " +
          safeError(error),
      },
      500,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     TEAM MEMBER #1
  ------------------------------------------------------- */

  try {
    await env.DB
      .prepare(
        `INSERT INTO team_members
         (
           team_id,
           game_name,
           uid,
           role
         )
         VALUES (?, ?, ?, 'OWNER')`
      )
      .bind(
        teamId,
        usernameOrEmail(user),
        "",
      )
      .run();

    /* -----------------------------------------------------
       TEAM MEMBER #2
    ----------------------------------------------------- */

    if (player2Email) {
      await env.DB
        .prepare(
          `INSERT INTO team_members
           (
             team_id,
             game_name,
             uid,
             role
           )
           VALUES (?, ?, ?, 'PLAYER')`
        )
        .bind(
          teamId,
          player2Email,
          "",
        )
        .run();
    }
  } catch (error) {
    /*
     * Không để team mồ côi nếu member insert lỗi.
     */

    await env.DB
      .prepare(
        `DELETE FROM teams
         WHERE id = ?`
      )
      .bind(teamId)
      .run()
      .catch(() => {});

    return json(
      {
        ok: false,
        error:
          "Không thể tạo thành viên team: " +
          safeError(error),
      },
      500,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     REGISTRATION
  ------------------------------------------------------- */

  const orderCode =
    createOrderCode();

  const amount =
    Number(
      tournament.fee || 0
    );

  let registrationId;

  try {
    const registrationResult =
      await env.DB
        .prepare(
          `INSERT INTO registrations
           (
             team_id,
             tournament_id,
             slot_id,
             order_code,
             amount,
             status
           )
           VALUES (?, ?, NULL, ?, ?, 'AWAITING_PAYMENT')`
        )
        .bind(
          teamId,
          tournament.id,
          orderCode,
          amount
        )
        .run();

    registrationId =
      Number(
        registrationResult
          .meta?.last_row_id
      );
  } catch (error) {
    await env.DB
      .prepare(
        `DELETE FROM team_members
         WHERE team_id = ?`
      )
      .bind(teamId)
      .run()
      .catch(() => {});

    await env.DB
      .prepare(
        `DELETE FROM teams
         WHERE id = ?`
      )
      .bind(teamId)
      .run()
      .catch(() => {});

    return json(
      {
        ok: false,
        error:
          "Không thể tạo đăng ký: " +
          safeError(error),
      },
      500,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     PAYMENT
  ------------------------------------------------------- */

  try {
    await env.DB
      .prepare(
        `INSERT INTO payments
         (
           registration_id,
           gateway,
           external_id,
           amount,
           status,
           raw_json
         )
         VALUES (?, 'BANK', NULL, ?, 'PENDING', NULL)`
      )
      .bind(
        registrationId,
        amount
      )
      .run();
  } catch (error) {
    console.error(
      "PAYMENT INSERT ERROR:",
      error
    );

    /*
     * Registration vẫn giữ lại.
     * Payment có thể tạo lại bằng admin/webhook.
     */
  }

  await writeAudit(
    env.DB,
    user.id,
    "TEAM_REGISTER",
    "teams",
    `Đăng ký team ${teamName}, registration ${registrationId}`
  );

  return json(
    {
      ok: true,

      message:
        "Đăng ký team thành công. Vui lòng hoàn tất thanh toán.",

      team: {
        id: teamId,

        name:
          teamName,

        tag:
          tag,

        registrationId,

        orderCode,

        amount,

        paymentStatus:
          "PENDING",
      },
    },
    200,
    null,
    request
  );
}

/* =========================================================
   RANKING
========================================================= */

async function handleRanking(
  request,
  env
) {
  const tournament =
    await getOrCreateTournament(
      env
    );

  if (!tournament) {
    return json(
      {
        ok: false,
        ranking: [],
      },
      200,
      null,
      request
    );
  }

  /*
   * Ranking lấy trực tiếp từ results.
   *
   * points = tổng points
   * wins   = placement = 1
   * losses = các trận có placement > 1
   */

  const rows =
    await env.DB
      .prepare(
        `SELECT
           t.id,
           t.name,
           t.logo_url,

           COALESCE(
             SUM(r.points),
             0
           ) AS points,

           COALESCE(
             SUM(
               CASE
                 WHEN r.placement = 1
                 THEN 1
                 ELSE 0
               END
             ),
             0
           ) AS wins,

           COUNT(r.id) AS matches

         FROM teams t

         INNER JOIN registrations reg
           ON reg.team_id = t.id

         LEFT JOIN results r
           ON r.team_id = t.id

         WHERE
           reg.tournament_id = ?

           AND reg.status IN
             (
               'PAID',
               'CONFIRMED'
             )

         GROUP BY
           t.id,
           t.name,
           t.logo_url

         ORDER BY
           points DESC,
           wins DESC,
           t.id ASC

         LIMIT 100`
      )
      .bind(
        tournament.id
      )
      .all();

  const ranking =
    (
      rows.results || []
    ).map(
      (row, index) => ({
        rank:
          index + 1,

        teamName:
          row.name,

        logoUrl:
          row.logo_url || "",

        points:
          Number(
            row.points || 0
          ),

        wins:
          Number(
            row.wins || 0
          ),

        matches:
          Number(
            row.matches || 0
          ),

        losses:
          Math.max(
            0,
            Number(
              row.matches || 0
            ) -
              Number(
                row.wins || 0
              )
          ),
      })
    );

  return json(
    {
      ok: true,

      ranking,
    },
    200,
    null,
    request
  );
}

/* =========================================================
   PAYMENT WEBHOOK
========================================================= */

async function handlePaymentWebhook(
  request,
  env
) {
  const secret =
    env.PAYMENT_WEBHOOK_SECRET;

  if (!secret) {
    return json(
      {
        ok: false,
        error:
          "Chưa cấu hình PAYMENT_WEBHOOK_SECRET.",
      },
      503,
      null,
      request
    );
  }

  const supplied =
    request.headers.get(
      "x-webhook-secret"
    ) || "";

  if (
    !timingSafeStringEqual(
      supplied,
      secret
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Webhook secret không hợp lệ.",
      },
      401,
      null,
      request
    );
  }

  const data =
    await readJson(request);

  /*
   * Có thể gửi:
   *
   * {
   *   registrationId: 123,
   *   status: "PAID",
   *   reference: "..."
   * }
   *
   * hoặc:
   *
   * {
   *   teamId: 123,
   *   status: "PAID"
   * }
   */

  let registrationId =
    Number(
      data.registrationId || 0
    );

  const teamId =
    Number(
      data.teamId || 0
    );

  const status =
    String(
      data.status || ""
    ).toUpperCase();

  const reference =
    String(
      data.reference ||
        data.transactionId ||
        ""
    );

  if (
    ![
      "PAID",
      "CONFIRMED",
      "PENDING",
      "FAILED",
    ].includes(status)
  ) {
    return json(
      {
        ok: false,
        error:
          "Trạng thái thanh toán không hợp lệ.",
      },
      400,
      null,
      request
    );
  }

  if (
    !registrationId &&
    teamId
  ) {
    const registration =
      await env.DB
        .prepare(
          `SELECT id
           FROM registrations
           WHERE team_id = ?
           ORDER BY id DESC
           LIMIT 1`
        )
        .bind(teamId)
        .first();

    registrationId =
      Number(
        registration?.id || 0
      );
  }

  if (!registrationId) {
    return json(
      {
        ok: false,
        error:
          "Thiếu registrationId hoặc teamId.",
      },
      400,
      null,
      request
    );
  }

  const registration =
    await env.DB
      .prepare(
        `SELECT *
         FROM registrations
         WHERE id = ?
         LIMIT 1`
      )
      .bind(registrationId)
      .first();

  if (!registration) {
    return json(
      {
        ok: false,
        error:
          "Không tìm thấy registration.",
      },
      404,
      null,
      request
    );
  }

  /* -------------------------------------------------------
     Registration status
  ------------------------------------------------------- */

  let registrationStatus =
    "AWAITING_PAYMENT";

  if (
    status === "PAID" ||
    status === "CONFIRMED"
  ) {
    registrationStatus =
      "CONFIRMED";
  }

  if (
    status === "FAILED"
  ) {
    registrationStatus =
      "FAILED";
  }

  await env.DB
    .prepare(
      `UPDATE registrations
       SET status = ?
       WHERE id = ?`
    )
    .bind(
      registrationStatus,
      registrationId
    )
    .run();

  /* -------------------------------------------------------
     Payment
  ------------------------------------------------------- */

  const payment =
    await env.DB
      .prepare(
        `SELECT id
         FROM payments
         WHERE registration_id = ?
         ORDER BY id DESC
         LIMIT 1`
      )
      .bind(
        registrationId
      )
      .first();

  if (payment) {
    await env.DB
      .prepare(
        `UPDATE payments
         SET
           status = ?,
           external_id = ?
         WHERE id = ?`
      )
      .bind(
        status,
        reference || null,
        payment.id
      )
      .run();
  } else {
    await env.DB
      .prepare(
        `INSERT INTO payments
         (
           registration_id,
           gateway,
           external_id,
           amount,
           status,
           raw_json
         )
         VALUES (?, 'BANK', ?, ?, ?, ?)`
      )
      .bind(
        registrationId,
        reference || null,
        Number(
          registration.amount || 0
        ),
        status,
        JSON.stringify(data)
      )
      .run();
  }

  /* -------------------------------------------------------
     Team
  ------------------------------------------------------- */

  const teamStatus =
    status === "PAID" ||
    status === "CONFIRMED"
      ? "CONFIRMED"
      : status === "FAILED"
      ? "REJECTED"
      : "PENDING";

  await env.DB
    .prepare(
      `UPDATE teams
       SET status = ?
       WHERE id = ?`
    )
    .bind(
      teamStatus,
      registration.team_id
    )
    .run();

  /* -------------------------------------------------------
     Audit
  ------------------------------------------------------- */

  const team =
    await env.DB
      .prepare(
        `SELECT owner_id
         FROM teams
         WHERE id = ?
         LIMIT 1`
      )
      .bind(
        registration.team_id
      )
      .first();

  if (team) {
    await writeAudit(
      env.DB,
      team.owner_id,
      "PAYMENT_UPDATE",
      "registrations",
      `Registration ${registrationId}: ${status}`
    );
  }

  return json(
    {
      ok: true,

      registrationId,

      status,

      registrationStatus,
    },
    200,
    null,
    request
  );
}

/* =========================================================
   AUDIT
========================================================= */

async function writeAudit(
  db,
  userId,
  action,
  target,
  details
) {
  try {
    await db
      .prepare(
        `INSERT INTO audit_logs
         (
           user_id,
           action,
           target,
           details,
           created_at
         )
         VALUES (?, ?, ?, ?, ?)`
      )
      .bind(
        userId || null,
        action,
        target || null,
        details || null,
        new Date().toISOString()
      )
      .run();
  } catch (error) {
    /*
     * Audit lỗi không được làm
     * login/register/payment chết.
     */

    console.error(
      "AUDIT ERROR:",
      error
    );
  }
}

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(
  value
) {
  return String(
    value || ""
  )
    .trim()
    .toLowerCase();
}

function normalizeUsername(
  value
) {
  return String(
    value || ""
  )
    .trim()
    .toLowerCase();
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(value);
}

function isUsername(
  value
) {
  return /^[a-z0-9_]{3,30}$/
    .test(value);
}

function usernameOrEmail(
  user
) {
  return (
    user.username ||
    user.email
  );
}

function chooseDefaultRole() {
  /*
   * 0001 dùng DEFAULT 'USER'.
   */

  return "USER";
}

function createOrderCode() {
  const random =
    bytesToB64Url(
      randomBytes(9)
    )
      .replace(
        /[^A-Za-z0-9]/g,
        ""
      )
      .slice(0, 10)
      .toUpperCase();

  return (
    "VT" +
    Date.now()
      .toString(36)
      .toUpperCase() +
    random
  );
}

/* =========================================================
   CRYPTO
========================================================= */

function randomBytes(
  length
) {
  const bytes =
    new Uint8Array(length);

  crypto.getRandomValues(
    bytes
  );

  return bytes;
}

function timingSafeEqual(
  a,
  b
) {
  if (
    !(a instanceof Uint8Array) ||
    !(b instanceof Uint8Array) ||
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {
    result |=
      a[i] ^ b[i];
  }

  return result === 0;
}

function timingSafeStringEqual(
  a,
  b
) {
  return timingSafeEqual(
    new TextEncoder().encode(a),
    new TextEncoder().encode(b)
  );
}

function bytesToB64Url(
  bytes
) {
  let binary = "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte
      );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64UrlToBytes(
  value
) {
  try {
    const normalized =
      String(value)
        .replace(
          /-/g,
          "+"
        )
        .replace(
          /_/g,
          "/"
        );

    const padded =
      normalized +
      "=".repeat(
        (4 -
          (normalized.length %
            4)) %
          4
      );

    const binary =
      atob(padded);

    return Uint8Array.from(
      binary,
      char =>
        char.charCodeAt(0)
    );
  } catch {
    return new Uint8Array();
  }
}

async function sha256Hex(
  value
) {
  const data =
    typeof value ===
    "string"
      ? new TextEncoder().encode(
          value
        )
      : value;

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return Array.from(
    new Uint8Array(digest)
  )
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}

/* =========================================================
   JSON
========================================================= */

async function readJson(
  request
) {
  const text =
    await request.text();

  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(
      "Dữ liệu gửi lên không phải JSON hợp lệ."
    );
  }
}

function safeError(error) {
  const message =
    String(
      error?.message ||
        error ||
        "Lỗi không xác định"
    );

  return message.length > 500
    ? message.slice(0, 500)
    : message;
}

/* =========================================================
   COOKIE
========================================================= */

function sessionCookie(
  token
) {
  return (
    `${SESSION_COOKIE}=${encodeURIComponent(token)}` +
    `; Max-Age=${SESSION_TTL_SECONDS}` +
    `; Path=/` +
    `; HttpOnly` +
    `; Secure` +
    `; SameSite=Lax`
  );
}

function deleteCookieHeader() {
  return (
    `${SESSION_COOKIE}=` +
    `; Max-Age=0` +
    `; Path=/` +
    `; HttpOnly` +
    `; Secure` +
    `; SameSite=Lax`
  );
}

function getCookie(
  request,
  name
) {
  const raw =
    request.headers.get(
      "Cookie"
    ) || "";

  for (
    const part of raw.split(";")
  ) {
    const index =
      part.indexOf("=");

    if (index < 0) {
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

    if (key === name) {
      try {
        return decodeURIComponent(
          value
        );
      } catch {
        return value;
      }
    }
  }

  return "";
}

/* =========================================================
   HTTP / CORS
========================================================= */

function corsHeaders(
  request
) {
  const origin =
    request?.headers?.get(
      "Origin"
    );

  const headers = {};

  if (origin) {
    headers[
      "access-control-allow-origin"
    ] = origin;

    headers[
      "access-control-allow-credentials"
    ] = "true";

    headers[
      "vary"
    ] = "Origin";
  }

  headers[
    "access-control-allow-methods"
  ] =
    "GET,POST,OPTIONS";

  headers[
    "access-control-allow-headers"
  ] =
    "Content-Type, Authorization";

  return headers;
}

function json(
  data,
  status = 200,
  cookie = null,
  request = null
) {
  const headers =
    new Headers(
      JSON_HEADERS
    );

  if (cookie) {
    headers.append(
      "Set-Cookie",
      cookie
    );
  }

  for (
    const [
      key,
      value,
    ] of Object.entries(
      corsHeaders(request)
    )
  ) {
    headers.set(
      key,
      value
    );
  }

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers,
    }
  );
}
