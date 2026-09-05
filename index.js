/**
 * GIẢI ĐẤU TỬ CHIẾN – MÙA 1
 * Cloudflare Worker + D1 + Web Crypto
 *
 * main = "index.js"
 *
 * Form đăng ký:
 *   Email
 *   Mật khẩu
 *   Nhập lại mật khẩu
 *
 * Không có tên tài khoản.
 *
 * PBKDF2 tối đa 100000 iterations vì Cloudflare Workers
 * không hỗ trợ giá trị cao hơn mức này.
 */

const PBKDF2_ITERATIONS = 100000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const SESSION_COOKIE = "vtc_session";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await api(request, env, url);
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return new Response("Assets chưa được cấu hình.", {
        status: 500,
      });
    } catch (error) {
      console.error("WORKER ERROR:", error);

      if (url.pathname.startsWith("/api/")) {
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

      return new Response("Internal Server Error", {
        status: 500,
      });
    }
  },
};


/* =========================================================
   API ROUTER
========================================================= */

async function api(request, env, url) {
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(request),
    });
  }

  if (url.pathname === "/api/health" && method === "GET") {
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
    url.pathname === "/api/auth/register" &&
    method === "POST"
  ) {
    return handleRegister(request, env);
  }

  if (
    url.pathname === "/api/auth/login" &&
    method === "POST"
  ) {
    return handleLogin(request, env);
  }

  if (
    url.pathname === "/api/auth/logout" &&
    method === "POST"
  ) {
    return handleLogout(request, env);
  }

  if (
    url.pathname === "/api/auth/me" &&
    method === "GET"
  ) {
    return handleMe(request, env);
  }

  if (
    url.pathname === "/api/tournament" &&
    method === "GET"
  ) {
    return handleTournament(env, request);
  }

  if (
    url.pathname === "/api/team/register" &&
    method === "POST"
  ) {
    return handleTeamRegister(request, env);
  }

  if (
    url.pathname === "/api/ranking" &&
    method === "GET"
  ) {
    return handleRanking(env, request);
  }

  if (
    url.pathname === "/api/payment/webhook" &&
    method === "POST"
  ) {
    return handlePaymentWebhook(request, env);
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

async function handleRegister(request, env) {
  const data = await readJson(request);

  const email = normalizeEmail(data.email);
  const password = String(data.password || "");

  const confirmPassword = String(
    data.confirmPassword ??
    data.passwordConfirm ??
    data.confirm ??
    ""
  );

  if (!isEmail(email)) {
    return json(
      {
        ok: false,
        error: "Email không hợp lệ.",
      },
      400,
      null,
      request
    );
  }

  if (password.length < 6) {
    return json(
      {
        ok: false,
        error: "Mật khẩu phải có ít nhất 6 ký tự.",
      },
      400,
      null,
      request
    );
  }

  if (password !== confirmPassword) {
    return json(
      {
        ok: false,
        error: "Mật khẩu nhập lại không khớp.",
      },
      400,
      null,
      request
    );
  }

  if (!env.DB) {
    return json(
      {
        ok: false,
        error: "D1 DB chưa được cấu hình.",
      },
      500,
      null,
      request
    );
  }

  /*
   * Tạo các bảng app_* trước.
   * Không phụ thuộc sessions cũ.
   */
  await ensureAppTables(env.DB);

  const schema = await getUsersSchema(env.DB);

  if (!schema.length) {
    return json(
      {
        ok: false,
        error: "Không tìm thấy bảng users trong D1.",
      },
      500,
      null,
      request
    );
  }

  const emailCol = findColumn(schema, [
    "email",
    "mail",
  ]);

  const passwordCol = findColumn(schema, [
    "password_hash",
    "passwordHash",
    "password",
    "pass_hash",
    "pass",
  ]);

  const saltCol = findColumn(schema, [
    "password_salt",
    "passwordSalt",
    "salt",
  ]);

  const idCol = findColumn(schema, [
    "id",
    "user_id",
    "userid",
  ]);

  const roleCol = findColumn(schema, [
    "role",
    "user_role",
  ]);

  const balanceCol = findColumn(schema, [
    "balance",
    "wallet_balance",
    "money",
    "so_du",
  ]);

  const createdCol = findColumn(schema, [
    "created_at",
    "createdAt",
    "created",
  ]);

  if (!emailCol || !passwordCol) {
    return json(
      {
        ok: false,
        error:
          "Bảng users không có cột email/password phù hợp.",
      },
      500,
      null,
      request
    );
  }

  const existing = await env.DB
    .prepare(
      `SELECT * FROM users
       WHERE lower(${qi(emailCol)}) = lower(?)
       LIMIT 1`
    )
    .bind(email)
    .first();

  if (existing) {
    return json(
      {
        ok: false,
        error: "Email này đã được đăng ký.",
      },
      409,
      null,
      request
    );
  }

  /*
   * Hash password.
   *
   * QUAN TRỌNG:
   * Không bao giờ dùng 120000.
   */
  const salt = randomBytes(16);

  const hash = await hashPassword(
    password,
    salt,
    PBKDF2_ITERATIONS
  );

  /*
   * Nếu DB có password_salt:
   *
   * password_hash = base64url(hash)
   * password_salt = base64url(salt)
   *
   * Nếu DB không có salt:
   * password = pbkdf2$100000$salt$hash
   */
  const encoded = [
    "pbkdf2",
    String(PBKDF2_ITERATIONS),
    bytesToB64Url(salt),
    bytesToB64Url(hash),
  ].join("$");

  const values = {};

  values[emailCol] = email;

  if (saltCol) {
    values[passwordCol] = bytesToB64Url(hash);
    values[saltCol] = bytesToB64Url(salt);
  } else {
    values[passwordCol] = encoded;
  }

  /*
   * Nếu id bắt buộc nhưng không có default,
   * tự tạo ID.
   */
  if (idCol) {
    const info = schema.find(
      c => c.name === idCol
    );

    if (
      info &&
      info.notnull &&
      info.dflt_value == null &&
      info.pk === 0
    ) {
      values[idCol] = randomId();
    }
  }

  /*
   * Role.
   *
   * Nếu schema có CHECK role IN (...),
   * chọn PLAYER/USER/MEMBER nếu có.
   */
  if (roleCol) {
    const tableSql = await getTableSql(
      env.DB,
      "users"
    );

    const role = chooseAllowedRole(tableSql);

    if (role) {
      values[roleCol] = role;
    }
  }

  /*
   * Số dư mặc định = 0.
   */
  if (balanceCol) {
    values[balanceCol] = 0;
  }

  if (createdCol) {
    values[createdCol] =
      new Date().toISOString();
  }

  /*
   * Không hỏi username.
   *
   * Nếu schema cũ có username NOT NULL,
   * chỉ những schema thật sự bắt buộc mới tự
   * sinh giá trị từ email để không làm INSERT chết.
   *
   * Không tạo thêm field trên giao diện.
   */
  for (const column of schema) {
    if (
      !column.notnull ||
      column.dflt_value != null ||
      column.pk
    ) {
      continue;
    }

    if (values[column.name] !== undefined) {
      continue;
    }

    const name =
      String(column.name).toLowerCase();

    if (
      [
        "username",
        "user_name",
        "account_name",
        "accountname",
        "display_name",
      ].includes(name)
    ) {
      values[column.name] =
        email
          .split("@")[0]
          .slice(0, 40) || "player";
    }
  }

  /*
   * Kiểm tra toàn bộ NOT NULL trước INSERT.
   */
  const missing = schema.filter(column => {
    return (
      column.notnull &&
      column.dflt_value == null &&
      !column.pk &&
      values[column.name] === undefined
    );
  });

  if (missing.length) {
    return json(
      {
        ok: false,
        error:
          "Schema users còn cột bắt buộc chưa thể xử lý: " +
          missing
            .map(c => c.name)
            .join(", "),
      },
      500,
      null,
      request
    );
  }

  const columns = Object.keys(values);

  const placeholders = columns
    .map(() => "?")
    .join(", ");

  const sql =
    `INSERT INTO users (` +
    columns.map(qi).join(", ") +
    `) VALUES (${placeholders})`;

  try {
    await env.DB
      .prepare(sql)
      .bind(
        ...columns.map(
          column => values[column]
        )
      )
      .run();
  } catch (error) {
    console.error(
      "REGISTER INSERT ERROR:",
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

  const user = await findUserByEmail(
    env.DB,
    email
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

  const session = await createSession(
    env.DB,
    user.userId
  );

  return json(
    {
      ok: true,
      message:
        "Tạo tài khoản thành công.",
      user: publicUser(user),
    },
    200,
    session.cookie,
    request
  );
}


/* =========================================================
   LOGIN
========================================================= */

async function handleLogin(request, env) {
  const data = await readJson(request);

  const email = normalizeEmail(data.email);
  const password =
    String(data.password || "");

  if (!isEmail(email) || !password) {
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

  await ensureAppTables(env.DB);

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
      user.userId
    );

  return json(
    {
      ok: true,
      message:
        "Đăng nhập thành công.",
      user: publicUser(user),
    },
    200,
    session.cookie,
    request
  );
}


/* =========================================================
   LOGOUT
========================================================= */

async function handleLogout(request, env) {
  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (token) {
    const tokenHash =
      await sha256Hex(token);

    await env.DB
      .prepare(
        `DELETE FROM app_sessions
         WHERE token_hash = ?`
      )
      .bind(tokenHash)
      .run()
      .catch(() => {});
  }

  return json(
    {
      ok: true,
      message: "Đã đăng xuất.",
    },
    200,
    deleteCookieHeader(),
    request
  );
}


/* =========================================================
   CURRENT USER
========================================================= */

async function handleMe(request, env) {
  await ensureAppTables(env.DB);

  const user =
    await getCurrentUser(
      request,
      env.DB
    );

  if (!user) {
    return json(
      {
        ok: true,
        authenticated: false,
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
      authenticated: true,
      user: publicUser(user),
    },
    200,
    null,
    request
  );
}


/* =========================================================
   USER HELPERS
========================================================= */

async function findUserByEmail(db, email) {
  const schema =
    await getUsersSchema(db);

  const emailCol =
    findColumn(schema, [
      "email",
      "mail",
    ]);

  if (!emailCol) {
    return null;
  }

  const row =
    await db
      .prepare(
        `SELECT * FROM users
         WHERE lower(${qi(emailCol)}) = lower(?)
         LIMIT 1`
      )
      .bind(email)
      .first();

  if (!row) {
    return null;
  }

  return normalizeUserRow(
    row,
    schema
  );
}


function normalizeUserRow(row, schema) {
  const idCol =
    findColumn(schema, [
      "id",
      "user_id",
      "userid",
    ]);

  const emailCol =
    findColumn(schema, [
      "email",
      "mail",
    ]);

  const passwordCol =
    findColumn(schema, [
      "password_hash",
      "passwordHash",
      "password",
      "pass_hash",
      "pass",
    ]);

  const saltCol =
    findColumn(schema, [
      "password_salt",
      "passwordSalt",
      "salt",
    ]);

  const roleCol =
    findColumn(schema, [
      "role",
      "user_role",
    ]);

  const balanceCol =
    findColumn(schema, [
      "balance",
      "wallet_balance",
      "money",
      "so_du",
    ]);

  const userId =
    idCol &&
    row[idCol] != null
      ? String(row[idCol])
      : String(row[emailCol]);

  return {
    raw: row,

    userId,

    email:
      String(row[emailCol] || ""),

    passwordStored:
      passwordCol
        ? String(
            row[passwordCol] ?? ""
          )
        : "",

    passwordSalt:
      saltCol
        ? String(
            row[saltCol] ?? ""
          )
        : "",

    role:
      roleCol
        ? String(
            row[roleCol] ??
            "PLAYER"
          )
        : "PLAYER",

    balance:
      balanceCol
        ? Number(
            row[balanceCol] ?? 0
          )
        : 0,
  };
}


function publicUser(user) {
  return {
    id: user.userId,
    email: user.email,
    role:
      user.role || "PLAYER",
    balance:
      Number.isFinite(user.balance)
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
  iterations = PBKDF2_ITERATIONS
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
  const stored =
    user.passwordStored;

  /*
   * Schema có salt riêng.
   */
  if (
    user.passwordSalt &&
    stored
  ) {
    const salt =
      b64UrlToBytes(
        user.passwordSalt
      );

    const expected =
      b64UrlToBytes(stored);

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
   * Schema self-contained:
   * pbkdf2$iterations$salt$hash
   */
  if (
    stored.startsWith(
      "pbkdf2$"
    )
  ) {
    const parts =
      stored.split("$");

    if (parts.length === 4) {
      const iterations =
        Number(parts[1]);

      const salt =
        b64UrlToBytes(parts[2]);

      const expected =
        b64UrlToBytes(parts[3]);

      /*
       * Không cho phép hash mới dùng
       * hơn 100000 iterations.
       *
       * Các record cũ <= 100000 vẫn
       * được verify.
       */
      if (
        iterations > 0 &&
        iterations <= 100000 &&
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
  userId
) {
  const token =
    bytesToB64Url(
      randomBytes(32)
    );

  const tokenHash =
    await sha256Hex(token);

  const now = Date.now();

  const createdAt =
    new Date(now)
      .toISOString();

  const expiresAt =
    new Date(
      now +
      SESSION_TTL_SECONDS * 1000
    ).toISOString();

  await db
    .prepare(
      `INSERT INTO app_sessions
       (user_id, token_hash, expires_at, created_at)
       VALUES (?, ?, ?, ?)`
    )
    .bind(
      String(userId),
      tokenHash,
      expiresAt,
      createdAt
    )
    .run();

  return {
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

  const tokenHash =
    await sha256Hex(token);

  const session =
    await db
      .prepare(
        `SELECT user_id, expires_at
         FROM app_sessions
         WHERE token_hash = ?
         LIMIT 1`
      )
      .bind(tokenHash)
      .first();

  if (!session) {
    return null;
  }

  const expires =
    Date.parse(
      String(
        session.expires_at || ""
      )
    );

  if (
    !Number.isFinite(expires) ||
    expires <= Date.now()
  ) {
    await db
      .prepare(
        `DELETE FROM app_sessions
         WHERE token_hash = ?`
      )
      .bind(tokenHash)
      .run()
      .catch(() => {});

    return null;
  }

  const schema =
    await getUsersSchema(db);

  const idCol =
    findColumn(schema, [
      "id",
      "user_id",
      "userid",
    ]);

  if (!idCol) {
    return null;
  }

  const row =
    await db
      .prepare(
        `SELECT * FROM users
         WHERE ${qi(idCol)} = ?
         LIMIT 1`
      )
      .bind(
        String(session.user_id)
      )
      .first();

  if (!row) {
    return null;
  }

  return normalizeUserRow(
    row,
    schema
  );
}


/* =========================================================
   TOURNAMENT
========================================================= */

async function handleTournament(
  env,
  request
) {
  await ensureAppTables(env.DB);

  let tournament =
    await env.DB
      .prepare(
        `SELECT *
         FROM app_tournaments
         ORDER BY id ASC
         LIMIT 1`
      )
      .first();

  if (!tournament) {
    await env.DB
      .prepare(
        `INSERT INTO app_tournaments
         (
           name,
           description,
           status,
           slots,
           entry_fee,
           scheduled_text,
           bank_name,
           bank_account,
           bank_owner,
           created_at
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        "Giải 2vs2 chủ nhật tới",
        "Giải đấu Tử Chiến Mùa 1 — thể thức 2vs2.",
        "OPEN",
        16,
        Number(
          env.ENTRY_FEE || 0
        ),
        "Giải 2vs2 chủ nhật tới",
        env.BANK_NAME || "",
        env.BANK_ACCOUNT || "",
        env.BANK_OWNER || "",
        new Date().toISOString()
      )
      .run();

    tournament =
      await env.DB
        .prepare(
          `SELECT *
           FROM app_tournaments
           ORDER BY id ASC
           LIMIT 1`
        )
        .first();
  }

  const count =
    await env.DB
      .prepare(
        `SELECT COUNT(*) AS c
         FROM app_teams
         WHERE tournament_id = ?`
      )
      .bind(tournament.id)
      .first();

  const registered =
    Number(count?.c || 0);

  const slots =
    Number(
      tournament.slots || 16
    );

  return json(
    {
      ok: true,

      tournament: {
        id:
          Number(tournament.id),

        name:
          tournament.name,

        description:
          tournament.description,

        status:
          registered < slots
            ? "OPEN"
            : "FULL",

        statusText:
          registered < slots
            ? "CÒN SLOT"
            : "ĐÃ ĐỦ SLOT",

        slots,

        registered,

        remaining:
          Math.max(
            0,
            slots - registered
          ),

        entryFee:
          Number(
            tournament.entry_fee ||
            0
          ),

        scheduledText:
          tournament.scheduled_text,

        bank: {
          name:
            tournament.bank_name ||
            env.BANK_NAME ||
            "",

          account:
            tournament.bank_account ||
            env.BANK_ACCOUNT ||
            "",

          owner:
            tournament.bank_owner ||
            env.BANK_OWNER ||
            "",
        },
      },
    },
    200,
    null,
    request
  );
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
      data.teamName || ""
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
      data.player2Email || ""
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

  await ensureAppTables(env.DB);

  const tournament =
    await env.DB
      .prepare(
        `SELECT *
         FROM app_tournaments
         ORDER BY id ASC
         LIMIT 1`
      )
      .first();

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
        `SELECT COUNT(*) AS c
         FROM app_teams
         WHERE tournament_id = ?`
      )
      .bind(tournament.id)
      .first();

  const registered =
    Number(count?.c || 0);

  const slots =
    Number(
      tournament.slots || 16
    );

  if (registered >= slots) {
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

  const duplicate =
    await env.DB
      .prepare(
        `SELECT id
         FROM app_teams
         WHERE tournament_id = ?
         AND (
           owner_user_id = ?
           OR lower(contact_email) = lower(?)
         )
         LIMIT 1`
      )
      .bind(
        tournament.id,
        String(user.userId),
        contactEmail
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

  let result;

  try {
    result =
      await env.DB
        .prepare(
          `INSERT INTO app_teams
           (
             tournament_id,
             owner_user_id,
             team_name,
             logo_url,
             contact_email,
             player2_email,
             payment_status,
             payment_reference,
             created_at
           )
           VALUES (?, ?, ?, ?, ?, ?, 'PENDING', '', ?)`
        )
        .bind(
          tournament.id,
          String(user.userId),
          teamName,
          logoUrl,
          contactEmail,
          player2Email,
          new Date().toISOString()
        )
        .run();
  } catch (error) {
    console.error(
      "TEAM REGISTER ERROR:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "Không thể đăng ký team: " +
          safeError(error),
      },
      500,
      null,
      request
    );
  }

  return json(
    {
      ok: true,
      message:
        "Đăng ký team thành công. Vui lòng hoàn tất thanh toán.",

      team: {
        id:
          result.meta?.last_row_id ||
          null,

        name:
          teamName,

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
  env,
  request
) {
  await ensureAppTables(env.DB);

  const rows =
    await env.DB
      .prepare(
        `SELECT
           id,
           team_name,
           logo_url,
           points,
           wins,
           losses
         FROM app_teams
         WHERE payment_status IN
           ('PAID', 'CONFIRMED')
         ORDER BY
           points DESC,
           wins DESC,
           id ASC
         LIMIT 100`
      )
      .all();

  return json(
    {
      ok: true,

      ranking:
        (rows.results || [])
          .map((row, index) => ({
            rank: index + 1,

            teamName:
              row.team_name,

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

            losses:
              Number(
                row.losses || 0
              ),
          })),
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
    !teamId ||
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
          "Dữ liệu webhook không hợp lệ.",
      },
      400,
      null,
      request
    );
  }

  await ensureAppTables(env.DB);

  await env.DB
    .prepare(
      `UPDATE app_teams
       SET
         payment_status = ?,
         payment_reference = ?
       WHERE id = ?`
    )
    .bind(
      status,
      reference,
      teamId
    )
    .run();

  return json(
    {
      ok: true,
    },
    200,
    null,
    request
  );
}


/* =========================================================
   DATABASE
========================================================= */

async function ensureAppTables(db) {
  /*
   * Các bảng app_* hoàn toàn riêng,
   * không phá schema users cũ.
   */
  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS app_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS app_tournaments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'OPEN',
        slots INTEGER NOT NULL DEFAULT 16,
        entry_fee INTEGER NOT NULL DEFAULT 0,
        scheduled_text TEXT NOT NULL DEFAULT '',
        bank_name TEXT NOT NULL DEFAULT '',
        bank_account TEXT NOT NULL DEFAULT '',
        bank_owner TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS app_teams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tournament_id INTEGER NOT NULL,
        owner_user_id TEXT NOT NULL,
        team_name TEXT NOT NULL,
        logo_url TEXT NOT NULL DEFAULT '',
        contact_email TEXT NOT NULL,
        player2_email TEXT NOT NULL DEFAULT '',
        payment_status TEXT NOT NULL DEFAULT 'PENDING',
        payment_reference TEXT NOT NULL DEFAULT '',
        points INTEGER NOT NULL DEFAULT 0,
        wins INTEGER NOT NULL DEFAULT 0,
        losses INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      )
    `),
  ]);

  /*
   * Quan trọng:
   *
   * Một số schema cũ có trigger:
   *
   * users -> audit_logs
   *
   * nhưng audit_logs có thể thiếu hoặc thiếu
   * column mà trigger cần.
   *
   * Không return sớm chỉ vì bảng đã tồn tại.
   * Luôn kiểm tra trigger + columns.
   */
  await ensureAuditLogs(db);
}


async function ensureAuditLogs(db) {
  const triggers =
    await db
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
         AND sql IS NOT NULL`
      )
      .all();

  const required =
    new Set([
      "user_id",
      "action",
      "details",
      "created_at",
    ]);

  for (
    const trigger
    of triggers.results || []
  ) {
    const sql =
      String(trigger.sql || "");

    if (
      !/audit_logs/i.test(sql)
    ) {
      continue;
    }

    /*
     * Lấy columns trong:
     *
     * INSERT INTO audit_logs (...)
     */
    const match =
      sql.match(
        /INSERT\s+INTO\s+(?:["'`])?audit_logs(?:["'`])?\s*\(([^)]+)\)/i
      );

    if (!match) {
      continue;
    }

    for (
      const part
      of match[1].split(",")
    ) {
      const name =
        part
          .trim()
          .replace(
            /^[`"']|[`"']$/g,
            ""
          );

      if (
        /^[A-Za-z_][A-Za-z0-9_]*$/.test(
          name
        )
      ) {
        required.add(name);
      }
    }
  }

  /*
   * Nếu chưa có audit_logs,
   * tạo bảng tương thích.
   */
  const exists =
    await db
      .prepare(
        `SELECT name
         FROM sqlite_master
         WHERE type = 'table'
         AND name = 'audit_logs'
         LIMIT 1`
      )
      .first();

  if (!exists) {
    const columns = [
      `"id" INTEGER PRIMARY KEY AUTOINCREMENT`,
      ...[...required]
        .filter(
          name => name !== "id"
        )
        .map(
          name =>
            `${qi(name)} TEXT`
        ),
    ];

    await db
      .prepare(
        `CREATE TABLE IF NOT EXISTS audit_logs
         (${columns.join(", ")})`
      )
      .run();

    return;
  }

  /*
   * Nếu bảng đã tồn tại,
   * kiểm tra columns hiện tại.
   */
  const info =
    await db
      .prepare(
        `PRAGMA table_info(audit_logs)`
      )
      .all();

  const existingColumns =
    new Set(
      (info.results || [])
        .map(
          row =>
            String(row.name)
              .toLowerCase()
        )
    );

  /*
   * Thiếu column nào thì ALTER TABLE ADD COLUMN.
   */
  for (
    const name
    of required
  ) {
    if (
      existingColumns.has(
        String(name).toLowerCase()
      )
    ) {
      continue;
    }

    /*
     * id không tự add.
     */
    if (name === "id") {
      continue;
    }

    try {
      await db
        .prepare(
          `ALTER TABLE audit_logs
           ADD COLUMN ${qi(name)} TEXT`
        )
        .run();
    } catch (error) {
      /*
       * Nếu race-condition khiến column vừa
       * được thêm bởi request khác thì bỏ qua.
       */
      console.error(
        "AUDIT COLUMN:",
        name,
        safeError(error)
      );
    }
  }
}


/* =========================================================
   SCHEMA
========================================================= */

async function getUsersSchema(db) {
  const result =
    await db
      .prepare(
        `PRAGMA table_info(users)`
      )
      .all();

  return result.results || [];
}


async function getTableSql(
  db,
  tableName
) {
  const row =
    await db
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'table'
         AND name = ?
         LIMIT 1`
      )
      .bind(tableName)
      .first();

  return String(
    row?.sql || ""
  );
}


function findColumn(
  schema,
  names
) {
  const map =
    new Map(
      schema.map(
        column => [
          String(
            column.name
          ).toLowerCase(),
          column.name,
        ]
      )
    );

  for (
    const name
    of names
  ) {
    const found =
      map.get(
        String(name)
          .toLowerCase()
      );

    if (found) {
      return found;
    }
  }

  return null;
}


function chooseAllowedRole(
  sql
) {
  if (!sql) {
    return "PLAYER";
  }

  const match =
    sql.match(
      /role\s+IN\s*\(([^)]+)\)/i
    );

  if (!match) {
    return "PLAYER";
  }

  const allowed =
    [
      ...match[1].matchAll(
        /['"]([^'"]+)['"]/g
      ),
    ].map(
      x => x[1]
    );

  if (!allowed.length) {
    return "PLAYER";
  }

  const preferred = [
    "PLAYER",
    "USER",
    "MEMBER",
    "player",
    "user",
    "member",
  ];

  for (
    const role
    of preferred
  ) {
    if (
      allowed.includes(role)
    ) {
      return role;
    }
  }

  /*
   * Nếu schema chỉ cho một role,
   * dùng role đầu tiên hợp lệ.
   */
  return allowed[0];
}


/* =========================================================
   CRYPTO
========================================================= */

async function sha256Hex(value) {
  const data =
    typeof value === "string"
      ? new TextEncoder()
          .encode(value)
      : value;

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return [
    ...new Uint8Array(digest),
  ]
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


function randomBytes(length) {
  const bytes =
    new Uint8Array(length);

  crypto.getRandomValues(bytes);

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
    new TextEncoder()
      .encode(a),
    new TextEncoder()
      .encode(b)
  );
}


function bytesToB64Url(
  bytes
) {
  let binary = "";

  for (
    const byte
    of bytes
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


/* =========================================================
   GENERAL HELPERS
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


function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(value);
}


function randomId() {
  return bytesToB64Url(
    randomBytes(16)
  );
}


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


function qi(identifier) {
  return `"${String(
    identifier
  ).replaceAll(
    '"',
    '""'
  )}"`;
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
   COOKIE / HTTP
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
    const part
    of raw.split(";")
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
  }

  headers[
    "access-control-allow-methods"
  ] = "GET,POST,OPTIONS";

  headers[
    "access-control-allow-headers"
  ] = "Content-Type";

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
    ]
    of Object.entries(
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
