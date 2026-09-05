const ITERATIONS = 100000;
const SESSION_TTL = 60 * 60 * 24 * 30;
const COOKIE_NAME = "vtc_session";

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

      return new Response("ASSETS chưa được cấu hình.", { status: 500 });
    } catch (error) {
      console.error(error);

      if (url.pathname.startsWith("/api/")) {
        return json({
          ok: false,
          error: cleanError(error),
        }, 500);
      }

      return new Response("Internal Server Error", { status: 500 });
    }
  },
};

async function api(request, env, url) {
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: cors(request),
    });
  }

  if (url.pathname === "/api/health" && method === "GET") {
    return json({
      ok: true,
      site: env.SITE_NAME || "GIẢI ĐẤU TỬ CHIẾN – MÙA 1",
    });
  }

  if (url.pathname === "/api/auth/register" && method === "POST") {
    return register(request, env);
  }

  if (url.pathname === "/api/auth/login" && method === "POST") {
    return login(request, env);
  }

  if (url.pathname === "/api/auth/logout" && method === "POST") {
    return logout(request, env);
  }

  if (url.pathname === "/api/auth/me" && method === "GET") {
    return me(request, env);
  }

  if (url.pathname === "/api/tournament" && method === "GET") {
    return tournament(env);
  }

  if (url.pathname === "/api/team/register" && method === "POST") {
    return registerTeam(request, env);
  }

  if (url.pathname === "/api/team/my" && method === "GET") {
    return myTeam(request, env);
  }

  if (url.pathname === "/api/ranking" && method === "GET") {
    return ranking(env);
  }

  if (url.pathname === "/api/payment/webhook" && method === "POST") {
    return paymentWebhook(request, env);
  }

  return json({
    ok: false,
    error: "API không tồn tại.",
  }, 404);
}

/* =========================================================
   AUTH
========================================================= */

async function register(request, env) {
  const data = await body(request);

  const email = normalizeEmail(data.email);
  const password = String(data.password || "");
  const confirm = String(
    data.confirmPassword ??
    data.passwordConfirm ??
    data.confirm ??
    ""
  );

  if (!validEmail(email)) {
    return json({
      ok: false,
      error: "Email không hợp lệ.",
    }, 400);
  }

  if (password.length < 6) {
    return json({
      ok: false,
      error: "Mật khẩu phải có ít nhất 6 ký tự.",
    }, 400);
  }

  if (password !== confirm) {
    return json({
      ok: false,
      error: "Mật khẩu nhập lại không khớp.",
    }, 400);
  }

  await setupTables(env.DB);

  const schema = await userSchema(env.DB);

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
    return json({
      ok: false,
      error: "Database users thiếu cột email hoặc password.",
    }, 500);
  }

  const old = await env.DB.prepare(
    `SELECT * FROM users
     WHERE lower(${quote(emailCol)}) = lower(?)
     LIMIT 1`
  ).bind(email).first();

  if (old) {
    return json({
      ok: false,
      error: "Email này đã được đăng ký.",
    }, 409);
  }

  const salt = randomBytes(16);
  const hash = await hashPassword(password, salt);

  const values = {};

  values[emailCol] = email;

  /*
   * Nếu DB cũ có password_salt:
   * passwordCol = hash
   * saltCol = salt
   *
   * Nếu không có password_salt:
   * passwordCol = pbkdf2$iterations$salt$hash
   */
  if (saltCol) {
    values[passwordCol] = base64(hash);
    values[saltCol] = base64(salt);
  } else {
    values[passwordCol] =
      `pbkdf2$${ITERATIONS}$${base64(salt)}$${base64(hash)}`;
  }

  /*
   * Nếu ID là NOT NULL nhưng không có default,
   * tự sinh ID.
   */
  if (idCol) {
    const info = schema.find(x => x.name === idCol);

    if (
      info &&
      Number(info.notnull) === 1 &&
      info.dflt_value == null &&
      Number(info.pk) === 0
    ) {
      values[idCol] = randomId();
    }
  }

  /*
   * Role phải hợp CHECK constraint của DB hiện tại.
   */
  if (roleCol) {
    const tableSql = await tableSQL(env.DB, "users");
    values[roleCol] = allowedRole(tableSql);
  }

  if (balanceCol) {
    values[balanceCol] = 0;
  }

  if (createdCol) {
    values[createdCol] = new Date().toISOString();
  }

  /*
   * UI không có tên tài khoản.
   *
   * Nhưng nếu schema DB cũ bắt buộc username/account_name,
   * backend tự tạo nội bộ từ email.
   */
  for (const column of schema) {
    if (
      Number(column.notnull) !== 1 ||
      column.dflt_value != null ||
      Number(column.pk) === 1
    ) {
      continue;
    }

    if (values[column.name] !== undefined) {
      continue;
    }

    const n = column.name.toLowerCase();

    if (
      n === "username" ||
      n === "user_name" ||
      n === "account_name" ||
      n === "accountname"
    ) {
      values[column.name] =
        email.split("@")[0].slice(0, 40);
    }

    if (n === "display_name") {
      values[column.name] =
        email.split("@")[0].slice(0, 40);
    }
  }

  const missing = schema.filter(column => {
    return (
      Number(column.notnull) === 1 &&
      column.dflt_value == null &&
      Number(column.pk) === 0 &&
      values[column.name] === undefined
    );
  });

  if (missing.length) {
    return json({
      ok: false,
      error:
        "Database users còn cột bắt buộc chưa được hệ thống nhận diện: " +
        missing.map(x => x.name).join(", "),
    }, 500);
  }

  const columns = Object.keys(values);

  const sql = `
    INSERT INTO users
    (${columns.map(quote).join(", ")})
    VALUES
    (${columns.map(() => "?").join(", ")})
  `;

  try {
    await env.DB.prepare(sql)
      .bind(...columns.map(x => values[x]))
      .run();
  } catch (error) {
    console.error("REGISTER:", error);

    return json({
      ok: false,
      error: "Không thể tạo tài khoản: " + cleanError(error),
    }, 500);
  }

  const user = await findUser(env.DB, email);

  if (!user) {
    return json({
      ok: false,
      error: "Tài khoản vừa tạo nhưng không đọc lại được từ database.",
    }, 500);
  }

  const session = await createSession(
    env.DB,
    user.userId,
    user.email
  );

  return json({
    ok: true,
    message: "Tạo tài khoản thành công.",
    user: publicUser(user),
  }, 200, session.cookie);
}

async function login(request, env) {
  const data = await body(request);

  const email = normalizeEmail(data.email);
  const password = String(data.password || "");

  if (!validEmail(email) || !password) {
    return json({
      ok: false,
      error: "Vui lòng nhập đúng email và mật khẩu.",
    }, 400);
  }

  await setupTables(env.DB);

  const user = await findUser(env.DB, email);

  if (!user) {
    return json({
      ok: false,
      error: "Email hoặc mật khẩu không đúng.",
    }, 401);
  }

  const valid = await verifyPassword(user, password);

  if (!valid) {
    return json({
      ok: false,
      error: "Email hoặc mật khẩu không đúng.",
    }, 401);
  }

  const session = await createSession(
    env.DB,
    user.userId,
    user.email
  );

  return json({
    ok: true,
    message: "Đăng nhập thành công.",
    user: publicUser(user),
  }, 200, session.cookie);
}

async function logout(request, env) {
  const token = cookie(request, COOKIE_NAME);

  if (token) {
    const tokenHash = await sha256(token);

    await env.DB.prepare(
      `DELETE FROM app_sessions
       WHERE token_hash = ?`
    ).bind(tokenHash).run().catch(() => {});
  }

  return json({
    ok: true,
    message: "Đã đăng xuất.",
  }, 200, deleteCookie());
}

async function me(request, env) {
  await setupTables(env.DB);

  const user = await currentUser(request, env.DB);

  if (!user) {
    return json({
      ok: true,
      authenticated: false,
      user: null,
    });
  }

  return json({
    ok: true,
    authenticated: true,
    user: publicUser(user),
  });
}

/* =========================================================
   USER
========================================================= */

async function findUser(db, email) {
  const schema = await userSchema(db);

  const emailCol = findColumn(schema, [
    "email",
    "mail",
  ]);

  if (!emailCol) {
    return null;
  }

  const row = await db.prepare(
    `SELECT * FROM users
     WHERE lower(${quote(emailCol)}) = lower(?)
     LIMIT 1`
  ).bind(email).first();

  if (!row) return null;

  return normalizeUser(row, schema);
}

function normalizeUser(row, schema) {
  const emailCol = findColumn(schema, [
    "email",
    "mail",
  ]);

  const idCol = findColumn(schema, [
    "id",
    "user_id",
    "userid",
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

  const email = String(row[emailCol] || "");

  return {
    raw: row,

    userId:
      idCol && row[idCol] != null
        ? String(row[idCol])
        : email,

    email,

    passwordStored:
      passwordCol
        ? String(row[passwordCol] || "")
        : "",

    passwordSalt:
      saltCol
        ? String(row[saltCol] || "")
        : "",

    role:
      roleCol
        ? String(row[roleCol] || "PLAYER")
        : "PLAYER",

    balance:
      balanceCol
        ? Number(row[balanceCol] || 0)
        : 0,
  };
}

async function verifyPassword(user, password) {
  /*
   * DB có password_salt riêng.
   */
  if (
    user.passwordSalt &&
    user.passwordStored
  ) {
    const salt = fromBase64(user.passwordSalt);
    const expected = fromBase64(user.passwordStored);

    if (salt.length && expected.length) {
      const actual =
        await hashPassword(password, salt);

      return equalBytes(actual, expected);
    }
  }

  /*
   * DB không có password_salt.
   */
  if (user.passwordStored.startsWith("pbkdf2$")) {
    const parts =
      user.passwordStored.split("$");

    if (parts.length === 4) {
      const iterations = Number(parts[1]);
      const salt = fromBase64(parts[2]);
      const expected = fromBase64(parts[3]);

      if (
        iterations > 0 &&
        iterations <= ITERATIONS &&
        salt.length &&
        expected.length
      ) {
        const actual =
          await hashPassword(
            password,
            salt,
            iterations
          );

        return equalBytes(actual, expected);
      }
    }
  }

  return false;
}

function publicUser(user) {
  return {
    id: user.userId,
    email: user.email,
    role: user.role || "PLAYER",
    balance:
      Number.isFinite(user.balance)
        ? user.balance
        : 0,
  };
}

/* =========================================================
   SESSION
========================================================= */

async function createSession(db, userId, email) {
  const token =
    base64(randomBytes(32));

  const tokenHash =
    await sha256(token);

  const created =
    new Date();

  const expires =
    new Date(
      created.getTime() +
      SESSION_TTL * 1000
    );

  await db.prepare(`
    INSERT INTO app_sessions
    (user_id, email, token_hash, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    String(userId),
    String(email),
    tokenHash,
    expires.toISOString(),
    created.toISOString()
  ).run();

  return {
    cookie:
      `${COOKIE_NAME}=${encodeURIComponent(token)}; ` +
      `Max-Age=${SESSION_TTL}; ` +
      `Path=/; ` +
      `HttpOnly; Secure; SameSite=Lax`,
  };
}

async function currentUser(request, db) {
  const token =
    cookie(request, COOKIE_NAME);

  if (!token) return null;

  const tokenHash =
    await sha256(token);

  const session =
    await db.prepare(`
      SELECT user_id, email, expires_at
      FROM app_sessions
      WHERE token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

  if (!session) return null;

  const expires =
    Date.parse(String(session.expires_at || ""));

  if (
    !Number.isFinite(expires) ||
    expires <= Date.now()
  ) {
    await db.prepare(
      `DELETE FROM app_sessions
       WHERE token_hash = ?`
    ).bind(tokenHash).run().catch(() => {});

    return null;
  }

  return findUser(
    db,
    String(session.email)
  );
}

/* =========================================================
   TOURNAMENT
========================================================= */

async function tournament(env) {
  await setupTables(env.DB);

  let row =
    await env.DB.prepare(`
      SELECT *
      FROM app_tournaments
      ORDER BY id ASC
      LIMIT 1
    `).first();

  if (!row) {
    await env.DB.prepare(`
      INSERT INTO app_tournaments
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
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      "Giải 2vs2 chủ nhật tới",
      "Giải đấu Tử Chiến Mùa 1 – thể thức 2vs2.",
      "OPEN",
      16,
      Number(env.ENTRY_FEE || 0),
      "Giải 2vs2 chủ nhật tới",
      env.BANK_NAME || "",
      env.BANK_ACCOUNT || "",
      env.BANK_OWNER || "",
      new Date().toISOString()
    ).run();

    row =
      await env.DB.prepare(`
        SELECT *
        FROM app_tournaments
        ORDER BY id ASC
        LIMIT 1
      `).first();
  }

  const count =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM app_teams
      WHERE tournament_id = ?
    `).bind(row.id).first();

  const registered =
    Number(count?.total || 0);

  const slots =
    Number(row.slots || 16);

  const remaining =
    Math.max(0, slots - registered);

  return json({
    ok: true,

    tournament: {
      id: Number(row.id),
      name: row.name,
      description: row.description,
      scheduledText: row.scheduled_text,

      slots,

      registered,

      remaining,

      status:
        remaining > 0
          ? "OPEN"
          : "FULL",

      statusText:
        remaining > 0
          ? "CÒN SLOT"
          : "ĐÃ ĐỦ SLOT",

      entryFee:
        Number(row.entry_fee || 0),

      bank: {
        name:
          row.bank_name ||
          env.BANK_NAME ||
          "",

        account:
          row.bank_account ||
          env.BANK_ACCOUNT ||
          "",

        owner:
          row.bank_owner ||
          env.BANK_OWNER ||
          "",
      },
    },
  });
}

/* =========================================================
   TEAM
========================================================= */

async function registerTeam(request, env) {
  await setupTables(env.DB);

  const user =
    await currentUser(request, env.DB);

  if (!user) {
    return json({
      ok: false,
      error: "Bạn cần đăng nhập trước.",
    }, 401);
  }

  const data =
    await body(request);

  const teamName =
    String(data.teamName || "").trim();

  const logoUrl =
    String(data.logoUrl || "").trim();

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
    return json({
      ok: false,
      error: "Tên team phải từ 2–60 ký tự.",
    }, 400);
  }

  if (!validEmail(contactEmail)) {
    return json({
      ok: false,
      error: "Email liên hệ không hợp lệ.",
    }, 400);
  }

  if (
    player2Email &&
    !validEmail(player2Email)
  ) {
    return json({
      ok: false,
      error: "Email thành viên 2 không hợp lệ.",
    }, 400);
  }

  const t =
    await env.DB.prepare(`
      SELECT *
      FROM app_tournaments
      ORDER BY id ASC
      LIMIT 1
    `).first();

  if (!t) {
    return json({
      ok: false,
      error: "Chưa có giải đấu.",
    }, 500);
  }

  const count =
    await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM app_teams
      WHERE tournament_id = ?
    `).bind(t.id).first();

  if (
    Number(count?.total || 0) >=
    Number(t.slots || 16)
  ) {
    return json({
      ok: false,
      error: "Giải đã đủ slot.",
    }, 409);
  }

  const duplicate =
    await env.DB.prepare(`
      SELECT id
      FROM app_teams
      WHERE tournament_id = ?
      AND (
        owner_user_id = ?
        OR lower(contact_email) = lower(?)
      )
      LIMIT 1
    `).bind(
      t.id,
      String(user.userId),
      contactEmail
    ).first();

  if (duplicate) {
    return json({
      ok: false,
      error:
        "Bạn đã đăng ký team cho giải này rồi.",
    }, 409);
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO app_teams
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
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      t.id,
      String(user.userId),
      teamName,
      logoUrl,
      contactEmail,
      player2Email,
      "PENDING",
      "",
      new Date().toISOString()
    ).run();

  return json({
    ok: true,

    message:
      "Đăng ký team thành công. Vui lòng hoàn tất thanh toán.",

    team: {
      id:
        result.meta?.last_row_id ||
        null,

      name: teamName,

      paymentStatus:
        "PENDING",
    },
  });
}

async function myTeam(request, env) {
  await setupTables(env.DB);

  const user =
    await currentUser(request, env.DB);

  if (!user) {
    return json({
      ok: true,
      team: null,
    });
  }

  const row =
    await env.DB.prepare(`
      SELECT *
      FROM app_teams
      WHERE owner_user_id = ?
      ORDER BY id DESC
      LIMIT 1
    `).bind(
      String(user.userId)
    ).first();

  if (!row) {
    return json({
      ok: true,
      team: null,
    });
  }

  return json({
    ok: true,

    team: {
      id: Number(row.id),
      name: row.team_name,
      logoUrl: row.logo_url || "",
      contactEmail: row.contact_email,
      player2Email: row.player2_email || "",
      paymentStatus: row.payment_status,
      paymentReference:
        row.payment_reference || "",
    },
  });
}

/* =========================================================
   RANKING
========================================================= */

async function ranking(env) {
  await setupTables(env.DB);

  const result =
    await env.DB.prepare(`
      SELECT
        team_name,
        logo_url,
        points,
        wins,
        losses
      FROM app_teams
      WHERE payment_status IN ('PAID', 'CONFIRMED')
      ORDER BY
        points DESC,
        wins DESC,
        id ASC
      LIMIT 100
    `).all();

  return json({
    ok: true,

    ranking:
      (result.results || [])
        .map((row, index) => ({
          rank: index + 1,

          teamName:
            row.team_name,

          logoUrl:
            row.logo_url || "",

          points:
            Number(row.points || 0),

          wins:
            Number(row.wins || 0),

          losses:
            Number(row.losses || 0),
        })),
  });
}

/* =========================================================
   PAYMENT WEBHOOK
========================================================= */

async function paymentWebhook(request, env) {
  const secret =
    String(env.PAYMENT_WEBHOOK_SECRET || "");

  if (!secret) {
    return json({
      ok: false,
      error:
        "Chưa cấu hình PAYMENT_WEBHOOK_SECRET.",
    }, 503);
  }

  const supplied =
    request.headers.get(
      "x-webhook-secret"
    ) || "";

  if (
    !safeStringEqual(
      supplied,
      secret
    )
  ) {
    return json({
      ok: false,
      error: "Webhook không hợp lệ.",
    }, 401);
  }

  const data =
    await body(request);

  const teamId =
    Number(data.teamId || 0);

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
      "PENDING",
      "PAID",
      "CONFIRMED",
      "FAILED",
    ].includes(status)
  ) {
    return json({
      ok: false,
      error: "Dữ liệu thanh toán không hợp lệ.",
    }, 400);
  }

  await setupTables(env.DB);

  await env.DB.prepare(`
    UPDATE app_teams
    SET
      payment_status = ?,
      payment_reference = ?
    WHERE id = ?
  `).bind(
    status,
    reference,
    teamId
  ).run();

  return json({
    ok: true,
  });
}

/* =========================================================
   DATABASE
========================================================= */

async function setupTables(db) {
  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS app_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
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
   * Một số DB cũ có trigger:
   * INSERT INTO audit_logs (...)
   *
   * Nếu audit_logs bị mất, register sẽ fail.
   * Tự dựng bảng tương thích từ trigger.
   */
  await repairAuditLogs(db);
}

async function repairAuditLogs(db) {
  const exists =
    await db.prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table'
      AND name = 'audit_logs'
      LIMIT 1
    `).first();

  const triggers =
    await db.prepare(`
      SELECT sql
      FROM sqlite_master
      WHERE type = 'trigger'
      AND sql IS NOT NULL
    `).all();

  const needed = new Set([
    "id",
  ]);

  for (const trigger of (
    triggers.results || []
  )) {
    const sql =
      String(trigger.sql || "");

    if (!/audit_logs/i.test(sql)) {
      continue;
    }

    const match =
      sql.match(
        /INSERT\s+INTO\s+(?:["'`]?audit_logs["'`]?)\s*\(([^)]+)\)/i
      );

    if (match) {
      for (
        const item of match[1].split(",")
      ) {
        const name =
          item
            .trim()
            .replace(/^["'`]|["'`]$/g, "");

        if (
          /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)
        ) {
          needed.add(name);
        }
      }
    }
  }

  if (!exists) {
    const definitions =
      [...needed].map(name => {
        if (name === "id") {
          return `"id" INTEGER PRIMARY KEY AUTOINCREMENT`;
        }

        return `${quote(name)} TEXT`;
      });

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS audit_logs
      (${definitions.join(", ")})
    `).run();

    return;
  }

  const existing =
    await db.prepare(
      `PRAGMA table_info(audit_logs)`
    ).all();

  const existingNames =
    new Set(
      (existing.results || [])
        .map(x => String(x.name).toLowerCase())
    );

  for (const name of needed) {
    if (
      name === "id" ||
      existingNames.has(name.toLowerCase())
    ) {
      continue;
    }

    /*
     * SQLite ALTER TABLE ADD COLUMN.
     */
    await db.prepare(
      `ALTER TABLE audit_logs
       ADD COLUMN ${quote(name)} TEXT`
    ).run().catch(() => {});
  }
}

async function userSchema(db) {
  const result =
    await db.prepare(
      `PRAGMA table_info(users)`
    ).all();

  return result.results || [];
}

async function tableSQL(db, table) {
  const row =
    await db.prepare(`
      SELECT sql
      FROM sqlite_master
      WHERE type = 'table'
      AND name = ?
      LIMIT 1
    `).bind(table).first();

  return String(row?.sql || "");
}

function findColumn(schema, names) {
  const map =
    new Map(
      schema.map(
        x => [
          String(x.name).toLowerCase(),
          x.name,
        ]
      )
    );

  for (const name of names) {
    const result =
      map.get(
        String(name).toLowerCase()
      );

    if (result) {
      return result;
    }
  }

  return null;
}

function allowedRole(sql) {
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
    ].map(x => x[1]);

  if (!allowed.length) {
    return "PLAYER";
  }

  if (allowed.includes("PLAYER")) {
    return "PLAYER";
  }

  if (allowed.includes("USER")) {
    return "USER";
  }

  if (allowed.includes("MEMBER")) {
    return "MEMBER";
  }

  return allowed[0];
}

/* =========================================================
   CRYPTO
========================================================= */

async function hashPassword(
  password,
  salt,
  iterations = ITERATIONS
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

async function sha256(value) {
  const data =
    typeof value === "string"
      ? new TextEncoder().encode(value)
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
      x =>
        x
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

function equalBytes(a, b) {
  if (
    !(a instanceof Uint8Array) ||
    !(b instanceof Uint8Array)
  ) {
    return false;
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

function safeStringEqual(a, b) {
  return equalBytes(
    new TextEncoder().encode(a),
    new TextEncoder().encode(b)
  );
}

function base64(bytes) {
  let text = "";

  for (const byte of bytes) {
    text += String.fromCharCode(byte);
  }

  return btoa(text)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64(value) {
  try {
    const normalized =
      String(value)
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const padded =
      normalized +
      "=".repeat(
        (4 - normalized.length % 4) % 4
      );

    const raw =
      atob(padded);

    return Uint8Array.from(
      raw,
      x => x.charCodeAt(0)
    );
  } catch {
    return new Uint8Array();
  }
}

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function randomId() {
  return base64(
    randomBytes(16)
  );
}

async function body(request) {
  const text =
    await request.text();

  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(
      "Dữ liệu gửi lên không hợp lệ."
    );
  }
}

function quote(identifier) {
  return `"${String(identifier)
    .replaceAll('"', '""')}"`;
}

function cookie(request, name) {
  const raw =
    request.headers.get("Cookie") || "";

  for (
    const item of raw.split(";")
  ) {
    const index =
      item.indexOf("=");

    if (index < 0) {
      continue;
    }

    const key =
      item.slice(0, index).trim();

    if (key !== name) {
      continue;
    }

    const value =
      item.slice(index + 1).trim();

    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  return "";
}

function deleteCookie() {
  return (
    `${COOKIE_NAME}=; ` +
    `Max-Age=0; ` +
    `Path=/; ` +
    `HttpOnly; Secure; SameSite=Lax`
  );
}

function cors(request) {
  const origin =
    request.headers.get("Origin");

  const headers = {
    "access-control-allow-methods":
      "GET,POST,OPTIONS",

    "access-control-allow-headers":
      "Content-Type",

    "access-control-allow-credentials":
      "true",
  };

  if (origin) {
    headers[
      "access-control-allow-origin"
    ] = origin;
  }

  return headers;
}

function json(
  data,
  status = 200,
  setCookie = null,
  request = null
) {
  const headers =
    new Headers(JSON_HEADERS);

  if (setCookie) {
    headers.append(
      "Set-Cookie",
      setCookie
    );
  }

  const extra =
    cors(request);

  for (
    const [key, value]
    of Object.entries(extra)
  ) {
    headers.set(key, value);
  }

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers,
    }
  );
}

function cleanError(error) {
  const message =
    String(
      error?.message ||
      error ||
      "Lỗi không xác định."
    );

  return message.length > 600
    ? message.slice(0, 600)
    : message;
}
