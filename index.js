/**
 * GIẢI ĐẤU TỬ CHIẾN – MÙA 1
 * Cloudflare Worker + D1 + Web Crypto
 *
 * Dùng đúng các bảng:
 * users / teams / team_members / tournaments / slots
 * registrations / payments / matches / results / sessions / audit_logs
 *
 * KHÔNG dùng app_sessions / app_teams / app_tournaments.
 */

const PBKDF2_ITERATIONS = 100000;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE = "vtc_session";

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });

const text = (data, status = 200, headers = {}) =>
  new Response(data, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...headers,
    },
  });

function base64url(bytes) {
  let binary = "";
  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(value) {
  const padded = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(String(value).length / 4) * 4, "=");

  const binary = atob(padded);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return base64url(data);
}

function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array)) {
    a = new TextEncoder().encode(String(a));
  }

  if (!(b instanceof Uint8Array)) {
    b = new TextEncoder().encode(String(b));
  }

  if (a.length !== b.length) return false;

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    key,
    256
  );

  return new Uint8Array(bits);
}

async function createPasswordHash(password) {
  const salt = new Uint8Array(16);

  crypto.getRandomValues(salt);

  const hash = await hashPassword(password, salt);

  return {
    salt: base64url(salt),
    hash: base64url(hash),
  };
}

async function verifyPassword(password, salt, storedHash) {
  try {
    const saltBytes = fromBase64url(salt);
    const calculated = await hashPassword(password, saltBytes);
    const stored = fromBase64url(storedHash);

    return timingSafeEqual(calculated, stored);
  } catch {
    return false;
  }
}

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key) {
      cookies[key] = decodeURIComponent(value);
    }
  }

  return cookies;
}

function sessionCookie(
  token,
  maxAgeSeconds = SESSION_TTL_MS / 1000
) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${Math.floor(maxAgeSeconds)}`,
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw new Error("Dữ liệu gửi lên không hợp lệ.");
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

function publicUser(row) {
  return {
    id: row.id,
    email: row.email,
    role: row.role || "PLAYER",
    balance: Number(row.balance || 0),
    createdAt: row.created_at,
  };
}

async function getUserBySession(request, env) {
  const token = parseCookies(request)[SESSION_COOKIE];

  if (!token) return null;

  const now = Date.now();

  const session = await env.DB.prepare(`
    SELECT
      s.token,
      s.user_id,
      s.expires_at,
      u.id,
      u.email,
      u.role,
      COALESCE(u.balance, 0) AS balance,
      u.created_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ?
      AND s.expires_at > ?
    LIMIT 1
  `)
    .bind(token, now)
    .first();

  if (!session) return null;

  return {
    token,
    user: publicUser(session),
  };
}

async function createSession(env, userId) {
  const token = randomToken(32);
  const expiresAt = Date.now() + SESSION_TTL_MS;

  await env.DB.prepare(`
    INSERT INTO sessions
      (token, user_id, expires_at)
    VALUES (?, ?, ?)
  `)
    .bind(token, userId, expiresAt)
    .run();

  return {
    token,
    expiresAt,
  };
}

async function audit(
  env,
  userId,
  action,
  target = null,
  details = null
) {
  try {
    await env.DB.prepare(`
      INSERT INTO audit_logs
        (user_id, action, target, details)
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        userId ?? null,
        action,
        target,
        details == null ? null : JSON.stringify(details)
      )
      .run();
  } catch {
    // Audit lỗi không làm hỏng thao tác chính.
  }
}

async function getOpenTournament(env) {
  return await env.DB.prepare(`
    SELECT
      t.id,
      t.name,
      t.fee,
      t.max_teams,
      t.status,
      t.description,
      t.created_at,

      COUNT(
        DISTINCT CASE
          WHEN r.status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
          )
          THEN r.id
        END
      ) AS registered

    FROM tournaments t

    LEFT JOIN registrations r
      ON r.tournament_id = t.id

    WHERE t.status = 'OPEN'

    GROUP BY t.id

    ORDER BY t.id ASC

    LIMIT 1
  `).first();
}

function bankConfig(env) {
  return {
    name: env.BANK_NAME || "MB BANK",
    account: env.BANK_ACCOUNT || "068686862",
    owner: env.BANK_OWNER || "Dang Gia Khanh",
  };
}

async function health(env) {
  try {
    const row = await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return json({
      ok: row?.ok === 1,
      service: "vua-tu-chien-mua1",
      database: true,
    });
  } catch (error) {
    return json(
      {
        ok: false,
        database: false,
        error: error?.message || "D1 error",
      },
      500
    );
  }
}

async function register(request, env) {
  const body = await readJson(request);

  const email = cleanEmail(body.email);
  const password = String(body.password || "");

  const confirmPassword = String(
    body.confirmPassword ??
    body.passwordConfirm ??
    ""
  );

  /*
   * FORM ĐĂNG KÝ CHỈ:
   * email
   * password
   * confirmPassword
   *
   * KHÔNG yêu cầu username.
   */

  if (!validEmail(email)) {
    return json(
      {
        ok: false,
        error: "Email không hợp lệ.",
      },
      400
    );
  }

  if (password.length < 6) {
    return json(
      {
        ok: false,
        error: "Mật khẩu phải có ít nhất 6 ký tự.",
      },
      400
    );
  }

  if (password !== confirmPassword) {
    return json(
      {
        ok: false,
        error: "Mật khẩu nhập lại không khớp.",
      },
      400
    );
  }

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
    return json(
      {
        ok: false,
        error: "Email này đã được đăng ký.",
      },
      409
    );
  }

  const {
    salt,
    hash,
  } = await createPasswordHash(password);

  let userId;

  try {
    const result = await env.DB
      .prepare(`
        INSERT INTO users
          (
            email,
            password_hash,
            password_salt,
            role,
            balance
          )
        VALUES
          (?, ?, ?, 'PLAYER', 0)
      `)
      .bind(
        email,
        hash,
        salt
      )
      .run();

    userId = result.meta?.last_row_id;
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          `Không thể tạo tài khoản: ` +
          `${error?.message || "D1 error"}`,
      },
      500
    );
  }

  const session = await createSession(
    env,
    userId
  );

  const user = await env.DB
    .prepare(`
      SELECT
        id,
        email,
        role,
        COALESCE(balance, 0) AS balance,
        created_at
      FROM users
      WHERE id = ?
    `)
    .bind(userId)
    .first();

  await audit(
    env,
    userId,
    "REGISTER",
    `user:${userId}`
  );

  return json(
    {
      ok: true,
      message: "Tạo tài khoản thành công.",
      user: publicUser(user),
    },
    201,
    {
      "set-cookie": sessionCookie(
        session.token
      ),
    }
  );
}

async function login(request, env) {
  const body = await readJson(request);

  const email = cleanEmail(body.email);
  const password = String(
    body.password || ""
  );

  if (!validEmail(email) || !password) {
    return json(
      {
        ok: false,
        error:
          "Vui lòng nhập đúng email và mật khẩu.",
      },
      400
    );
  }

  const user = await env.DB
    .prepare(`
      SELECT
        id,
        email,
        password_hash,
        password_salt,
        role,
        COALESCE(balance, 0) AS balance,
        created_at
      FROM users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
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

  const valid = await verifyPassword(
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

  const session = await createSession(
    env,
    user.id
  );

  await audit(
    env,
    user.id,
    "LOGIN",
    `user:${user.id}`
  );

  return json(
    {
      ok: true,
      message: "Đăng nhập thành công.",
      user: publicUser(user),
    },
    200,
    {
      "set-cookie": sessionCookie(
        session.token
      ),
    }
  );
}

async function logout(request, env) {
  const token =
    parseCookies(request)[SESSION_COOKIE];

  if (token) {
    try {
      const session = await env.DB
        .prepare(`
          SELECT user_id
          FROM sessions
          WHERE token = ?
          LIMIT 1
        `)
        .bind(token)
        .first();

      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token = ?
        `)
        .bind(token)
        .run();

      if (session?.user_id) {
        await audit(
          env,
          session.user_id,
          "LOGOUT",
          `user:${session.user_id}`
        );
      }
    } catch {
      // Vẫn xoá cookie.
    }
  }

  return json(
    {
      ok: true,
      message: "Đã đăng xuất.",
    },
    200,
    {
      "set-cookie": clearSessionCookie(),
    }
  );
}

async function me(request, env) {
  const session =
    await getUserBySession(
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
    user: session.user,
  });
}

async function tournament(request, env) {
  const t =
    await getOpenTournament(env);

  if (!t) {
    return json({
      ok: true,
      tournament: {
        id: null,
        name: "Chưa có giải đấu",
        description:
          "Hiện chưa có giải đấu đang mở.",
        registered: 0,
        slots: 0,
        remaining: 0,
        entryFee: 0,
        status: "CLOSED",
        statusText: "CHƯA MỞ",
        bank: bankConfig(env),
      },
    });
  }

  const registered =
    Number(t.registered || 0);

  const slots =
    Number(t.max_teams || 0);

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
        Number(t.fee || 0),

      status,

      statusText:
        status === "OPEN"
          ? "CÒN SLOT"
          : "HẾT SLOT",

      bank:
        bankConfig(env),
    },
  });
}

async function teamRegister(
  request,
  env
) {
  const session =
    await getUserBySession(
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
    await readJson(request);

  const teamName =
    String(
      body.teamName || ""
    ).trim();

  const logoUrl =
    String(
      body.logoUrl || ""
    ).trim();

  const contactEmail =
    cleanEmail(
      body.contactEmail ||
      session.user.email
    );

  const player2Email =
    cleanEmail(
      body.player2Email || ""
    );

  if (teamName.length < 2) {
    return json(
      {
        ok: false,
        error:
          "Tên team phải có ít nhất 2 ký tự.",
      },
      400
    );
  }

  if (teamName.length > 60) {
    return json(
      {
        ok: false,
        error:
          "Tên team tối đa 60 ký tự.",
      },
      400
    );
  }

  if (!validEmail(contactEmail)) {
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
    !validEmail(player2Email)
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
    await getOpenTournament(env);

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

  const registered =
    Number(t.registered || 0);

  const maxTeams =
    Number(t.max_teams || 0);

  if (registered >= maxTeams) {
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
          "Tài khoản này đã có team đăng ký giải này.",
      },
      409
    );
  }

  const orderCode =
    "VTC" +
    new Date()
      .toISOString()
      .replace(/\D/g, "")
      .slice(2, 14) +
    randomToken(5)
      .toUpperCase();

  const amount =
    Number(t.fee || 0);

  try {
    const teamResult =
      await env.DB
        .prepare(`
          INSERT INTO teams
            (
              owner_id,
              name,
              tag,
              logo_url,
              status,
              contact_email,
              player2_email
            )
          VALUES
            (
              ?,
              ?,
              NULL,
              ?,
              'PENDING',
              ?,
              ?
            )
        `)
        .bind(
          session.user.id,
          teamName,
          logoUrl || null,
          contactEmail,
          player2Email || null
        )
        .run();

    const teamId =
      teamResult.meta?.last_row_id;

    /*
     * Schema gốc yêu cầu game_name + uid.
     * Form hiện tại không yêu cầu UID nên dùng
     * dữ liệu liên hệ tạm thời.
     */

    await env.DB
      .prepare(`
        INSERT INTO team_members
          (
            team_id,
            game_name,
            uid,
            role
          )
        VALUES
          (?, ?, ?, 'PLAYER')
      `)
      .bind(
        teamId,
        teamName,
        `CONTACT:${session.user.id}`
      )
      .run();

    if (player2Email) {
      await env.DB
        .prepare(`
          INSERT INTO team_members
            (
              team_id,
              game_name,
              uid,
              role
            )
          VALUES
            (?, ?, ?, 'PLAYER')
        `)
        .bind(
          teamId,
          player2Email,
          `EMAIL:${player2Email}`
        )
        .run();
    }

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
          VALUES
            (
              ?,
              ?,
              NULL,
              ?,
              ?,
              'AWAITING_PAYMENT'
            )
        `)
        .bind(
          teamId,
          t.id,
          orderCode,
          amount
        )
        .run();

    const registrationId =
      registrationResult.meta?.last_row_id;

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
        VALUES
          (
            ?,
            'BANK',
            NULL,
            ?,
            'PENDING',
            ?
          )
      `)
      .bind(
        registrationId,
        amount,
        JSON.stringify({
          type: "BANK_QR",
          orderCode,
          createdBy:
            session.user.id,
        })
      )
      .run();

    await audit(
      env,
      session.user.id,
      "TEAM_REGISTER",
      `registration:${registrationId}`,
      {
        teamId,
        tournamentId: t.id,
        orderCode,
        amount,
      }
    );

    return json(
      {
        ok: true,

        message:
          amount > 0
            ? `Đăng ký thành công. Mã thanh toán: ${orderCode}. Vui lòng thanh toán đúng số tiền.`
            : `Đăng ký team thành công. Mã đăng ký: ${orderCode}.`,

        registration: {
          id: registrationId,
          teamId,
          tournamentId: t.id,
          orderCode,
          amount,
          status:
            "AWAITING_PAYMENT",
        },

        bank:
          bankConfig(env),
      },
      201
    );
  } catch (error) {
    return json(
      {
        ok: false,
        error:
          `Không thể đăng ký team: ` +
          `${error?.message || "D1 error"}`,
      },
      500
    );
  }
}

async function ranking(request, env) {
  const t =
    await getOpenTournament(env);

  if (!t) {
    return json({
      ok: true,
      ranking: [],
    });
  }

  const rows =
    await env.DB
      .prepare(`
        SELECT
          tm.id AS team_id,
          tm.name AS team_name,
          tm.logo_url,

          COALESCE(
            SUM(r.points),
            0
          ) AS points

        FROM teams tm

        JOIN registrations reg
          ON reg.team_id = tm.id

        LEFT JOIN results r
          ON r.team_id = tm.id

        WHERE
          reg.tournament_id = ?
          AND reg.status IN (
            'PAID',
            'CONFIRMED',
            'APPROVED'
          )

        GROUP BY tm.id

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
        })),
  });
}

/*
 * WEBHOOK THANH TOÁN
 *
 * QR VietQR chỉ tạo QR.
 * Muốn tự nhận biết tiền 24/7 phải có
 * provider/webhook thật.
 */

async function paymentWebhook(
  request,
  env
) {
  const configuredSecret =
    env.PAYMENT_WEBHOOK_SECRET;

  if (!configuredSecret) {
    return json(
      {
        ok: false,
        error:
          "PAYMENT_WEBHOOK_SECRET chưa được cấu hình.",
      },
      503
    );
  }

  const body =
    await readJson(request);

  if (
    !body.secret ||
    !timingSafeEqual(
      new TextEncoder().encode(
        String(body.secret)
      ),
      new TextEncoder().encode(
        String(configuredSecret)
      )
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
      body.orderCode ||
      body.order_code ||
      body.content ||
      ""
    ).trim();

  const amount =
    Number(
      body.amount ||
      body.transferAmount ||
      body.transfer_amount ||
      0
    );

  const externalId =
    String(
      body.externalId ||
      body.external_id ||
      body.transactionId ||
      body.transaction_id ||
      ""
    ).trim();

  if (!orderCode || !amount) {
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
      .bind(orderCode)
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

  if (
    amount <
    Number(
      registration.amount || 0
    )
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

  if (
    registration.status ===
      "PAID" ||
    registration.status ===
      "CONFIRMED" ||
    registration.status ===
      "APPROVED"
  ) {
    return json({
      ok: true,
      message:
        "Giao dịch này đã được xử lý.",
    });
  }

  const payment =
    await env.DB
      .prepare(`
        SELECT id
        FROM payments
        WHERE registration_id = ?
          AND external_id = ?
        LIMIT 1
      `)
      .bind(
        registration.id,
        externalId || orderCode
      )
      .first();

  if (payment) {
    return json({
      ok: true,
      message:
        "Giao dịch đã tồn tại.",
    });
  }

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
      externalId || orderCode,
      amount,
      JSON.stringify(
        body.raw ?? body
      )
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE registrations
      SET status = 'PAID'
      WHERE id = ?
    `)
    .bind(
      registration.id
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE teams
      SET status = 'APPROVED'
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
    status: "PAID",
  });
}

async function cleanupExpiredSessions(
  env
) {
  try {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE expires_at <= ?
      `)
      .bind(Date.now())
      .run();
  } catch {
    // Không ảnh hưởng request chính.
  }
}

async function route(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname;

  const method =
    request.method.toUpperCase();

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    return health(env);
  }

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    return register(
      request,
      env
    );
  }

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    return login(
      request,
      env
    );
  }

  if (
    path === "/api/auth/logout" &&
    method === "POST"
  ) {
    return logout(
      request,
      env
    );
  }

  if (
    path === "/api/auth/me" &&
    method === "GET"
  ) {
    return me(
      request,
      env
    );
  }

  if (
    path === "/api/tournament" &&
    method === "GET"
  ) {
    return tournament(
      request,
      env
    );
  }

  if (
    path === "/api/team/register" &&
    method === "POST"
  ) {
    return teamRegister(
      request,
      env
    );
  }

  if (
    path === "/api/ranking" &&
    method === "GET"
  ) {
    return ranking(
      request,
      env
    );
  }

  if (
    path === "/api/payment/webhook" &&
    method === "POST"
  ) {
    return paymentWebhook(
      request,
      env
    );
  }

  if (path.startsWith("/api/")) {
    return json(
      {
        ok: false,
        error:
          "API không tồn tại.",
      },
      404
    );
  }

  if (env.ASSETS) {
    return env.ASSETS.fetch(
      request
    );
  }

  return text(
    "GIẢI ĐẤU TỬ CHIẾN – MÙA 1"
  );
}

export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    ctx.waitUntil(
      cleanupExpiredSessions(
        env
      )
    );

    return route(
      request,
      env
    );
  },
};
