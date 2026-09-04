const SESSION_DAYS = 7;
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================================================
    // CORS / RESPONSE HELPERS
    // =========================================================

    const json = (data, status = 200, extraHeaders = {}) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store",
          ...extraHeaders
        }
      });
    };

    const ok = (data = {}) => json({
      success: true,
      ...data
    });

    const fail = (message, status = 400, extra = {}) => json({
      success: false,
      error: message,
      ...extra
    }, status);

    const setCookie = (token) => {
      return [
        `session=${token}`,
        "Path=/",
        `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`,
        "HttpOnly",
        "Secure",
        "SameSite=Lax"
      ].join("; ");
    };

    const clearCookie = () => {
      return [
        "session=",
        "Path=/",
        "Max-Age=0",
        "HttpOnly",
        "Secure",
        "SameSite=Lax"
      ].join("; ");
    };

    const getCookie = (request, name) => {
      const cookie = request.headers.get("Cookie") || "";

      const parts = cookie.split(";");

      for (const part of parts) {
        const [key, ...rest] = part.trim().split("=");

        if (key === name) {
          return rest.join("=");
        }
      }

      return null;
    };

    const readBody = async (request) => {
      try {
        return await request.json();
      } catch {
        return null;
      }
    };

    // =========================================================
    // PASSWORD - WEB CRYPTO
    //
    // DB chỉ dùng:
    // users.password_hash
    //
    // Không dùng password_salt.
    //
    // Format:
    // sha256$HEX_HASH
    // =========================================================

    const bytesToHex = (bytes) => {
      return [...new Uint8Array(bytes)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    };

    const sha256 = async (text) => {
      const data = new TextEncoder().encode(text);

      const hash = await crypto.subtle.digest(
        "SHA-256",
        data
      );

      return bytesToHex(hash);
    };

    const hashPassword = async (password) => {
      const hash = await sha256(password);

      return `sha256$${hash}`;
    };

    const verifyPassword = async (password, storedHash) => {
      if (!storedHash || typeof storedHash !== "string") {
        return false;
      }

      // Hash mới của hệ thống này
      if (storedHash.startsWith("sha256$")) {
        const expected = await hashPassword(password);

        return timingSafeEqual(
          expected,
          storedHash
        );
      }

      // Hỗ trợ trường hợp password_hash hiện tại
      // chỉ lưu SHA-256 hex, để tránh khóa tài khoản
      // nếu trước đây hệ thống đã lưu kiểu này.
      if (/^[a-f0-9]{64}$/i.test(storedHash)) {
        const expected = await sha256(password);

        return timingSafeEqual(
          expected,
          storedHash
        );
      }

      return false;
    };

    const timingSafeEqual = (a, b) => {
      if (
        typeof a !== "string" ||
        typeof b !== "string" ||
        a.length !== b.length
      ) {
        return false;
      }

      let result = 0;

      for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
      }

      return result === 0;
    };

    // =========================================================
    // SESSION
    // =========================================================

    const generateToken = () => {
      const bytes = new Uint8Array(32);

      crypto.getRandomValues(bytes);

      return bytesToHex(bytes);
    };

    const getCurrentUser = async () => {
      const token = getCookie(request, "session");

      if (!token) {
        return null;
      }

      try {
        const session = await env.DB
          .prepare(`
            SELECT
              s.token,
              s.user_id,
              s.expires_at,
              u.id,
              u.email,
              u.role,
              u.created_at
            FROM sessions s
            INNER JOIN users u
              ON u.id = s.user_id
            WHERE s.token = ?
              AND s.expires_at > ?
            LIMIT 1
          `)
          .bind(token, Date.now())
          .first();

        if (!session) {
          return null;
        }

        return {
          id: session.id,
          email: session.email,
          role: session.role,
          created_at: session.created_at
        };
      } catch {
        return null;
      }
    };

    const createSession = async (userId) => {
      const token = generateToken();
      const expiresAt = Date.now() + SESSION_MS;

      await env.DB
        .prepare(`
          INSERT INTO sessions
            (token, user_id, expires_at)
          VALUES (?, ?, ?)
        `)
        .bind(
          token,
          userId,
          expiresAt
        )
        .run();

      return token;
    };

    const deleteCurrentSession = async () => {
      const token = getCookie(request, "session");

      if (!token) {
        return;
      }

      try {
        await env.DB
          .prepare(`
            DELETE FROM sessions
            WHERE token = ?
          `)
          .bind(token)
          .run();
      } catch {
        // Cookie vẫn sẽ được clear phía client.
      }
    };

    // =========================================================
    // HEALTH
    // =========================================================

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
          database: result?.ok === 1
            ? "connected"
            : "error",
          site: env.SITE_NAME || "CUSTOM 151"
        });
      } catch (error) {
        return fail(
          `D1 lỗi: ${error.message}`,
          500
        );
      }
    }

    // =========================================================
    // AUTH: REGISTER
    // =========================================================

    if (
      url.pathname === "/api/auth/register" &&
      request.method === "POST"
    ) {
      const body = await readBody(request);

      if (!body) {
        return fail("Dữ liệu gửi lên không hợp lệ.");
      }

      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const password = String(body.password || "");

      if (!email) {
        return fail("Vui lòng nhập email.");
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return fail("Email không hợp lệ.");
      }

      if (password.length < 8) {
        return fail(
          "Mật khẩu phải có ít nhất 8 ký tự."
        );
      }

      try {
        // Kiểm tra email tồn tại
        const existing = await env.DB
          .prepare(`
            SELECT id
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(email)
          .first();

        if (existing) {
          return fail(
            "Email này đã được đăng ký."
          );
        }

        const passwordHash =
          await hashPassword(password);

        // ROLE USER đúng với DB hiện tại
        const result = await env.DB
          .prepare(`
            INSERT INTO users
              (email, password_hash, role)
            VALUES (?, ?, ?)
          `)
          .bind(
            email,
            passwordHash,
            "USER"
          )
          .run();

        if (!result.success) {
          return fail(
            "Không thể tạo tài khoản.",
            500
          );
        }

        const userId =
          result.meta?.last_row_id;

        // Ghi audit nếu có thể
        try {
          await env.DB
            .prepare(`
              INSERT INTO audit_logs
                (user_id, action, target, details)
              VALUES (?, ?, ?, ?)
            `)
            .bind(
              userId || null,
              "REGISTER",
              "users",
              JSON.stringify({ email })
            )
            .run();
        } catch {
          // Audit không được làm hỏng đăng ký.
        }

        return ok({
          message: "Tạo tài khoản thành công!",
          user: {
            id: userId,
            email,
            role: "USER"
          }
        });

      } catch (error) {
        // D1 UNIQUE vẫn có thể bắt lỗi race-condition
        if (
          String(error.message || "")
            .toLowerCase()
            .includes("unique")
        ) {
          return fail(
            "Email này đã được đăng ký."
          );
        }

        return fail(
          `Không thể tạo tài khoản: ${error.message}`,
          500
        );
      }
    }

    // =========================================================
    // AUTH: LOGIN
    // =========================================================

    if (
      url.pathname === "/api/auth/login" &&
      request.method === "POST"
    ) {
      const body = await readBody(request);

      if (!body) {
        return fail("Dữ liệu đăng nhập không hợp lệ.");
      }

      const email = String(body.email || "")
        .trim()
        .toLowerCase();

      const password = String(body.password || "");

      if (!email || !password) {
        return fail(
          "Vui lòng nhập đầy đủ email và mật khẩu."
        );
      }

      try {
        const user = await env.DB
          .prepare(`
            SELECT
              id,
              email,
              password_hash,
              role,
              created_at
            FROM users
            WHERE email = ?
            LIMIT 1
          `)
          .bind(email)
          .first();

        if (!user) {
          return fail(
            "Email hoặc mật khẩu không chính xác.",
            401
          );
        }

        const valid =
          await verifyPassword(
            password,
            user.password_hash
          );

        if (!valid) {
          return fail(
            "Email hoặc mật khẩu không chính xác.",
            401
          );
        }

        // Xóa session cũ của user
        try {
          await env.DB
            .prepare(`
              DELETE FROM sessions
              WHERE user_id = ?
            `)
            .bind(user.id)
            .run();
        } catch {
          // Không chặn login nếu cleanup lỗi.
        }

        const token =
          await createSession(user.id);

        // Audit
        try {
          await env.DB
            .prepare(`
              INSERT INTO audit_logs
                (user_id, action, target, details)
              VALUES (?, ?, ?, ?)
            `)
            .bind(
              user.id,
              "LOGIN",
              "users",
              JSON.stringify({
                email: user.email
              })
            )
            .run();
        } catch {
          // Không chặn login.
        }

        return ok(
          {
            message: "Đăng nhập thành công!",
            user: {
              id: user.id,
              email: user.email,
              role: user.role,
              created_at: user.created_at
            }
          },
          200,
          {
            "Set-Cookie": setCookie(token)
          }
        );

      } catch (error) {
        return fail(
          `Đăng nhập thất bại: ${error.message}`,
          500
        );
      }
    }

    // =========================================================
    // AUTH: ME
    // =========================================================

    if (
      url.pathname === "/api/auth/me" &&
      request.method === "GET"
    ) {
      const user = await getCurrentUser();

      if (!user) {
        return ok({
          authenticated: false,
          user: null
        });
      }

      return ok({
        authenticated: true,
        user
      });
    }

    // =========================================================
    // AUTH: LOGOUT
    // =========================================================

    if (
      url.pathname === "/api/auth/logout" &&
      request.method === "POST"
    ) {
      await deleteCurrentSession();

      return ok(
        {
          message: "Đã đăng xuất."
        },
        200,
        {
          "Set-Cookie": clearCookie()
        }
      );
    }

    // =========================================================
    // TOURNAMENTS
    // =========================================================

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
            ORDER BY id DESC
          `)
          .all();

        return ok({
          tournaments: result.results || []
        });

      } catch (error) {
        return fail(
          `Không thể tải giải đấu: ${error.message}`,
          500
        );
      }
    }

    // =========================================================
    // D1 TABLES
    // =========================================================

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
          500
        );
      }
    }

    // =========================================================
    // D1 TABLE DATA
    // =========================================================

    if (
      url.pathname === "/api/table" &&
      request.method === "GET"
    ) {
      const table =
        url.searchParams.get("name");

      if (!table) {
        return fail(
          "Thiếu tên bảng."
        );
      }

      if (!/^[A-Za-z0-9_]+$/.test(table)) {
        return fail(
          "Tên bảng không hợp lệ."
        );
      }

      try {
        const result = await env.DB
          .prepare(`
            SELECT *
            FROM "${table}"
            LIMIT 100
          `)
          .all();

        return ok({
          table,
          rows: result.results || []
        });

      } catch (error) {
        return fail(
          error.message,
          500
        );
      }
    }

    // =========================================================
    // CLEAN EXPIRED SESSIONS
    // =========================================================

    if (
      url.pathname === "/api/cleanup-sessions" &&
      request.method === "POST"
    ) {
      const user = await getCurrentUser();

      if (!user) {
        return fail(
          "Bạn chưa đăng nhập.",
          401
        );
      }

      if (user.role !== "ADMIN") {
        return fail(
          "Bạn không có quyền.",
          403
        );
      }

      try {
        const result = await env.DB
          .prepare(`
            DELETE FROM sessions
            WHERE expires_at <= ?
          `)
          .bind(Date.now())
          .run();

        return ok({
          deleted: result.meta?.changes || 0
        });

      } catch (error) {
        return fail(
          error.message,
          500
        );
      }
    }

    // =========================================================
    // WEBSITE
    // =========================================================

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "CUSTOM 151",
      {
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  }
};
