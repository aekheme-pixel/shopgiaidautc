export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // API: kiểm tra Worker + D1
    // =========================
    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS ok")
          .first();

        return Response.json({
          success: true,
          worker: "online",
          database: result?.ok === 1 ? "connected" : "error",
          site: env.SITE_NAME
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            worker: "online",
            database: "error",
            message: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // API: lấy danh sách bảng D1
    // =========================
    if (url.pathname === "/api/tables") {
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

        return Response.json({
          success: true,
          tables: result.results || []
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            message: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // API: lấy dữ liệu một bảng
    // =========================
    if (url.pathname === "/api/table") {
      const table = url.searchParams.get("name");

      if (!table) {
        return Response.json(
          {
            success: false,
            message: "Thiếu tên bảng"
          },
          { status: 400 }
        );
      }

      // Chỉ cho phép tên bảng an toàn
      if (!/^[A-Za-z0-9_]+$/.test(table)) {
        return Response.json(
          {
            success: false,
            message: "Tên bảng không hợp lệ"
          },
          { status: 400 }
        );
      }

      try {
        const result = await env.DB
          .prepare(`SELECT * FROM "${table}" LIMIT 100`)
          .all();

        return Response.json({
          success: true,
          table,
          rows: result.results || []
        });
      } catch (error) {
        return Response.json(
          {
            success: false,
            message: error.message
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // Website
    // =========================
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("GIẢI ĐẤU VUA TỬ CHIẾN – MÙA 1", {
      headers: {
        "content-type": "text/plain; charset=UTF-8"
      }
    });
  }
};
