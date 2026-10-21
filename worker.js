/** Cloudflare Worker API for the Nghĩalq TVpassword page.
 * Bind a KV namespace named PASSWORDS and set secret ADMIN_TOKEN.
 * Public read: GET /api/password?id=PUBLIC_ID
 * Authenticated write: POST /api/password {id, filename, password, expiresAt?}
 */
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, max-age=0",
};
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: cors });
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (url.pathname !== "/api/password") return json({ ok: false, error: "Not found" }, 404);

    if (request.method === "GET") {
      const id = (url.searchParams.get("id") || "").trim();
      if (!/^[A-Za-z0-9_-]{6,64}$/.test(id)) return json({ ok: false, error: "Mã nhận không hợp lệ." }, 400);
      const raw = await env.PASSWORDS.get(id);
      if (!raw) return json({ ok: false, error: "Không tìm thấy mã hoặc mã đã hết hạn." }, 404);
      let record;
      try { record = JSON.parse(raw); } catch { return json({ ok: false, error: "Dữ liệu mật khẩu bị lỗi." }, 500); }
      if (record.expiresAt && Date.now() >= Date.parse(record.expiresAt)) {
        await env.PASSWORDS.delete(id);
        return json({ ok: false, error: "Mã nhận mật khẩu đã hết hạn." }, 410);
      }
      return json({ ok: true, id, filename: record.filename, password: record.password, expiresAt: record.expiresAt || null });
    }

    if (request.method === "POST") {
      if (!env.ADMIN_TOKEN || request.headers.get("Authorization") !== `Bearer ${env.ADMIN_TOKEN}`)
        return json({ ok: false, error: "Unauthorized" }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ ok: false, error: "JSON không hợp lệ." }, 400); }
      const { id, filename, password, expiresAt } = body || {};
      if (typeof id !== "string" || !/^[A-Za-z0-9_-]{6,64}$/.test(id) ||
          typeof filename !== "string" || filename.length > 240 ||
          typeof password !== "string" || password.length < 8 || password.length > 256)
        return json({ ok: false, error: "Thiếu hoặc sai id, filename, password." }, 400);
      let ttl;
      if (expiresAt) {
        const t = Date.parse(expiresAt);
        if (!Number.isFinite(t) || t <= Date.now()) return json({ ok: false, error: "expiresAt phải là thời điểm trong tương lai." }, 400);
        ttl = Math.ceil((t - Date.now()) / 1000);
      }
      // Prevent overwriting an existing public code.
      if (await env.PASSWORDS.get(id)) return json({ ok: false, error: "Mã nhận đã tồn tại; hãy tạo mã mới." }, 409);
      const record = JSON.stringify({ filename, password, expiresAt: expiresAt || null, createdAt: new Date().toISOString() });
      await env.PASSWORDS.put(id, record, ttl ? { expirationTtl: ttl } : undefined);
      return json({ ok: true, id });
    }
    return json({ ok: false, error: "Method not allowed" }, 405);
  }
};
