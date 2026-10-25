type Env = { SESSION_SECRET: string; GITHUB_CLIENT_ID: string; GITHUB_CLIENT_SECRET: string; ROUTEFORCE_DB: D1Database };
type Context = { request: Request; env: Env };

function readCookie(request: Request, name: string) {
  return request.headers.get("Cookie")?.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="))?.slice(name.length + 1);
}
function toBase64URL(data: ArrayBuffer | string) {
  const text = typeof data === "string" ? data : String.fromCharCode(...new Uint8Array(data));
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
async function sign(value: string, secret: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toBase64URL(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

export async function onRequestGet(context: Context) {
  const url = new URL(context.request.url), state = url.searchParams.get("state"), code = url.searchParams.get("code");
  if (!code || !state || state !== readCookie(context.request, "rf_oauth_state")) return new Response("OAuth doğrulaması başarısız oldu.", { status: 400 });
  if (!context.env.SESSION_SECRET || !context.env.GITHUB_CLIENT_ID || !context.env.GITHUB_CLIENT_SECRET) return new Response("Eksik OAuth secret ayarı.", { status: 503 });

  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST", headers: { "Accept": "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: context.env.GITHUB_CLIENT_ID, client_secret: context.env.GITHUB_CLIENT_SECRET, code })
  });
  const token = (await tokenResponse.json() as { access_token?: string }).access_token;
  if (!token) return new Response("GitHub erişim tokenı alınamadı.", { status: 401 });
  const userResponse = await fetch("https://api.github.com/user", { headers: { "Authorization": "Bearer " + token, "User-Agent": "RouteForce" } });
  const user = await userResponse.json() as { login?: string; id?: number };
  if (!user.login || !user.id) return new Response("GitHub kullanıcı bilgisi alınamadı.", { status: 401 });

  await context.env.ROUTEFORCE_DB.prepare("INSERT INTO users (id,github_login) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET github_login=excluded.github_login").bind(String(user.id), user.login).run();
  const payload = toBase64URL(JSON.stringify({ sub: user.id, login: user.login, exp: Date.now() + 604800000 }));
  const signature = await sign(payload, context.env.SESSION_SECRET);
  const secure = new URL(context.request.url).protocol === "https:" ? " Secure;" : "";
  return new Response(null, { status: 302, headers: { "Location": new URL("/app.html", context.request.url).toString(), "Set-Cookie": "rf_session=" + payload + "." + signature + "; HttpOnly;" + secure + " SameSite=Lax; Path=/; Max-Age=604800" } });
}