type Env = { SESSION_SECRET: string; GOOGLE_CLIENT_ID: string; GOOGLE_CLIENT_SECRET: string; ROUTEFORCE_DB: D1Database };
type Context = { request: Request; env: Env };
type GoogleUser = { sub?: string; email?: string; name?: string; picture?: string };

function cookie(request: Request, name: string) {
  return request.headers.get("Cookie")?.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="))?.slice(name.length + 1);
}
function b64(data: ArrayBuffer | string) {
  const value = typeof data === "string" ? data : String.fromCharCode(...new Uint8Array(data));
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
async function sign(value: string, secret: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

export async function onRequestGet(context: Context) {
  const url = new URL(context.request.url);
  const code = url.searchParams.get("code"), state = url.searchParams.get("state");
  if (!code || !state || state !== cookie(context.request, "rf_oauth_state")) return new Response("Oturum doğrulaması başarısız oldu.", { status: 400 });
  const env = context.env;
  if (!env.SESSION_SECRET || !env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return new Response("Google giriş ayarı henüz tamamlanmadı.", { status: 503 });

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: new URL("/api/auth/callback", context.request.url).toString(), grant_type: "authorization_code" })
  });
  const token = (await tokenResponse.json() as { access_token?: string }).access_token;
  if (!token) return new Response("Google erişim izni alınamadı.", { status: 401 });
  const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: "Bearer " + token } });
  const profile = await profileResponse.json() as GoogleUser;
  if (!profile.sub || !profile.email) return new Response("Google profil bilgisi alınamadı.", { status: 401 });

  const id = "google:" + profile.sub, label = profile.name || profile.email;
  await env.ROUTEFORCE_DB.prepare("INSERT INTO users (id,github_login) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET github_login=excluded.github_login").bind(id, label).run();
  const payload = b64(JSON.stringify({ sub: id, login: label, exp: Date.now() + 604800000 }));
  const signature = await sign(payload, env.SESSION_SECRET);
  return new Response(null, { status: 302, headers: {
    Location: new URL("/app.html", context.request.url).toString(),
    "Set-Cookie": "rf_session=" + payload + "." + signature + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800"
  }});
}