type Env = { SESSION_SECRET: string; ROUTEFORCE_DB: D1Database };
type Context = { request: Request; env: Env };

function readCookie(request: Request, name: string) {
  return request.headers.get("Cookie")?.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="))?.slice(name.length + 1);
}
function fromBase64URL(value: string) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function toBase64URL(data: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
async function sign(value: string, secret: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toBase64URL(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

export async function onRequestGet(context: Context) {
  const token = readCookie(context.request, "rf_session");
  if (!token || !context.env.SESSION_SECRET) return Response.json({ authenticated: false }, { status: 401 });
  const [payload, signature] = token.split(".");
  if (!payload || !signature || signature !== await sign(payload, context.env.SESSION_SECRET)) {
    return Response.json({ authenticated: false }, { status: 401 });
  }
  try {
    const session = JSON.parse(new TextDecoder().decode(fromBase64URL(payload))) as { sub: number; login: string; exp: number };
    if (!session.sub || !session.login || session.exp < Date.now()) throw new Error("expired");
    return Response.json({ authenticated: true, user: { id: String(session.sub), login: session.login } });
  } catch {
    return Response.json({ authenticated: false }, { status: 401 });
  }
}