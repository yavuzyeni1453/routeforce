type Env = { GOOGLE_CLIENT_ID: string };
type Context = { request: Request; env: Env };

export async function onRequestGet(context: Context) {
  if (!context.env.GOOGLE_CLIENT_ID) {
    return Response.json({ error: "google_oauth_not_configured" }, { status: 503 });
  }
  const state = crypto.randomUUID();
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", context.env.GOOGLE_CLIENT_ID);
  url.searchParams.set("redirect_uri", new URL("/api/auth/callback", context.request.url).toString());
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "select_account");
  return new Response(null, {
    status: 302,
    headers: {
      Location: url.toString(),
      "Set-Cookie": "rf_oauth_state=" + state + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600"
    }
  });
}