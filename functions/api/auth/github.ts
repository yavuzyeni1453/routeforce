export async function onRequestGet(context: { env: Record<string, string> }) {
  const clientID = context.env.GITHUB_CLIENT_ID;
  if (!clientID) return new Response("GitHub OAuth is not configured.", { status: 503 });
  const state = crypto.randomUUID();
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientID);
  url.searchParams.set("redirect_uri", new URL("/api/auth/callback", context.request.url).toString());
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  return Response.redirect(url.toString(), 302, {
    headers: { "Set-Cookie": "rf_oauth_state=" + state + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600" }
  });
}