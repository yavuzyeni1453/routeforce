type Env = { AI_ASSISTANT: Fetcher };
type Context = { request: Request; env: Env };

export async function onRequestPost(context: Context) {
  if (!context.env.AI_ASSISTANT) return Response.json({ error: "assistant_not_configured" }, { status: 503 });
  let body: { message?: string; config?: string; vendor?: string };
  try { body = await context.request.json(); } catch { return Response.json({ error: "invalid_json" }, { status: 400 }); }
  if (!body.message?.trim()) return Response.json({ error: "message_required" }, { status: 400 });
  return context.env.AI_ASSISTANT.fetch("https://routeforce-ai/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: body.message, config: body.config, vendor: body.vendor })
  });
}