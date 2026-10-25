export interface Env { AI: Ai; }
type ChatRequest = { message?: string; config?: string; vendor?: string };
const SYSTEM = "You are RouteForce Assistant, an expert BGP configuration reviewer. Answer in Turkish unless asked otherwise. Be concise, practical and safety-conscious. Explain Cisco IOS/XE, Huawei VRP and Juniper Junos differences precisely. Never claim a configuration is safe without noting missing prefix filters, max-prefix, route policy and session protection where relevant. Do not invent command output.";
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/chat") return new Response("Not found", { status: 404 });
    let body: ChatRequest;
    try { body = await request.json(); } catch { return Response.json({ error: "invalid_json" }, { status: 400 }); }
    const message = body.message?.trim().slice(0, 1600);
    if (!message) return Response.json({ error: "message_required" }, { status: 400 });
    const config = body.config?.trim().slice(0, 12000) || "(Config paylaşılmadı)";
    const prompt = "Hedef vendor: " + (body.vendor || "Belirtilmedi") + "\n\nBGP config:\n" + config + "\n\nKullanıcı sorusu: " + message;
    try {
      const result = await env.AI.run("@cf/zai-org/glm-4.7-flash", { messages: [{ role: "system", content: SYSTEM }, { role: "user", content: prompt }], max_tokens: 500 }) as { response?: string };
      return Response.json({ answer: result.response || "Şu anda yanıt üretilemedi." });
    } catch (error) {
      console.error("RouteForce AI inference failed", error);
      return Response.json({ error: "ai_unavailable" }, { status: 503 });
    }
  }
};
