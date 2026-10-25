export interface Env {
  AI: Ai;
}

type ChatRequest = {
  message?: string;
  config?: string;
  vendor?: string;
};

type AiResult = {
  [key: string]: unknown;
};

function extractText(value: unknown, depth = 0): string | undefined {
  if (depth > 6 || value == null) return undefined;
  if (typeof value === "string") return value.trim() || undefined;
  if (Array.isArray(value)) {
    for (const item of value) {
      const text = extractText(item, depth + 1);
      if (text) return text;
    }
    return undefined;
  }
  if (typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  for (const key of ["choices", "messages", "message", "content", "text", "generated_text", "output_text", "output", "result", "delta", "parts", "completion", "response"]) {
    const text = extractText(record[key], depth + 1);
    if (text) return text;
  }
  return undefined;
}

function compactAnswer(value: string) {
  const limit = 700;
  if (value.length <= limit) return value;
  const excerpt = value.slice(0, limit);
  const ending = Math.max(excerpt.lastIndexOf("."), excerpt.lastIndexOf("!"), excerpt.lastIndexOf("?"));
  return ending > 180 ? excerpt.slice(0, ending + 1) : excerpt.trimEnd() + "…";
}

const SYSTEM = `You are RouteForce Assistant, an expert BGP configuration reviewer. Answer in Turkish unless asked otherwise. Give the final answer directly in at most 100 Turkish words and use at most 4 concise bullets; do not reveal reasoning steps. Be practical and safety-conscious. Explain Cisco IOS/XE, Huawei VRP and Juniper Junos differences precisely. Never claim a configuration is safe without noting missing prefix filters, max-prefix, route policy and session protection where relevant. Do not invent command output.`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/chat") return new Response("Not found", { status: 404 });
    let body: ChatRequest;
    try { body = await request.json(); } catch { return Response.json({ error: "invalid_json" }, { status: 400 }); }
    const message = body.message?.trim().slice(0, 1600);
    if (!message) return Response.json({ error: "message_required" }, { status: 400 });
    const context = body.config?.trim().slice(0, 12000) || "(Config paylaşılmadı)";
    const prompt = `Hedef vendor: ${body.vendor || "Belirtilmedi"}\n\nBGP config:\n${context}\n\nKullanıcı sorusu: ${message}`;
    try {
      const result = await env.AI.run("@cf/zai-org/glm-4.7-flash", {
        messages: [{ role: "system", content: SYSTEM }, { role: "user", content: prompt }],
        max_completion_tokens: 1024
      }) as AiResult;
      const choices = result.choices as Array<{ message?: { content?: unknown } }> | undefined;
      const answer = extractText(choices?.[0]?.message?.content) || extractText(result);
      if (!answer) {
        console.error("RouteForce AI returned an empty response", JSON.stringify(result).slice(0, 800));
        return Response.json({ error: "empty_ai_response" }, { status: 502 });
      }
      return Response.json({ answer: compactAnswer(answer) });
    } catch (error) {
      console.error("RouteForce AI inference failed", error);
      return Response.json({ error: "ai_unavailable" }, { status: 503 });
    }
  }
};
