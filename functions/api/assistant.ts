type Env = { GEMINI_API_KEY: string; ROUTEFORCE_DB: D1Database };
type Context = { request: Request; env: Env };
type AssistantBody = { message?: string; config?: string; vendor?: string };

async function hash(value: string) { const bytes=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)); return [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,"0")).join(""); }
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function allowed(request: Request, db: D1Database) { const id=await hash(request.headers.get("CF-Connecting-IP") || "unknown"); const row=await db.prepare("SELECT COUNT(*) AS count FROM assistant_requests WHERE ip_hash=? AND created_at >= datetime('now','-1 minute')").bind(id).first<{count:number}>(); if ((row?.count || 0) >= 12) return false; await db.prepare("INSERT INTO assistant_requests(ip_hash) VALUES(?)").bind(id).run(); return true; }

const SYSTEM = "Sen RouteForce Assistant'sın: BGP config incelemesi konusunda uzmansın. Türkçe, profesyonel ve kısa yanıt ver. Cisco IOS/XE, Huawei VRP ve Juniper Junos farklarını doğru açıkla. Gerekliyse prefix filter, max-prefix, route-policy ve session security eksiklerini belirt. Emin olmadığın güvenlik iddiasında bulunma. En fazla 6 kısa madde kullan.";

export async function onRequestPost(context: Context) {
  if (!context.env.GEMINI_API_KEY) return Response.json({ error: "assistant_not_configured" }, { status: 503 });
  if (!await allowed(context.request, context.env.ROUTEFORCE_DB)) return Response.json({ error: "rate_limited" }, { status: 429 });
  let body: AssistantBody;
  try { body = await context.request.json(); } catch { return Response.json({ error: "invalid_json" }, { status: 400 }); }
  const message = body.message?.trim().slice(0, 1600);
  if (!message) return Response.json({ error: "message_required" }, { status: 400 });
  const config = body.config?.trim().slice(0, 12000) || "(Config paylaşılmadı)";
  const prompt = "Hedef vendor: " + (body.vendor || "Belirtilmedi") + "\n\nBGP config:\n" + config + "\n\nKullanıcı sorusu: " + message;
  try {
    const baseRequest = {
          systemInstruction: { parts: [{ text: SYSTEM }] },
          contents: [{ role: "user", parts: [{ text: prompt }] }]
        };
        let upstream: Response | undefined;
        // Prefer the stronger model; retain a tested low-latency fallback during capacity spikes.
        for (const model of ["gemini-3.8-flash", "gemini-3.5-flash-lite"]) {
          const generationConfig: Record<string, unknown> = { temperature: 0.2, maxOutputTokens: 900, responseMimeType: "application/json" };
          if (model === "gemini-3.8-flash") generationConfig.thinkingConfig = { thinkingLevel: "low" };
          try {
            upstream = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent", {
              method: "POST",
              headers: { "Content-Type": "application/json", "x-goog-api-key": context.env.GEMINI_API_KEY },
              body: JSON.stringify({ ...baseRequest, generationConfig }),
              signal: AbortSignal.timeout(12000)
            });
          } catch {
            continue;
          }
          if (upstream.ok || (upstream.status !== 429 && upstream.status !== 503)) break;
          await delay(400);
        }
        if (!upstream?.ok) return Response.json({ error: "gemini_unavailable" }, { status: 502 });
    const result = await upstream.json() as { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }> };
    const raw = result.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("").trim();
    if (!raw) return Response.json({ error: "empty_ai_response" }, { status: 502 });
    let parsed: { answer?: unknown; config_patch?: unknown; description?: unknown; steps?: unknown } = {};
        try { parsed = JSON.parse(raw); } catch { parsed.answer = raw; }
        const linesOf = (value: unknown, depth = 0): string[] => {
          if (depth > 4 || value == null) return [];
          if (typeof value === "string") {
            const trimmed = value.trim();
            if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
              try { return linesOf(JSON.parse(trimmed), depth + 1); } catch { return [trimmed]; }
            }
            return trimmed.split("\n").map(line => line.trim()).filter(Boolean);
          }
          if (Array.isArray(value)) return value.flatMap(item => linesOf(item, depth + 1));
          if (typeof value === "object") {
            const record = value as { answer?: unknown; description?: unknown; steps?: unknown };
            const nested = [...linesOf(record.answer, depth + 1), ...linesOf(record.description, depth + 1), ...linesOf(record.steps, depth + 1)];
            return nested.length ? nested : [];
          }
          return [String(value)];
        };
        if (Array.isArray(parsed)) parsed = { answer: parsed };
        if (typeof parsed.answer === "string" && parsed.answer.trim().startsWith("{")) {
          try {
            const nested = JSON.parse(parsed.answer);
            parsed.description = nested.description || parsed.description;
            parsed.steps = nested.steps || parsed.steps;
            parsed.answer = nested.answer || nested.description || parsed.answer;
          } catch { /* keep the original answer */ }
        }
        const directPatch = Array.isArray(parsed.config_patch) ? parsed.config_patch : [];
        const stepPatch = Array.isArray(parsed.steps) ? parsed.steps.flatMap(step => {
          if (typeof step !== "string") return [];
          const snippets = [...step.matchAll(/`([^`\\n]+)`/g)].map(m => m[1]);
          return snippets.length ? snippets : [];
        }) : [];
        const answer = linesOf(parsed.answer || parsed.description || parsed.steps || raw).join("\n").slice(0, 5000);
        const configPatch = [...directPatch, ...stepPatch].filter(x => typeof x === "string").map(x => String(x).trim()).filter(Boolean).slice(0, 100);
        return Response.json({ answer, configPatch });
  } catch {
    return Response.json({ error: "assistant_unavailable" }, { status: 502 });
  }
}