type Env = { GEMINI_API_KEY: string };
type Context = { request: Request; env: Env };
type AssistantBody = { message?: string; config?: string; vendor?: string };

const SYSTEM = "Sen RouteForce Assistant'sın: BGP config incelemesi konusunda uzmansın. Türkçe, profesyonel ve kısa yanıt ver. Cisco IOS/XE, Huawei VRP ve Juniper Junos farklarını doğru açıkla. Gerekliyse prefix filter, max-prefix, route-policy ve session security eksiklerini belirt. Emin olmadığın güvenlik iddiasında bulunma. En fazla 6 kısa madde kullan.";

export async function onRequestPost(context: Context) {
  if (!context.env.GEMINI_API_KEY) return Response.json({ error: "assistant_not_configured" }, { status: 503 });
  let body: AssistantBody;
  try { body = await context.request.json(); } catch { return Response.json({ error: "invalid_json" }, { status: 400 }); }
  const message = body.message?.trim().slice(0, 1600);
  if (!message) return Response.json({ error: "message_required" }, { status: 400 });
  const config = body.config?.trim().slice(0, 12000) || "(Config paylaşılmadı)";
  const prompt = "Hedef vendor: " + (body.vendor || "Belirtilmedi") + "\n\nBGP config:\n" + config + "\n\nKullanıcı sorusu: " + message;
  try {
    const upstream = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": context.env.GEMINI_API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM }] },
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.25, maxOutputTokens: 700 }
      })
    });
    if (!upstream.ok) return Response.json({ error: "gemini_unavailable" }, { status: 502 });
    const result = await upstream.json() as { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }> };
    const answer = result.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("").trim();
    if (!answer) return Response.json({ error: "empty_ai_response" }, { status: 502 });
    return Response.json({ answer });
  } catch {
    return Response.json({ error: "assistant_unavailable" }, { status: 502 });
  }
}