import { LookupError, bgpLookup, dnsLookup, probeLookup, whoisLookup } from "../../lib/lookup";

type Tool = "bgp" | "whois" | "dns" | "ping" | "trace" | "mtr";
const privateV4 = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;

function validTarget(value: string) {
  return value.length > 0 && value.length < 254 && /^[a-zA-Z0-9.:/_-]+$/.test(value) && !privateV4.test(value);
}

function json(body: unknown, status = 200) {
  return Response.json(body, { status });
}

export async function onRequestGet(context: { request: Request }) {
  const url = new URL(context.request.url);
  const tool = url.searchParams.get("tool") as Tool;
  const target = (url.searchParams.get("target") || "").trim();
  if (!["bgp", "whois", "dns", "ping", "trace", "mtr"].includes(tool) || !validTarget(target)) {
    return json({ error: "invalid_target", message: "Hedef boş, özel bir ağ veya desteklenmeyen bir değer." }, 400);
  }
  try {
    if (tool === "ping" || tool === "trace" || tool === "mtr") {
      const kind = tool === "trace" ? "traceroute" : tool;
      const result = await probeLookup(kind, target);
      return json({ tool, target, summary: result.summary, output: result.output, brief: result.brief });
    }
    if (tool === "dns") {
      const result = await dnsLookup(target);
      return json({ tool, target, summary: result.summary, output: result.output, brief: result.brief });
    }
    if (tool === "whois") {
      const result = await whoisLookup(target);
      return json({ tool, target, summary: result.summary, output: result.output, brief: result.brief });
    }
    const result = await bgpLookup(target);
    return json({ tool, target, summary: result.summary, output: result.output, brief: result.brief });
  } catch (error) {
    if (error instanceof LookupError) return json({ error: error.code, message: error.message }, error.status);
    return json({ error: "upstream_unavailable", message: "Sağlayıcı şu anda RouteForce üzerinden yanıt vermiyor." }, 502);
  }
}
