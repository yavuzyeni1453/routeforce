type Tool = "bgp" | "whois" | "dns";
const privateV4 = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
function validTarget(value: string) {
  return value.length > 0 && value.length < 254 && /^[a-zA-Z0-9.:/_-]+$/.test(value) && !privateV4.test(value);
}
function text(value: unknown) { return JSON.stringify(value, null, 2); }

export async function onRequestGet(context: { request: Request }) {
  const url = new URL(context.request.url);
  const tool = url.searchParams.get("tool") as Tool;
  const target = (url.searchParams.get("target") || "").trim();
  if (!["bgp", "whois", "dns"].includes(tool) || !validTarget(target)) {
    return Response.json({ error: "invalid_target" }, { status: 400 });
  }
  try {
    if (tool === "dns") {
      const answer = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(target) + "&type=A", { headers: { Accept: "application/dns-json" } });
      const data = await answer.json() as { Answer?: Array<{ name?: string; type?: number; TTL?: number; data?: string }>; Status?: number };
      return Response.json({ tool, target, summary: data.Answer?.length ? data.Answer.length + " DNS kaydı bulundu" : "A kaydı bulunamadı", output: text(data.Answer || []) });
    }
    if (tool === "whois") {
      const kind = /^\d{1,3}(?:\.\d{1,3}){3}$|:/.test(target) ? "ip" : "domain";
      const response = await fetch("https://rdap.org/" + kind + "/" + encodeURIComponent(target), { headers: { Accept: "application/rdap+json" } });
      if (!response.ok) return Response.json({ error: "lookup_not_found" }, { status: 404 });
      const data = await response.json() as { handle?: string; name?: string; country?: string; startAddress?: string; endAddress?: string; ldHName?: string };
      return Response.json({ tool, target, summary: [data.name || data.handle || data.ldHName, data.country].filter(Boolean).join(" · ") || "RDAP kaydı bulundu", output: text(data) });
    }
    const resource = target.toUpperCase().startsWith("AS") ? target.toUpperCase() : target;
    const endpoint = target.toUpperCase().startsWith("AS") ? "as-overview" : "prefix-overview";
    const response = await fetch("https://stat.ripe.net/data/" + endpoint + "/data.json?resource=" + encodeURIComponent(resource));
    if (!response.ok) return Response.json({ error: "bgp_lookup_failed" }, { status: 502 });
    const body = await response.json() as { data?: unknown };
    return Response.json({ tool, target, summary: "RIPEstat BGP görünürlüğü", output: text(body.data || body) });
  } catch {
    return Response.json({ error: "upstream_unavailable" }, { status: 502 });
  }
}