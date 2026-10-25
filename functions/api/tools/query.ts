type Tool = "dns" | "whois" | "bgp" | "rpki" | "certificates" | "urlhaus";
const privateV4 = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const tools: Tool[] = ["dns", "whois", "bgp", "rpki", "certificates", "urlhaus"];
const pretty = (value: unknown) => JSON.stringify(value, null, 2);
function valid(value: string) {
  return value.length > 0 && value.length < 254 && /^[a-zA-Z0-9.:/_-]+$/.test(value) && !privateV4.test(value);
}
export async function onRequestGet(context: { request: Request }) {
  const url = new URL(context.request.url);
  const tool = url.searchParams.get("tool") as Tool;
  const target = (url.searchParams.get("target") || "").trim();
  if (!tools.includes(tool) || !valid(target)) return Response.json({ error: "invalid_target" }, { status: 400 });
  try {
    if (tool === "dns") {
      const records: Record<string, unknown> = {};
      for (const type of ["A", "AAAA", "MX", "NS", "TXT"]) {
        const r = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(target) + "&type=" + type, { headers: { Accept: "application/dns-json" } });
        const body = await r.json() as { Answer?: unknown[] };
        records[type] = body.Answer || [];
      }
      const count = Object.values(records).flat().length;
      return Response.json({ summary: count ? count + " DNS kaydı bulundu" : "Kayıt bulunamadı", output: pretty(records) });
    }
    if (tool === "whois") {
      const kind = /^\d{1,3}(?:\.\d{1,3}){3}$|:/.test(target) ? "ip" : "domain";
      const r = await fetch("https://rdap.org/" + kind + "/" + encodeURIComponent(target), { headers: { Accept: "application/rdap+json" } });
      if (!r.ok) return Response.json({ error: "lookup_not_found" }, { status: 404 });
      const body = await r.json() as { name?: string; handle?: string; ldHName?: string; country?: string };
      return Response.json({ summary: [body.name || body.handle || body.ldHName, body.country].filter(Boolean).join(" · ") || "RDAP kaydı bulundu", output: pretty(body) });
    }
    if (tool === "bgp") {
      const resource = target.toUpperCase().startsWith("AS") ? target.toUpperCase() : target;
      const endpoint = resource.startsWith("AS") ? "as-overview" : "prefix-overview";
      const r = await fetch("https://stat.ripe.net/data/" + endpoint + "/data.json?resource=" + encodeURIComponent(resource));
      if (!r.ok) throw Error("bgp_lookup_failed");
      const body = await r.json() as { data?: unknown };
      return Response.json({ summary: "RIPEstat BGP görünürlüğü", output: pretty(body.data || body) });
    }
    if (tool === "rpki") {
      if (!target.includes("/")) return Response.json({ error: "prefix_required" }, { status: 400 });
      const r = await fetch("https://stat.ripe.net/data/rpki-validation/data.json?resource=" + encodeURIComponent(target));
      if (!r.ok) throw Error("rpki_lookup_failed");
      const body = await r.json() as { data?: unknown };
      return Response.json({ summary: "RPKI doğrulama sonucu", output: pretty(body.data || body) });
    }
    if (tool === "certificates") {
      const r = await fetch("https://crt.sh/?q=" + encodeURIComponent(target) + "&output=json", { headers: { Accept: "application/json" } });
      if (!r.ok) throw Error("certificate_lookup_failed");
      const rows = await r.json() as Array<Record<string, unknown>>;
      const selected = rows.slice(0, 25).map(x => ({ common_name: x.common_name, name_value: x.name_value, issuer_name: x.issuer_name, not_before: x.not_before, not_after: x.not_after }));
      return Response.json({ summary: selected.length + " sertifika kaydı bulundu", output: pretty(selected) });
    }
    const r = await fetch("https://urlhaus-api.abuse.ch/v1/host/", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "host=" + encodeURIComponent(target) });
    if (!r.ok) throw Error("threat_lookup_failed");
    const body = await r.json() as { query_status?: string; urls?: unknown[] };
    return Response.json({ summary: body.query_status === "ok" ? (body.urls?.length || 0) + " URLHaus kaydı bulundu" : "URLHaus kaydı bulunamadı", output: pretty(body) });
  } catch {
    return Response.json({ error: "upstream_unavailable" }, { status: 502 });
  }
}