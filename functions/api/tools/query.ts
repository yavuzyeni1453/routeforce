import { LookupError, rpkiLookup, whoisLookup } from "../../lib/lookup";

type Tool = "dns" | "whois" | "bgp" | "rpki" | "certificates" | "urlhaus" | "bgp_history" | "bgp_prefixes" | "peeringdb" | "threatfox" | "ipapi" | "macvendor";
const privateV4 = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const tools: Tool[] = ["dns", "whois", "bgp", "rpki", "certificates", "urlhaus", "bgp_history", "bgp_prefixes", "peeringdb", "threatfox", "ipapi", "macvendor"];
const pretty = (value: unknown) => JSON.stringify(value, null, 2);

function valid(value: string) {
  return value.length > 0 && value.length < 254 && /^[a-zA-Z0-9.:/_-]+$/.test(value) && !privateV4.test(value);
}

export async function onRequestGet(context: { request: Request }) {
  const url = new URL(context.request.url);
  const tool = url.searchParams.get("tool") as Tool;
  const target = (url.searchParams.get("target") || "").trim();
  if (!tools.includes(tool) || !valid(target)) return Response.json({ error: "invalid_target", message: "Hedef boş, özel bir ağ veya desteklenmeyen bir değer." }, { status: 400 });
  try {
    if (tool === "dns") {
      const records: Record<string, unknown> = {};
      for (const type of ["A", "AAAA", "MX", "NS", "TXT"]) {
        const response = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(target) + "&type=" + type, { headers: { Accept: "application/dns-json" } });
        const body = await response.json() as { Answer?: unknown[] };
        records[type] = body.Answer || [];
      }
      const count = Object.values(records).flat().length;
      return Response.json({ summary: count ? count + " DNS kaydı bulundu" : "Kayıt bulunamadı", output: pretty(records) });
    }
    if (tool === "whois") return Response.json(await whoisLookup(target));
    if (tool === "bgp") {
      const resource = target.toUpperCase().startsWith("AS") ? target.toUpperCase() : target;
      const endpoint = resource.startsWith("AS") ? "as-overview" : "prefix-overview";
      const response = await fetch("https://stat.ripe.net/data/" + endpoint + "/data.json?resource=" + encodeURIComponent(resource));
      if (!response.ok) throw new LookupError("upstream_unavailable", "RIPEstat yanıt vermiyor.", 424);
      const body = await response.json() as { data?: unknown };
      return Response.json({ summary: "RIPEstat BGP görünürlüğü", output: pretty(body.data || body) });
    }
    if (tool === "bgp_history" || tool === "bgp_prefixes") {
      const endpoint = tool === "bgp_history" ? "routing-history" : "announced-prefixes";
      const dates = tool === "bgp_history" ? "&starttime=" + encodeURIComponent(new Date(Date.now() - 12096e5).toISOString()) + "&endtime=" + encodeURIComponent(new Date().toISOString()) : "";
      const response = await fetch("https://stat.ripe.net/data/" + endpoint + "/data.json?resource=" + encodeURIComponent(target) + dates);
      if (!response.ok) throw new LookupError("upstream_unavailable", "RIPEstat yanıt vermiyor.", 424);
      const body = await response.json() as { data?: unknown };
      return Response.json({ summary: tool === "bgp_history" ? "BGP rota geçmişi" : "Duyurulan prefixler", output: pretty(body.data || body) });
    }
    if (tool === "peeringdb") {
      const asn = target.toUpperCase().replace(/^AS/, "");
      if (!/^\d+$/.test(asn)) return Response.json({ error: "asn_required", message: "PeeringDB için ASN girin. Örnek: AS13335" }, { status: 400 });
      const response = await fetch("https://www.peeringdb.com/api/net?asn=" + asn, { headers: { Accept: "application/json", "User-Agent": "RouteForce/1.0" } });
      if (!response.ok) throw new LookupError("upstream_unavailable", "PeeringDB yanıt vermiyor.", 424);
      return Response.json({ summary: "PeeringDB ağı bulundu", output: pretty(await response.json()) });
    }
    if (tool === "rpki") return Response.json(await rpkiLookup(target));
    if (tool === "certificates") {
      const response = await fetch("https://crt.sh/?q=" + encodeURIComponent(target) + "&output=json", { headers: { Accept: "application/json" } });
      if (!response.ok) throw new LookupError("upstream_unavailable", "crt.sh yanıt vermiyor.", 424);
      const rows = await response.json() as Array<Record<string, unknown>>;
      const selected = rows.slice(0, 25).map(row => ({ common_name: row.common_name, name_value: row.name_value, issuer_name: row.issuer_name, not_before: row.not_before, not_after: row.not_after }));
      return Response.json({ summary: selected.length + " sertifika kaydı bulundu", output: pretty(selected) });
    }
    if (tool === "urlhaus" || tool === "threatfox") {
      return Response.json({ error: "integration_not_configured", message: "abuse.ch bu sorguyu artık API anahtarı olmadan vermiyor. Yönetim → Entegrasyonlar ekranından anahtar ekleyin." }, { status: 424 });
    }
    if (tool === "ipapi") {
      const response = await fetch("https://ipinfo.io/" + encodeURIComponent(target) + "/json");
      if (!response.ok) throw new LookupError("upstream_unavailable", "IP konum servisi yanıt vermiyor.", 424);
      return Response.json({ summary: "IP konum ve ASN bilgisi", output: pretty(await response.json()) });
    }
    const response = await fetch("https://api.macvendors.com/" + encodeURIComponent(target));
    if (!response.ok) return Response.json({ summary: "MAC vendor kaydı bulunamadı", output: pretty({}) });
    return Response.json({ summary: "MAC üreticisi bulundu", output: pretty({ vendor: await response.text() }) });
  } catch (error) {
    if (error instanceof LookupError) return Response.json({ error: error.code, message: error.message }, { status: error.status >= 400 && error.status < 500 ? error.status : 424 });
    return Response.json({ error: "upstream_unavailable", message: "Sağlayıcı şu anda RouteForce üzerinden yanıt vermiyor." }, { status: 424 });
  }
}
