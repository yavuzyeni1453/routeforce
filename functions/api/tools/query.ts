import {
  LookupError,
  announcedPrefixesLookup,
  bgpHistoryLookup,
  bgpLookup,
  certificatesLookup,
  dnsLookup,
  ipIntelLookup,
  macVendorLookup,
  peeringdbLookup,
  rpkiLookup,
  whoisLookup
} from "../../lib/lookup";

type Tool = "dns" | "whois" | "bgp" | "rpki" | "certificates" | "urlhaus" | "bgp_history" | "bgp_prefixes" | "peeringdb" | "threatfox" | "ipapi" | "macvendor";
const privateV4 = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const tools: Tool[] = ["dns", "whois", "bgp", "rpki", "certificates", "urlhaus", "bgp_history", "bgp_prefixes", "peeringdb", "threatfox", "ipapi", "macvendor"];

function valid(value: string) {
  return value.length > 0 && value.length < 254 && /^[a-zA-Z0-9.:/_-]+$/.test(value) && !privateV4.test(value);
}

export async function onRequestGet(context: { request: Request }) {
  const url = new URL(context.request.url);
  const tool = url.searchParams.get("tool") as Tool;
  const target = (url.searchParams.get("target") || "").trim();
  if (!tools.includes(tool) || !valid(target)) {
    return Response.json({ error: "invalid_target", message: "Hedef boş, özel bir ağ veya desteklenmeyen bir değer." }, { status: 400 });
  }
  try {
    if (tool === "dns") return Response.json(await dnsLookup(target));
    if (tool === "whois") return Response.json(await whoisLookup(target));
    if (tool === "bgp") return Response.json(await bgpLookup(target));
    if (tool === "bgp_history") return Response.json(await bgpHistoryLookup(target));
    if (tool === "bgp_prefixes") return Response.json(await announcedPrefixesLookup(target));
    if (tool === "peeringdb") return Response.json(await peeringdbLookup(target));
    if (tool === "rpki") return Response.json(await rpkiLookup(target));
    if (tool === "certificates") return Response.json(await certificatesLookup(target));
    if (tool === "urlhaus" || tool === "threatfox") {
      return Response.json({
        error: "integration_not_configured",
        message: "abuse.ch bu sorguyu artık API anahtarı olmadan vermiyor. Yönetim → Entegrasyonlar ekranından anahtar ekleyin."
      }, { status: 424 });
    }
    if (tool === "ipapi") return Response.json(await ipIntelLookup(target));
    return Response.json(await macVendorLookup(target));
  } catch (error) {
    if (error instanceof LookupError) {
      return Response.json({ error: error.code, message: error.message }, { status: error.status >= 400 && error.status < 500 ? error.status : 424 });
    }
    return Response.json({ error: "upstream_unavailable", message: "Sağlayıcı şu anda RouteForce üzerinden yanıt vermiyor." }, { status: 424 });
  }
}
