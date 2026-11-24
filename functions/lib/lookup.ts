export class LookupError extends Error {
  status: number;
  code: string;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const pretty = (value: unknown) => JSON.stringify(value, null, 2);

async function readJson(url: string, init?: RequestInit) {
  const response = await fetch(url, {
    ...init,
    headers: {
      Accept: "application/json",
      "User-Agent": "RouteForce/1.0",
      ...(init?.headers || {})
    }
  });
  if (!response.ok) throw new LookupError("upstream_unavailable", "Sağlayıcı şu anda yanıt vermiyor.", response.status === 404 ? 404 : 424);
  return response.json() as Promise<Record<string, unknown>>;
}

function flattenWhois(data: Record<string, unknown>) {
  const groups = Array.isArray(data.records) ? data.records : [];
  const fields: Record<string, string> = {};
  const lines: string[] = [];
  for (const group of groups) {
    if (!Array.isArray(group)) continue;
    for (const row of group) {
      if (!row || typeof row !== "object") continue;
      const key = String((row as { key?: unknown }).key || "");
      const value = (row as { value?: unknown }).value;
      if (!key || value == null || value === "") continue;
      const text = String(value);
      lines.push(key + ": " + text);
      const id = key.toLowerCase();
      fields[id] = fields[id] ? fields[id] + " | " + text : text;
    }
  }
  return {
    name: fields.netname || fields["domain name"] || fields.domain || fields.descr || "",
    handle: fields.netname || fields["domain name"] || "",
    country: fields.country || "",
    resource: String(data.resource || fields.inetnum || fields.route || ""),
    descr: fields.descr || "",
    source: "RIPEstat WHOIS",
    records: lines.slice(0, 80)
  };
}

async function ripeWhois(target: string) {
  const body = await readJson("https://stat.ripe.net/data/whois/data.json?resource=" + encodeURIComponent(target));
  const data = (body.data || {}) as Record<string, unknown>;
  const flat = flattenWhois(data);
  if (!flat.records.length) throw new LookupError("lookup_not_found", "WHOIS kaydı bulunamadı.", 404);
  const summary = [flat.name || flat.resource || target, flat.country].filter(Boolean).join(" · ");
  return { summary: summary || "WHOIS kaydı bulundu", output: pretty(flat) };
}

export async function whoisLookup(target: string) {
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(target) || target.includes(":");
  if (isIp) return ripeWhois(target);
  const tld = target.split(".").pop()?.toLowerCase() || "";
  const urls = tld === "com" || tld === "net"
    ? ["https://rdap.verisign.com/" + tld + "/v1/domain/" + encodeURIComponent(target)]
    : ["https://rdap.org/domain/" + encodeURIComponent(target)];
  for (const url of urls) {
    try {
      const response = await fetch(url, { headers: { Accept: "application/rdap+json", "User-Agent": "RouteForce/1.0" }, redirect: "follow" });
      if (!response.ok) continue;
      const body = await response.json() as { ldhName?: string; handle?: string; name?: string };
      const name = body.ldhName || body.name || body.handle || target;
      return { summary: name + " · RDAP", output: pretty(body) };
    } catch { /* try the next registry */ }
  }
  return ripeWhois(target);
}

async function originAsn(prefix: string) {
  const body = await readJson("https://stat.ripe.net/data/prefix-overview/data.json?resource=" + encodeURIComponent(prefix));
  const data = (body.data || {}) as { asns?: Array<{ asn?: number }> };
  const asn = data.asns?.[0]?.asn;
  return asn ? String(asn) : "";
}

async function validatePrefix(asn: string, prefix: string) {
  const body = await readJson("https://stat.ripe.net/data/rpki-validation/data.json?resource=" + encodeURIComponent(asn) + "&prefix=" + encodeURIComponent(prefix));
  const data = (body.data || {}) as { status?: string; validator?: string; validating_roas?: unknown[] };
  return {
    prefix,
    origin: "AS" + asn,
    status: data.status || "unknown",
    validator: data.validator || "RIPEstat",
    roa_count: Array.isArray(data.validating_roas) ? data.validating_roas.length : 0
  };
}

export async function rpkiLookup(target: string) {
  const asn = target.toUpperCase().match(/^AS(\d+)$/);
  if (asn) {
    const body = await readJson("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn[1]);
    const data = (body.data || {}) as { prefixes?: Array<{ prefix?: string }> };
    const prefixes = (data.prefixes || []).map(row => row.prefix || "").filter(prefix => prefix.includes(".")).slice(0, 6);
    if (!prefixes.length) return { summary: "Bu ASN için duyurulan IPv4 prefix bulunamadı", output: pretty({ asn: "AS" + asn[1], checked: 0 }) };
    const samples = await Promise.all(prefixes.map(prefix => validatePrefix(asn[1], prefix).catch(() => ({ prefix, origin: "AS" + asn[1], status: "unknown", validator: "RIPEstat", roa_count: 0 }))));
    const valid = samples.filter(row => row.status === "valid").length;
    const invalid = samples.filter(row => row.status === "invalid").length;
    return {
      summary: valid + "/" + samples.length + " örnek prefix RPKI valid",
      output: pretty({ asn: "AS" + asn[1], checked: samples.length, valid, invalid, unknown: samples.length - valid - invalid, status: invalid ? "invalid" : valid ? "valid" : "unknown", samples })
    };
  }
  if (!/^[\d.a-fA-F:]+\/\d{1,3}$/.test(target)) {
    throw new LookupError("prefix_or_asn_required", "RPKI için ASN (AS13335) veya prefix (1.1.1.0/24) girin.");
  }
  const origin = await originAsn(target);
  if (!origin) throw new LookupError("origin_not_found", "Bu prefix için origin ASN bulunamadı.", 404);
  const row = await validatePrefix(origin, target);
  return { summary: "RPKI " + row.status + " · AS" + origin, output: pretty(row) };
}

export async function probeLookup(kind: "ping" | "traceroute" | "mtr", target: string) {
  if (/^AS\d+$/i.test(target)) throw new LookupError("host_required", "Ping, traceroute ve MTR için IP adresi veya alan adı girin.");
  const created = await fetch("https://api.globalping.io/v1/measurements", {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "RouteForce/1.0" },
    body: JSON.stringify({
      type: kind,
      target,
      locations: [{ magic: "world", limit: kind === "ping" ? 3 : 2 }],
      ...(kind === "ping" ? { measurementOptions: { packets: 3 } } : {})
    })
  });
  if (!created.ok) {
    const detail = (await created.text()).slice(0, 180);
    throw new LookupError("probe_rejected", detail || "Probe isteği kabul edilmedi.", 424);
  }
  const job = await created.json() as { id?: string };
  if (!job.id) throw new LookupError("probe_rejected", "Probe kimliği alınamadı.", 424);
  let measurement: { status?: string; results?: Array<{ probe?: { city?: string; country?: string; network?: string }; result?: { rawOutput?: string; status?: string; stats?: { min?: number; avg?: number; max?: number; loss?: number } } }> } = {};
  for (let attempt = 0; attempt < 10; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 800));
    const response = await fetch("https://api.globalping.io/v1/measurements/" + job.id, { headers: { "User-Agent": "RouteForce/1.0" } });
    if (!response.ok) continue;
    measurement = await response.json();
    if (measurement.status === "finished" || measurement.status === "failed") break;
  }
  const results = measurement.results || [];
  const output = results.map(row => {
    const where = [row.probe?.city, row.probe?.country, row.probe?.network].filter(Boolean).join(", ") || "probe";
    return "--- " + where + " ---\n" + (row.result?.rawOutput || row.result?.status || "sonuç yok");
  }).join("\n\n");
  if (!output) throw new LookupError("probe_timeout", "Probe zaman aşımına uğradı. Tekrar deneyin.", 424);
  const stats = results.find(row => row.result?.stats)?.result?.stats;
  const summary = kind === "ping" && stats
    ? "min " + stats.min + " ms · avg " + stats.avg + " ms · loss %" + (stats.loss ?? 0)
    : results.length + " probe tamamlandı";
  return { summary, output };
}
