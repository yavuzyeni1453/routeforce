export class LookupError extends Error {
  status: number;
  code: string;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export type BriefRow = { label: string; value: string };
export type Brief = { title: string; rows: BriefRow[] };
export type LookupResult = { summary: string; output: string; brief: Brief };

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

const statusTr: Record<string, string> = {
  "client delete prohibited": "silme kilitli",
  "client transfer prohibited": "transfer kilitli",
  "client update prohibited": "güncelleme kilitli",
  "server delete prohibited": "registry silme kilidi",
  "server transfer prohibited": "registry transfer kilidi",
  "server update prohibited": "registry güncelleme kilidi",
  "client renew prohibited": "yenileme kilitli",
  "ASSIGNED PORTABLE": "taşınabilir tahsis",
  "ALLOCATED PORTABLE": "taşınabilir blok",
  "ASSIGNED NON-PORTABLE": "sağlayıcıya bağlı tahsis",
  "ALLOCATED PA": "sağlayıcı tahsisi",
  "Direct Allocation": "doğrudan tahsis",
  "Direct Assignment": "doğrudan atama"
};

function readableDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.slice(0, 10);
  return new Intl.DateTimeFormat("tr-TR", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }).format(date);
}

function countryName(code: string) {
  const clean = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(clean)) return code;
  try {
    const name = new Intl.DisplayNames(["tr"], { type: "region" }).of(clean);
    return name ? name + " (" + clean + ")" : clean;
  } catch {
    return clean;
  }
}

function num(value: unknown, digits = 1) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toFixed(digits) : "—";
}

function present(rows: Array<[string, string]>, title: string): LookupResult {
  const brief: Brief = { title, rows: rows.filter(([, value]) => String(value || "").trim()).map(([label, value]) => ({ label, value: String(value).trim() })) };
  return {
    summary: title,
    output: brief.rows.map(row => row.label + ": " + row.value.replace(/\n/g, "\n  ")).join("\n"),
    brief
  };
}

function ripeRows(data: Record<string, unknown>) {
  const grouped = new Map<string, string[]>();
  for (const group of Array.isArray(data.records) ? data.records : []) {
    if (!Array.isArray(group)) continue;
    for (const row of group) {
      if (!row || typeof row !== "object") continue;
      const key = String((row as { key?: unknown }).key || "").toLowerCase();
      const value = String((row as { value?: unknown }).value || "").trim();
      if (!key || !value || /^[-.\s]+$/.test(value)) continue;
      const list = grouped.get(key) || [];
      if (!list.includes(value)) list.push(value);
      grouped.set(key, list);
    }
  }
  const first = (key: string) => grouped.get(key)?.[0] || "";
  const joined = (key: string) => (grouped.get(key) || []).join("\n");
  const status = [...(grouped.get("status") || []), ...(grouped.get("nettype") || [])].map(value => statusTr[value] || value).join(", ");
  const rawOwner = first("orgname") || first("organization") || first("org-name") || first("org");
  const owner = /[a-z]|\s/.test(rawOwner) ? rawOwner : "";
  const networkName = first("netname");
  const showName = networkName && (!owner || networkName.length > 6 || networkName.includes("-"));
  const place = [first("address"), [first("city"), first("stateprov"), first("postalcode")].filter(Boolean).join(", ")].filter(Boolean).join("\n");
  const abuse = [first("orgabuseemail"), first("abuse-mailbox"), first("orgabusephone")].filter(Boolean).join("\n");
  const country = first("country") ? countryName(first("country")) : "";
  const title = [owner || first("netname") || first("inetnum") || first("cidr") || String(data.resource || ""), country].filter(Boolean).join(" · ");
  return present([
    ["Ağ", first("cidr") || first("inetnum") || first("route") || first("netrange") || String(data.resource || "")],
    ["Aralık", first("cidr") && first("netrange") ? first("netrange") : ""],
    ["Ad", showName ? networkName : ""],
    ["Sahip", owner],
    ["Adres", place],
    ["Açıklama", joined("descr")],
    ["Ülke", country],
    ["Durum", status],
    ["Origin AS", first("originas") || first("origin")],
    ["Kötüye kullanım", abuse],
    ["Kayıt tarihi", first("regdate") ? readableDate(first("regdate")) : ""],
    ["Son güncelleme", first("last-modified") ? readableDate(first("last-modified")) : ""]
  ], title || "WHOIS kaydı");
}

function vcardValue(entity: Record<string, unknown>, key: string) {
  const card = entity.vcardArray as [string, unknown[]] | undefined;
  const items = Array.isArray(card?.[1]) ? card[1] : [];
  for (const item of items) {
    if (Array.isArray(item) && item[0] === key && item[3]) return String(item[3]).replace(/^tel:/, "");
  }
  return "";
}

function domainRows(body: Record<string, unknown>, target: string) {
  let registrar = "";
  let abuse = "";
  const walk = (entities: unknown) => {
    if (!Array.isArray(entities)) return;
    for (const entity of entities) {
      if (!entity || typeof entity !== "object") continue;
      const record = entity as Record<string, unknown>;
      const roles = Array.isArray(record.roles) ? record.roles.map(String) : [];
      if (roles.includes("registrar")) registrar = registrar || vcardValue(record, "fn");
      if (roles.includes("abuse")) abuse = abuse || [vcardValue(record, "email"), vcardValue(record, "tel")].filter(Boolean).join(" · ");
      walk(record.entities);
    }
  };
  walk(body.entities);
  const events = Array.isArray(body.events) ? body.events as Array<{ eventAction?: string; eventDate?: string }> : [];
  const when = (action: string) => readableDate(events.find(event => event.eventAction === action)?.eventDate || "");
  const nameservers = (Array.isArray(body.nameservers) ? body.nameservers : [])
    .map(server => server && typeof server === "object" ? String((server as { ldhName?: string }).ldhName || "") : "")
    .filter(Boolean);
  const statuses = (Array.isArray(body.status) ? body.status : []).map(status => statusTr[String(status)] || String(status));
  const signed = (body.secureDNS as { delegationSigned?: boolean } | undefined)?.delegationSigned;
  const name = String(body.ldhName || body.name || target).toUpperCase();
  return present([
    ["Alan adı", name],
    ["Kayıt firması", registrar],
    ["Kötüye kullanım", abuse],
    ["Kayıt tarihi", when("registration")],
    ["Bitiş tarihi", when("expiration")],
    ["Son değişiklik", when("last changed")],
    ["DNSSEC", signed == null ? "" : signed ? "İmzalı" : "İmzasız"],
    ["Nameserver", nameservers.join("\n")],
    ["Kilitler", statuses.join("\n")]
  ], [name, registrar].filter(Boolean).join(" · "));
}

async function ripeWhois(target: string) {
  const body = await readJson("https://stat.ripe.net/data/whois/data.json?resource=" + encodeURIComponent(target));
  const data = (body.data || {}) as Record<string, unknown>;
  const result = ripeRows(data);
  if (!result.brief.rows.length) throw new LookupError("lookup_not_found", "WHOIS kaydı bulunamadı.", 404);
  return result;
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
      const body = await response.json() as Record<string, unknown>;
      const result = domainRows(body, target);
      if (result.brief.rows.length) return result;
    } catch { /* try next */ }
  }
  return ripeWhois(target);
}

export async function dnsLookup(target: string) {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(target) || target.includes(":")) {
    throw new LookupError("domain_required", "DNS için alan adı girin. Örnek: cloudflare.com");
  }
  const records: Record<string, string[]> = {};
  for (const type of ["A", "AAAA", "MX", "NS", "TXT"]) {
    const response = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(target) + "&type=" + type, { headers: { Accept: "application/dns-json" } });
    const body = await response.json() as { Answer?: Array<{ data?: string; TTL?: number }> };
    records[type] = (body.Answer || []).map(row => {
      const ttl = row.TTL != null ? " (" + row.TTL + " sn)" : "";
      return String(row.data || "") + ttl;
    }).filter(Boolean);
  }
  const count = Object.values(records).flat().length;
  const title = count ? target + " · " + count + " DNS kaydı" : target + " · DNS kaydı yok";
  return present([
    ["A", records.A.join("\n")],
    ["AAAA", records.AAAA.join("\n")],
    ["MX", records.MX.join("\n")],
    ["NS", records.NS.join("\n")],
    ["TXT", records.TXT.slice(0, 6).join("\n")]
  ], title);
}

export async function bgpLookup(target: string) {
  const resource = target.toUpperCase().startsWith("AS") ? target.toUpperCase() : target;
  const isAsn = resource.startsWith("AS");
  const endpoint = isAsn ? "as-overview" : "prefix-overview";
  const body = await readJson("https://stat.ripe.net/data/" + endpoint + "/data.json?resource=" + encodeURIComponent(resource));
  const data = (body.data || {}) as Record<string, unknown>;
  if (isAsn) {
    const holder = String(data.holder || "");
    const announced = data.announced === true ? "Anons ediliyor" : data.announced === false ? "Anons yok" : "";
    return present([
      ["ASN", String(data.resource || resource.replace(/^AS/, ""))],
      ["Sahip", holder],
      ["Durum", announced],
      ["Blok", String((data.block as { resource?: string; desc?: string } | undefined)?.resource || "")],
      ["Blok açıklaması", String((data.block as { desc?: string } | undefined)?.desc || "")]
    ], [holder || resource, announced].filter(Boolean).join(" · "));
  }
  const asns = Array.isArray(data.asns) ? data.asns as Array<{ asn?: number; holder?: string }> : [];
  const origin = asns.map(row => "AS" + row.asn + (row.holder ? " · " + row.holder : "")).join("\n");
  return present([
    ["Prefix", String(data.resource || resource)],
    ["Anons", data.announced === true ? "Evet" : data.announced === false ? "Hayır" : ""],
    ["Origin ASN", origin],
    ["Blok", String((data.block as { resource?: string; name?: string } | undefined)?.resource || "")],
    ["Blok adı", String((data.block as { name?: string } | undefined)?.name || "")]
  ], [resource, asns[0] ? "AS" + asns[0].asn : ""].filter(Boolean).join(" · "));
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
    if (!prefixes.length) return present([["ASN", "AS" + asn[1]], ["Kontrol", "Duyurulan IPv4 prefix yok"]], "AS" + asn[1] + " · RPKI örnek yok");
    const samples = await Promise.all(prefixes.map(prefix => validatePrefix(asn[1], prefix).catch(() => ({ prefix, origin: "AS" + asn[1], status: "unknown", validator: "RIPEstat", roa_count: 0 }))));
    const valid = samples.filter(row => row.status === "valid").length;
    const invalid = samples.filter(row => row.status === "invalid").length;
    return present([
      ["ASN", "AS" + asn[1]],
      ["Kontrol", samples.length + " örnek prefix"],
      ["Valid", String(valid)],
      ["Invalid", String(invalid)],
      ["Örnekler", samples.map(row => row.prefix + " → " + row.status).join("\n")]
    ], "AS" + asn[1] + " · " + valid + "/" + samples.length + " valid");
  }
  if (!/^[\d.a-fA-F:]+\/\d{1,3}$/.test(target)) {
    throw new LookupError("prefix_or_asn_required", "RPKI için ASN (AS13335) veya prefix (1.1.1.0/24) girin.");
  }
  const origin = await originAsn(target);
  if (!origin) throw new LookupError("origin_not_found", "Bu prefix için origin ASN bulunamadı.", 404);
  const row = await validatePrefix(origin, target);
  return present([
    ["Prefix", row.prefix],
    ["Origin", row.origin],
    ["Durum", row.status],
    ["ROA sayısı", String(row.roa_count)],
    ["Doğrulayıcı", row.validator]
  ], "RPKI " + row.status + " · " + row.origin);
}

export async function ipIntelLookup(target: string) {
  const urls = [
    "https://ipapi.co/" + encodeURIComponent(target) + "/json/",
    "https://ipinfo.io/" + encodeURIComponent(target) + "/json"
  ];
  let data: Record<string, unknown> | null = null;
  for (const url of urls) {
    try {
      const response = await fetch(url, { headers: { Accept: "application/json", "User-Agent": "RouteForce/1.0" } });
      if (!response.ok) continue;
      data = await response.json() as Record<string, unknown>;
      if (data.error) continue;
      break;
    } catch { /* next */ }
  }
  if (!data) throw new LookupError("upstream_unavailable", "IP konum servisi yanıt vermiyor.", 424);
  const country = String(data.country_name || data.country || "");
  const org = String(data.org || data.asn || data.organization || "");
  const city = [data.city, data.region || data.region_code].filter(Boolean).join(", ");
  return present([
    ["IP", String(data.ip || target)],
    ["Hostname", String(data.hostname || "")],
    ["Konum", city],
    ["Ülke", country.includes("(") ? country : countryName(String(data.country_code || data.country || country))],
    ["Organizasyon", org],
    ["ASN", String(data.asn || "")],
    ["Saat dilimi", String(data.timezone || "")]
  ], [String(data.ip || target), org || city].filter(Boolean).join(" · "));
}

type ProbeKind = "ping" | "traceroute" | "mtr";
type ProbeHop = {
  resolvedAddress?: string | null;
  resolvedHostname?: string | null;
  asn?: number[];
  stats?: { avg?: number; min?: number; max?: number; loss?: number; rcv?: number; drop?: number; stDev?: number; jAvg?: number };
  timings?: Array<{ rtt?: number }>;
};
type ProbeResult = {
  status?: string;
  rawOutput?: string;
  resolvedAddress?: string;
  resolvedHostname?: string;
  hops?: ProbeHop[];
  stats?: { min?: number; avg?: number; max?: number; loss?: number; rcv?: number; drop?: number };
  timings?: Array<{ rtt?: number; ttl?: number }>;
};
type ProbeRow = {
  probe?: { city?: string; country?: string; network?: string; asn?: number };
  result?: ProbeResult;
};

function placeOf(row: ProbeRow) {
  return [row.probe?.city, row.probe?.country ? countryName(row.probe.country).replace(/ \([A-Z]{2}\)$/, "") : "", row.probe?.network].filter(Boolean).join(" · ") || "Probe";
}

function hopLabel(hop: ProbeHop, index: number) {
  const host = hop.resolvedHostname || hop.resolvedAddress || "yanıt yok";
  const asn = hop.asn?.[0] ? "AS" + hop.asn[0] : "";
  const ip = hop.resolvedAddress && hop.resolvedAddress !== hop.resolvedHostname ? hop.resolvedAddress : "";
  return [String(index + 1).padStart(2, "0"), asn, host, ip ? "(" + ip + ")" : ""].filter(Boolean).join(" ");
}

function formatPing(row: ProbeRow) {
  const stats = row.result?.stats;
  const timings = (row.result?.timings || []).map(item => num(item.rtt, 2) + " ms").join(", ");
  return present([
    ["Probe", placeOf(row)],
    ["Probe ASN", row.probe?.asn ? "AS" + row.probe.asn : ""],
    ["Hedef", [row.result?.resolvedHostname, row.result?.resolvedAddress].filter(Boolean).join(" · ")],
    ["Min / Ort / Maks", [num(stats?.min), num(stats?.avg), num(stats?.max)].join(" / ") + " ms"],
    ["Kayıp", stats?.loss == null ? "" : "%" + num(stats.loss, 0) + " (" + (stats.drop || 0) + "/" + (stats.rcv || 0) + " paket)"],
    ["RTT örnekleri", timings]
  ], placeOf(row) + " · ort " + num(stats?.avg) + " ms");
}

function formatTrace(row: ProbeRow) {
  const hops = row.result?.hops || [];
  const lines = hops.map((hop, index) => {
    const rtts = (hop.timings || []).map(item => num(item.rtt, 2)).filter(value => value !== "—");
    const avg = rtts.length ? (rtts.reduce((sum, value) => sum + Number(value), 0) / rtts.length).toFixed(1) + " ms" : "*";
    return hopLabel(hop, index) + "  " + avg;
  });
  return present([
    ["Probe", placeOf(row)],
    ["Hedef", [row.result?.resolvedHostname, row.result?.resolvedAddress].filter(Boolean).join(" · ")],
    ["Hop sayısı", String(hops.filter(hop => hop.resolvedAddress).length)],
    ["Rota", lines.join("\n")]
  ], placeOf(row) + " · " + hops.filter(hop => hop.resolvedAddress).length + " hop");
}

function formatMtr(row: ProbeRow) {
  const hops = (row.result?.hops || []).filter(hop => hop.resolvedAddress || (hop.timings || []).length || hop.stats);
  const lines = hops.map((hop, index) => {
    const stats = hop.stats;
    const loss = stats?.loss == null ? "—" : "%" + num(stats.loss, 0);
    const avg = stats?.avg == null ? "—" : num(stats.avg, 1) + " ms";
    const jitter = stats?.jAvg == null ? "" : " j" + num(stats.jAvg, 1);
    return hopLabel(hop, index) + "  loss " + loss + "  avg " + avg + jitter;
  });
  const last = hops[hops.length - 1]?.stats;
  return present([
    ["Probe", placeOf(row)],
    ["Hedef", [row.result?.resolvedHostname, row.result?.resolvedAddress].filter(Boolean).join(" · ")],
    ["Hop", String(hops.length)],
    ["Son hop ort", last?.avg == null ? "" : num(last.avg, 1) + " ms"],
    ["Son hop kayıp", last?.loss == null ? "" : "%" + num(last.loss, 0)],
    ["Yol", lines.join("\n")]
  ], placeOf(row) + " · " + hops.length + " hop");
}

export async function probeLookup(kind: ProbeKind, target: string) {
  if (/^AS\d+$/i.test(target)) throw new LookupError("host_required", "Ping, traceroute ve MTR için IP adresi veya alan adı girin.");
  const packets = kind === "ping" ? 4 : kind === "mtr" ? 5 : undefined;
  const created = await fetch("https://api.globalping.io/v1/measurements", {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "RouteForce/1.0" },
    body: JSON.stringify({
      type: kind,
      target,
      locations: [
        { magic: "turkey", limit: kind === "ping" ? 2 : 1 },
        { magic: "europe", limit: kind === "ping" ? 1 : 1 }
      ],
      ...(packets ? { measurementOptions: { packets } } : {})
    })
  });
  if (!created.ok) {
    const detail = (await created.text()).slice(0, 180);
    throw new LookupError("probe_rejected", detail || "Probe isteği kabul edilmedi.", 424);
  }
  const job = await created.json() as { id?: string };
  if (!job.id) throw new LookupError("probe_rejected", "Probe kimliği alınamadı.", 424);

  let measurement: { status?: string; results?: ProbeRow[] } = {};
  for (let attempt = 0; attempt < 16; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 900));
    const response = await fetch("https://api.globalping.io/v1/measurements/" + job.id, { headers: { "User-Agent": "RouteForce/1.0" } });
    if (!response.ok) continue;
    measurement = await response.json();
    if (measurement.status === "finished" || measurement.status === "failed") break;
  }

  const results = (measurement.results || []).filter(row => row.result?.status !== "failed" || row.result?.rawOutput || row.result?.hops);
  if (!results.length) throw new LookupError("probe_timeout", "Probe zaman aşımına uğradı. Tekrar deneyin.", 424);

  const formatted = results.map(row => {
    if (kind === "ping") return formatPing(row);
    if (kind === "traceroute") return formatTrace(row);
    return formatMtr(row);
  });

  const rows: BriefRow[] = [];
  formatted.forEach((item, index) => {
    if (formatted.length > 1) rows.push({ label: "Probe " + (index + 1), value: item.summary });
    for (const row of item.brief.rows) rows.push(row);
  });

  let summary = formatted[0].summary;
  if (kind === "ping") {
    const avgs = results.map(row => Number(row.result?.stats?.avg)).filter(Number.isFinite);
    const losses = results.map(row => Number(row.result?.stats?.loss)).filter(Number.isFinite);
    if (avgs.length) {
      const avg = avgs.reduce((a, b) => a + b, 0) / avgs.length;
      const worst = Math.max(...losses, 0);
      summary = results.length + " probe · ort " + avg.toFixed(1) + " ms · kayıp %" + worst.toFixed(0);
    }
  } else {
    summary = results.length + " probe · " + formatted.map(item => item.summary.split(" · ").pop()).join(" / ");
  }

  return {
    summary,
    output: formatted.map(item => item.output).join("\n\n────────────────\n\n"),
    brief: { title: summary, rows }
  } satisfies LookupResult;
}

export async function peeringdbLookup(target: string) {
  const asn = target.toUpperCase().replace(/^AS/, "");
  if (!/^\d+$/.test(asn)) throw new LookupError("asn_required", "PeeringDB için ASN girin. Örnek: AS13335");
  const body = await readJson("https://www.peeringdb.com/api/net?asn=" + asn);
  const row = Array.isArray(body.data) ? (body.data as Array<Record<string, unknown>>)[0] : null;
  if (!row) throw new LookupError("lookup_not_found", "PeeringDB kaydı bulunamadı.", 404);
  return present([
    ["Ağ", String(row.name || "")],
    ["ASN", "AS" + asn],
    ["Web", String(row.website || "")],
    ["Politika", String(row.policy_general || "")],
    ["Info prefixes v4", String(row.info_prefixes4 || "")],
    ["Info prefixes v6", String(row.info_prefixes6 || "")],
    ["IRR", String(row.irr_as_set || "")],
    ["Looking Glass", String(row.looking_glass || "")]
  ], String(row.name || "AS" + asn) + " · PeeringDB");
}

export async function certificatesLookup(target: string) {
  try {
    const response = await fetch("https://api.certspotter.com/v1/issuances?domain=" + encodeURIComponent(target) + "&include_subdomains=false&expand=dns_names&expand=issuer", {
      headers: { Accept: "application/json", "User-Agent": "RouteForce/1.0" },
      signal: AbortSignal.timeout(12000)
    });
    if (response.ok) {
      const rows = await response.json() as Array<{ dns_names?: string[]; issuer?: { friendly_name?: string; name?: string }; not_before?: string }>;
      const selected = rows.slice(0, 10).map(row => {
        const name = (row.dns_names || []).find(item => !item.startsWith("*")) || (row.dns_names || [])[0] || target;
        const issuer = row.issuer?.friendly_name || row.issuer?.name || "issuer?";
        return name + " · " + issuer;
      });
      return present([
        ["Hedef", target],
        ["Kayıt", String(rows.length)],
        ["Son sertifikalar", selected.join("\n")]
      ], target + " · " + rows.length + " sertifika");
    }
  } catch { /* fall through to crt.sh */ }

  const response = await fetch("https://crt.sh/?q=" + encodeURIComponent(target) + "&output=json", {
    headers: { Accept: "application/json", "User-Agent": "RouteForce/1.0" },
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new LookupError("upstream_unavailable", "Sertifika kaydı şu anda yanıt vermiyor.", 424);
  const text = await response.text();
  const rows = JSON.parse(text.length > 250000 ? text.slice(0, 250000).replace(/,[^,\]]*$/, "]") : text) as Array<Record<string, unknown>>;
  const selected = rows.slice(0, 8).map(row => String(row.common_name || "") + " · " + String(row.not_before || "").slice(0, 10));
  return present([
    ["Hedef", target],
    ["Kayıt", String(Math.min(rows.length, 25)) + "+"],
    ["Son sertifikalar", selected.join("\n")]
  ], target + " · " + Math.min(rows.length, 25) + " sertifika");
}

export async function macVendorLookup(target: string) {
  const response = await fetch("https://api.macvendors.com/" + encodeURIComponent(target), { headers: { "User-Agent": "RouteForce/1.0" } });
  if (!response.ok) return present([["MAC", target], ["Üretici", "Bulunamadı"]], target + " · üretici yok");
  const vendor = await response.text();
  return present([["MAC", target], ["Üretici", vendor]], vendor + " · MAC");
}

export async function announcedPrefixesLookup(target: string) {
  const body = await readJson("https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + encodeURIComponent(target));
  const data = (body.data || {}) as { prefixes?: Array<{ prefix?: string }> };
  const prefixes = (data.prefixes || []).map(row => row.prefix || "").filter(Boolean);
  return present([
    ["Kaynak", target.toUpperCase()],
    ["Toplam", String(prefixes.length)],
    ["Örnekler", prefixes.slice(0, 20).join("\n")]
  ], target.toUpperCase() + " · " + prefixes.length + " prefix");
}

export async function bgpHistoryLookup(target: string) {
  const start = new Date(Date.now() - 12096e5).toISOString();
  const end = new Date().toISOString();
  const body = await readJson("https://stat.ripe.net/data/routing-history/data.json?resource=" + encodeURIComponent(target) + "&starttime=" + encodeURIComponent(start) + "&endtime=" + encodeURIComponent(end));
  const data = (body.data || {}) as { by_origin?: Array<{ origin?: string; prefixes?: unknown[] }> };
  const origins = data.by_origin || [];
  return present([
    ["Kaynak", target],
    ["Pencere", "Son 14 gün"],
    ["Origin sayısı", String(origins.length)],
    ["Originler", origins.slice(0, 12).map(row => "AS" + row.origin + " · " + (row.prefixes?.length || 0) + " prefix").join("\n")]
  ], target + " · " + origins.length + " origin");
}

export { pretty };
