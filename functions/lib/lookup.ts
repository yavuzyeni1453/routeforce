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

type BriefRow = { label: string; value: string };
type WhoisBrief = { title: string; rows: BriefRow[] };

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

function present(rows: Array<[string, string]>, title: string) {
  const brief: WhoisBrief = { title, rows: rows.filter(([, value]) => value.trim()).map(([label, value]) => ({ label, value: value.trim() })) };
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
