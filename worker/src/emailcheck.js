// /email-check: a domain's email authentication posture from public DNS (DNS over HTTPS via Cloudflare's resolver):
// MX, SPF (with the RFC 7208 10-lookup count), DMARC, common DKIM selectors, MTA-STS, TLS-RPT and BIMI.
import { Report } from "./core.js";
import { siteOf } from "./fetchsafe.js";
import { LookupUnavailable } from "./profile.js";

export const DOH_URL = "https://cloudflare-dns.com/dns-query";
export const DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1"];
export const EMAIL_NOTICE =
  "DNS posture only: this doesn't send mail, test delivery or check sender reputation, and DKIM can only be found " +
  "for the common selectors tried.";
const TYPES = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };
const BAD_TLDS = new Set(["localhost", "local", "internal", "test", "invalid", "onion", "arpa", "lan", "home", "corp", "localdomain", "intranet", "private"]);
const SPF_EXPANSION_BUDGET = 12;

/** {domain} (lowercase, no trailing dot) or {error}. */
export function parseEmailTarget(raw) {
  if (typeof raw !== "string" || !raw.trim()) return { error: "domain is required, e.g. example.com" };
  const d = raw.trim().toLowerCase().replace(/\.$/, "");
  if (d.length > 253) return { error: "domain is longer than 253 characters" };
  if (/[^a-z0-9.-]/.test(d)) return { error: "domain must be a plain host name (letters, digits, '-' and '.'; IDNs in xn-- form)" };
  const labels = d.split(".");
  if (labels.length < 2) return { error: "domain must have at least two labels, e.g. example.com" };
  for (const l of labels) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) return { error: `invalid label '${l}' in the domain` };
  }
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return { error: "the top-level domain is not valid" };
  if (BAD_TLDS.has(tld)) return { error: "local or reserved top-level domains are refused" };
  return { domain: d };
}

/** Join a TXT answer's quoted character-strings ("a" "b" -> ab), undoing \" \\ and \DDD escapes. */
export function txtData(data) {
  const s = String(data);
  const parts = [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  const joined = parts.length ? parts.join("") : s;
  return joined.replace(/\\(\d{3}|.)/g, (m, e) => (/^\d{3}$/.test(e) ? String.fromCharCode(Number(e)) : e));
}

export class Dns {
  constructor(fetcher) {
    this.fetcher = fetcher;
    this.cache = new Map();
  }

  /** {status: NOERROR|NXDOMAIN|SERVFAIL|..., answers: [string data of the requested type]}. Throws LookupUnavailable. */
  async query(name, type) {
    const key = `${type} ${name}`;
    if (this.cache.has(key)) return this.cache.get(key);
    const p = (async () => {
      const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;
      const r = await this.fetcher.fetch(url, { headers: { Accept: "application/dns-json" }, maxBytes: 64 * 1024 });
      if (r.status !== 200) throw new LookupUnavailable(`DNS lookup failed (HTTP ${r.status} from the resolver)`);
      let j;
      try {
        j = JSON.parse(r.text);
      } catch {
        throw new LookupUnavailable("DNS lookup returned an unreadable answer");
      }
      const status = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED" }[j.Status] || `RCODE${j.Status}`;
      const want = TYPES[type];
      const answers = (j.Answer || []).filter((a) => a.type === want).map((a) => (type === "TXT" ? txtData(a.data) : String(a.data)));
      return { status, answers };
    })();
    this.cache.set(key, p);
    return p;
  }

  /** Like query, but SERVFAIL/REFUSED become an "unknown" answer instead of throwing. */
  async soft(name, type) {
    try {
      return await this.query(name, type);
    } catch {
      return { status: "UNKNOWN", answers: [] };
    }
  }
}

const SPF_RE = /^v=spf1(\s|$)/i;
const DMARC_RE = /^v\s*=\s*DMARC1\s*(;|$)/i;

/** Parse one SPF record's terms. */
export function parseSpf(record) {
  const terms = record.trim().split(/\s+/).slice(1);
  const out = { lookups: 0, all: null, includes: [], redirect: null, ptr: false, mechanisms: [] };
  for (const t of terms) {
    const m = /^([+?~-]?)([a-z][a-z0-9_.-]*)(?:([:=])(.*))?$/i.exec(t);
    if (!m) continue;
    const q = m[1] || "+";
    const name = m[2].toLowerCase();
    const arg = m[4];
    if (m[3] === "=") {
      if (name === "redirect") { out.redirect = arg; out.lookups++; }
      continue;
    }
    out.mechanisms.push(`${q === "+" ? "" : q}${name}${arg ? ":" + arg : ""}`);
    if (name === "include") { out.lookups++; if (arg) out.includes.push(arg); }
    else if (name === "a" || name === "mx" || name === "exists") out.lookups++;
    else if (name === "ptr") { out.lookups++; out.ptr = true; }
    else if (name === "all") out.all = q;
  }
  return out;
}

/** Parse a DMARC record's tags (keys lowercased). */
export function parseDmarc(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (k && !(k in tags)) tags[k] = part.slice(i + 1).trim();
  }
  return tags;
}

/** Expand includes/redirects to count DNS lookups (RFC 7208 4.6.4 limit: 10). */
async function expandSpf(dns, domain, record, state, depth = 0) {
  const p = parseSpf(record);
  let lookups = p.lookups;
  let all = p.all;
  const targets = [...p.includes.map((d) => ({ d, kind: "include" })), ...(p.redirect ? [{ d: p.redirect, kind: "redirect" }] : [])];
  for (const { d, kind } of targets) {
    if (/%\{/.test(d)) { state.capped = true; state.notes.push(`${kind}:${d} uses SPF macros, which aren't expanded here`); continue; }
    const target = d.toLowerCase().replace(/\.$/, "");
    if (state.visited.has(target)) { state.notes.push(`${kind}:${d} was already counted (a loop or repeat)`); continue; }
    if (depth >= 4 || state.budget <= 0) { state.capped = true; continue; }
    state.visited.add(target);
    state.budget--;
    const r = await dns.soft(target, "TXT");
    const recs = r.answers.filter((s) => SPF_RE.test(s));
    if (r.status === "UNKNOWN") { state.capped = true; continue; }
    if (recs.length !== 1) {
      state.broken.push(`${kind}:${d} ${recs.length ? "has more than one SPF record" : "has no SPF record"}`);
      continue;
    }
    const sub = await expandSpf(dns, target, recs[0], state, depth + 1);
    lookups += sub.lookups;
    if (kind === "redirect" && all === null) all = sub.all;
  }
  return { lookups, all };
}

export async function emailCheck(target, fetcher, { now = () => new Date().toISOString() } = {}) {
  const dns = new Dns(fetcher);
  const d = target.domain;
  const rep = new Report();
  // The three core answers must come back; everything else degrades to "unknown".
  const [mx, rootTxt, dmarcTxt] = await Promise.all([dns.query(d, "MX"), dns.query(d, "TXT"), dns.query(`_dmarc.${d}`, "TXT")]);
  for (const r of [mx, rootTxt]) if (r.status === "SERVFAIL" || r.status === "REFUSED") throw new LookupUnavailable(`the resolver answered ${r.status} for ${d}`);
  const out = {
    domain: d, exists: true, mx: { records: [], null_mx: false }, spf: null, dmarc: null,
    dkim: { checked: DKIM_SELECTORS, found: [] }, mta_sts: null, tls_rpt: null, bimi: null,
    risk: "LOW", findings: [], notice: EMAIL_NOTICE, resolver: "cloudflare-dns.com (DNS over HTTPS)", checked_at: now(),
  };
  if (mx.status === "NXDOMAIN" && rootTxt.status === "NXDOMAIN") {
    out.exists = false;
    rep.add("DOMAIN_NOT_FOUND", "HIGH", `${d} doesn't exist in DNS (NXDOMAIN): nobody can send or receive mail as this domain.`);
    out.findings = rep.findings;
    out.risk = rep.risk();
    return out;
  }

  // MX
  out.mx.records = mx.answers.map((a) => {
    const [prio, host] = a.trim().split(/\s+/);
    return { priority: Number(prio), host: (host || "").replace(/\.$/, "") };
  }).sort((a, b) => a.priority - b.priority);
  out.mx.null_mx = out.mx.records.length === 1 && out.mx.records[0].host === "";
  if (out.mx.null_mx) rep.add("NULL_MX", "INFO", `${d} publishes a null MX (RFC 7505): it explicitly doesn't accept email.`);
  else if (!out.mx.records.length) rep.add("NO_MX", "LOW", `${d} has no MX records: it doesn't advertise a mail server (mail falls back to its A/AAAA address, if any).`);

  // Side lookups in parallel, all soft.
  const [mtaSts, tlsRpt, bimi, ...dkim] = await Promise.all([
    dns.soft(`_mta-sts.${d}`, "TXT"), dns.soft(`_smtp._tls.${d}`, "TXT"), dns.soft(`default._bimi.${d}`, "TXT"),
    ...DKIM_SELECTORS.map((s) => dns.soft(`${s}._domainkey.${d}`, "TXT")),
  ]);

  // SPF
  const spfRecs = rootTxt.answers.filter((s) => SPF_RE.test(s));
  if (!spfRecs.length) {
    rep.add("NO_SPF", "MEDIUM", "No SPF record: receivers can't check which servers may send mail as this domain.");
  } else {
    if (spfRecs.length > 1) rep.add("SPF_MULTIPLE", "HIGH", `${spfRecs.length} SPF records: RFC 7208 treats that as a permanent error, so SPF fails for every message.`);
    const state = { budget: SPF_EXPANSION_BUDGET, visited: new Set([d]), capped: false, broken: [], notes: [] };
    const exp = await expandSpf(dns, d, spfRecs[0], state);
    const p = parseSpf(spfRecs[0]);
    out.spf = {
      record: spfRecs[0], all: exp.all, lookups: exp.lookups, lookups_capped: state.capped, includes: p.includes,
      redirect: p.redirect, mechanisms: p.mechanisms, problems: state.broken, notes: state.notes,
    };
    const allMap = { "+": ["SPF_PASS_ALL", "HIGH", "SPF ends in +all: any server in the world passes SPF as this domain."], "?": ["SPF_NEUTRAL_ALL", "MEDIUM", "SPF ends in ?all (neutral): it doesn't tell receivers to reject unlisted senders."], "~": ["SPF_SOFTFAIL", "INFO", "SPF ends in ~all (soft fail): unlisted senders are marked, not rejected; -all is stricter."] };
    if (exp.all === null) rep.add("SPF_NO_ALL", "MEDIUM", "SPF has no 'all' mechanism (or redirect): unlisted senders get a neutral result.");
    else if (allMap[exp.all]) rep.add(...allMap[exp.all]);
    if (exp.lookups > 10) rep.add("SPF_TOO_MANY_LOOKUPS", "HIGH", `SPF needs ${state.capped ? "at least " : ""}${exp.lookups} DNS lookups; over 10 is a permanent error (RFC 7208 4.6.4), so SPF fails.`);
    else if (exp.lookups >= 8) rep.add("SPF_LOOKUPS_NEAR_LIMIT", "LOW", `SPF needs ${state.capped ? "at least " : ""}${exp.lookups} of the 10 allowed DNS lookups.`);
    if (p.ptr) rep.add("SPF_PTR", "LOW", "SPF uses the 'ptr' mechanism, which RFC 7208 says not to use (slow and unreliable).");
    for (const b of state.broken) rep.add("SPF_BROKEN_INCLUDE", "MEDIUM", `SPF ${b}: that's a permanent error for receivers that reach it.`);
  }

  // DMARC (falls back to the organizational domain, approximated)
  let dmarcRecs = dmarcTxt.answers.filter((s) => DMARC_RE.test(s));
  let source = d;
  if (!dmarcRecs.length) {
    const org = siteOf(d);
    if (org !== d) {
      const r = await dns.soft(`_dmarc.${org}`, "TXT");
      const recs = r.answers.filter((s) => DMARC_RE.test(s));
      if (recs.length) { dmarcRecs = recs; source = org; }
    }
  }
  if (!dmarcRecs.length) {
    rep.add("NO_DMARC", "MEDIUM", "No DMARC record: receivers get no policy for mail that fails SPF/DKIM, and spoofing this domain is easier.");
  } else {
    if (dmarcRecs.length > 1) rep.add("DMARC_MULTIPLE", "HIGH", "More than one DMARC record: receivers ignore DMARC entirely.");
    const tags = parseDmarc(dmarcRecs[0]);
    const policy = (tags.p || "").toLowerCase();
    const sp = tags.sp ? tags.sp.toLowerCase() : null;
    out.dmarc = {
      record: dmarcRecs[0], source_domain: source, policy: policy || null, subdomain_policy: sp,
      pct: tags.pct !== undefined ? Number(tags.pct) : 100, rua: tags.rua || null, ruf: tags.ruf || null,
      adkim: tags.adkim || "r", aspf: tags.aspf || "r",
    };
    if (source !== d) rep.add("DMARC_INHERITED", "INFO", `No DMARC record at ${d}; the organizational domain ${source}'s policy applies.`);
    if (!["none", "quarantine", "reject"].includes(policy)) rep.add("DMARC_INVALID", "MEDIUM", "The DMARC record has no valid p= policy, so receivers may ignore it.");
    else if (policy === "none") rep.add("DMARC_MONITOR_ONLY", "LOW", "DMARC p=none: monitoring only, failing mail is still delivered.");
    if (sp === "none" && policy !== "none") rep.add("DMARC_SUBDOMAINS_NONE", "LOW", "DMARC sp=none: subdomains aren't protected.");
    if (out.dmarc.pct < 100 && policy !== "none") rep.add("DMARC_PARTIAL", "INFO", `DMARC applies to only ${out.dmarc.pct}% of failing mail (pct=${out.dmarc.pct}).`);
    if (!out.dmarc.rua) rep.add("DMARC_NO_REPORTS", "INFO", "DMARC has no rua= address, so the owner gets no aggregate reports.");
  }

  // DKIM (common selectors only)
  dkim.forEach((r, i) => {
    const rec = r.answers.find((s) => /(^|;)\s*p\s*=/i.test(s) || /v\s*=\s*DKIM1/i.test(s));
    if (!rec) return;
    const tags = parseDmarc(rec);
    out.dkim.found.push({ selector: DKIM_SELECTORS[i], key_type: (tags.k || "rsa").toLowerCase(), revoked: tags.p !== undefined && tags.p === "" });
  });
  if (!out.dkim.found.length) rep.add("DKIM_NOT_FOUND", "INFO", `No DKIM key at the common selectors (${DKIM_SELECTORS.join(", ")}); the domain may still sign with another selector.`);

  // MTA-STS, TLS-RPT, BIMI
  const sts = mtaSts.answers.find((s) => /^v\s*=\s*STSv1/i.test(s));
  out.mta_sts = sts ? { record: sts, present: true } : { present: mtaSts.status === "UNKNOWN" ? null : false };
  const rpt = tlsRpt.answers.find((s) => /^v\s*=\s*TLSRPTv1/i.test(s));
  out.tls_rpt = rpt ? { record: rpt, present: true } : { present: tlsRpt.status === "UNKNOWN" ? null : false };
  const bi = bimi.answers.find((s) => /^v\s*=\s*BIMI1/i.test(s));
  out.bimi = bi ? { record: bi, present: true, logo: parseDmarc(bi).l || null } : { present: bimi.status === "UNKNOWN" ? null : false };
  if (!out.mx.null_mx && out.mx.records.length && out.mta_sts.present === false) {
    rep.add("NO_MTA_STS", "INFO", "No MTA-STS: senders can't require TLS when delivering to this domain.");
  }

  out.findings = rep.findings;
  out.risk = rep.risk();
  return out;
}
