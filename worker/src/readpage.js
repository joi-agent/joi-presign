// /read (a web page as clean Markdown + metadata) and /url-meta (status, headers, title, OpenGraph, favicon...).
// Both behave like a polite crawler named "joi-reader": robots.txt is read first and a disallowed URL is never
// fetched. A refusal (robots, error page, unsupported content type) answers without settling the payment.
import { checkUrl, Refused } from "./fetchsafe.js";
import { evaluate, parseRobots } from "./robots.js";
import { parseHtml, pageMetadata, scanHead, selectContent, textOf, toMarkdown, wordCount } from "./html.js";

export const READER_TOKEN = "joi-reader";
export const READER_UA = "joi-reader/0.1 (AI agent; +https://joi-presign.joi-agent.workers.dev)";
export const READ_MAX_BYTES = 1024 * 1024; // keeps the strip pass ~1-2 ms
export const META_MAX_BYTES = 1024 * 1024;
// Workers CPU budget: HTML parsing is the expensive part. Scripts, styles, SVG and comments are removed with native
// regexes first, and at most this much HTML is parsed into the tree.
export const PARSE_MAX_CHARS = 100 * 1024; // ~3.5 ms warm to parse+convert on a 600 KB Wikipedia page; free plan CPU is 10 ms

/** Cheap pre-pass: drop script/style/svg/noscript/template blocks and comments, then cap the size. */
export function prepareHtml(html) {
  const stripped = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style|svg|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, "");
  if (stripped.length <= PARSE_MAX_CHARS) return { html: stripped, cut: false };
  const cutAt = stripped.lastIndexOf("<", PARSE_MAX_CHARS);
  return { html: stripped.slice(0, cutAt > 0 ? cutAt : PARSE_MAX_CHARS), cut: true };
}

/** The <head> part only (for metadata): up to </head>, or the first 64 KB. */
export function headOnly(html) {
  const m = /<\/head\s*>|<body[\s>]/i.exec(html);
  return m ? html.slice(0, m.index) : html.slice(0, 64 * 1024);
}
const HEADERS = { "User-Agent": READER_UA, Accept: "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.8,*/*;q=0.1" };

export function parsePageTarget(urlRaw) {
  try {
    return { url: checkUrl(urlRaw).toString() };
  } catch (e) {
    return { error: e.message };
  }
}

/** robots.txt verdict for joi-reader (RFC 9309: its own group if any, else "*"). Cached per origin per call. */
export async function robotsVerdict(fetcher, url, cache) {
  const u = new URL(url);
  const robotsUrl = u.origin + "/robots.txt";
  let parsed = cache.get(u.origin);
  if (parsed === undefined) {
    const r = await fetcher.fetch(robotsUrl, { headers: HEADERS, maxBytes: 512 * 1024 });
    if (r.blocked) parsed = { unavailable: `its redirect wasn't followed (${r.blocked})` };
    else if (r.status >= 200 && r.status < 300) parsed = parseRobots(r.text);
    else if (r.status === 429 || r.status >= 500) parsed = { unreachable: r.status };
    else parsed = { unavailable: `HTTP ${r.status}` };
    cache.set(u.origin, parsed);
  }
  const path = (u.pathname || "/") + (u.search || "");
  if (parsed.unreachable) {
    return { verdict: "disallowed", robots_url: robotsUrl, rule: null, group: null, reason: `robots.txt answered HTTP ${parsed.unreachable}; RFC 9309 says to assume a complete disallow while it's unreachable` };
  }
  if (parsed.unavailable) return { verdict: "allowed", robots_url: robotsUrl, rule: null, group: null, note: `robots.txt unavailable (${parsed.unavailable}): no restrictions apply` };
  const d = evaluate(parsed, READER_TOKEN, path);
  if (d.verdict === "disallowed") {
    return { verdict: "disallowed", robots_url: robotsUrl, rule: d.rule, group: d.group, reason: `robots.txt disallows this path for ${READER_TOKEN} (group "${d.group}", rule "${d.rule}")` };
  }
  return { verdict: "allowed", robots_url: robotsUrl, rule: d.rule, group: d.group };
}

function refuseRobots(url, rb) {
  return new Refused(451, {
    allowed: false, url, reason: rb.reason, robots_url: rb.robots_url, rule: rb.rule, group: rb.group,
    user_agent: READER_UA, charged: false, note: "The page was not fetched and you were not charged.",
  });
}

/** Fetch the page after the robots check; re-check robots when a same-site redirect lands on another URL. */
async function politeFetch(target, fetcher, maxBytes, clock = () => Date.now()) {
  const cache = new Map();
  const rb = await robotsVerdict(fetcher, target.url, cache);
  if (rb.verdict === "disallowed") throw refuseRobots(target.url, rb);
  const t0 = clock();
  const r = await fetcher.fetch(target.url, { headers: HEADERS, maxBytes });
  const ms = Math.max(0, clock() - t0);
  let robots = rb;
  if (r.url !== target.url) {
    const rb2 = await robotsVerdict(fetcher, r.url, cache);
    if (rb2.verdict === "disallowed") throw refuseRobots(r.url, rb2);
    robots = rb2;
  }
  return { r, robots, ms };
}

const contentType = (r) => (r.headers.get("content-type") || "").toLowerCase().split(";")[0].trim();
const looksHtml = (text) => /^\s*(<!--[\s\S]*?-->\s*)*<(!doctype\s+html|html|head|body)\b/i.test(text.slice(0, 2048));

function robotsSummary(rb) {
  const out = { verdict: rb.verdict, rule: rb.rule, group: rb.group };
  if (rb.note) out.note = rb.note;
  return out;
}

export async function readPage(target, fetcher, { clock, now = () => new Date().toISOString() } = {}) {
  const { r, robots } = await politeFetch(target, fetcher, READ_MAX_BYTES, clock);
  const base = { url: target.url, final_url: r.url, http_status: r.status, charged: false };
  if (r.blocked) throw new Refused(422, { ...base, reason: `the page ${r.blocked}`, note: "Nothing was read and you were not charged." });
  if (r.status < 200 || r.status >= 300) {
    throw new Refused(422, { ...base, reason: `the page answered HTTP ${r.status}`, note: "Nothing was read and you were not charged." });
  }
  const ct = contentType(r);
  const notes = [];
  if (r.truncated) notes.push(`The page is larger than ${READ_MAX_BYTES / 1048576} MB; only the first ${READ_MAX_BYTES / 1048576} MB was read.`);
  let out;
  if (ct === "text/plain" || (ct === "" && !looksHtml(r.text))) {
    const text = r.text.replace(/\r\n?/g, "\n").trim();
    out = { title: null, byline: null, published: null, canonical: null, language: r.headers.get("content-language") || null, description: null, site_name: null, markdown: text, links_count: 0 };
  } else if (ct === "text/html" || ct === "application/xhtml+xml" || (ct === "" && looksHtml(r.text))) {
    const prepared = prepareHtml(r.text);
    if (prepared.cut) notes.push(`The page's HTML is very large; only the first ${PARSE_MAX_CHARS / 1024} KB (after removing scripts and styles) was converted.`);
    const doc = parseHtml(prepared.html);
    const content = selectContent(doc);
    const meta = pageMetadata(doc, r.url, content);
    const { markdown, links } = toMarkdown(content, meta.base);
    out = {
      title: meta.title, byline: meta.byline, published: meta.published, canonical: meta.canonical,
      language: meta.language || r.headers.get("content-language") || null, description: meta.description,
      site_name: meta.site_name, markdown, links_count: links,
    };
    if (!markdown) notes.push("No readable text was found; the page may build its content with JavaScript, which this reader doesn't run.");
  } else {
    throw new Refused(415, { ...base, content_type: ct || null, reason: `the page is ${ct || "of unknown type"}, not HTML or plain text`, note: "Nothing was read and you were not charged." });
  }
  return {
    url: target.url, final_url: r.url, http_status: r.status, allowed: true, robots: robotsSummary(robots),
    title: out.title, byline: out.byline, published: out.published, canonical: out.canonical, language: out.language,
    description: out.description, site_name: out.site_name,
    word_count: wordCount(out.markdown), links_count: out.links_count, content_type: ct || null, truncated: r.truncated,
    markdown: out.markdown, notes, user_agent: READER_UA, fetched_at: now(),
  };
}

// ---------------------------------------------------------------- /url-meta

const SECURITY_HEADERS = {
  hsts: "strict-transport-security", csp: "content-security-policy", x_frame_options: "x-frame-options",
  x_content_type_options: "x-content-type-options", referrer_policy: "referrer-policy", permissions_policy: "permissions-policy",
};

function prefixed(meta, prefix) {
  const out = {};
  for (const [k, v] of Object.entries(meta)) if (k.startsWith(prefix)) out[k.slice(prefix.length)] = v.slice(0, 1000);
  return out;
}

function robotsMeta(meta) {
  const raw = meta.robots || null;
  const directives = new Set((raw || "").toLowerCase().split(/\s*,\s*/).filter(Boolean));
  const none = directives.has("none");
  return {
    raw, noindex: none || directives.has("noindex"), nofollow: none || directives.has("nofollow"),
    noarchive: directives.has("noarchive"), nosnippet: directives.has("nosnippet"), noai: directives.has("noai") || directives.has("noimageai"),
    googlebot: meta.googlebot || null,
  };
}

function favicon(rels, origin) {
  const icons = rels.filter((l) => l.rel.includes("icon"));
  const pick = icons.find((l) => (l.type || "").includes("svg")) || icons.find((l) => l.sizes && /\d/.test(l.sizes)) || icons[0]
    || rels.find((l) => l.rel.includes("apple-touch-icon"));
  if (pick) return { url: pick.href, source: "link" };
  return { url: origin + "/favicon.ico", source: "default (not checked)" };
}

export async function urlMeta(target, fetcher, { clock, now = () => new Date().toISOString() } = {}) {
  const { r, robots, ms } = await politeFetch(target, fetcher, META_MAX_BYTES, clock);
  const ct = contentType(r);
  const security = {};
  for (const [k, h] of Object.entries(SECURITY_HEADERS)) {
    const v = r.headers.get(h);
    security[k] = v ? { present: true, value: v.slice(0, 500) } : { present: false };
  }
  const notes = [];
  const out = {
    url: target.url, final_url: r.url, redirects: r.redirects, http_status: r.status, response_ms: ms,
    content_type: ct || null, content_length: r.headers.get("content-length") ? Number(r.headers.get("content-length")) : null,
    bytes_read: new TextEncoder().encode(r.text).length, truncated: r.truncated,
    title: null, description: null, canonical: null, favicon: null, language: r.headers.get("content-language") || null,
    open_graph: {}, twitter: {}, robots_meta: null, x_robots_tag: r.headers.get("x-robots-tag") || null,
    security_headers: security, server: r.headers.get("server") || null, robots: robotsSummary(robots), notes,
    user_agent: READER_UA, fetched_at: now(),
  };
  if (r.blocked) {
    out.blocked = r.blocked;
    notes.push(`Stopped at a redirect: ${r.blocked}.`);
    return out;
  }
  if (ct === "text/html" || ct === "application/xhtml+xml" || (ct === "" && looksHtml(r.text))) {
    const doc = parseHtml(headOnly(r.text));
    const h = scanHead(doc, r.url);
    const meta = h.meta;
    const rels = h.rels;
    out.title = h.title ? textOf(h.title).replace(/\s+/g, " ").trim().slice(0, 500) || null : null;
    out.description = meta.description ? meta.description.slice(0, 1000) : null;
    out.canonical = (rels.find((l) => l.rel.includes("canonical")) || {}).href || null;
    out.favicon = favicon(rels, new URL(r.url).origin);
    out.language = (h.html && h.html.attrs.lang) || out.language;
    out.open_graph = prefixed(meta, "og:");
    out.twitter = prefixed(meta, "twitter:");
    out.robots_meta = robotsMeta(meta);
    if (out.robots_meta.noindex) notes.push("The page asks search engines not to index it (robots meta noindex).");
    if (!out.title) notes.push("The page has no <title>.");
    out.images_count = (r.text.match(/<img\b/gi) || []).length;
  }
  if (r.status >= 400) notes.push(`The page answered HTTP ${r.status}.`);
  if (!security.hsts.present) notes.push("No Strict-Transport-Security header.");
  return out;
}
