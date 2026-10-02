// robots.txt per RFC 9309: groups by user-agent (case-insensitive product token, matching groups merged, "*" as the
// fallback), Allow/Disallow with "*" and "$", the longest match wins and Allow wins a tie. Fetch outcomes follow the
// RFC: 4xx = no restrictions, 5xx/unreachable = assume complete disallow.
import { checkUrl } from "./fetchsafe.js";
import { LookupUnavailable } from "./profile.js";

export const AGENTS = ["*", "GPTBot", "ClaudeBot", "Claude-User", "Google-Extended", "CCBot", "PerplexityBot"];
export const ROBOTS_NOTICE =
  "robots.txt states a site's crawling preferences (RFC 9309). It isn't a terms-of-service or a license: a site's " +
  "terms may still forbid automated access, and robots.txt doesn't grant permission to use the content.";
const PARSE_LIMIT = 500 * 1024; // RFC 9309 2.5: parse at least 500 KiB
const MAX_RULES = 5000; // keeps a call inside the Workers CPU limit; real files are far smaller

export function parseRobotsTarget(urlRaw, agentRaw) {
  let u;
  try {
    u = checkUrl(urlRaw);
  } catch (e) {
    return { error: e.message };
  }
  let agent = null;
  if (agentRaw !== undefined && agentRaw !== null && agentRaw !== "") {
    if (typeof agentRaw !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(agentRaw)) return { error: "agent must be a product token of letters, digits, '_' or '-' (max 64)" };
    agent = agentRaw;
  }
  return { url: u.toString(), agent };
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;

/** Percent-encoding normalization (RFC 9309 2.2.2): UTF-8 encode non-ASCII, decode unreserved, uppercase hex.
 *  For a URL path (not a rule), a literal "*" or "$" is encoded as %2A / %24 so only rules spelling them that way match it. */
export function normalizePath(s, isPath = false) {
  if (/^[\x21-\x7e]*$/.test(s) && !s.includes("%") && !(isPath && /[*$]/.test(s))) return s; // common fast path
  let out = "";
  const bytes = new TextEncoder().encode(s);
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x25 && i + 2 < bytes.length && /^[0-9A-Fa-f]{2}$/.test(String.fromCharCode(bytes[i + 1], bytes[i + 2]))) {
      const hex = String.fromCharCode(bytes[i + 1], bytes[i + 2]).toUpperCase();
      const ch = String.fromCharCode(parseInt(hex, 16));
      out += UNRESERVED.test(ch) ? ch : "%" + hex;
      i += 2;
    } else if (b < 0x21 || b > 0x7e || (isPath && (b === 0x2a || b === 0x24))) {
      out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    } else {
      out += String.fromCharCode(b);
    }
  }
  return out;
}

export function parseRobots(text) {
  const groups = [];
  const sitemaps = [];
  let cur = null;
  let lastWasAgent = false;
  let ruleCount = 0;
  let truncatedRules = false;
  for (let line of String(text).slice(0, PARSE_LIMIT).split(/\r\n|\r|\n/)) {
    const hash = line.indexOf("#");
    if (hash >= 0) line = line.slice(0, hash);
    const colon = line.indexOf(":");
    if (colon < 1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    if (!/^[a-z-]+$/.test(key)) continue;
    const value = line.slice(colon + 1).trim();
    if (key === "user-agent") {
      if (!cur || !lastWasAgent) {
        cur = { agents: [], rules: [] };
        groups.push(cur);
      }
      const token = value === "*" ? "*" : (value.match(/^[A-Za-z_-]+/) || [""])[0].toLowerCase();
      if (token) cur.agents.push(token);
      lastWasAgent = true;
    } else if (key === "allow" || key === "disallow") {
      lastWasAgent = false;
      if (cur && ruleCount < MAX_RULES) { cur.rules.push({ allow: key === "allow", pattern: value }); ruleCount++; }
      else if (cur) truncatedRules = true;
    } else if (key === "sitemap") {
      if (value) sitemaps.push(value);
    } else {
      lastWasAgent = false;
    }
  }
  return { groups, sitemaps, truncatedRules };
}

function patternRegex(pattern) {
  const norm = normalizePath(pattern);
  const anchored = norm.endsWith("$");
  const body = anchored ? norm.slice(0, -1) : norm;
  const star = body.indexOf("*");
  const literal = star < 0 ? body : body.slice(0, star);
  // Plain prefix rules (the vast majority) need no regex.
  if (star < 0 && !anchored) return { prefix: body, re: null, literal, length: norm.length };
  const re = body.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return { prefix: null, re: new RegExp("^" + re + (anchored ? "$" : "")), literal, length: norm.length };
}

/** {verdict: allowed|disallowed|no rule, group, rule} for one agent and path. */
export function evaluate(parsed, agent, path) {
  const token = agent === "*" ? "*" : agent.toLowerCase();
  let matched = token === "*" ? [] : parsed.groups.filter((g) => g.agents.includes(token));
  let group = matched.length ? agent : null;
  if (!matched.length) {
    matched = parsed.groups.filter((g) => g.agents.includes("*"));
    group = matched.length ? "*" : null;
  }
  if (!matched.length) return { verdict: "no rule", group: null, rule: null };
  const p = normalizePath(path || "/", true);
  if (p === "/robots.txt") return { verdict: "allowed", group, rule: "(robots.txt itself is always allowed)" };
  let best = null;
  for (const r of matched.flatMap((g) => g.rules)) {
    if (r.pattern === "") continue;
    if (!r.compiled) r.compiled = patternRegex(r.pattern);
    const { prefix, re, literal, length } = r.compiled;
    if (prefix !== null ? !p.startsWith(prefix) : !p.startsWith(literal) || !re.test(p)) continue;
    if (!best || length > best.length || (length === best.length && r.allow && !best.allow)) best = { ...r, length };
  }
  if (!best) return { verdict: "no rule", group, rule: null };
  return { verdict: best.allow ? "allowed" : "disallowed", group, rule: `${best.allow ? "Allow" : "Disallow"}: ${best.pattern}` };
}

async function sidecar(fetcher, url) {
  try {
    const r = await fetcher.fetch(url, { maxBytes: 4096 });
    if (r.blocked || r.status !== 200) return { present: false, status: r.status };
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    return { present: !ct.includes("text/html") && !/^\s*<(!doctype|html)/i.test(r.text), status: r.status };
  } catch {
    return { present: null, status: null };
  }
}

export async function checkRobots(target, fetcher) {
  const u = new URL(target.url);
  const origin = u.origin;
  const path = (u.pathname || "/") + (u.search || "");
  const agents = target.agent && !AGENTS.some((a) => a.toLowerCase() === target.agent.toLowerCase()) ? [...AGENTS, target.agent] : AGENTS;
  const r = await fetcher.fetch(origin + "/robots.txt", { maxBytes: 512 * 1024 });
  const notes = [];
  let parsed = { groups: [], sitemaps: [] };
  let robotsFound = false;
  let assume = null;
  if (r.blocked) {
    assume = "unknown";
    notes.push(`robots.txt redirects and the redirect wasn't followed (${r.blocked}); RFC 9309 asks crawlers to follow at least 5 redirects, this service follows only 2 within the same site.`);
  } else if (r.status >= 200 && r.status < 300) {
    robotsFound = true;
    parsed = parseRobots(r.text);
    if (r.truncated) notes.push("robots.txt is larger than 512 KiB; only the start was read (RFC 9309 requires at least 500 KiB to be parsed).");
    if (parsed.truncatedRules) notes.push(`robots.txt has more than ${MAX_RULES} rules; only the first ${MAX_RULES} were evaluated.`);
  } else if (r.status === 429 || r.status >= 500) {
    assume = "disallowed";
    notes.push(`robots.txt answered HTTP ${r.status}: RFC 9309 says to assume complete disallow while it's unreachable.`);
  } else if (r.status >= 400) {
    notes.push(`robots.txt answered HTTP ${r.status} (unavailable): RFC 9309 lets crawlers access everything.`);
  } else {
    assume = "unknown";
    notes.push(`robots.txt answered HTTP ${r.status}.`);
  }
  const results = {};
  const details = {};
  for (const a of agents) {
    const d = assume ? { verdict: assume, group: null, rule: null } : evaluate(parsed, a, path);
    results[a] = d.verdict;
    details[a] = d;
  }
  const [ai, llms] = await Promise.all([sidecar(fetcher, origin + "/ai.txt"), sidecar(fetcher, origin + "/llms.txt")]);
  return {
    url: target.url, origin, path, robots_url: origin + "/robots.txt", robots_found: robotsFound, http_status: r.status,
    results, details, sitemaps: parsed.sitemaps, ai_txt: ai, llms_txt: llms,
    legend: { allowed: "an Allow rule is the most specific match", disallowed: "a Disallow rule is the most specific match", "no rule": "nothing matches this path: allowed by default", unknown: "robots.txt couldn't be read" },
    notes, notice: ROBOTS_NOTICE,
  };
}

export { LookupUnavailable };
