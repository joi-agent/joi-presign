// Outbound fetches to URLs that callers supply (/x402-check, /robots): https only, public DNS names only (no IP
// literals, no local or internal names), default port, no credentials, at most 2 redirects and only within the same
// site, one overall time limit and a size cap. Workers can't reach private networks anyway; these rules keep the
// service pointed at the public web and stop it from being used as an open proxy.
import { LookupUnavailable } from "./profile.js";

export class UnsafeUrl extends Error {}

const BLOCKED_SUFFIXES = [
  ".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".home.arpa", ".corp", ".private",
  ".test", ".example", ".invalid", ".onion", ".arpa", ".localdomain",
];
// Shared-hosting suffixes where every subdomain is a different site (a hand-picked subset of the Public Suffix List).
const PUBLIC_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "co.za", "com.br", "com.cn",
  "com.mx", "co.in", "co.kr", "com.tr", "com.sg", "com.hk", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
  "github.io", "herokuapp.com", "fly.dev", "onrender.com", "web.app", "firebaseapp.com", "appspot.com",
  "azurewebsites.net", "cloudfront.net", "amazonaws.com", "replit.app", "glitch.me", "deno.dev", "railway.app",
  "up.railway.app", "trycloudflare.com", "ngrok.io", "ngrok-free.app", "gitlab.io", "blogspot.com",
]);

/** A URL object for a public https URL, or throws UnsafeUrl with a plain-language reason. */
export function checkUrl(raw) {
  if (typeof raw !== "string" || raw.trim() === "") throw new UnsafeUrl("url is required (an https:// URL)");
  if (raw.length > 2048) throw new UnsafeUrl("url is longer than 2048 characters");
  let u;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new UnsafeUrl("url is not a valid URL");
  }
  if (u.protocol !== "https:") throw new UnsafeUrl("only https:// URLs are checked");
  if (u.username || u.password) throw new UnsafeUrl("URLs with credentials are refused");
  if (u.port !== "" && u.port !== "443") throw new UnsafeUrl("only the default https port (443) is allowed");
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || host.includes(":")) throw new UnsafeUrl("IP addresses are refused; use a public host name");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) throw new UnsafeUrl("IP addresses are refused; use a public host name");
  if (!host.includes(".") || host.split(".").some((l) => l === "")) throw new UnsafeUrl("the host name must be a public domain name");
  if (host === "localhost" || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) throw new UnsafeUrl("local or internal host names are refused");
  u.hash = "";
  return u;
}

/** The registrable site of a host name: the public suffix plus one label (approximation of eTLD+1). */
export function siteOf(hostname) {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  for (let i = 1; i < labels.length; i++) {
    const suffix = labels.slice(i).join(".");
    if (PUBLIC_SUFFIXES.has(suffix)) return labels.slice(i - 1).join(".");
  }
  return labels.slice(-2).join(".");
}

async function readCapped(r, maxBytes) {
  let truncated = false;
  if (r.body && typeof r.body.getReader === "function") {
    const reader = r.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (total + value.length > maxBytes) {
        chunks.push(value.slice(0, maxBytes - total));
        truncated = true;
        reader.cancel().catch(() => {}); // don't await: on a tee'd body it waits for the other branch
        break;
      }
      chunks.push(value);
      total += value.length;
    }
    const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let off = 0;
    for (const c of chunks) { all.set(c, off); off += c.length; }
    return { text: new TextDecoder().decode(all), truncated };
  }
  const t = await r.text();
  return t.length > maxBytes ? { text: t.slice(0, maxBytes), truncated: true } : { text: t, truncated };
}

export class SafeFetcher {
  constructor({ fetchFn = fetch, maxRequests = 10, timeoutMs = 8000, maxBytes = 256 * 1024, maxRedirects = 2, clock = () => Date.now() } = {}) {
    Object.assign(this, { fetchFn, remaining: maxRequests, timeoutMs, maxBytes, maxRedirects, clock });
  }

  /**
   * {status, headers, text, truncated, url (final), redirects[], blocked} for an https URL. Redirects are followed
   * only within the same site; anything else stops with `blocked` set to a reason. Network failures and timeouts
   * throw LookupUnavailable.
   */
  async fetch(rawUrl, { method = "GET", body, headers = {}, maxBytes } = {}) {
    let url = checkUrl(typeof rawUrl === "string" ? rawUrl : String(rawUrl));
    const site = siteOf(url.hostname);
    const redirects = [];
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      for (let hop = 0; ; hop++) {
        if (this.remaining <= 0) throw new LookupUnavailable("outbound request budget exhausted");
        this.remaining--;
        let r;
        try {
          r = await this.fetchFn(url.toString(), {
            method,
            redirect: "manual",
            headers: { "User-Agent": "joi-presign/0.1 (+https://joi-presign.joi-agent.workers.dev)", Accept: "*/*", ...headers },
            body: method === "GET" || method === "HEAD" ? undefined : body,
            signal: ctrl.signal,
          });
        } catch {
          throw new LookupUnavailable(`could not reach ${url.hostname}`);
        }
        if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
          const loc = r.headers.get("location");
          const base = { status: r.status, headers: r.headers, text: "", truncated: false, url: url.toString(), redirects };
          if (hop >= this.maxRedirects) return { ...base, blocked: `more than ${this.maxRedirects} redirects` };
          let next;
          try {
            next = checkUrl(new URL(loc, url).toString());
          } catch (e) {
            return { ...base, blocked: `redirect to a refused URL: ${e.message}` };
          }
          if (siteOf(next.hostname) !== site) return { ...base, blocked: `redirect to another site (${next.hostname}) not followed` };
          redirects.push(next.toString());
          url = next;
          continue;
        }
        let read;
        try {
          read = method === "HEAD" ? { text: "", truncated: false } : await readCapped(r, maxBytes ?? this.maxBytes);
        } catch {
          throw new LookupUnavailable(`could not read the response from ${url.hostname}`);
        }
        return { status: r.status, headers: r.headers, text: read.text, truncated: read.truncated, url: url.toString(), redirects, blocked: null };
      }
    } finally {
      clearTimeout(timer);
    }
  }
}
