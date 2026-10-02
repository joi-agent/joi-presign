// Network lookups with timeouts. Every method resolves to null when the answer is unknown.
// One instance per request: memoizes within the request and caps subrequests (Workers limit them).

export const RPCS = {
  1: "https://ethereum-rpc.publicnode.com",
  42161: "https://arb1.arbitrum.io/rpc",
  8453: "https://mainnet.base.org",
};
const SOURCIFY = (chain, a) => `https://sourcify.dev/server/v2/contract/${chain}/${a}`;
const FOURBYTE = (sel) => `https://www.4byte.directory/api/v1/signatures/?hex_signature=${sel}`;

// Per-isolate cache of 4byte answers: public data, safe to share between requests.
const fourbyteCache = new Map();

export class NetLookups {
  constructor({ fetchFn = fetch, timeoutMs = 5000, maxRequests = 40, clock = () => Date.now() / 1000 } = {}) {
    this.fetchFn = fetchFn;
    this.timeoutMs = timeoutMs;
    this.remaining = maxRequests;
    this.clock = clock;
    this.memo = new Map();
  }

  now() {
    return Math.floor(this.clock());
  }

  async request(url, body) {
    if (this.remaining <= 0) throw new Error("subrequest budget exhausted");
    this.remaining--;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      return await this.fetchFn(url, {
        method: body === undefined ? "GET" : "POST",
        headers: { "User-Agent": "joi-presign/0.1", Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  async rpc(chainId, method, params) {
    const url = RPCS[chainId];
    if (!url) return null;
    const key = JSON.stringify([chainId, method, params]);
    if (this.memo.has(key)) return this.memo.get(key);
    let result = null;
    try {
      const r = await this.request(url, { jsonrpc: "2.0", id: 1, method, params });
      if (r.ok) result = (await r.json()).result ?? null;
    } catch { result = null; }
    this.memo.set(key, result);
    return result;
  }

  /** 'none' (no code), '7702' (EOA with delegation), 'contract', or null if unknown. */
  async codeKind(chainId, a) {
    const code = await this.rpc(chainId, "eth_getCode", [a, "latest"]);
    if (typeof code !== "string") return null;
    if (code === "0x" || code === "0x0") return "none";
    if (code.toLowerCase().startsWith("0xef0100") && code.length === 2 + 46) return "7702";
    return "contract";
  }

  async txCount(chainId, a) {
    const n = await this.rpc(chainId, "eth_getTransactionCount", [a, "latest"]);
    if (typeof n !== "string" || !/^0x[0-9a-f]+$/i.test(n)) return null;
    return Number.parseInt(n, 16);
  }

  async sourcifyVerified(chainId, a) {
    const key = `sourcify:${chainId}:${a.toLowerCase()}`;
    if (this.memo.has(key)) return this.memo.get(key);
    let result = null;
    try {
      const r = await this.request(SOURCIFY(chainId, a));
      if (r.status === 404) result = false;
      else if (r.ok) result = ["match", "exact_match", "partial", "perfect"].includes((await r.json()).match);
    } catch { result = null; }
    this.memo.set(key, result);
    return result;
  }

  /** Text signatures for a selector, oldest registration first (newer ones are often spam). */
  async selectorSignatures(sel) {
    if (fourbyteCache.has(sel)) return fourbyteCache.get(sel);
    try {
      const r = await this.request(FOURBYTE(sel));
      if (!r.ok) return null;
      const results = (await r.json()).results || [];
      const sigs = results
        .filter((x) => typeof x.text_signature === "string")
        .sort((x, y) => (x.id || 0) - (y.id || 0))
        .map((x) => x.text_signature);
      fourbyteCache.set(sel, sigs);
      return sigs;
    } catch {
      return null;
    }
  }
}

export function _clearFourbyteCache() {
  fourbyteCache.clear();
}
