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

  /** Runtime bytecode as 0x-hex, or null if unknown. Shares the eth_getCode memo with codeKind. */
  async getCode(chainId, a) {
    const code = await this.rpc(chainId, "eth_getCode", [a, "latest"]);
    return typeof code === "string" && /^0x[0-9a-f]*$/i.test(code) ? code.toLowerCase() : null;
  }

  /** Native balance in wei as a BigInt, or null if unknown. */
  async balance(chainId, a) {
    const v = await this.rpc(chainId, "eth_getBalance", [a, "latest"]);
    return typeof v === "string" && /^0x[0-9a-f]+$/i.test(v) ? BigInt(v) : null;
  }

  /** A 32-byte storage word as 0x-hex, or null if unknown. */
  async getStorageAt(chainId, a, slot) {
    const v = await this.rpc(chainId, "eth_getStorageAt", [a, slot, "latest"]);
    return typeof v === "string" && /^0x[0-9a-f]{1,64}$/i.test(v) ? "0x" + v.slice(2).toLowerCase().padStart(64, "0") : null;
  }

  /** eth_call return data as 0x-hex, or null on revert or failure. */
  async ethCall(chainId, to, data) {
    const v = await this.rpc(chainId, "eth_call", [{ to, data }, "latest"]);
    return typeof v === "string" && /^0x[0-9a-f]*$/i.test(v) ? v.toLowerCase() : null;
  }

  /** {verified: true|false|null, name: string|null} from Sourcify, including the contract name when verified. */
  async sourcifyInfo(chainId, a) {
    const key = `sourcify-info:${chainId}:${a.toLowerCase()}`;
    if (this.memo.has(key)) return this.memo.get(key);
    let result = { verified: null, name: null };
    try {
      const r = await this.request(SOURCIFY(chainId, a) + "?fields=compilation");
      if (r.status === 404) result = { verified: false, name: null };
      else if (r.ok) {
        const d = await r.json();
        const verified = ["match", "exact_match", "partial", "perfect"].includes(d.match);
        const name = verified && d.compilation && typeof d.compilation.name === "string" ? d.compilation.name : null;
        result = { verified, name };
      }
    } catch { /* unknown */ }
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
