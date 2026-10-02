// Network lookups with timeouts. Every method resolves to null when the answer is unknown.
// One instance per request: memoizes within the request and caps subrequests (Workers limit them).

export const RPCS = {
  1: "https://ethereum-rpc.publicnode.com",
  42161: "https://arb1.arbitrum.io/rpc",
  8453: "https://base-rpc.publicnode.com",
};
// Checked 2026-10-02: publicnode serves bursts of state reads but refuses some tx/receipt lookups on Base and
// Arbitrum ("archive requests require a personal token"); the official Base/Arbitrum RPCs serve those but rate-limit
// bursts (HTTP 429). cloudflare-eth was rejected: it answered null for a real recent transaction.
const HISTORY = new Set(["eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber"]);
const ENDPOINTS = {
  1: { state: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"], history: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"] },
  42161: { state: ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"], history: ["https://arb1.arbitrum.io/rpc"] },
  8453: { state: ["https://base-rpc.publicnode.com", "https://mainnet.base.org"], history: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"] },
};
export function endpointsFor(chainId, method) {
  const e = ENDPOINTS[chainId];
  if (!e) return [];
  return HISTORY.has(method) ? e.history : e.state;
}
const isRevert = (err) => err && (err.code === 3 || String(err.message || "").toLowerCase().includes("revert"));

const SOURCIFY = (chain, a) => `https://sourcify.dev/server/v2/contract/${chain}/${a}`;
const FOURBYTE = (sel) => `https://www.4byte.directory/api/v1/signatures/?hex_signature=${sel}`;
const FOURBYTE_EVENT = (t) => `https://www.4byte.directory/api/v1/event-signatures/?hex_signature=${t}`;

// Per-isolate cache of 4byte answers: public data, safe to share between requests.
const fourbyteCache = new Map();
const fourbyteEventCache = new Map();

export class NetLookups {
  constructor({ fetchFn = fetch, timeoutMs = 5000, maxRequests = 40, clock = () => Date.now() / 1000, retryDelaysMs = [300, 900] } = {}) {
    this.fetchFn = fetchFn;
    this.retryDelaysMs = retryDelaysMs;
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

  /** {ok: true, result} when the node answered (result may be null = "not found"), {ok: false} on any failure. */
  async rpcStatus(chainId, method, params) {
    const urls = endpointsFor(chainId, method);
    if (!urls.length) return { ok: false };
    const key = JSON.stringify([chainId, method, params]);
    if (this.memo.has(key)) return this.memo.get(key);
    let out = { ok: false };
    // Public RPCs rate-limit bursts (429) or refuse some calls with a JSON error: retry on the next endpoint,
    // with a short backoff after a 429/503, within the subrequest budget. Reverts are answers, not retried.
    let lastStatus = 0;
    for (let attempt = 0; attempt <= this.retryDelaysMs.length; attempt++) {
      if (attempt > 0 && (lastStatus === 429 || lastStatus === 503)) await new Promise((res) => setTimeout(res, this.retryDelaysMs[attempt - 1]));
      let retryable = false;
      lastStatus = 0;
      try {
        const r = await this.request(urls[Math.min(attempt, urls.length - 1)], { jsonrpc: "2.0", id: 1, method, params });
        lastStatus = r.status;
        if (r.ok) {
          const d = await r.json();
          if (d && typeof d === "object" && !d.error && "result" in d) out = { ok: true, result: d.result ?? null };
          else if (d && d.error && !isRevert(d.error)) retryable = true;
        } else if (r.status === 429 || r.status === 503) retryable = true;
      } catch { out = { ok: false }; }
      if (out.ok || !retryable || this.remaining <= 0) break;
    }
    this.memo.set(key, out);
    return out;
  }

  async rpc(chainId, method, params) {
    const r = await this.rpcStatus(chainId, method, params);
    return r.ok ? r.result : null;
  }

  /** The transaction object, false if the node says it doesn't exist, null if unknown (lookup failed). */
  async getTransaction(chainId, hash) {
    const r = await this.rpcStatus(chainId, "eth_getTransactionByHash", [hash]);
    if (!r.ok) return null;
    return r.result && typeof r.result === "object" ? r.result : false;
  }

  /** The receipt, false if there is none yet (pending or unknown tx), null if the lookup failed. */
  async getReceipt(chainId, hash) {
    const r = await this.rpcStatus(chainId, "eth_getTransactionReceipt", [hash]);
    if (!r.ok) return null;
    return r.result && typeof r.result === "object" ? r.result : false;
  }

  /** Block header (no transactions) or null. */
  async getBlock(chainId, numberHex) {
    const b = await this.rpc(chainId, "eth_getBlockByNumber", [numberHex, false]);
    return b && typeof b === "object" ? b : null;
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

  /** eth_call telling a revert apart from a failed lookup: {status: "ok", data} | {status: "reverted"} | {status: "unknown"}. */
  async ethCallStrict(chainId, to, data) {
    const url = endpointsFor(chainId, "eth_call")[0];
    if (!url) return { status: "unknown" };
    try {
      const r = await this.request(url, { jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] });
      if (!r.ok) return { status: "unknown" };
      const d = await r.json();
      if (d && d.error) {
        const msg = String(d.error.message || "").toLowerCase();
        return d.error.code === 3 || msg.includes("revert") ? { status: "reverted" } : { status: "unknown" };
      }
      return d && typeof d.result === "string" && /^0x[0-9a-f]*$/i.test(d.result) ? { status: "ok", data: d.result.toLowerCase() } : { status: "unknown" };
    } catch {
      return { status: "unknown" };
    }
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

  /** Text signatures for an event topic0, oldest first. */
  async eventSignatures(topic) {
    if (fourbyteEventCache.has(topic)) return fourbyteEventCache.get(topic);
    try {
      const r = await this.request(FOURBYTE_EVENT(topic));
      if (!r.ok) return null;
      const results = (await r.json()).results || [];
      const sigs = results
        .filter((x) => typeof x.text_signature === "string")
        .sort((x, y) => (x.id || 0) - (y.id || 0))
        .map((x) => x.text_signature);
      fourbyteEventCache.set(topic, sigs);
      return sigs;
    } catch {
      return null;
    }
  }

  /** The verified ABI (array) from Sourcify, false if not verified, null if unknown. */
  async sourcifyAbi(chainId, a) {
    const key = `sourcify-abi:${chainId}:${a.toLowerCase()}`;
    if (this.memo.has(key)) return this.memo.get(key);
    let result = null;
    try {
      const r = await this.request(SOURCIFY(chainId, a) + "?fields=abi");
      if (r.status === 404) result = false;
      else if (r.ok) {
        const d = await r.json();
        result = Array.isArray(d.abi) ? d.abi : false;
      }
    } catch { result = null; }
    this.memo.set(key, result);
    return result;
  }
}

export function _clearFourbyteCache() {
  fourbyteCache.clear();
  fourbyteEventCache.clear();
}
