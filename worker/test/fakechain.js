// A small fake chain for the /tx, /verify-signature and /token tests. Unlisted state = defaults;
// entries in `unknown` force the matching lookup to fail (null).
export const ZERO_WORD = "0x" + "0".repeat(64);

export class FakeChain {
  constructor({
    code = {}, storage = {}, calls = {}, strict = {}, sourcify = {}, abi = {}, nonce = {}, balance = {},
    txs = {}, receipts = {}, blocks = {}, selectors = {}, events = {}, unknown = [],
  } = {}) {
    Object.assign(this, { code, storage, calls, strict, sourcify, abi, nonce, balances: balance, txs, receipts, blocks, selectors, events, unknown: new Set(unknown) });
    this.callLog = [];
  }
  k(a) { return a.toLowerCase(); }
  async getCode(_c, a) { return this.unknown.has("code:" + this.k(a)) || this.unknown.has("code") ? null : (this.code[this.k(a)] ?? "0x"); }
  async codeKind(c, a) {
    const code = await this.getCode(c, a);
    if (code === null) return null;
    if (code === "0x") return "none";
    if (code.startsWith("0xef0100")) return "7702";
    return "contract";
  }
  async getStorageAt(_c, a, slot) { return this.unknown.has("storage") ? null : (this.storage[`${this.k(a)}:${slot}`] ?? ZERO_WORD); }
  async ethCall(_c, to, data) { this.callLog.push(`${this.k(to)}:${data}`); return this.calls[`${this.k(to)}:${data}`] ?? null; }
  async ethCallStrict(_c, to, data) {
    if (this.unknown.has("strict")) return { status: "unknown" };
    return this.strict[this.k(to)] ?? { status: "reverted" };
  }
  async sourcifyInfo(_c, a) { return this.sourcify[this.k(a)] ?? { verified: null, name: null }; }
  async sourcifyAbi(_c, a) { return this.unknown.has("abi") ? null : (this.abi[this.k(a)] ?? false); }
  async txCount(_c, a) { return this.nonce[this.k(a)] ?? 0; }
  async balance(_c, a) { return this.balances[this.k(a)] ?? 0n; }
  async getTransaction(_c, h) { return this.unknown.has("tx") ? null : (this.txs[h] ?? false); }
  async getReceipt(_c, h) { return this.unknown.has("receipt") ? null : (this.receipts[h] ?? false); }
  async getBlock(_c, n) { return this.blocks[n] ?? null; }
  async selectorSignatures(sel) { return this.selectors[sel] ?? []; }
  async eventSignatures(t) { return this.events[t] ?? []; }
}

export const word = (hexNoPrefix) => hexNoPrefix.padStart(64, "0");
export const addrWord = (a) => "0x" + word(a.slice(2).toLowerCase());
export const uintWord = (n) => "0x" + word(BigInt(n).toString(16));
/** ABI-encoded string return value. */
export function abiString(s) {
  const b = Buffer.from(s, "utf8").toString("hex");
  return "0x" + word("20") + word(b.length / 2 === 0 ? "0" : (b.length / 2).toString(16)) + b.padEnd(Math.ceil(b.length / 64) * 64, "0");
}
