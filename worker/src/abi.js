// Addresses, selector table and strict ABI decoding for the handful of types the checks need.
import { keccak256, utf8, toHex } from "./keccak.js";

export function hexToBytes(hex) {
  let s = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error("not valid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toChecksumAddress(addr) {
  const lower = addr.toLowerCase().replace(/^0x/, "");
  const hash = toHex(keccak256(utf8(lower)));
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  return out;
}

// Same rule as eth_utils.is_address: 40 hex chars (0x optional); mixed case must be a valid checksum.
export function isAddress(v) {
  if (typeof v !== "string") return false;
  const body = v.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{40}$/.test(body)) return false;
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  return toChecksumAddress(body) === "0x" + body;
}

export const selectorOf = (sig) => "0x" + toHex(keccak256(utf8(sig))).slice(0, 8);

const SIGNATURES = {
  approve: "approve(address,uint256)",
  increaseAllowance: "increaseAllowance(address,uint256)",
  transfer: "transfer(address,uint256)",
  transferFrom: "transferFrom(address,address,uint256)",
  setApprovalForAll: "setApprovalForAll(address,bool)",
  safeTransferFrom721: "safeTransferFrom(address,address,uint256)",
  safeTransferFrom721Data: "safeTransferFrom(address,address,uint256,bytes)",
  safeTransferFrom1155: "safeTransferFrom(address,address,uint256,uint256,bytes)",
  safeBatchTransferFrom1155: "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
  permit: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
  permit2Approve: "approve(address,address,uint160,uint48)",
  multicall: "multicall(bytes[])",
  multicallDeadline: "multicall(uint256,bytes[])",
  aggregate: "aggregate((address,bytes)[])",
  aggregate3: "aggregate3((address,bool,bytes)[])",
  tryAggregate: "tryAggregate(bool,(address,bytes)[])",
  multiSend: "multiSend(bytes)",
};

export function splitTypes(types) {
  const out = [];
  let depth = 0, cur = "";
  for (const ch of types) {
    if (ch === "," && depth === 0) { out.push(cur); cur = ""; continue; }
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

export const KNOWN = {};
for (const [name, sig] of Object.entries(SIGNATURES)) {
  KNOWN[selectorOf(sig)] = { name, sig, types: sig.slice(sig.indexOf("(") + 1, -1) };
}

// ---------------------------------------------------------------- decoder

function isDynamic(t) {
  if (t === "bytes" || t === "string" || t.endsWith("[]")) return true;
  if (t.startsWith("(")) return splitTypes(t.slice(1, -1)).some(isDynamic);
  return false;
}

function headSize(t) {
  if (isDynamic(t)) return 32;
  if (t.startsWith("(")) return splitTypes(t.slice(1, -1)).reduce((n, x) => n + headSize(x), 0);
  return 32;
}

function word(data, p) {
  if (p + 32 > data.length) throw new Error("insufficient data");
  return data.subarray(p, p + 32);
}

const wordToBig = (w) => BigInt("0x" + (toHex(w) || "0"));

function zeroAt(w, from, to) {
  for (let i = from; i < to; i++) if (w[i] !== 0) return false;
  return true;
}

function toIndex(big, data) {
  if (big > BigInt(data.length)) throw new Error("offset or length out of bounds");
  return Number(big);
}

function decodeAt(t, data, p) {
  if (t.endsWith("[]")) {
    const inner = t.slice(0, -2);
    const n = toIndex(wordToBig(word(data, p)), data);
    if (p + 32 + n * headSize(inner) > data.length) throw new Error("array exceeds data");
    return decodeTuple(Array(n).fill(inner), data, p + 32);
  }
  if (t.startsWith("(")) return decodeTuple(splitTypes(t.slice(1, -1)), data, p);
  if (t === "bytes" || t === "string") {
    const n = toIndex(wordToBig(word(data, p)), data);
    const end = p + 32 + n, padEnd = p + 32 + Math.ceil(n / 32) * 32;
    if (padEnd > data.length) throw new Error("bytes exceed data");
    if (!zeroAt(data, end, padEnd)) throw new Error("non-zero padding");
    const raw = data.slice(p + 32, end);
    return t === "string" ? new TextDecoder().decode(raw) : raw;
  }
  const w = word(data, p);
  if (t === "address") {
    if (!zeroAt(w, 0, 12)) throw new Error("dirty address padding");
    return toChecksumAddress(toHex(w.subarray(12)));
  }
  if (t === "bool") {
    const v = wordToBig(w);
    if (v > 1n) throw new Error("invalid bool");
    return v === 1n;
  }
  let m = /^uint(\d+)$/.exec(t);
  if (m) {
    const v = wordToBig(w);
    if (v >> BigInt(m[1]) !== 0n) throw new Error(`value out of range for ${t}`);
    return v;
  }
  m = /^bytes(\d+)$/.exec(t);
  if (m) {
    const n = Number(m[1]);
    if (!zeroAt(w, n, 32)) throw new Error("non-zero padding");
    return w.slice(0, n);
  }
  throw new Error(`unsupported type ${t}`);
}

function decodeTuple(types, data, base) {
  const out = [];
  let pos = base;
  for (const t of types) {
    if (isDynamic(t)) {
      const off = toIndex(wordToBig(word(data, pos)), data);
      out.push(decodeAt(t, data, base + off));
    } else {
      out.push(decodeAt(t, data, pos));
    }
    pos += headSize(t);
  }
  return out;
}

export function decode(types, data) {
  return decodeTuple(types, data, 0);
}

/** {selector, name, signature, args} or null when shorter than a selector; throws on malformed args. */
export function decodeCall(data) {
  if (data.length < 4) return null;
  const sel = "0x" + toHex(data.subarray(0, 4));
  const k = KNOWN[sel];
  if (!k) return { selector: sel, name: null, signature: null, args: null };
  let args;
  try {
    args = decode(splitTypes(k.types), data.subarray(4));
  } catch (e) {
    throw new Error(`cannot decode ${k.sig}: ${e.message}`);
  }
  return { selector: sel, name: k.name, signature: k.sig, args };
}

/** For batching functions: [[target, value, data, operation]]; operation 1 = delegatecall. */
export function innerCalls(call, outerTo) {
  const a = call.args;
  switch (call.name) {
    case "multicall": return a[0].map((d) => [outerTo, 0n, d, 0]);
    case "multicallDeadline": return a[1].map((d) => [outerTo, 0n, d, 0]);
    case "aggregate": return a[0].map(([t, d]) => [t, 0n, d, 0]);
    case "aggregate3": return a[0].map(([t, , d]) => [t, 0n, d, 0]);
    case "tryAggregate": return a[1].map(([t, d]) => [t, 0n, d, 0]);
    case "multiSend": return decodeMultisend(a[0]);
    default: return [];
  }
}

/** Safe MultiSend packed encoding: operation(1) | to(20) | value(32) | dataLength(32) | data. */
export function decodeMultisend(blob) {
  const out = [];
  let i = 0;
  while (i < blob.length) {
    if (i + 85 > blob.length) throw new Error("truncated multiSend entry header");
    const op = blob[i];
    const to = toChecksumAddress(toHex(blob.subarray(i + 1, i + 21)));
    const value = wordToBig(blob.subarray(i + 21, i + 53));
    const len = wordToBig(blob.subarray(i + 53, i + 85));
    if (BigInt(i + 85) + len > BigInt(blob.length)) throw new Error("truncated multiSend entry data");
    out.push([to, value, blob.slice(i + 85, i + 85 + Number(len)), op]);
    i += 85 + Number(len);
  }
  return out;
}
