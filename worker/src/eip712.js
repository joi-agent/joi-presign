// Message digests that wallets sign: EIP-191 personal_sign and EIP-712 typed data (v4 rules).
import { keccak256, utf8, toHex } from "./keccak.js";
import { hexToBytes, isAddress } from "./abi.js";

export class TypedDataError extends Error {}

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};

const word = (big) => hexToBytes(big.toString(16).padStart(64, "0"));

/** EIP-191 personal_sign digest. A 0x-hex message is signed as raw bytes (as wallets do); anything else as UTF-8. */
export function personalDigest(message) {
  let bytes;
  if (typeof message === "string" && /^0x([0-9a-fA-F]{2})*$/.test(message)) bytes = hexToBytes(message);
  else if (typeof message === "string") bytes = utf8(message);
  else throw new TypedDataError("message must be a string");
  return keccak256(concat([utf8(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes]));
}

function toBig(v, what) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
  if (typeof v === "boolean") throw new TypedDataError(`${what}: expected a number`);
  if (typeof v === "string") {
    const s = v.trim();
    if (/^-?0x[0-9a-fA-F]+$/.test(s)) return s.startsWith("-") ? -BigInt(s.slice(1)) : BigInt(s);
    if (/^-?\d+$/.test(s)) return BigInt(s);
  }
  throw new TypedDataError(`${what}: expected a number`);
}

function hexBytes(v, what) {
  if (typeof v !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(v)) throw new TypedDataError(`${what}: expected 0x-hex bytes`);
  return hexToBytes(v);
}

const baseType = (t) => t.replace(/(\[\d*\])+$/, "");

function deps(primary, types, found = new Set()) {
  if (found.has(primary) || !types[primary]) return found;
  found.add(primary);
  for (const f of types[primary]) deps(baseType(f.type), types, found);
  return found;
}

function encodeType(primary, types) {
  const [, ...rest] = [...deps(primary, types)];
  return [primary, ...rest.sort()].map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(",")})`).join("");
}

const typeHash = (primary, types) => keccak256(utf8(encodeType(primary, types)));

function encodeValue(type, value, types, path) {
  const arr = /^(.*)\[(\d*)\]$/.exec(type);
  if (arr) {
    if (!Array.isArray(value)) throw new TypedDataError(`${path}: expected an array`);
    if (arr[2] !== "" && value.length !== Number(arr[2])) throw new TypedDataError(`${path}: expected ${arr[2]} items`);
    return keccak256(concat(value.map((v, i) => encodeValue(arr[1], v, types, `${path}[${i}]`))));
  }
  if (types[type]) return hashStruct(type, value, types, path);
  if (type === "string") {
    if (typeof value !== "string") throw new TypedDataError(`${path}: expected a string`);
    return keccak256(utf8(value));
  }
  if (type === "bytes") return keccak256(hexBytes(value, path));
  if (type === "address") {
    if (typeof value !== "string" || !isAddress(value)) throw new TypedDataError(`${path}: expected an address`);
    return word(BigInt("0x" + value.replace(/^0x/, "")));
  }
  if (type === "bool") {
    if (typeof value === "boolean") return word(value ? 1n : 0n);
    if (value === "true" || value === "false") return word(value === "true" ? 1n : 0n);
    throw new TypedDataError(`${path}: expected a boolean`);
  }
  let m = /^(u?)int(\d*)$/.exec(type);
  if (m) {
    const bits = BigInt(m[2] || 256);
    if (bits < 8n || bits > 256n || bits % 8n !== 0n) throw new TypedDataError(`${path}: unsupported type ${type}`);
    const v = toBig(value, path);
    if (m[1] === "u") {
      if (v < 0n || v >> bits !== 0n) throw new TypedDataError(`${path}: out of range for ${type}`);
      return word(v);
    }
    const lim = 1n << (bits - 1n);
    if (v < -lim || v >= lim) throw new TypedDataError(`${path}: out of range for ${type}`);
    return word(v < 0n ? (1n << 256n) + v : v);
  }
  m = /^bytes(\d+)$/.exec(type);
  if (m) {
    const n = Number(m[1]);
    const b = hexBytes(value, path);
    if (n < 1 || n > 32 || b.length !== n) throw new TypedDataError(`${path}: expected ${type}`);
    const out = new Uint8Array(32);
    out.set(b);
    return out;
  }
  throw new TypedDataError(`${path}: unknown type ${type}`);
}

function hashStruct(primary, data, types, path = primary) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) throw new TypedDataError(`${path}: expected an object`);
  const parts = [typeHash(primary, types)];
  for (const f of types[primary]) {
    const v = data[f.name];
    if (v === undefined || v === null) throw new TypedDataError(`${path}.${f.name}: missing`);
    parts.push(encodeValue(f.type, v, types, `${path}.${f.name}`));
  }
  return keccak256(concat(parts));
}

const DOMAIN_FIELDS = [["name", "string"], ["version", "string"], ["chainId", "uint256"], ["verifyingContract", "address"], ["salt", "bytes32"]];

/** EIP-712 digest keccak256(0x1901 || domainSeparator || hashStruct(message)). Throws TypedDataError on malformed input. */
export function typedDataDigest(td) {
  if (td === null || typeof td !== "object" || Array.isArray(td)) throw new TypedDataError("typedData must be an object");
  const { types, primaryType, domain, message } = td;
  if (!types || typeof types !== "object" || Array.isArray(types)) throw new TypedDataError("typedData.types missing");
  if (typeof primaryType !== "string" || !types[primaryType]) throw new TypedDataError("typedData.primaryType missing or not in types");
  for (const [name, fields] of Object.entries(types)) {
    if (!Array.isArray(fields) || fields.some((f) => !f || typeof f.name !== "string" || typeof f.type !== "string")) {
      throw new TypedDataError(`typedData.types.${name} must be a list of {name, type}`);
    }
  }
  const dom = domain && typeof domain === "object" && !Array.isArray(domain) ? domain : {};
  const allTypes = { ...types };
  if (!allTypes.EIP712Domain) {
    allTypes.EIP712Domain = DOMAIN_FIELDS.filter(([n]) => dom[n] !== undefined).map(([name, type]) => ({ name, type }));
  }
  const domainSeparator = hashStruct("EIP712Domain", dom, allTypes, "domain");
  const msgHash = primaryType === "EIP712Domain" ? null : hashStruct(primaryType, message, allTypes, "message");
  const parts = [new Uint8Array([0x19, 0x01]), domainSeparator];
  if (msgHash) parts.push(msgHash);
  return keccak256(concat(parts));
}

export const digestHex = (d) => "0x" + toHex(d);
