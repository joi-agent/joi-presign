// Name resolution: ENS on Ethereum and Basenames on Base, forward (name -> address) and reverse (address -> primary
// name, checked by resolving the name forward again). Only the ASCII part of ENSIP-15 normalization is implemented:
// names with any non-ASCII character are refused rather than normalized wrongly.
import { toChecksumAddress } from "./abi.js";
import { keccak256, utf8, toHex } from "./keccak.js";
import { decodeString } from "./price.js";
import { LookupUnavailable } from "./profile.js";

// ENS registry (same address on mainnet and testnets). Source: https://docs.ens.domains/learn/deployments
export const ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
// Basenames on Base mainnet. Source: https://github.com/base/basenames README, "Base Mainnet" table (checked 2026-10-02);
// verified on-chain: the registry holds jesse.base.eth -> L2Resolver, and ReverseRegistrar.node(addr) equals
// keccak256(namehash("80002105.reverse"), keccak256(hex address)) as computed below.
export const BASENAMES = {
  registry: "0xb94704422c2a1e396835a571837aa5ae53285a95",
  reverseRegistrar: "0x79ea96012eea67a83431f1701b3dff7e37f9e282",
  l2Resolver: "0xC6d566A56A1aFf6508b41f6c90ff131615583BCD",
};
// ENSIP-11 coin type for Base: 0x80000000 | 8453.
export const BASE_REVERSE_PARENT = "80002105.reverse";
const ETH = 1;
const BASE = 8453;
const ZERO = "0x" + "00".repeat(20);

const SEL = {
  resolver: "0x0178b8bf", // resolver(bytes32)
  addr: "0x3b3b57de", // addr(bytes32)
  name: "0x691f3431", // name(bytes32)
  supportsInterface: "0x01ffc9a7",
  resolve: "0x9061b923", // resolve(bytes,bytes) = ENSIP-10 interface id
};

export class NameError extends Error {}

/** ENSIP-15 normalization for ASCII names: lowercase, labels of [a-z0-9-_], underscores only at the start. */
export function normalizeName(raw) {
  if (typeof raw !== "string" || raw.trim() === "") throw new NameError("name is required (e.g. vitalik.eth)");
  const s = raw.trim();
  if (s.length > 255) throw new NameError("name is longer than 255 characters");
  if (/[^\x20-\x7e]/.test(s)) throw new NameError("names with non-ASCII characters (emoji, accents, other scripts) aren't supported: this service doesn't implement full ENSIP-15 normalization");
  const name = s.toLowerCase();
  const labels = name.split(".");
  if (labels.length < 2) throw new NameError("give a full name with its top-level part, e.g. vitalik.eth or jesse.base.eth");
  for (const l of labels) {
    if (l === "") throw new NameError("empty label (two dots in a row, or a leading/trailing dot)");
    if (!/^[a-z0-9_-]+$/.test(l)) throw new NameError(`label '${l}' has characters ENS doesn't allow (only a-z, 0-9, hyphen and underscore)`);
    if (/_/.test(l.replace(/^_+/, ""))) throw new NameError(`label '${l}': an underscore is only allowed at the start of a label`);
    if (l.length >= 4 && l[2] === "-" && l[3] === "-") throw new NameError(`label '${l}': '--' in the 3rd and 4th position is reserved`);
  }
  return name;
}

export function labelhash(label) {
  return keccak256(utf8(label));
}

/** EIP-137 namehash as 0x-hex. */
export function namehash(name) {
  let node = new Uint8Array(32);
  if (name) {
    for (const label of name.split(".").reverse()) {
      const buf = new Uint8Array(64);
      buf.set(node, 0);
      buf.set(labelhash(label), 32);
      node = keccak256(buf);
    }
  }
  return "0x" + toHex(node);
}

/** DNS wire format of a name (ENSIP-10 resolve()). */
export function dnsEncode(name) {
  const parts = [];
  for (const l of name.split(".")) {
    const b = utf8(l);
    parts.push(b.length, ...b);
  }
  parts.push(0);
  return toHex(Uint8Array.from(parts));
}

const wordToAddress = (hex) => (typeof hex === "string" && /^0x[0-9a-f]{64}$/i.test(hex.slice(0, 66)) ? toChecksumAddress("0x" + hex.slice(26, 66)) : null);
const pad = (hexNoPrefix) => hexNoPrefix.padStart(64, "0");

function abiBytes(hexNoPrefix) {
  const len = hexNoPrefix.length / 2;
  return pad(len.toString(16)) + hexNoPrefix.padEnd(Math.ceil(hexNoPrefix.length / 64) * 64, "0");
}

async function registryResolver(chainId, registry, node, lookups) {
  const r = await lookups.ethCall(chainId, registry, SEL.resolver + node.slice(2));
  if (r === null) throw new LookupUnavailable("could not read the name registry");
  const a = wordToAddress(r);
  return a && a !== toChecksumAddress(ZERO) ? a : null;
}

/** {address, resolver, wildcard, note} for a normalized name, on Ethereum (ENS) or Base (Basenames). */
export async function forward(name, lookups) {
  const base = name.endsWith(".base.eth");
  const chainId = base ? BASE : ETH;
  const registry = base ? BASENAMES.registry : ENS_REGISTRY;
  const node = namehash(name);
  const resolver = await registryResolver(chainId, registry, node, lookups);
  if (resolver) {
    const r = await lookups.ethCallStrict(chainId, resolver, SEL.addr + node.slice(2));
    if (r.status === "unknown") throw new LookupUnavailable("could not read the name's resolver");
    const a = r.status === "ok" ? wordToAddress(r.data) : null;
    return { chainId, registry, resolver, address: a && a !== toChecksumAddress(ZERO) ? a : null, wildcard: false, note: r.status === "reverted" ? "The resolver has no address record for this name." : null };
  }
  // ENSIP-10: the closest parent with a resolver may answer for subnames (wildcard resolution).
  const labels = name.split(".");
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join(".");
    const pr = await registryResolver(chainId, registry, namehash(parent), lookups);
    if (!pr) continue;
    const supports = await lookups.ethCall(chainId, pr, SEL.supportsInterface + SEL.resolve.slice(2).padEnd(64, "0"));
    if (!supports || BigInt(supports.slice(0, 66)) !== 1n) return { chainId, registry, resolver: null, address: null, wildcard: false, note: `No resolver is set for this name (its parent ${parent} has one, but it doesn't resolve subnames).` };
    const dns = dnsEncode(name);
    const inner = SEL.addr.slice(2) + node.slice(2);
    const data = SEL.resolve + pad("40") + pad((64 + abiBytes(dns).length / 2).toString(16)) + abiBytes(dns) + abiBytes(inner);
    const r = await lookups.ethCallStrict(chainId, pr, data);
    if (r.status === "unknown") throw new LookupUnavailable("could not read the parent's resolver");
    if (r.status === "reverted") {
      return { chainId, registry, resolver: pr, address: null, wildcard: true, note: `${parent}'s resolver answers subnames off-chain (CCIP-Read) or has no record; this service doesn't follow off-chain lookups.` };
    }
    // resolve() returns bytes holding the ABI-encoded addr() result
    let a = null;
    try {
      const off = Number(BigInt("0x" + r.data.slice(2, 66))) * 2 + 2;
      const len = Number(BigInt("0x" + r.data.slice(off, off + 64)));
      if (len >= 32) a = wordToAddress("0x" + r.data.slice(off + 64, off + 128));
    } catch { a = null; }
    return { chainId, registry, resolver: pr, address: a && a !== toChecksumAddress(ZERO) ? a : null, wildcard: true, note: null };
  }
  return { chainId, registry, resolver: null, address: null, wildcard: false, note: "No resolver is set for this name: it isn't registered, or it has expired." };
}

export function reverseNode(address, chainId) {
  const hex = address.toLowerCase().replace(/^0x/, "");
  if (chainId === ETH) return namehash(`${hex}.addr.reverse`);
  const parent = namehash(BASE_REVERSE_PARENT);
  const buf = new Uint8Array(64);
  buf.set(Uint8Array.from(parent.slice(2).match(/../g).map((b) => parseInt(b, 16))), 0);
  buf.set(keccak256(utf8(hex)), 32);
  return "0x" + toHex(keccak256(buf));
}

/** The primary name an address claims on Ethereum (ENS) or Base (Basenames), or null. */
export async function primaryName(address, chainId, lookups) {
  const registry = chainId === ETH ? ENS_REGISTRY : BASENAMES.registry;
  const node = reverseNode(address, chainId);
  const resolver = await registryResolver(chainId, registry, node, lookups);
  if (!resolver) return null;
  const r = await lookups.ethCallStrict(chainId, resolver, SEL.name + node.slice(2));
  if (r.status === "unknown") throw new LookupUnavailable("could not read the reverse record");
  if (r.status !== "ok") return null;
  const name = decodeString(r.data);
  return name && name.trim() ? name.trim() : null;
}

const SOURCE = {
  [ETH]: `ENS registry ${ENS_REGISTRY} on Ethereum`,
  [BASE]: `Basenames registry ${BASENAMES.registry} on Base`,
};
const CHAIN_NAME = { [ETH]: "ethereum", [BASE]: "base" };

export function parseNameTarget(nameRaw, addressRaw) {
  const hasName = typeof nameRaw === "string" && nameRaw.trim() !== "";
  const hasAddr = typeof addressRaw === "string" && addressRaw.trim() !== "";
  if (hasName === hasAddr) return { error: "give exactly one of name (e.g. vitalik.eth) or address (0x...)" };
  if (hasName) {
    try {
      return { name: normalizeName(nameRaw) };
    } catch (e) {
      return { error: e.message };
    }
  }
  const a = addressRaw.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return { error: "address must be a 0x-prefixed 20-byte hex address" };
  return { address: toChecksumAddress(a.toLowerCase()) };
}

async function reverseOne(address, chainId, lookups) {
  const claimed = await primaryName(address, chainId, lookups);
  const out = { system: chainId === ETH ? "ens" : "basenames", chain: CHAIN_NAME[chainId], name: claimed, verified_reverse: null, source: SOURCE[chainId], note: null };
  if (!claimed) return out;
  let norm;
  try {
    norm = normalizeName(claimed);
  } catch {
    return { ...out, verified_reverse: false, note: "The reverse record holds a name this service can't normalize, so it wasn't verified." };
  }
  const f = await forward(norm, lookups);
  const ok = !!f.address && f.address.toLowerCase() === address.toLowerCase();
  return { ...out, name: norm, verified_reverse: ok, note: ok ? null : `The reverse record claims ${norm}, but ${norm} doesn't resolve back to this address: don't trust it.` };
}

export async function resolveName(target, lookups) {
  if (target.name) {
    const f = await forward(target.name, lookups);
    let verified = null;
    if (f.address) {
      const back = await primaryName(f.address, f.chainId, lookups);
      verified = !!back && back.trim().toLowerCase() === target.name;
    }
    return {
      query: { name: target.name },
      name: target.name,
      address: f.address,
      found: !!f.address,
      chain: CHAIN_NAME[f.chainId],
      chain_id: f.chainId,
      resolver: f.resolver,
      wildcard: f.wildcard,
      verified_reverse: verified,
      source: SOURCE[f.chainId],
      notes: [
        ...(f.note ? [f.note] : []),
        ...(verified === false ? [`${f.address} doesn't name ${target.name} as its primary name; the forward record still resolves.`] : []),
      ],
    };
  }
  const results = [await reverseOne(target.address, ETH, lookups), await reverseOne(target.address, BASE, lookups)];
  const best = results.find((r) => r.verified_reverse) || results.find((r) => r.name) || null;
  return {
    query: { address: target.address },
    address: target.address,
    name: best ? best.name : null,
    chain: best ? best.chain : null,
    verified_reverse: best ? best.verified_reverse : null,
    source: best ? best.source : null,
    results,
  };
}
