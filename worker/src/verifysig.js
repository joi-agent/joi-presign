// Signature verification for agents doing auth: EIP-191 personal_sign, EIP-712 typed data and raw 32-byte
// digests, for wallets (ecrecover) and contract accounts (ERC-1271), including EIP-7702-delegated wallets.
// Never takes or stores private keys: only addresses, messages and signatures.
import { hexToBytes, isAddress, toChecksumAddress } from "./abi.js";
import { CHAINS } from "./core.js";
import { toHex } from "./keccak.js";
import { personalDigest, typedDataDigest, TypedDataError } from "./eip712.js";
import { recoverAddress, splitSignature, HALF_N } from "./secp256k1.js";
import { LookupUnavailable } from "./profile.js";

const MAX_SIG_BYTES = 4096;
const MAGIC_1271 = "0x1626ba7e";

/** Validate and pre-compute everything that needs no network. Returns {error} or the target. */
export function parseVerify(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return { error: "body must be a JSON object {chain?, address, message | typedData | hash, signature}" };
  const chainName = body.chain === undefined || body.chain === null || body.chain === "" ? "base" : String(body.chain);
  const chainId = CHAINS[chainName];
  if (!chainId) return { error: `unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}` };
  if (typeof body.address !== "string" || !isAddress(body.address) || !body.address.startsWith("0x")) {
    return { error: "address must be a 0x-prefixed 20-byte hex address (mixed case must be a valid EIP-55 checksum)" };
  }
  const given = ["message", "typedData", "hash"].filter((k) => body[k] !== undefined && body[k] !== null);
  if (given.length !== 1) return { error: "give exactly one of: message (personal_sign), typedData (EIP-712), hash (raw 32-byte digest)" };
  if (typeof body.signature !== "string" || !/^0x([0-9a-fA-F]{2})+$/.test(body.signature)) return { error: "signature must be 0x-hex bytes" };
  const signature = hexToBytes(body.signature);
  if (signature.length > MAX_SIG_BYTES) return { error: `signature longer than ${MAX_SIG_BYTES} bytes` };
  let digest, digestType;
  try {
    if (given[0] === "message") {
      digest = personalDigest(body.message);
      digestType = "personal_sign";
    } else if (given[0] === "typedData") {
      let td = body.typedData;
      if (typeof td === "string") {
        try { td = JSON.parse(td); } catch { return { error: "typedData is not valid JSON" }; }
      }
      digest = typedDataDigest(td);
      digestType = "eip712";
    } else {
      if (typeof body.hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(body.hash)) return { error: "hash must be a 0x-prefixed 32-byte hex digest" };
      digest = hexToBytes(body.hash);
      digestType = "hash";
    }
  } catch (e) {
    if (e instanceof TypedDataError) return { error: `typedData: ${e.message}` };
    return { error: "message must be a string" };
  }
  return { chainId, address: toChecksumAddress(body.address), signature, digest, digestType };
}

function encode1271(digest, sig) {
  const len = sig.length.toString(16).padStart(64, "0");
  const padded = toHex(sig).padEnd(Math.ceil(sig.length / 32) * 64, "0");
  return MAGIC_1271 + toHex(digest) + (64).toString(16).padStart(64, "0") + len + padded;
}

export async function verifySignature(t, lookups) {
  const notes = [];
  const out = {
    kind: "signature", chain_id: t.chainId, address: t.address, valid: false, method: null, recovered: null,
    account_kind: null, digest: "0x" + toHex(t.digest), digest_type: t.digestType, notes,
  };

  // 1) A plain ECDSA signature by the address itself (works for wallets and 7702-delegated wallets).
  const split = splitSignature(t.signature);
  if (split) {
    out.recovered = recoverAddress(t.digest, split.r, split.s, split.v);
    if (out.recovered === t.address) {
      out.valid = true;
      out.method = "ecrecover";
      if (split.s > HALF_N) notes.push("Valid for ecrecover, but s is in the upper half (malleable); OpenZeppelin's ECDSA library would reject it.");
      if (t.signature.length === 64) notes.push("EIP-2098 compact signature.");
      return out;
    }
  }

  // 2) Otherwise ask the account itself (ERC-1271), if it has code.
  const code = await lookups.getCode(t.chainId, t.address);
  if (code === null) throw new LookupUnavailable("could not read the account's code");
  if (code === "0x") {
    out.account_kind = "eoa";
    out.method = "ecrecover";
    notes.push(split
      ? `Not signed by ${t.address}${out.recovered ? `: this signature was made by ${out.recovered}` : ": the signature doesn't recover to any address"}.`
      : "A plain wallet can only sign with a 64- or 65-byte ECDSA signature.");
    return out;
  }
  out.account_kind = code.startsWith("0xef0100") && code.length === 2 + 46 ? "eoa-7702" : "contract";
  out.method = "erc1271";
  const r = await lookups.ethCallStrict(t.chainId, t.address, encode1271(t.digest, t.signature));
  if (r.status === "unknown") throw new LookupUnavailable("could not call isValidSignature on the account");
  if (r.status === "ok" && r.data.length >= 10 && r.data.slice(0, 10) === MAGIC_1271) {
    out.valid = true;
    return out;
  }
  notes.push(r.status === "reverted"
    ? "The account's isValidSignature reverted: it doesn't accept this signature (or doesn't implement ERC-1271)."
    : "The account's isValidSignature didn't return the ERC-1271 magic value.");
  if (out.recovered && split) notes.push(`As a plain signature it recovers to ${out.recovered}, not ${t.address}.`);
  notes.push("Counterfactual (not yet deployed, ERC-6492) smart accounts aren't supported.");
  return out;
}
