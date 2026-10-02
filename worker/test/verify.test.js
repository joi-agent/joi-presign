import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { recoverAddress, splitSignature, HALF_N } from "../src/secp256k1.js";
import { personalDigest, typedDataDigest, digestHex, TypedDataError } from "../src/eip712.js";
import { parseVerify, verifySignature } from "../src/verifysig.js";
import { LookupUnavailable } from "../src/profile.js";
import { hexToBytes, toChecksumAddress } from "../src/abi.js";
import { FakeChain } from "./fakechain.js";

// Generated with eth_account (Python) from throwaway test keys; typed[0] is the EIP-712 spec's "Ether Mail" vector.
const V = JSON.parse(fs.readFileSync(new URL("./sig-vectors.json", import.meta.url), "utf8"));
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const recover = (digest, sigHex) => {
  const s = splitSignature(hexToBytes(sigHex));
  return recoverAddress(digest, s.r, s.s, s.v);
};

test("ecrecover: raw digests from eth_account recover to the signer", () => {
  for (const r of V.raw) assert.equal(recover(hexToBytes(r.hash), r.signature), r.address);
});

test("personal_sign: UTF-8 (incl. non-ASCII) and 0x-hex messages", () => {
  for (const p of V.personal) assert.equal(recover(personalDigest(p.message), p.signature), p.address, p.message);
});

test("EIP-712: the spec's Ether Mail digest and signature, plus nested structs, arrays, bytes, int, fixed arrays", () => {
  const mail = V.typed[0];
  assert.equal(digestHex(typedDataDigest(mail.typedData)), "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
  assert.equal(recover(typedDataDigest(mail.typedData), mail.signature), "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");
  for (const t of V.typed) {
    assert.equal(digestHex(typedDataDigest(t.typedData)), t.digest);
    assert.equal(recover(typedDataDigest(t.typedData), t.signature), t.address);
  }
});

test("EIP-712: domain types are derived when EIP712Domain is omitted", () => {
  const td = structuredClone(V.typed[0].typedData);
  delete td.types.EIP712Domain;
  assert.equal(digestHex(typedDataDigest(td)), V.typed[0].digest);
});

test("EIP-712: malformed typed data throws TypedDataError", () => {
  const base = V.typed[0].typedData;
  const bad = [
    { ...base, primaryType: "Nope" },
    { ...base, message: { ...base.message, contents: 5 } },
    { ...base, message: { ...base.message, from: { name: "Cow", wallet: "0x123" } } },
    { ...base, message: { from: base.message.from, to: base.message.to } },
    { ...base, types: { ...base.types, Mail: "nope" } },
  ];
  for (const td of bad) assert.throws(() => typedDataDigest(td), TypedDataError);
});

test("splitSignature: 65-byte with v 27/28 or 0/1, and EIP-2098 64-byte compact", () => {
  const sig = hexToBytes(V.raw[0].signature);
  const s65 = splitSignature(sig);
  const zeroV = sig.slice(); zeroV[64] -= 27;
  assert.deepEqual(splitSignature(zeroV), s65);
  // compact: s with the top bit = yParity (v - 27)
  const compact = new Uint8Array(64);
  compact.set(sig.subarray(0, 32));
  const vs = s65.s | (BigInt(s65.v - 27) << 255n);
  compact.set(hexToBytes(vs.toString(16).padStart(64, "0")), 32);
  assert.deepEqual(splitSignature(compact), s65);
  assert.equal(recoverAddress(hexToBytes(V.raw[0].hash), ...Object.values(splitSignature(compact))), V.raw[0].address);
  assert.equal(splitSignature(new Uint8Array(63)), null);
});

test("ecrecover rejects r/s out of range, bad v, an x that's not on the curve, and wrong digest length", () => {
  const d = hexToBytes(V.raw[0].hash);
  const { r, s, v } = splitSignature(hexToBytes(V.raw[0].signature));
  assert.equal(recoverAddress(d, 0n, s, v), null);
  assert.equal(recoverAddress(d, r, N, v), null);
  assert.equal(recoverAddress(d, r, s, 29), null);
  assert.equal(recoverAddress(d, 5n, s, v), null); // x = 5 is not on secp256k1
  assert.equal(recoverAddress(d.subarray(1), r, s, v), null);
  assert.notEqual(recoverAddress(d, r, s, v === 27 ? 28 : 27), V.raw[0].address); // other parity = other key
});

// ---------------------------------------------------------------- parseVerify (free validation)

const mail = V.typed[0];
const ok = { address: mail.address, typedData: mail.typedData, signature: mail.signature, chain: "ethereum" };

test("parseVerify: validates before any payment", () => {
  assert.equal(parseVerify(ok).digestType, "eip712");
  assert.equal(parseVerify({ ...ok, chain: undefined }).chainId, 8453);
  const errs = [
    [null, /JSON object/],
    [{ ...ok, chain: "solana" }, /unknown chain/],
    [{ ...ok, address: "0x1234" }, /address/],
    [{ ...ok, message: "hi" }, /exactly one/],
    [{ address: ok.address, signature: ok.signature }, /exactly one/],
    [{ ...ok, signature: "nothex" }, /signature/],
    [{ ...ok, signature: "0x" + "ab".repeat(5000) }, /longer than/],
    [{ address: ok.address, hash: "0x1234", signature: ok.signature }, /hash/],
    [{ ...ok, typedData: { ...mail.typedData, primaryType: "Nope" } }, /typedData/],
    [{ ...ok, typedData: "{not json" }, /typedData is not valid JSON/],
    [{ address: ok.address, message: 42, signature: ok.signature }, /message/],
  ];
  for (const [body, re] of errs) assert.match(parseVerify(body).error, re);
  assert.equal(parseVerify({ ...ok, typedData: JSON.stringify(mail.typedData) }).digestType, "eip712");
});

// ---------------------------------------------------------------- verifySignature

const target = (over = {}) => parseVerify({ ...ok, ...over });

test("ecrecover match: valid without any network lookup", async () => {
  const chain = new FakeChain({ unknown: ["code", "strict"] }); // any lookup would fail
  const r = await verifySignature(target(), chain);
  assert.equal(r.valid, true);
  assert.equal(r.method, "ecrecover");
  assert.equal(r.recovered, mail.address);
  assert.equal(r.digest, mail.digest);
});

test("wallet (no code) with someone else's signature: invalid, and says who did sign", async () => {
  const other = V.raw[0];
  const r = await verifySignature(parseVerify({ address: other.address, typedData: mail.typedData, signature: mail.signature }), new FakeChain());
  assert.equal(r.valid, false);
  assert.equal(r.account_kind, "eoa");
  assert.equal(r.recovered, mail.address);
  assert.match(r.notes.join(" "), new RegExp(`made by ${mail.address}`));
});

test("contract account: ERC-1271 magic = valid; revert = invalid; failed call = 503 (LookupUnavailable)", async () => {
  const SAFE = toChecksumAddress("0x" + "5a".repeat(20));
  const t = parseVerify({ address: SAFE, hash: "0x" + "11".repeat(32), signature: "0x" + "22".repeat(130) }); // contract sig, any length
  const code = { [SAFE.toLowerCase()]: "0x6080604052" };
  let r = await verifySignature(t, new FakeChain({ code, strict: { [SAFE.toLowerCase()]: { status: "ok", data: "0x1626ba7e" + "0".repeat(56) } } }));
  assert.deepEqual([r.valid, r.method, r.account_kind], [true, "erc1271", "contract"]);
  r = await verifySignature(t, new FakeChain({ code }));
  assert.deepEqual([r.valid, r.method], [false, "erc1271"]);
  assert.match(r.notes.join(" "), /reverted/);
  r = await verifySignature(t, new FakeChain({ code, strict: { [SAFE.toLowerCase()]: { status: "ok", data: "0xffffffff" + "0".repeat(56) } } }));
  assert.equal(r.valid, false);
  await assert.rejects(verifySignature(t, new FakeChain({ code, unknown: ["strict"] })), LookupUnavailable);
  await assert.rejects(verifySignature(t, new FakeChain({ unknown: ["code"] })), LookupUnavailable);
});

test("EIP-7702 wallet: ecrecover first, then ERC-1271 through the delegate", async () => {
  const W = mail.address;
  const code = { [W.toLowerCase()]: "0xef0100" + "63c0c19a282a1b52b07dd5a65b58948a07dae32b" };
  // its own key signed: valid by ecrecover, no call needed
  let r = await verifySignature(target(), new FakeChain({ code, unknown: ["strict"] }));
  assert.deepEqual([r.valid, r.method], [true, "ecrecover"]);
  // a different (session) key signed: falls through to 1271
  const t2 = parseVerify({ address: W, hash: V.raw[1].hash, signature: V.raw[1].signature });
  r = await verifySignature(t2, new FakeChain({ code, strict: { [W.toLowerCase()]: { status: "ok", data: "0x1626ba7e" + "0".repeat(56) } } }));
  assert.deepEqual([r.valid, r.method, r.account_kind], [true, "erc1271", "eoa-7702"]);
});

test("high-s signatures are valid for ecrecover but flagged as malleable", async () => {
  const r0 = V.raw[0];
  const { r, s, v } = splitSignature(hexToBytes(r0.signature));
  const hs = N - s; // flip to the upper half, with the opposite parity
  assert.ok(hs > HALF_N);
  const hex = "0x" + r.toString(16).padStart(64, "0") + hs.toString(16).padStart(64, "0") + (v === 27 ? "1c" : "1b");
  const res = await verifySignature(parseVerify({ address: r0.address, hash: r0.hash, signature: hex }), new FakeChain());
  assert.equal(res.valid, true);
  assert.match(res.notes.join(" "), /malleable/);
});
