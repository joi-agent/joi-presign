// Parity: every case in fixtures.json was produced by the Python joi_presign.analyze with the same
// fake lookups. The Worker must return the same kind, risk, findings and decoded data.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyze } from "../src/core.js";
import { keccak256, utf8, toHex } from "../src/keccak.js";
import { decode, hexToBytes, isAddress, toChecksumAddress } from "../src/abi.js";
import { parseJsonLossless } from "../src/json.js";
import { FakeLookups, NOW } from "./fake.js";

const fx = parseJsonLossless(readFileSync(new URL("./fixtures.json", import.meta.url), "utf8"));

// Value-level comparison: the fixtures store every integer as a string, the Worker keeps small counts as numbers.
const norm = (v) => (typeof v === "number" ? String(v) : Array.isArray(v) ? v.map(norm)
  : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, norm(x)])) : v);

// eth_abi's error text differs from ours, so MALFORMED_CALLDATA messages are compared by code only.
const comparable = (findings) => findings.map((f) => (f.code === "MALFORMED_CALLDATA" ? { ...f, message: "*" } : f));

for (const c of fx.cases) {
  test(`parity: ${c.name}`, async () => {
    const r = await analyze(c.payload, c.chain, new FakeLookups());
    assert.equal(r.kind, c.expected.kind);
    assert.equal(r.risk, c.expected.risk);
    assert.deepEqual(comparable(r.findings), comparable(c.expected.findings));
    assert.deepEqual(norm(JSON.parse(JSON.stringify(r.decoded))), norm(c.expected.decoded));
  });
}

test("keccak vectors", () => {
  assert.equal(toHex(keccak256(utf8(""))), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(toHex(keccak256(utf8("abc"))), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  assert.equal(toHex(keccak256(utf8("a".repeat(136)))), "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e");
});

test("checksum addresses (EIP-55 vectors)", () => {
  for (const a of ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"]) {
    assert.equal(toChecksumAddress(a.toLowerCase()), a);
    assert.ok(isAddress(a));
  }
  assert.ok(!isAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")); // bad checksum
  assert.ok(isAddress("0x" + "ab".repeat(20)));
});

test("strict decoder rejects dirty padding and out-of-range values", () => {
  const word = (hex) => hex.padStart(64, "0");
  assert.throws(() => decode(["address"], hexToBytes(word("ff" + "11".repeat(20)))), /padding/);
  assert.throws(() => decode(["bool"], hexToBytes(word("02"))), /bool/);
  assert.throws(() => decode(["uint8"], hexToBytes(word("0100"))), /range/);
  assert.throws(() => decode(["bytes"], hexToBytes(word("20") + word("ffffffff"))), /bounds|exceed/);
  assert.throws(() => decode(["uint256[]"], hexToBytes(word("20") + word("10"))), /exceeds/);
});

test("lossless JSON keeps big integers exact and leaves strings alone", () => {
  const v = parseJsonLossless('{"a": 115792089237316195423570985008687907853269984665640564039457584007913129639935, "b": 12, "c": "99999999999999999999", "d": -12345678901234567890, "e": 1.5e30, "f": "x\\"123456789012345678"}');
  assert.equal(v.a, "115792089237316195423570985008687907853269984665640564039457584007913129639935");
  assert.equal(v.b, 12);
  assert.equal(v.c, "99999999999999999999");
  assert.equal(v.d, "-12345678901234567890");
  assert.equal(v.e, 1.5e30);
  assert.equal(v.f, 'x"123456789012345678'); // the escaped quote must not end the string
});
