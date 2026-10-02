import test from "node:test";
import assert from "node:assert/strict";
import {
  LookupUnavailable, parseTarget, profileAddress, SLOT_ADMIN, SLOT_BEACON, SLOT_IMPLEMENTATION,
  SLOT_PROXIABLE, SLOT_ZOS_ADMIN, SLOT_ZOS_IMPLEMENTATION,
} from "../src/profile.js";
import { toChecksumAddress } from "../src/abi.js";
import { handle, _resetRateLimit } from "../src/worker.js";
import { BAZAAR_CONTRACT, DEFAULTS, b64decodeJson, b64encodeJson } from "../src/x402.js";

const A = (b) => toChecksumAddress("0x" + b.repeat(20));
const word = (addr) => "0x" + addr.slice(2).toLowerCase().padStart(64, "0");
const ZERO_WORD = "0x" + "0".repeat(64);
const [TARGET, IMPL, ADMIN, BEACON, OWNER, DELEGATE] = ["a1", "b2", "c3", "d4", "e5", "f6"].map(A);
const KNOWN = "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B"; // allowlisted 7702 delegate
const SEL_OWNER = "0x8da5cb5b", SEL_ADMIN = "0xf851a440", SEL_GETOWNER = "0x893d20e8", SEL_IMPL = "0x5c60da1b";

// A tiny fake chain: code, storage, call results, Sourcify, nonces and balances. Unlisted = default; `unknown` sets force null.
class FakeChain {
  constructor({ code = {}, storage = {}, calls = {}, sourcify = {}, nonce = {}, balance = {}, unknown = [] } = {}) {
    Object.assign(this, { code, storage, calls, sourcify, nonce, balances: balance, unknown: new Set(unknown) });
  }
  k(a) { return a.toLowerCase(); }
  async getCode(_c, a) { return this.unknown.has("code:" + this.k(a)) ? null : (this.code[this.k(a)] ?? "0x"); }
  async codeKind(c, a) {
    const code = await this.getCode(c, a);
    if (code === null) return null;
    if (code === "0x") return "none";
    if (code.startsWith("0xef0100")) return "7702";
    return "contract";
  }
  async getStorageAt(_c, a, slot) {
    if (this.unknown.has("storage")) return null;
    return this.storage[`${this.k(a)}:${slot}`] ?? ZERO_WORD;
  }
  async ethCall(_c, to, data) { return this.calls[`${this.k(to)}:${data}`] ?? null; }
  async sourcifyInfo(_c, a) { return this.sourcify[this.k(a)] ?? { verified: null, name: null }; }
  async txCount(_c, a) { return this.unknown.has("nonce") ? null : (this.nonce[this.k(a)] ?? 0); }
  async balance(_c, a) { return this.unknown.has("balance") ? null : (this.balances[this.k(a)] ?? 0n); }
}

const k = (a) => a.toLowerCase();
const CONTRACT_CODE = "0x6080604052";
const findingCodes = (r) => r.findings.map((f) => `${f.code}:${f.severity}`);

test("parseTarget: chain defaults to base, rejects bad chains and addresses", () => {
  assert.deepEqual(parseTarget(undefined, TARGET.toLowerCase()), { chainId: 8453, address: TARGET });
  assert.equal(parseTarget("ethereum", TARGET).chainId, 1);
  assert.match(parseTarget("solana", TARGET).error, /unknown chain/);
  assert.match(parseTarget("base", "0x1234").error, /address/);
  assert.match(parseTarget("base", TARGET.slice(2)).error, /address/); // no 0x
  assert.match(parseTarget("base", null).error, /address/);
  // flip the case of one letter in a valid mixed-case checksum: invalid checksum
  const i = [...TARGET].findIndex((c, j) => j > 1 && /[a-fA-F]/.test(c));
  const flipped = TARGET.slice(0, i) + (TARGET[i] === TARGET[i].toUpperCase() ? TARGET[i].toLowerCase() : TARGET[i].toUpperCase()) + TARGET.slice(i + 1);
  assert.notEqual(flipped.toLowerCase() === flipped, true, "test needs a mixed-case result");
  assert.match(parseTarget("base", flipped).error, /checksum/);
});

test("no code, no nonce, no balance: kind none with a MEDIUM NO_CODE", async () => {
  const r = await profileAddress(1, TARGET, new FakeChain());
  assert.equal(r.kind, "none");
  assert.equal(r.risk, "MEDIUM");
  assert.deepEqual(findingCodes(r), ["NO_CODE:MEDIUM"]);
  assert.equal(r.profile.balance_wei, "0");
});

test("a funded wallet that never sent anything is an EOA, not empty", async () => {
  const r = await profileAddress(1, TARGET, new FakeChain({ balance: { [k(TARGET)]: 10n ** 16n } }));
  assert.equal(r.kind, "eoa");
  assert.equal(r.risk, "LOW");
  assert.deepEqual(findingCodes(r), ["EOA:INFO", "NEVER_SENT:INFO"]);
});

test("an active wallet is an EOA; unknown activity is reported, not guessed as empty", async () => {
  let r = await profileAddress(1, TARGET, new FakeChain({ nonce: { [k(TARGET)]: 7 } }));
  assert.deepEqual(findingCodes(r), ["EOA:INFO"]);
  r = await profileAddress(1, TARGET, new FakeChain({ unknown: ["nonce"] }));
  assert.equal(r.kind, "eoa");
  assert.ok(findingCodes(r).includes("LOOKUP_UNAVAILABLE:INFO"));
});

test("an EIP-7702 delegated wallet names its delegate and flags an unverified one", async () => {
  const chain = new FakeChain({
    code: { [k(TARGET)]: "0xef0100" + DELEGATE.slice(2).toLowerCase() },
    sourcify: { [k(DELEGATE)]: { verified: false, name: null } },
  });
  const r = await profileAddress(8453, TARGET, chain);
  assert.equal(r.kind, "eoa-7702");
  assert.equal(r.profile.delegate, DELEGATE);
  assert.deepEqual(findingCodes(r), ["DELEGATED_EOA:MEDIUM", "DELEGATE_UNVERIFIED:MEDIUM"]);
  const known = await profileAddress(8453, TARGET, new FakeChain({
    code: { [k(TARGET)]: "0xef0100" + KNOWN.slice(2).toLowerCase() },
    sourcify: { [k(KNOWN)]: { verified: true, name: "EIP7702StatelessDeleGator" } },
  }));
  assert.equal(known.profile.delegate_known_as, "MetaMask EIP7702StatelessDeleGator");
  assert.deepEqual(findingCodes(known), ["DELEGATED_EOA:MEDIUM"]);
});

test("a verified plain contract with no owner is LOW", async () => {
  const r = await profileAddress(1, TARGET, new FakeChain({
    code: { [k(TARGET)]: CONTRACT_CODE }, sourcify: { [k(TARGET)]: { verified: true, name: "Permit2" } },
  }));
  assert.equal(r.kind, "contract");
  assert.equal(r.risk, "LOW");
  assert.deepEqual(findingCodes(r), ["SOURCE_VERIFIED:INFO"]);
  assert.equal(r.profile.name, "Permit2");
  assert.equal(r.profile.proxy, null);
  assert.equal(r.profile.owner, null);
  assert.equal(r.profile.code_size, 5);
});

test("unverified source is MEDIUM; unknown verification is INFO only", async () => {
  let r = await profileAddress(1, TARGET, new FakeChain({ code: { [k(TARGET)]: CONTRACT_CODE }, sourcify: { [k(TARGET)]: { verified: false, name: null } } }));
  assert.deepEqual(findingCodes(r), ["UNVERIFIED_SOURCE:MEDIUM"]);
  r = await profileAddress(1, TARGET, new FakeChain({ code: { [k(TARGET)]: CONTRACT_CODE } }));
  assert.equal(r.risk, "LOW");
  assert.deepEqual(findingCodes(r), ["LOOKUP_UNAVAILABLE:INFO"]);
});

test("owner(): EOA owner is MEDIUM, contract owner INFO, zero owner = renounced", async () => {
  const base = { code: { [k(TARGET)]: CONTRACT_CODE }, sourcify: { [k(TARGET)]: { verified: true, name: "X" } } };
  let r = await profileAddress(1, TARGET, new FakeChain({ ...base, calls: { [`${k(TARGET)}:${SEL_OWNER}`]: word(OWNER) } }));
  assert.ok(findingCodes(r).includes("OWNER_IS_EOA:MEDIUM"));
  assert.deepEqual(r.profile.owner, { function: "owner()", address: OWNER, kind: "eoa" });
  r = await profileAddress(1, TARGET, new FakeChain({
    ...base, code: { ...base.code, [k(OWNER)]: CONTRACT_CODE }, calls: { [`${k(TARGET)}:${SEL_ADMIN}`]: word(OWNER) },
  }));
  assert.ok(findingCodes(r).includes("OWNER_IS_CONTRACT:INFO"));
  assert.equal(r.profile.owner.function, "admin()");
  r = await profileAddress(1, TARGET, new FakeChain({ ...base, calls: { [`${k(TARGET)}:${SEL_GETOWNER}`]: ZERO_WORD } }));
  assert.ok(findingCodes(r).includes("OWNERSHIP_RENOUNCED:INFO"));
  // a return value that isn't an address is ignored
  r = await profileAddress(1, TARGET, new FakeChain({ ...base, calls: { [`${k(TARGET)}:${SEL_OWNER}`]: "0x" + "ff".repeat(32) } }));
  assert.equal(r.profile.owner, null);
});

test("EIP-1967 proxy with an EOA admin and a verified implementation", async () => {
  const r = await profileAddress(1, TARGET, new FakeChain({
    code: { [k(TARGET)]: CONTRACT_CODE, [k(IMPL)]: CONTRACT_CODE },
    storage: { [`${k(TARGET)}:${SLOT_IMPLEMENTATION}`]: word(IMPL), [`${k(TARGET)}:${SLOT_ADMIN}`]: word(ADMIN) },
    sourcify: { [k(TARGET)]: { verified: true, name: "TransparentUpgradeableProxy" }, [k(IMPL)]: { verified: true, name: "TokenV2" } },
  }));
  assert.deepEqual(findingCodes(r), ["SOURCE_VERIFIED:INFO", "UPGRADEABLE_PROXY:MEDIUM", "ADMIN_IS_EOA:MEDIUM", "IMPLEMENTATION_VERIFIED:INFO"]);
  assert.equal(r.profile.proxy.type, "eip1967");
  assert.equal(r.profile.proxy.implementation_name, "TokenV2");
});

test("EIP-1967 proxy: contract admin INFO, no admin = UUPS note, unverified or codeless implementation flagged", async () => {
  const proxyChain = (extra) => new FakeChain({
    code: { [k(TARGET)]: CONTRACT_CODE, [k(IMPL)]: CONTRACT_CODE, ...(extra.code || {}) },
    storage: { [`${k(TARGET)}:${SLOT_IMPLEMENTATION}`]: word(IMPL), ...(extra.storage || {}) },
    sourcify: { [k(TARGET)]: { verified: true, name: "P" }, ...(extra.sourcify || {}) },
  });
  let r = await profileAddress(1, TARGET, proxyChain({ code: { [k(ADMIN)]: CONTRACT_CODE }, storage: { [`${k(TARGET)}:${SLOT_ADMIN}`]: word(ADMIN) }, sourcify: { [k(IMPL)]: { verified: true, name: "I" } } }));
  assert.ok(findingCodes(r).includes("ADMIN_IS_CONTRACT:INFO"));
  r = await profileAddress(1, TARGET, proxyChain({ sourcify: { [k(IMPL)]: { verified: false, name: null } } }));
  assert.ok(findingCodes(r).includes("UPGRADE_VIA_IMPLEMENTATION:INFO"));
  assert.ok(findingCodes(r).includes("IMPLEMENTATION_UNVERIFIED:MEDIUM"));
  r = await profileAddress(1, TARGET, proxyChain({ code: { [k(IMPL)]: "0x" } }));
  assert.ok(findingCodes(r).includes("IMPLEMENTATION_NO_CODE:HIGH"));
  assert.equal(r.risk, "HIGH");
});

test("beacon proxy reads the implementation from the beacon", async () => {
  const r = await profileAddress(1, TARGET, new FakeChain({
    code: { [k(TARGET)]: CONTRACT_CODE, [k(IMPL)]: CONTRACT_CODE, [k(BEACON)]: CONTRACT_CODE },
    storage: { [`${k(TARGET)}:${SLOT_BEACON}`]: word(BEACON) },
    calls: { [`${k(BEACON)}:${SEL_IMPL}`]: word(IMPL) },
    sourcify: { [k(TARGET)]: { verified: true, name: "BeaconProxy" }, [k(IMPL)]: { verified: true, name: "Impl" } },
  }));
  assert.equal(r.profile.proxy.type, "eip1967-beacon");
  assert.equal(r.profile.proxy.implementation, IMPL);
  assert.ok(findingCodes(r).includes("UPGRADEABLE_BEACON:MEDIUM"));
  assert.ok(findingCodes(r).includes("IMPLEMENTATION_VERIFIED:INFO"));
});

test("EIP-1167 minimal proxy is detected from bytecode and can't be upgraded", async () => {
  const minimal = "0x363d3d373d3d3d363d73" + IMPL.slice(2).toLowerCase() + "5af43d82803e903d91602b57fd5bf3";
  const r = await profileAddress(1, TARGET, new FakeChain({
    code: { [k(TARGET)]: minimal, [k(IMPL)]: CONTRACT_CODE },
    sourcify: { [k(TARGET)]: { verified: false, name: null }, [k(IMPL)]: { verified: true, name: "Wallet" } },
  }));
  assert.equal(r.profile.proxy.type, "eip1167");
  assert.equal(r.profile.proxy.implementation, IMPL);
  assert.ok(findingCodes(r).includes("MINIMAL_PROXY:INFO"));
  assert.ok(!findingCodes(r).some((c) => c.startsWith("UPGRADEABLE")));
});

test("legacy ZeppelinOS proxy (like USDC's FiatTokenProxy) and EIP-1822 UUPS are detected", async () => {
  let r = await profileAddress(8453, TARGET, new FakeChain({
    code: { [k(TARGET)]: CONTRACT_CODE, [k(IMPL)]: CONTRACT_CODE },
    storage: { [`${k(TARGET)}:${SLOT_ZOS_IMPLEMENTATION}`]: word(IMPL), [`${k(TARGET)}:${SLOT_ZOS_ADMIN}`]: word(ADMIN) },
    sourcify: { [k(TARGET)]: { verified: true, name: "FiatTokenProxy" }, [k(IMPL)]: { verified: true, name: "FiatTokenV2_2" } },
  }));
  assert.equal(r.profile.proxy.type, "zeppelinos");
  assert.deepEqual(findingCodes(r), ["SOURCE_VERIFIED:INFO", "UPGRADEABLE_PROXY:MEDIUM", "ADMIN_IS_EOA:MEDIUM", "IMPLEMENTATION_VERIFIED:INFO"]);
  r = await profileAddress(1, TARGET, new FakeChain({
    code: { [k(TARGET)]: CONTRACT_CODE, [k(IMPL)]: CONTRACT_CODE },
    storage: { [`${k(TARGET)}:${SLOT_PROXIABLE}`]: word(IMPL) },
    sourcify: { [k(TARGET)]: { verified: true, name: "P" }, [k(IMPL)]: { verified: true, name: "I" } },
  }));
  assert.equal(r.profile.proxy.type, "eip1822");
  assert.ok(findingCodes(r).includes("UPGRADE_VIA_IMPLEMENTATION:INFO"));
});

test("unreadable proxy slots are reported; unreadable code aborts so the caller isn't charged", async () => {
  const r = await profileAddress(1, TARGET, new FakeChain({ code: { [k(TARGET)]: CONTRACT_CODE }, sourcify: { [k(TARGET)]: { verified: true, name: "X" } }, unknown: ["storage"] }));
  assert.ok(findingCodes(r).includes("LOOKUP_UNAVAILABLE:INFO"));
  await assert.rejects(profileAddress(1, TARGET, new FakeChain({ unknown: ["code:" + k(TARGET)] })), LookupUnavailable);
});

// ---------------------------------------------------------------- HTTP: /contract

function facilitator() {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    const answer = url.endsWith("/verify")
      ? { isValid: true, payer: "0x" + "99".repeat(20) }
      : { success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453", payer: "0x" + "99".repeat(20) };
    return new Response(JSON.stringify(answer), { headers: { "Content-Type": "application/json" } });
  };
  f.calls = calls;
  return f;
}

function payment(resource) {
  return b64encodeJson({
    x402Version: 2,
    resource: { url: resource },
    accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra },
    payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32) } },
  });
}

const ORIGIN = "https://joi-presign.example.workers.dev";
const plainChain = () => new FakeChain({ code: { [k(TARGET)]: CONTRACT_CODE }, sourcify: { [k(TARGET)]: { verified: true, name: "Thing" } } });

test.beforeEach(() => _resetRateLimit());

test("GET /contract unpaid: 402 with the contract route's own description and Bazaar info", async () => {
  const fac = facilitator();
  const r = await handle(new Request(`${ORIGIN}/contract?chain=base&address=${TARGET}`), {}, { fetch: fac, lookups: plainChain });
  assert.equal(r.status, 402);
  const pr = b64decodeJson(r.headers.get("PAYMENT-REQUIRED"));
  assert.equal(pr.resource.url, `${ORIGIN}/contract`);
  assert.match(pr.resource.description, /Contract profile/);
  assert.deepEqual(pr.extensions.bazaar, BAZAAR_CONTRACT);
  assert.equal(pr.extensions.bazaar.info.input.method, "GET");
  assert.equal(fac.calls.length, 0);
});

test("bad /contract input is refused with 400 before payment and never reaches the facilitator", async () => {
  const fac = facilitator();
  const pay = { "PAYMENT-SIGNATURE": payment(`${ORIGIN}/contract`) };
  const bad = [
    new Request(`${ORIGIN}/contract?chain=base&address=0x1234`, { headers: pay }),
    new Request(`${ORIGIN}/contract?chain=solana&address=${TARGET}`, { headers: pay }),
    new Request(`${ORIGIN}/contract?chain=base`, { headers: pay }),
    new Request(`${ORIGIN}/contract`, { method: "POST", headers: { ...pay, "Content-Type": "application/json" }, body: "not json" }),
    new Request(`${ORIGIN}/contract`, { method: "POST", headers: { ...pay, "Content-Type": "application/json" }, body: "[1,2]" }),
  ];
  for (const req of bad) {
    const r = await handle(req, {}, { fetch: fac, lookups: plainChain });
    assert.equal(r.status, 400, await r.clone().text());
  }
  assert.equal(fac.calls.length, 0);
});

test("paid GET /contract: verify, profile, settle, report with PAYMENT-RESPONSE", async () => {
  const fac = facilitator();
  const r = await handle(new Request(`${ORIGIN}/contract?chain=ethereum&address=${TARGET.toLowerCase()}`, {
    headers: { "PAYMENT-SIGNATURE": payment(`${ORIGIN}/contract`) },
  }), {}, { fetch: fac, lookups: plainChain });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.kind, "contract");
  assert.equal(body.chain_id, 1);
  assert.equal(body.profile.address, TARGET);
  assert.equal(body.profile.name, "Thing");
  assert.ok(r.headers.get("PAYMENT-RESPONSE"));
  assert.deepEqual(fac.calls.map((c) => c.url.split("/").pop()), ["verify", "settle"]);
  assert.equal(fac.calls[1].body.paymentRequirements.payTo, DEFAULTS.payTo);
});

test("paid POST /contract with a JSON body works the same", async () => {
  const fac = facilitator();
  const r = await handle(new Request(`${ORIGIN}/contract`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": payment(`${ORIGIN}/contract`) },
    body: JSON.stringify({ chain: "base", address: TARGET }),
  }), {}, { fetch: fac, lookups: plainChain });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).chain_id, 8453);
});

test("a failed code lookup returns 503 and is never settled", async () => {
  const fac = facilitator();
  const r = await handle(new Request(`${ORIGIN}/contract?address=${TARGET}`, {
    headers: { "PAYMENT-SIGNATURE": payment(`${ORIGIN}/contract`) },
  }), {}, { fetch: fac, lookups: () => new FakeChain({ unknown: ["code:" + k(TARGET)] }) });
  assert.equal(r.status, 503);
  assert.match((await r.json()).error, /not charged/);
  assert.deepEqual(fac.calls.map((c) => c.url.split("/").pop()), ["verify"]);
});

test("openapi lists /contract GET and POST at the configured price; about text mentions it", async () => {
  const spec = await (await handle(new Request(`${ORIGIN}/openapi.json`), { PRICE_ATOMIC: "10000" }, {})).json();
  for (const m of ["get", "post"]) {
    const op = spec.paths["/contract"][m];
    assert.deepEqual(op.security, []);
    assert.equal(op["x-payment-info"].price.amount, "0.01");
    assert.ok(op.responses["402"] && op.responses["400"] && op.responses["503"]);
  }
  assert.ok(spec.paths["/contract"].get.parameters.some((p) => p.name === "address" && p.required));
  assert.ok(spec.paths["/check"].post);
  const about = await (await handle(new Request(`${ORIGIN}/llms.txt`), {}, {})).text();
  assert.match(about, /GET \/contract\?chain=/);
});
