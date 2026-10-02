import test from "node:test";
import assert from "node:assert/strict";
import { handle, _resetRateLimit } from "../src/worker.js";
import { DEFAULTS, b64decodeJson, b64encodeJson, facilitators, verifyPayment, settlePayment } from "../src/x402.js";
import { cdpJwt, importCdpKey, _clearCdpKeyCache } from "../src/cdpauth.js";
import { FakeLookups } from "./fake.js";

// A throwaway Ed25519 key generated per run. Never the real one.
async function throwawayKey() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const un = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const raw = new Uint8Array([...un(jwk.d), ...un(jwk.x)]);
  let bin = "";
  for (const b of raw) bin += String.fromCharCode(b);
  return { secret: btoa(bin), publicKey: kp.publicKey, keyId: "test-key-" + crypto.randomUUID() };
}

const b64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
const jsonPart = (s) => JSON.parse(new TextDecoder().decode(b64urlDecode(s)));

const URL_CHECK = "https://joi-presign.example.workers.dev/check?chain=ethereum";
const EOA = "0x" + "44".repeat(20);
const TOKEN = "0x" + "11".repeat(20);
const APPROVE_EOA = { chainId: 1, to: TOKEN, data: "0x095ea7b3" + EOA.slice(2).padStart(64, "0") + "1".padStart(64, "0") };
const v2Payment = () => ({
  x402Version: 2,
  resource: { url: "https://joi-presign.example.workers.dev/check" },
  accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra },
  payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32) } },
});
const paidPost = () => new Request(URL_CHECK, {
  method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) }, body: JSON.stringify(APPROVE_EOA),
});

const OK_VERIFY = { isValid: true, payer: "0x" + "99".repeat(20) };
const OK_SETTLE = { success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453" };

/** Scripted fetch: `script(url, init)` returns a Response or throws. Records every call. */
function fakeFetch(script) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, auth: init.headers.Authorization || null, body: JSON.parse(init.body) });
    return script(url, init);
  };
  f.calls = calls;
  return f;
}
const reply = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
const isCdp = (url) => url.startsWith(DEFAULTS.cdpUrl);
const isPayai = (url) => url.startsWith(DEFAULTS.facilitatorUrl);
const tail = (url) => url.split("/").pop();

function captureLogs() {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  return { lines, restore: () => { console.log = orig; } };
}

test.beforeEach(() => { _resetRateLimit(); _clearCdpKeyCache(); });

test("cdpJwt: header/payload fields, uri bound to method+host+path, 120 s validity, Ed25519 signature verifies", async () => {
  const k = await throwawayKey();
  const now = 1_790_000_000;
  const url = DEFAULTS.cdpUrl + "/verify";
  const jwt = await cdpJwt({ keyId: k.keyId, secret: k.secret, method: "post", url, now, nonce: "ab12" });
  const [h, p, s] = jwt.split(".");
  assert.deepEqual(jsonPart(h), { alg: "EdDSA", kid: k.keyId, typ: "JWT", nonce: "ab12" });
  assert.deepEqual(jsonPart(p), { sub: k.keyId, iss: "cdp", nbf: now, exp: now + 120, uri: "POST api.cdp.coinbase.com/platform/v2/x402/verify" });
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, k.publicKey, b64urlDecode(s), new TextEncoder().encode(`${h}.${p}`));
  assert.equal(ok, true);
  const settleJwt = await cdpJwt({ keyId: k.keyId, secret: k.secret, method: "POST", url: DEFAULTS.cdpUrl + "/settle", now });
  assert.equal(jsonPart(settleJwt.split(".")[1]).uri, "POST api.cdp.coinbase.com/platform/v2/x402/settle");
  // Random nonce by default.
  const a = jsonPart((await cdpJwt({ keyId: k.keyId, secret: k.secret, method: "POST", url })).split(".")[0]).nonce;
  const b = jsonPart((await cdpJwt({ keyId: k.keyId, secret: k.secret, method: "POST", url })).split(".")[0]).nonce;
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});

test("importCdpKey rejects secrets that aren't 64 bytes", async () => {
  await assert.rejects(importCdpKey(btoa("short")), /64 bytes/);
});

test("facilitator selection: PayAI only without CDP credentials; CDP first, PayAI fallback with them", async () => {
  assert.deepEqual(facilitators({ ...DEFAULTS }).map((f) => f.name), ["payai"]);
  const cfg = { ...DEFAULTS, cdpCreds: () => ({ keyId: "k", secret: "s" }) };
  assert.deepEqual(facilitators(cfg).map((f) => f.name), ["cdp", "payai"]);
  assert.deepEqual(facilitators({ ...DEFAULTS, cdpCreds: () => null }).map((f) => f.name), ["payai"]);
});

test("paid request with CDP configured: verify and settle on CDP with a fresh Bearer JWT each, PayAI never called", async () => {
  const k = await throwawayKey();
  const env = { CDP_API_KEY_ID: k.keyId, CDP_API_KEY_SECRET: k.secret };
  const f = fakeFetch((url) => (isCdp(url) ? reply(tail(url) === "verify" ? OK_VERIFY : OK_SETTLE) : reply({ error: "should not be called" }, 500)));
  const logs = captureLogs();
  let r;
  try { r = await handle(paidPost(), env, { fetch: f, lookups: () => new FakeLookups() }); } finally { logs.restore(); }
  assert.equal(r.status, 200);
  assert.deepEqual(f.calls.map((c) => [isCdp(c.url) ? "cdp" : "other", tail(c.url)]), [["cdp", "verify"], ["cdp", "settle"]]);
  for (const c of f.calls) {
    assert.match(c.auth, /^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    assert.equal(jsonPart(c.auth.slice(7).split(".")[1]).uri, `POST api.cdp.coinbase.com/platform/v2/x402/${tail(c.url)}`);
  }
  // Bazaar extension is still echoed to the facilitator (CDP catalogs on settle) via the client's payload as before.
  assert.equal(f.calls[1].body.paymentRequirements.payTo, DEFAULTS.payTo);
  assert.deepEqual(logs.lines.map((l) => JSON.parse(l).outcome), ["paid_ok:cdp"]);
});

for (const [label, down] of [
  ["network error", () => { throw new Error("connect ECONNREFUSED"); }],
  ["5xx", () => reply({ errorType: "internal" }, 503)],
  ["401 (our credentials)", () => reply({ errorType: "unauthorized" }, 401)],
  ["429", () => reply({ errorType: "rate_limited" }, 429)],
]) {
  test(`CDP verify ${label}: falls back to PayAI for BOTH verify and settle (no mixing)`, async () => {
    const k = await throwawayKey();
    const env = { CDP_API_KEY_ID: k.keyId, CDP_API_KEY_SECRET: k.secret };
    const f = fakeFetch((url) => (isCdp(url) ? down() : reply(tail(url) === "verify" ? OK_VERIFY : OK_SETTLE)));
    const logs = captureLogs();
    let r;
    try { r = await handle(paidPost(), env, { fetch: f, lookups: () => new FakeLookups() }); } finally { logs.restore(); }
    assert.equal(r.status, 200);
    assert.deepEqual(f.calls.map((c) => [isCdp(c.url) ? "cdp" : isPayai(c.url) ? "payai" : "?", tail(c.url)]), [["cdp", "verify"], ["payai", "verify"], ["payai", "settle"]]);
    assert.equal(f.calls[1].auth, null, "PayAI never gets the CDP token");
    assert.deepEqual(logs.lines.map((l) => JSON.parse(l).outcome), ["paid_ok:payai"]);
  });
}

test("CDP says the payment is invalid (4xx answer): final, 402, no fallback, nothing settled", async () => {
  const k = await throwawayKey();
  const env = { CDP_API_KEY_ID: k.keyId, CDP_API_KEY_SECRET: k.secret };
  const f = fakeFetch((url) => (isCdp(url) ? reply({ isValid: false, invalidReason: "insufficient_funds" }, 400) : reply(OK_VERIFY)));
  const logs = captureLogs();
  let r;
  try { r = await handle(paidPost(), env, { fetch: f, lookups: () => new FakeLookups() }); } finally { logs.restore(); }
  assert.equal(r.status, 402);
  assert.deepEqual(f.calls.map((c) => tail(c.url)), ["verify"]);
  assert.equal(b64decodeJson(r.headers.get("PAYMENT-REQUIRED")).error, "insufficient_funds");
  assert.deepEqual(logs.lines.map((l) => JSON.parse(l).outcome), ["verify_failed:insufficient_funds:cdp"]);
});

test("verified on CDP, CDP settle down: NOT retried on PayAI (no mixing), payer gets 402, not charged twice", async () => {
  const k = await throwawayKey();
  const env = { CDP_API_KEY_ID: k.keyId, CDP_API_KEY_SECRET: k.secret };
  const f = fakeFetch((url) => {
    if (isCdp(url) && tail(url) === "verify") return reply(OK_VERIFY);
    if (isCdp(url)) throw new Error("down");
    return reply(OK_SETTLE);
  });
  const logs = captureLogs();
  let r;
  try { r = await handle(paidPost(), env, { fetch: f, lookups: () => new FakeLookups() }); } finally { logs.restore(); }
  assert.equal(r.status, 402);
  assert.deepEqual(f.calls.map((c) => [isCdp(c.url) ? "cdp" : "payai", tail(c.url)]), [["cdp", "verify"], ["cdp", "settle"]]);
  assert.deepEqual(logs.lines.map((l) => JSON.parse(l).outcome), ["settle_failed:unexpected_settle_error:cdp"]);
});

test("both facilitators down: 502, nothing settled", async () => {
  const k = await throwawayKey();
  const env = { CDP_API_KEY_ID: k.keyId, CDP_API_KEY_SECRET: k.secret };
  const f = fakeFetch(() => reply({ error: "down" }, 502));
  const r = await handle(paidPost(), env, { fetch: f, lookups: () => new FakeLookups() });
  assert.equal(r.status, 502);
  assert.deepEqual(f.calls.map((c) => tail(c.url)), ["verify", "verify"]);
});

test("the CDP secret and key id never appear in responses, response headers, facilitator bodies or logs", async () => {
  const k = await throwawayKey();
  const env = { CDP_API_KEY_ID: k.keyId, CDP_API_KEY_SECRET: k.secret };
  const f = fakeFetch((url) => reply(tail(url) === "verify" ? OK_VERIFY : OK_SETTLE));
  const logs = captureLogs();
  const seen = [];
  try {
    const reqs = [
      paidPost(),
      new Request(URL_CHECK, { method: "POST", body: JSON.stringify(APPROVE_EOA) }),
      new Request("https://joi-presign.example.workers.dev/"),
      new Request("https://joi-presign.example.workers.dev/openapi.json"),
      new Request("https://joi-presign.example.workers.dev/llms.txt"),
    ];
    for (const req of reqs) {
      const r = await handle(req, env, { fetch: f, lookups: () => new FakeLookups() });
      seen.push(await r.text());
      for (const [, v] of r.headers) seen.push(v);
      const pr = r.headers.get("PAYMENT-REQUIRED");
      if (pr) seen.push(JSON.stringify(b64decodeJson(pr)));
    }
  } finally { logs.restore(); }
  seen.push(...logs.lines, ...f.calls.map((c) => JSON.stringify(c.body)));
  const all = seen.join("\n");
  assert.ok(!all.includes(k.secret), "secret leaked");
  assert.ok(!all.includes(k.secret.slice(0, 20)), "secret prefix leaked");
  assert.ok(!all.includes(k.keyId), "key id leaked");
});

test("verifyPayment/settlePayment directly: settle uses the facilitator named by verify", async () => {
  const k = await throwawayKey();
  const cfg = { ...DEFAULTS, cdpCreds: () => ({ keyId: k.keyId, secret: k.secret }) };
  const payment = { version: 2, payload: v2Payment() };
  const f = fakeFetch((url) => (isCdp(url) ? reply({}, 500) : reply(tail(url) === "verify" ? OK_VERIFY : OK_SETTLE)));
  const v = await verifyPayment(cfg, "https://x/check", payment, f);
  assert.equal(v.facilitator, "payai");
  const s = await settlePayment(cfg, "https://x/check", payment, f, { facilitator: v.facilitator });
  assert.equal(s.success, true);
  assert.deepEqual(f.calls.map((c) => [isCdp(c.url) ? "cdp" : "payai", tail(c.url)]), [["cdp", "verify"], ["payai", "verify"], ["payai", "settle"]]);
});
