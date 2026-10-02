import test from "node:test";
import assert from "node:assert/strict";
import { handle, _resetRateLimit, rateLimited } from "../src/worker.js";
import { DEFAULTS, b64decodeJson, b64encodeJson } from "../src/x402.js";
import { FakeLookups } from "./fake.js";

const URL_CHECK = "https://joi-presign.example.workers.dev/check?chain=ethereum";
const EOA = "0x" + "44".repeat(20);
const TOKEN = "0x" + "11".repeat(20);
const APPROVE_EOA = { chainId: 1, to: TOKEN, data: "0x095ea7b3" + EOA.slice(2).padStart(64, "0") + "1".padStart(64, "0") };

function v2Payment(over = {}, authOver = {}) {
  return {
    x402Version: 2,
    resource: { url: "https://joi-presign.example.workers.dev/check" },
    accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra, ...over },
    payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32), ...authOver } },
  };
}

function v1Payment() {
  const p = v2Payment();
  return { x402Version: 1, scheme: "exact", network: "base", payload: p.payload };
}

// Mock facilitator: records calls, answers per the script.
function facilitator({ verify = { isValid: true, payer: "0x" + "99".repeat(20) }, settle = { success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453", payer: "0x" + "99".repeat(20) }, fail } = {}) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    if (fail) throw new Error("down");
    const answer = url.endsWith("/verify") ? verify : settle;
    return new Response(JSON.stringify(answer), { headers: { "Content-Type": "application/json" } });
  };
  f.calls = calls;
  return f;
}

const post = (body, headers = {}, url = URL_CHECK) =>
  new Request(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });

const deps = (fetchFn) => ({ fetch: fetchFn, lookups: () => new FakeLookups() });

test.beforeEach(() => _resetRateLimit());

test("unpaid request gets 402 with v2 header and v1 body", async () => {
  const fac = facilitator();
  const r = await handle(post(APPROVE_EOA), {}, deps(fac));
  assert.equal(r.status, 402);
  const req = b64decodeJson(r.headers.get("PAYMENT-REQUIRED"));
  assert.equal(req.x402Version, 2);
  assert.deepEqual(req.accepts[0], { scheme: "exact", network: "eip155:8453", amount: "5000", asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } });
  assert.match(req.resource.description, /Joi, an AI agent/);
  assert.equal(req.resource.url, "https://joi-presign.example.workers.dev/check");
  const body = await r.json();
  assert.equal(body.x402Version, 1);
  assert.equal(body.accepts[0].network, "base");
  assert.equal(body.accepts[0].maxAmountRequired, "5000");
  assert.equal(fac.calls.length, 0);
});

test("bad input is rejected before payment and never charged", async () => {
  const fac = facilitator();
  const pay = { "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) };
  for (const body of ["{not json", JSON.stringify({ hello: 1 }), JSON.stringify([1, 2])]) {
    const r = await handle(post(body, pay), {}, deps(fac));
    assert.equal(r.status, 400);
  }
  assert.equal((await handle(post(APPROVE_EOA, pay, URL_CHECK.replace("ethereum", "solana")), {}, deps(fac))).status, 400);
  assert.equal(fac.calls.length, 0);
});

test("paid v2 request: verify, analyze, settle, report + PAYMENT-RESPONSE", async () => {
  const fac = facilitator();
  const r = await handle(post(APPROVE_EOA, { "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) }), {}, deps(fac));
  assert.equal(r.status, 200);
  const rep = await r.json();
  assert.equal(rep.risk, "HIGH");
  assert.equal(rep.findings[0].code, "APPROVAL_TO_EOA");
  const settled = b64decodeJson(r.headers.get("PAYMENT-RESPONSE"));
  assert.equal(settled.success, true);
  assert.deepEqual(fac.calls.map((c) => c.url), ["https://facilitator.payai.network/verify", "https://facilitator.payai.network/settle"]);
  const vb = fac.calls[0].body;
  assert.equal(vb.x402Version, 2);
  assert.equal(vb.paymentRequirements.amount, "5000");
  assert.equal(vb.paymentRequirements.network, "eip155:8453");
  assert.equal(vb.paymentPayload.payload.authorization.value, "5000");
});

test("paid v1 request uses v1 requirements and X-PAYMENT-RESPONSE", async () => {
  const fac = facilitator({ settle: { success: true, transaction: "0x" + "cd".repeat(32), network: "base" } });
  const r = await handle(post(APPROVE_EOA, { "X-PAYMENT": b64encodeJson(v1Payment()) }), {}, deps(fac));
  assert.equal(r.status, 200);
  assert.ok(r.headers.get("X-PAYMENT-RESPONSE"));
  assert.equal(r.headers.get("PAYMENT-RESPONSE"), null);
  const vb = fac.calls[0].body;
  assert.equal(vb.x402Version, 1);
  assert.equal(vb.paymentRequirements.maxAmountRequired, "5000");
  assert.equal(vb.paymentRequirements.network, "base");
});

test("wrong amount, recipient, network or asset is refused locally without calling the facilitator", async () => {
  const fac = facilitator();
  const cases = [
    v2Payment({ amount: "1" }),
    v2Payment({ payTo: EOA }),
    v2Payment({ network: "eip155:1" }),
    v2Payment({ asset: TOKEN }),
    v2Payment({}, { to: EOA }),
    v2Payment({}, { value: "1" }),
  ];
  for (const p of cases) {
    const r = await handle(post(APPROVE_EOA, { "PAYMENT-SIGNATURE": b64encodeJson(p) }), {}, deps(fac));
    assert.equal(r.status, 402);
    assert.ok(b64decodeJson(r.headers.get("PAYMENT-REQUIRED")).error);
  }
  assert.equal(fac.calls.length, 0);
});

test("malformed payment header is a 400", async () => {
  const fac = facilitator();
  const r = await handle(post(APPROVE_EOA, { "PAYMENT-SIGNATURE": "!!!not base64" }), {}, deps(fac));
  assert.equal(r.status, 400);
  assert.equal(fac.calls.length, 0);
});

test("facilitator says invalid: 402 with its reason, no report, no settle", async () => {
  const fac = facilitator({ verify: { isValid: false, invalidReason: "insufficient_funds" } });
  const r = await handle(post(APPROVE_EOA, { "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) }), {}, deps(fac));
  assert.equal(r.status, 402);
  assert.equal(b64decodeJson(r.headers.get("PAYMENT-REQUIRED")).error, "insufficient_funds");
  assert.deepEqual(fac.calls.map((c) => c.url.split("/").pop()), ["verify"]);
});

test("settlement failure: 402 with the failed PAYMENT-RESPONSE and no report", async () => {
  const fac = facilitator({ settle: { success: false, errorReason: "invalid_transaction_state", transaction: "", network: "eip155:8453" } });
  const r = await handle(post(APPROVE_EOA, { "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) }), {}, deps(fac));
  assert.equal(r.status, 402);
  const body = await r.json();
  assert.equal(body.risk, undefined);
  assert.equal(b64decodeJson(r.headers.get("PAYMENT-RESPONSE")).success, false);
});

test("facilitator unreachable: 502, nothing settled", async () => {
  const fac = facilitator({ fail: true });
  const r = await handle(post(APPROVE_EOA, { "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) }), {}, deps(fac));
  assert.equal(r.status, 502);
});

test("analysis error after verify is not settled (payer not charged)", async () => {
  const fac = facilitator();
  const bad = { chainId: "not-a-number", to: TOKEN, data: "0x" };
  const r = await handle(post(bad, { "PAYMENT-SIGNATURE": b64encodeJson(v2Payment()) }), {}, deps(fac));
  assert.equal(r.status, 400);
  assert.deepEqual(fac.calls.map((c) => c.url.split("/").pop()), ["verify"]);
});

test("env overrides price, recipient and facilitator", async () => {
  const fac = facilitator();
  const env = { PRICE_ATOMIC: "10000", FACILITATOR_URL: "https://fac.example/", PAY_TO: "0x" + "12".repeat(20) };
  const r = await handle(post(APPROVE_EOA), env, deps(fac));
  const acc = b64decodeJson(r.headers.get("PAYMENT-REQUIRED")).accepts[0];
  assert.equal(acc.amount, "10000");
  assert.equal(acc.payTo, env.PAY_TO);
});

test("GET / describes the service honestly, /health works, CORS preflight", async () => {
  const r = await handle(new Request("https://x.example/"), {}, deps(facilitator()));
  const text = await r.text();
  assert.match(text, /Run by Joi, an autonomous AI agent/);
  assert.match(text, /0\.005 USDC/);
  assert.match(text, /not a guarantee/);
  assert.equal((await handle(new Request("https://x.example/health"), {}, deps(facilitator()))).status, 200);
  const o = await handle(new Request("https://x.example/check", { method: "OPTIONS" }), {}, deps(facilitator()));
  assert.equal(o.status, 204);
  assert.match(o.headers.get("Access-Control-Allow-Headers"), /PAYMENT-SIGNATURE/);
  assert.equal((await handle(new Request("https://x.example/nope"), {}, deps(facilitator()))).status, 404);
});

test("oversized body is refused", async () => {
  const r = await handle(post("{" + " ".repeat(70 * 1024) + "}"), {}, deps(facilitator()));
  assert.equal(r.status, 413);
});

test("rate limit: 30 per IP per minute", () => {
  _resetRateLimit();
  const t = 1_000_000_000_000;
  for (let i = 0; i < 30; i++) assert.equal(rateLimited("1.2.3.4", t), false);
  assert.equal(rateLimited("1.2.3.4", t), true);
  assert.equal(rateLimited("5.6.7.8", t), false);
  assert.equal(rateLimited("1.2.3.4", t + 60_000), false);
});

test("GET /openapi.json describes the paid /check operation with the configured price", async () => {
  _resetRateLimit();
  const get = (env) => handle(new Request("https://joi-presign.example/openapi.json"), env, {});
  let r = await get({});
  assert.equal(r.status, 200);
  let spec = await r.json();
  assert.equal(spec.openapi, "3.1.0");
  assert.equal(spec.info.contact.email, "joi-ai@agentmail.to");
  const op = spec.paths["/check"].post;
  assert.deepEqual(op.security, []);
  assert.equal(op["x-payment-info"].price.amount, "0.005");
  assert.deepEqual(op["x-payment-info"].protocols, [{ x402: {} }]);
  assert.ok(op.responses["402"]);
  spec = await (await get({ PRICE_ATOMIC: "10000" })).json();
  assert.equal(spec.paths["/check"].post["x-payment-info"].price.amount, "0.01");
  assert.equal(spec.servers[0].url, "https://joi-presign.example");
});
