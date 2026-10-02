import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { handle, _resetRateLimit } from "../src/worker.js";
import { DEFAULTS, b64decodeJson, b64encodeJson } from "../src/x402.js";
import { BAZAAR_TOKEN, BAZAAR_TX, BAZAAR_VERIFY } from "../src/routes-meta.js";
import { toChecksumAddress } from "../src/abi.js";
import { FakeChain, addrWord, uintWord, abiString } from "./fakechain.js";
import { TOPICS } from "../src/txexplain.js";

const ORIGIN = "https://joi-presign.example.workers.dev";
const V = JSON.parse(fs.readFileSync(new URL("./sig-vectors.json", import.meta.url), "utf8"));
const MAIL = V.typed[0];
const A = (b) => toChecksumAddress("0x" + b.repeat(20));
const [ALICE, BOB, TOKEN] = ["a1", "b2", "c3"].map(A);
const H = "0x" + "ab".repeat(32);
const k = (a) => a.toLowerCase();

function payment(resource) {
  return b64encodeJson({
    x402Version: 2,
    resource: { url: ORIGIN + resource },
    accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra },
    payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32) } },
  });
}

function facilitator({ settle = { success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453" } } = {}) {
  const calls = [];
  const f = async (url, init) => {
    calls.push(url);
    const answer = url.endsWith("/verify") ? { isValid: true } : settle;
    return new Response(JSON.stringify(answer), { headers: { "Content-Type": "application/json" } });
  };
  f.calls = calls;
  return f;
}

function txChain() {
  return new FakeChain({
    txs: { [H]: { from: ALICE, to: TOKEN, value: "0x0", input: "0x" } },
    receipts: { [H]: { status: "0x1", gasUsed: "0x5208", effectiveGasPrice: "0x1", blockNumber: "0x10", logs: [{ address: TOKEN, topics: [TOPICS.T_TRANSFER, addrWord(ALICE), addrWord(BOB)], data: uintWord(5_000_000) }] } },
    calls: { [`${k(TOKEN)}:0x95d89b41`]: abiString("USDC"), [`${k(TOKEN)}:0x313ce567`]: uintWord(6) },
  });
}
function tokenChain() {
  return new FakeChain({
    code: { [k(TOKEN)]: "0x6080604052" },
    calls: { [`${k(TOKEN)}:0x95d89b41`]: abiString("TST"), [`${k(TOKEN)}:0x313ce567`]: uintWord(18), [`${k(TOKEN)}:0x18160ddd`]: uintWord(1000) },
    sourcify: { [k(TOKEN)]: { verified: false, name: null } },
  });
}

const get = (path, headers = {}) => new Request(ORIGIN + path, { headers });
const post = (path, body, headers = {}) => new Request(ORIGIN + path, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });

// Capture logs and check they only ever contain {route, outcome}.
function captureLogs() {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  return { lines, restore: () => { console.log = orig; } };
}

test.beforeEach(() => _resetRateLimit());

test("bad input on every new route (payment attached): 400 before verifying payment, never reaches the facilitator, logged as bad_input", async () => {
  const fac = facilitator();
  const deps = { fetch: fac, lookups: () => new FakeChain() };
  const cases = [
    get("/tx?hash=0x1234"),
    get("/tx?chain=solana&hash=" + H),
    post("/tx", "{nope"),
    post("/verify-signature", "{nope"),
    post("/verify-signature", { address: MAIL.address, signature: MAIL.signature }),
    post("/verify-signature", { address: MAIL.address, typedData: { ...MAIL.typedData, primaryType: "X" }, signature: MAIL.signature }),
    get("/token?address=0x1234"),
    post("/token", { chain: "solana", address: TOKEN }),
  ];
  const logs = captureLogs();
  try {
    for (const req of cases) {
      // A payment is attached: input is validated before the facilitator is ever called.
      const paid = new Request(req, { headers: { ...Object.fromEntries(req.headers), "PAYMENT-SIGNATURE": "eyJ4IjoxfQ==" } });
      const r = await handle(paid, {}, deps);
      assert.equal(r.status, 400, req.url);
      assert.ok((await r.json()).error);
    }
  } finally { logs.restore(); }
  assert.equal(fac.calls.length, 0);
  assert.equal(logs.lines.length, cases.length);
  for (const l of logs.lines) assert.equal(JSON.parse(l).outcome, "bad_input");
});

test("unpaid: 402 with each route's own description, Bazaar info and input schema", async () => {
  const deps = { fetch: facilitator(), lookups: () => new FakeChain() };
  const cases = [
    [get("/tx?chain=base&hash=" + H), "/tx", BAZAAR_TX, /Transaction explainer/],
    [post("/verify-signature", { address: MAIL.address, typedData: MAIL.typedData, signature: MAIL.signature }), "/verify-signature", BAZAAR_VERIFY, /Signature verifier/],
    [get("/token?address=" + TOKEN), "/token", BAZAAR_TOKEN, /Token profile/],
  ];
  const logs = captureLogs();
  try {
    for (const [req, path, bazaar, desc] of cases) {
      const r = await handle(req, {}, deps);
      assert.equal(r.status, 402);
      const pr = b64decodeJson(r.headers.get("PAYMENT-REQUIRED"));
      assert.equal(pr.resource.url, ORIGIN + path);
      assert.match(pr.resource.description, desc);
      assert.deepEqual(pr.extensions.bazaar, bazaar);
      assert.ok(pr.extensions.bazaar.schema.properties.input);
      assert.equal(pr.accepts[0].payTo, DEFAULTS.payTo);
    }
  } finally { logs.restore(); }
  assert.deepEqual(logs.lines.map((l) => JSON.parse(l)), [
    { route: "/tx", outcome: "unpaid_402" }, { route: "/verify-signature", outcome: "unpaid_402" }, { route: "/token", outcome: "unpaid_402" },
  ]);
});

test("paid /tx (GET and POST): verified, explained, settled, logged paid_ok", async () => {
  for (const req of [
    get("/tx?chain=ethereum&hash=" + H, { "PAYMENT-SIGNATURE": payment("/tx") }),
    post("/tx", { chain: "ethereum", hash: H }, { "PAYMENT-SIGNATURE": payment("/tx") }),
  ]) {
    const fac = facilitator();
    const logs = captureLogs();
    let r;
    try { r = await handle(req, {}, { fetch: fac, lookups: txChain }); } finally { logs.restore(); }
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.kind, "tx");
    assert.match(body.summary.join(" "), /sent 5 USDC/);
    assert.ok(r.headers.get("PAYMENT-RESPONSE"));
    assert.deepEqual(fac.calls.map((u) => u.split("/").pop()), ["verify", "settle"]);
    assert.deepEqual(logs.lines.map((l) => JSON.parse(l)), [{ route: "/tx", outcome: "paid_ok" }]);
  }
});

test("paid /tx for an unknown hash: 404, never settled, logged run_failed:not_found", async () => {
  const fac = facilitator();
  const logs = captureLogs();
  let r;
  try { r = await handle(get("/tx?hash=" + H, { "PAYMENT-SIGNATURE": payment("/tx") }), {}, { fetch: fac, lookups: () => new FakeChain() }); } finally { logs.restore(); }
  assert.equal(r.status, 404);
  assert.match((await r.json()).error, /not charged/);
  assert.deepEqual(fac.calls.map((u) => u.split("/").pop()), ["verify"]);
  assert.deepEqual(JSON.parse(logs.lines[0]), { route: "/tx", outcome: "run_failed:not_found" });
});

test("paid /verify-signature and /token", async () => {
  const fac = facilitator();
  const logs = captureLogs();
  let r1, r2;
  try {
    r1 = await handle(post("/verify-signature", { address: MAIL.address, typedData: MAIL.typedData, signature: MAIL.signature }, { "PAYMENT-SIGNATURE": payment("/verify-signature") }), {}, { fetch: fac, lookups: () => new FakeChain() });
    r2 = await handle(get("/token?chain=base&address=" + TOKEN, { "PAYMENT-SIGNATURE": payment("/token") }), {}, { fetch: fac, lookups: tokenChain });
  } finally { logs.restore(); }
  assert.equal(r1.status, 200);
  assert.deepEqual((({ valid, method, recovered }) => ({ valid, method, recovered }))(await r1.json()), { valid: true, method: "ecrecover", recovered: MAIL.address });
  assert.equal(r2.status, 200);
  const t = await r2.json();
  assert.deepEqual([t.kind, t.token.symbol, t.token.decimals], ["token", "TST", 18]);
  assert.deepEqual(logs.lines.map((l) => JSON.parse(l).outcome), ["paid_ok", "paid_ok"]);
});

test("verify and settle failures are logged with cleaned reasons; logs never contain addresses or IPs", async () => {
  const logs = captureLogs();
  try {
    // facilitator rejects the payment
    const badVerify = async (url) => new Response(JSON.stringify(url.endsWith("/verify") ? { isValid: false, invalidReason: "Insufficient funds for 0x9999999999999999999999999999999999999999!" } : {}), { headers: { "Content-Type": "application/json" } });
    let r = await handle(get("/token?address=" + TOKEN, { "PAYMENT-SIGNATURE": payment("/token"), "CF-Connecting-IP": "203.0.113.9" }), {}, { fetch: badVerify, lookups: tokenChain });
    assert.equal(r.status, 402);
    // settlement fails
    r = await handle(get("/token?address=" + TOKEN, { "PAYMENT-SIGNATURE": payment("/token"), "CF-Connecting-IP": "203.0.113.9" }), {}, { fetch: facilitator({ settle: { success: false, errorReason: "invalid_transaction_state" } }), lookups: tokenChain });
    assert.equal(r.status, 402);
    // lookup failure
    r = await handle(get("/token?address=" + TOKEN, { "PAYMENT-SIGNATURE": payment("/token") }), {}, { fetch: facilitator(), lookups: () => new FakeChain({ unknown: ["code"] }) });
    assert.equal(r.status, 503);
  } finally { logs.restore(); }
  const outcomes = logs.lines.map((l) => JSON.parse(l).outcome);
  assert.deepEqual(outcomes, ["verify_failed:insufficient_funds_for_0x_", "settle_failed:invalid_transaction_state", "run_failed:unavailable"]);
  for (const l of logs.lines) {
    assert.deepEqual(Object.keys(JSON.parse(l)).sort(), ["outcome", "route"]);
    assert.doesNotMatch(l, /203\.0\.113\.9|0x[0-9a-fA-F]{6,}/);
  }
});

test("openapi lists every paid route with x-payment-info; llms.txt describes them", async () => {
  const spec = await (await handle(get("/openapi.json"), { PRICE_ATOMIC: "10000" }, {})).json();
  for (const [path, methods] of [["/check", ["post"]], ["/contract", ["get", "post"]], ["/tx", ["get", "post"]], ["/verify-signature", ["post"]], ["/token", ["get", "post"]]]) {
    for (const m of methods) {
      const op = spec.paths[path][m];
      assert.ok(op, `${m} ${path}`);
      assert.equal(op["x-payment-info"].price.amount, "0.01");
      assert.deepEqual(op.security, []);
      assert.ok(op.responses["402"]);
    }
  }
  assert.ok(spec.paths["/tx"].get.responses["404"]);
  const txt = await (await handle(get("/llms.txt"), {}, {})).text();
  for (const re of [/GET \/tx/, /POST \/verify-signature/, /GET \/token/, /honeypots/, /Never send private keys/]) assert.match(txt, re);
});

test("Bazaar examples are real captured outputs, not placeholders", () => {
  assert.equal(BAZAAR_TX.info.output.example.kind, "tx");
  assert.ok(BAZAAR_TX.info.output.example.summary.length);
  assert.equal(BAZAAR_VERIFY.info.output.example.valid, true);
  assert.equal(BAZAAR_TOKEN.info.output.example.token.symbol, "USDC");
});
