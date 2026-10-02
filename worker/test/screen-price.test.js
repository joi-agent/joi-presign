import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { handle, openapi, _resetRateLimit } from "../src/worker.js";
import { DEFAULTS, b64decodeJson, b64encodeJson } from "../src/x402.js";
import { OFAC, OFAC_META } from "../src/ofac-data.js";
import { SCREEN_NOTICE, parseScreenTarget, screenAddress, screenMatches } from "../src/screen.js";
import { FEEDS, SEL, decodeString, formatUnits, parsePriceTarget, readPrice, supportedPairs } from "../src/price.js";
import { LookupUnavailable } from "../src/profile.js";
import { toChecksumAddress } from "../src/abi.js";
import { FakeChain, abiString, uintWord, word } from "./fakechain.js";

const ORIGIN = "https://joi-presign.example.workers.dev";
const TOOLS = new URL("../tools/", import.meta.url);
const FIXTURE = new URL("./fixtures/sdn-sample.xml", import.meta.url);

// ---------------------------------------------------------------- generator (tools/gen_ofac.py)

function runGenerator(args) {
  return spawnSync("python3", [new URL("gen_ofac.py", TOOLS).pathname, ...args], { encoding: "utf8" });
}

test("gen_ofac.py: extracts only EVM digital-currency addresses, lowercased, with entity, label, uid and programs", async () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ofac-")), "ofac-data.js");
  const r = runGenerator(["--file", FIXTURE.pathname, "--out", out, "--min-count", "0"]);
  assert.equal(r.status, 0, r.stderr);
  const m = await import(pathToFileURL(out).href + "?v=" + Date.now());
  assert.equal(m.OFAC_META.published, "2026-09-28");
  assert.equal(m.OFAC_META.sdn_record_count, 3);
  assert.equal(m.OFAC_META.evm_address_count, 2);
  assert.equal(m.OFAC_META.entity_count, 2);
  assert.match(m.OFAC_GENERATED_AT, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  // The same address listed as ETH and as USDT (different case) collapses to one key with two matches.
  assert.deepEqual(m.OFAC["0x" + "aa".repeat(20)], [
    ["EXAMPLE SHIPPING LTD", "ETH", 900001, ["TESTPROG"]],
    ["EXAMPLE SHIPPING LTD", "USDT", 900001, ["TESTPROG"]],
  ]);
  // Individuals get "First LAST"; programs are sorted; malformed 0x values, Tron, Bitcoin and emails are skipped.
  assert.deepEqual(m.OFAC["0x" + "bb".repeat(20)], [["Jane DOE", "ARB", 900002, ["PROG-A", "PROG-B"]]]);
  assert.deepEqual(Object.keys(m.OFAC).sort(), ["0x" + "aa".repeat(20), "0x" + "bb".repeat(20)]);
  const text = fs.readFileSync(out, "utf8");
  assert.equal(text.split("\n").filter((l) => l.includes("OFAC_GENERATED_AT")).length, 1, "generated_at on its own line, so refresh diffs can ignore it");
});

test("gen_ofac.py: refuses to write when too few addresses are found (format change guard)", () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ofac-")), "ofac-data.js");
  const r = runGenerator(["--file", FIXTURE.pathname, "--out", out, "--min-count", "50"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /REFUSED/);
  assert.equal(fs.existsSync(out), false);
});

test("bundled OFAC data: lowercased 0x keys, metadata consistent with the entries", () => {
  const keys = Object.keys(OFAC);
  assert.ok(keys.length >= 50);
  assert.equal(keys.length, OFAC_META.evm_address_count);
  for (const k of keys) assert.match(k, /^0x[0-9a-f]{40}$/);
  assert.match(OFAC_META.source, /^https:\/\/sanctionslistservice\.ofac\.treas\.gov\//);
  assert.match(OFAC_META.published, /^\d{4}-\d\d-\d\d$/);
});

// ---------------------------------------------------------------- /screen logic

const LISTED = Object.keys(OFAC)[0];

test("screen: a listed address matches in lower, upper-hex and checksummed form", async () => {
  for (const form of [LISTED, "0x" + LISTED.slice(2).toUpperCase(), toChecksumAddress(LISTED)]) {
    const t = parseScreenTarget("ethereum", form);
    assert.equal(t.error, undefined, form);
    const r = await screenAddress(t, new FakeChain());
    assert.equal(r.sanctioned, true, form);
    assert.ok(r.matches.length >= 1);
    assert.deepEqual(Object.keys(r.matches[0]).sort(), ["currency_label", "entity", "programs", "sdn_uid"]);
    assert.equal(r.address, toChecksumAddress(LISTED));
    assert.equal(r.notice, SCREEN_NOTICE);
    assert.equal(r.list_published, OFAC_META.published);
    assert.deepEqual(r.warnings, []);
  }
});

test("screen: an unlisted address is not sanctioned, with the same notice", async () => {
  const a = "0x" + "12".repeat(20);
  assert.deepEqual(screenMatches(a), []);
  const r = await screenAddress(parseScreenTarget(undefined, a), new FakeChain());
  assert.equal(r.sanctioned, false);
  assert.deepEqual(r.matches, []);
  assert.equal(r.chain_id, 8453);
  assert.match(r.notice, /absence from the list is not a clearance/);
});

test("screen: a mixed-case address with a bad checksum is screened but warned about", async () => {
  const good = toChecksumAddress(LISTED);
  const flipped = good.slice(0, 2) + [...good.slice(2)].map((c) => (/[a-f]/.test(c) ? c.toUpperCase() : /[A-F]/.test(c) ? c.toLowerCase() : c)).join("");
  const t = parseScreenTarget("base", flipped);
  assert.equal(t.checksumOk, false);
  const r = await screenAddress(t, new FakeChain());
  assert.equal(r.sanctioned, true);
  assert.equal(r.warnings.length, 1);
});

test("screen: input validation and account kind", async () => {
  assert.ok(parseScreenTarget("base", "0x1234").error);
  assert.ok(parseScreenTarget("solana", "0x" + "12".repeat(20)).error);
  assert.ok(parseScreenTarget("base", 42).error);
  const a = "0x" + "34".repeat(20);
  const kindOf = async (chain) => (await screenAddress(parseScreenTarget("base", a), chain)).kind;
  assert.equal(await kindOf(new FakeChain()), "eoa");
  assert.equal(await kindOf(new FakeChain({ code: { [a]: "0x6080" } })), "contract");
  assert.equal(await kindOf(new FakeChain({ code: { [a]: "0xef0100" + "56".repeat(20) } })), "eoa-7702");
  assert.equal(await kindOf(new FakeChain({ unknown: ["code"] })), "unknown");
});

// ---------------------------------------------------------------- /price logic

const T0 = 1_790_000_000;
function feedChain(t, { description = t.pair, decimals = 8, answer = 274897796500n, updatedAt = T0 - 60, roundId = 42n, now = T0, missing = [] } = {}) {
  const f = t.feed.toLowerCase();
  const signed = (v) => (v < 0n ? (1n << 256n) + v : v);
  const calls = {
    [`${f}:${SEL.description}`]: abiString(description),
    [`${f}:${SEL.decimals}`]: uintWord(decimals),
    [`${f}:${SEL.latestRoundData}`]: "0x" + [roundId, signed(answer), BigInt(updatedAt), BigInt(updatedAt), roundId].map((v) => word(v.toString(16))).join(""),
  };
  for (const m of missing) delete calls[`${f}:${SEL[m]}`];
  const c = new FakeChain({ calls });
  c.now = () => now;
  return c;
}

test("price: reads latestRoundData, formats the price exactly, reports age and freshness", async () => {
  const t = parsePriceTarget("base", "eth");
  assert.equal(t.asset, "ETH");
  const r = await readPrice(t, feedChain(t));
  assert.equal(r.price, "2748.977965");
  assert.equal(r.decimals, 8);
  assert.equal(r.age_seconds, 60);
  assert.equal(r.stale, false);
  assert.equal(r.round_id, "42");
  assert.equal(r.description, "ETH / USD");
  assert.equal(r.feed, FEEDS.base.ETH[1]);
  assert.equal(r.updated_at, new Date((T0 - 60) * 1000).toISOString());
});

test("price: stale once the last update is older than the heartbeat plus 10%", async () => {
  const t = parsePriceTarget("ethereum", "ETH"); // heartbeat 3600
  assert.equal((await readPrice(t, feedChain(t, { updatedAt: T0 - 3900 }))).stale, false);
  assert.equal((await readPrice(t, feedChain(t, { updatedAt: T0 - 4000 }))).stale, true);
});

test("price: a description mismatch, a failed call or an unusable answer is LookupUnavailable (503, never charged)", async () => {
  const t = parsePriceTarget("arbitrum", "BTC");
  await assert.rejects(readPrice(t, feedChain(t, { description: "ETH / USD" })), (e) => e instanceof LookupUnavailable && /mismatch/.test(e.message));
  await assert.rejects(readPrice(t, feedChain(t, { missing: ["latestRoundData"] })), LookupUnavailable);
  await assert.rejects(readPrice(t, feedChain(t, { answer: -5n })), LookupUnavailable);
  await assert.rejects(readPrice(t, feedChain(t, { answer: 0n })), LookupUnavailable);
  await assert.rejects(readPrice(t, feedChain(t, { updatedAt: 0 })), LookupUnavailable);
  // Case and spacing differences in the description are tolerated.
  assert.equal((await readPrice(t, feedChain(t, { description: "btc /  usd" }))).asset, "BTC");
});

test("price: input validation and the supported list", () => {
  assert.equal(parsePriceTarget(undefined, "USDC").chain, "base");
  assert.match(parsePriceTarget("base", "DOGE").error, /no feed for DOGE on base.*ETH/);
  assert.match(parsePriceTarget("solana", "ETH").error, /unknown chain/);
  assert.match(parsePriceTarget("base", "").error, /asset is required/);
  assert.ok(parsePriceTarget("ethereum", "steth").feed);
  assert.ok(parsePriceTarget("base", "cbETH").feed);
  const pairs = supportedPairs();
  assert.ok(pairs.includes("base:ETH") && pairs.includes("arbitrum:LINK") && pairs.includes("ethereum:STETH"));
  for (const [, m] of Object.entries(FEEDS)) for (const [, [pair, feed, hb]] of Object.entries(m)) {
    assert.match(pair, / \/ USD$/);
    assert.match(feed, /^0x[0-9a-fA-F]{40}$/);
    assert.ok(hb > 0);
  }
});

test("price helpers: formatUnits and decodeString", () => {
  assert.equal(formatUnits(274897796500n, 8), "2748.977965");
  assert.equal(formatUnits(100000000n, 8), "1");
  assert.equal(formatUnits(5n, 8), "0.00000005");
  assert.equal(decodeString(abiString("LINK / USD")), "LINK / USD");
  assert.equal(decodeString("0x12"), null);
});

// ---------------------------------------------------------------- HTTP: 402, paid flow, bad input, openapi

function payment(resource) {
  return b64encodeJson({
    x402Version: 2,
    resource: { url: ORIGIN + resource },
    accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra },
    payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32) } },
  });
}
function facilitator() {
  const calls = [];
  const f = async (url) => {
    calls.push(url);
    const answer = url.endsWith("/verify") ? { isValid: true } : { success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453" };
    return new Response(JSON.stringify(answer), { headers: { "Content-Type": "application/json" } });
  };
  f.calls = calls;
  return f;
}
const req = (pathq, { method = "GET", body, pay } = {}) => new Request(ORIGIN + pathq, {
  method,
  headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(pay ? { "PAYMENT-SIGNATURE": payment(pathq.split("?")[0]) } : {}) },
  body: body === undefined ? undefined : JSON.stringify(body),
});

test("unpaid /screen and /price: 402 on GET, HEAD and POST with each route's description and Bazaar info", async () => {
  _resetRateLimit();
  for (const p of ["/screen", "/price"]) {
    for (const method of ["GET", "HEAD", "POST"]) {
      const r = await handle(req(p, { method }), {}, { fetch: facilitator() });
      assert.equal(r.status, 402, `${method} ${p}`);
      const pr = b64decodeJson(r.headers.get("PAYMENT-REQUIRED"));
      assert.equal(pr.resource.url, ORIGIN + p);
      assert.equal(pr.accepts[0].payTo, DEFAULTS.payTo);
      assert.ok(pr.extensions.bazaar.info && pr.extensions.bazaar.schema);
      assert.match(pr.resource.description, p === "/screen" ? /OFAC/ : /Chainlink/);
    }
  }
});

test("paid /screen: verify, screen, settle (GET and POST)", async () => {
  _resetRateLimit();
  const fac = facilitator();
  const deps = { fetch: fac, lookups: () => new FakeChain() };
  let r = await handle(req(`/screen?chain=ethereum&address=${LISTED}`, { pay: true }), {}, deps);
  assert.equal(r.status, 200);
  let body = await r.json();
  assert.equal(body.sanctioned, true);
  assert.ok(r.headers.get("PAYMENT-RESPONSE"));
  r = await handle(req("/screen", { method: "POST", body: { address: "0x" + "12".repeat(20) }, pay: true }), {}, deps);
  body = await r.json();
  assert.equal(r.status, 200);
  assert.equal(body.sanctioned, false);
  assert.deepEqual(fac.calls.map((u) => u.split("/").pop()), ["verify", "settle", "verify", "settle"]);
});

test("paid /price: 200 with the price; a feed mismatch is 503 and never settled", async () => {
  _resetRateLimit();
  const t = parsePriceTarget("base", "ETH");
  let fac = facilitator();
  let r = await handle(req("/price?asset=ETH&chain=base", { pay: true }), {}, { fetch: fac, lookups: () => feedChain(t, { now: Math.floor(Date.now() / 1000), updatedAt: Math.floor(Date.now() / 1000) - 30 }) });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).price, "2748.977965");
  assert.deepEqual(fac.calls.map((u) => u.split("/").pop()), ["verify", "settle"]);
  fac = facilitator();
  r = await handle(req("/price?asset=ETH&chain=base", { pay: true }), {}, { fetch: fac, lookups: () => feedChain(t, { description: "BTC / USD" }) });
  assert.equal(r.status, 503);
  assert.match((await r.json()).error, /not charged/);
  assert.deepEqual(fac.calls.map((u) => u.split("/").pop()), ["verify"]);
});

test("paid but bad input on /screen and /price: 400 before the facilitator is called", async () => {
  _resetRateLimit();
  const fac = facilitator();
  const deps = { fetch: fac, lookups: () => new FakeChain() };
  for (const p of ["/screen?address=0x1234", "/screen?address=0x" + "12".repeat(20) + "&chain=solana", "/price?asset=DOGE", "/price?chain=solana&asset=ETH", "/price"]) {
    const r = await handle(req(p, { pay: true }), {}, deps);
    assert.equal(r.status, 400, p);
  }
  assert.equal(fac.calls.length, 0);
});

test("openapi and llms.txt list /screen and /price with payment info and the supported pairs", async () => {
  const spec = openapi({ ...DEFAULTS }, ORIGIN);
  for (const p of ["/screen", "/price"]) {
    for (const m of ["get", "post"]) assert.deepEqual(spec.paths[p][m]["x-payment-info"].protocols, [{ x402: {} }], `${m} ${p}`);
  }
  assert.ok(spec.paths["/price"].get.parameters[0].schema.enum.includes("ETH"));
  assert.ok(spec.paths["/screen"].get.responses["200"].content["application/json"].example.notice);
  _resetRateLimit();
  const text = await (await handle(new Request(ORIGIN + "/llms.txt"), {}, {})).text();
  assert.match(text, /GET \/screen/);
  assert.match(text, /base:ETH/);
  assert.match(text, /not legal advice/);
});
