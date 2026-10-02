import test from "node:test";
import assert from "node:assert/strict";
import { handle, openapi, _resetRateLimit } from "../src/worker.js";
import { DEFAULTS, b64decodeJson, b64encodeJson } from "../src/x402.js";
import { checkUrl, siteOf, SafeFetcher, UnsafeUrl } from "../src/fetchsafe.js";
import { LookupUnavailable } from "../src/profile.js";
import { analyzeOption, parseX402CheckTarget, usdValue, x402Check, USDC } from "../src/x402check.js";
import { BASENAMES, ENS_REGISTRY, dnsEncode, namehash, normalizeName, parseNameTarget, resolveName, reverseNode } from "../src/ens.js";
import { AGENTS, checkRobots, evaluate, normalizePath, parseRobots, parseRobotsTarget } from "../src/robots.js";
import { OFAC } from "../src/ofac-data.js";
import { FEEDS } from "../src/price.js";
import { toChecksumAddress } from "../src/abi.js";
import { FakeChain, abiString, uintWord, word } from "./fakechain.js";

const ORIGIN = "https://joi-presign.example.workers.dev";
const BASE_USDC = USDC["eip155:8453"];
const PAY = "0x" + "a1".repeat(20);
const SANCTIONED = Object.keys(OFAC)[0];
const k = (a) => a.toLowerCase();

test.beforeEach(() => _resetRateLimit());

// ---------------------------------------------------------------- helpers

/** A fetch that serves fixed responses by URL ("METHOD URL" or "URL"), records calls, and answers the facilitator. */
function fakeFetch(routes = {}, { facilitator = true, fail = [] } = {}) {
  const calls = [];
  const f = async (url, init = {}) => {
    const method = (init.method || "GET").toUpperCase();
    calls.push({ url, method, redirect: init.redirect, body: init.body });
    if (facilitator && url.endsWith("/verify")) return Response.json({ isValid: true });
    if (facilitator && url.endsWith("/settle")) return Response.json({ success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453" });
    if (fail.includes(url)) throw new TypeError("network down");
    const r = routes[`${method} ${url}`] ?? routes[url];
    if (!r) return new Response("not found", { status: 404, headers: { "Content-Type": "text/plain" } });
    return typeof r === "function" ? r(init) : r.clone();
  };
  f.calls = calls;
  return f;
}

function v2Requirements(over = {}, accepts = null) {
  return {
    x402Version: 2,
    error: "payment required",
    resource: { url: "https://api.example.com/data", description: "Example data", mimeType: "application/json" },
    accepts: accepts ?? [{ scheme: "exact", network: "eip155:8453", amount: "10000", asset: BASE_USDC, payTo: PAY, maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" }, ...over }],
  };
}
function v1Body(over = {}) {
  return { x402Version: 1, error: "payment required", accepts: [{ scheme: "exact", network: "base", maxAmountRequired: "10000", asset: BASE_USDC, payTo: PAY, resource: "https://api.example.com/data", description: "Example data", mimeType: "application/json", maxTimeoutSeconds: 60, ...over }] };
}
function resp402({ v2 = v2Requirements(), v1 = v1Body() } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (v2) headers["PAYMENT-REQUIRED"] = b64encodeJson(v2);
  return new Response(v1 ? JSON.stringify(v1) : "", { status: 402, headers });
}

function payment(resource) {
  return b64encodeJson({
    x402Version: 2,
    resource: { url: ORIGIN + resource },
    accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra },
    payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32) } },
  });
}
const req = (pathq, { method = "GET", body, pay } = {}) => new Request(ORIGIN + pathq, {
  method,
  headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(pay ? { "PAYMENT-SIGNATURE": payment(pathq.split("?")[0]) } : {}) },
  body: body === undefined ? undefined : JSON.stringify(body),
});

// ---------------------------------------------------------------- fetchsafe

test("checkUrl refuses non-https, IP literals, local names, credentials, other ports and junk", () => {
  for (const bad of [
    "http://example.com/", "https://127.0.0.1/", "https://2130706433/", "https://0x7f.1/", "https://[::1]/", "https://localhost/",
    "https://foo.localhost/", "https://printer.local/", "https://db.internal/", "https://intranet/", "https://u:p@example.com/",
    "https://example.com:8443/", "ftp://example.com/", "not a url", "", "https://example.com/" + "a".repeat(2100), "https://a..b.com/",
  ]) {
    assert.throws(() => checkUrl(bad), UnsafeUrl, bad);
  }
  assert.equal(checkUrl("https://Example.COM/a?b=1#frag").toString(), "https://example.com/a?b=1");
  assert.equal(checkUrl("https://example.com:443/x").toString(), "https://example.com/x");
});

test("siteOf: registrable domain, with shared-hosting suffixes treated as public", () => {
  assert.equal(siteOf("a.b.example.com"), "example.com");
  assert.equal(siteOf("joi-presign.joi-agent.workers.dev"), "joi-agent.workers.dev");
  assert.equal(siteOf("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(siteOf("someone.github.io"), "someone.github.io");
});

test("SafeFetcher: same-site redirects followed, cross-site / unsafe / too many refused, manual redirects, size cap", async () => {
  const f = fakeFetch({
    "https://www.example.com/a": new Response(null, { status: 301, headers: { Location: "https://example.com/b" } }),
    "https://example.com/b": new Response("ok-b"),
    "https://example.com/x": new Response(null, { status: 302, headers: { Location: "https://evil.org/" } }),
    "https://example.com/ip": new Response(null, { status: 302, headers: { Location: "https://10.0.0.1/" } }),
    "https://example.com/h": new Response(null, { status: 302, headers: { Location: "http://example.com/" } }),
    "https://example.com/r1": new Response(null, { status: 302, headers: { Location: "/r2" } }),
    "https://example.com/r2": new Response(null, { status: 302, headers: { Location: "/r3" } }),
    "https://example.com/r3": new Response(null, { status: 302, headers: { Location: "/r4" } }),
    "https://example.com/big": new Response("x".repeat(5000)),
  }, { facilitator: false });
  const s = new SafeFetcher({ fetchFn: f, maxRequests: 50 });
  let r = await s.fetch("https://www.example.com/a");
  assert.equal(r.status, 200);
  assert.equal(r.text, "ok-b");
  assert.deepEqual(r.redirects, ["https://example.com/b"]);
  assert.ok(f.calls.every((c) => c.redirect === "manual"));
  r = await s.fetch("https://example.com/x");
  assert.match(r.blocked, /another site/);
  r = await s.fetch("https://example.com/ip");
  assert.match(r.blocked, /refused URL/);
  r = await s.fetch("https://example.com/h");
  assert.match(r.blocked, /refused URL/);
  r = await s.fetch("https://example.com/r1");
  assert.match(r.blocked, /more than 2 redirects/);
  r = await s.fetch("https://example.com/big", { maxBytes: 100 });
  assert.equal(r.text.length, 100);
  assert.equal(r.truncated, true);
});

test("SafeFetcher: network failures and an exhausted budget throw LookupUnavailable", async () => {
  const f = fakeFetch({ "https://example.com/": new Response("hi") }, { facilitator: false, fail: ["https://down.example.org/"] });
  await assert.rejects(new SafeFetcher({ fetchFn: f }).fetch("https://down.example.org/"), LookupUnavailable);
  const s = new SafeFetcher({ fetchFn: f, maxRequests: 1 });
  await s.fetch("https://example.com/");
  await assert.rejects(s.fetch("https://example.com/"), LookupUnavailable);
});

// ---------------------------------------------------------------- x402-check

const SITE = "https://api.example.com/data";

test("x402-check: v2 header + v1 body, canonical USDC to a plain wallet = LOW, amounts in units and USD", async () => {
  const f = fakeFetch({ [SITE]: resp402(), "https://api.example.com/llms.txt": new Response("# Example API\n", { headers: { "Content-Type": "text/plain" } }) }, { facilitator: false });
  const r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.x402, true);
  assert.deepEqual(r.versions, [2, 1]);
  assert.equal(r.risk, "LOW");
  assert.equal(r.verdict, "no red flags found");
  const o = r.options[0];
  assert.equal(o.network.name, "base");
  assert.equal(o.asset.kind, "usdc");
  assert.deepEqual(o.amount, { atomic: "10000", human: "0.01", usd: "0.01" });
  assert.equal(o.pay_to.kind, "eoa");
  assert.equal(o.pay_to.sanctioned, false);
  assert.deepEqual(r.discovery, { openapi: false, openapi_lists_path: null, llms_txt: true });
  assert.match(r.notice, /never pays/);
});

test("x402-check: a sanctioned payTo is HIGH and the verdict is 'do not pay'", async () => {
  const f = fakeFetch({ [SITE]: resp402({ v2: v2Requirements({ payTo: SANCTIONED }), v1: null }) }, { facilitator: false });
  const r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.risk, "HIGH");
  assert.equal(r.verdict, "do not pay");
  assert.equal(r.options[0].pay_to.sanctioned, true);
  assert.ok(r.options[0].findings.some((x) => x.code === "PAYTO_SANCTIONED" && x.severity === "HIGH"));
});

test("x402-check: per-option findings (scheme, asset, network, testnet, malformed, unverified contract, timeout)", async () => {
  const fc = new FakeChain({
    code: { [k(PAY)]: "0x6080" },
    sourcify: { [k(PAY)]: { verified: false, name: null } },
    calls: { [`${"0x" + "77".repeat(20)}:0x95d89b41`]: abiString("FAKEUSD"), [`${"0x" + "77".repeat(20)}:0x313ce567`]: uintWord(6) },
  });
  const opt = (over) => ({ scheme: "exact", network: "eip155:8453", amount: "10000", asset: BASE_USDC, payTo: "0x" + "b2".repeat(20), maxTimeoutSeconds: 60, ...over });
  const codes = async (over, v = 2) => (await analyzeOption(opt(over), v, fc)).findings.map((f) => `${f.code}:${f.severity}`);
  assert.ok((await codes({ scheme: "upto" })).includes("NOT_EXACT_SCHEME:MEDIUM"));
  const unk = await analyzeOption(opt({ asset: "0x" + "77".repeat(20) }), 2, fc);
  assert.ok(unk.findings.some((f) => f.code === "NON_USDC_ASSET" && /FAKEUSD/.test(f.message)));
  assert.equal(unk.amount.human, "0.01");
  assert.equal(unk.amount.usd, null);
  assert.ok((await codes({ network: "eip155:999999" })).includes("UNKNOWN_NETWORK:MEDIUM"));
  assert.ok((await codes({ network: "eip155:84532", asset: USDC["eip155:84532"] })).includes("TESTNET:INFO"));
  assert.ok((await codes({ amount: "1.5" })).includes("MALFORMED_REQUIREMENTS:HIGH"));
  assert.ok((await codes({ payTo: undefined })).includes("MALFORMED_REQUIREMENTS:HIGH"));
  assert.ok((await codes({ payTo: "0xnope" })).includes("MALFORMED_REQUIREMENTS:HIGH"));
  assert.ok((await codes({ payTo: PAY })).includes("PAYTO_UNVERIFIED_CONTRACT:MEDIUM"));
  assert.ok((await codes({ maxTimeoutSeconds: 86400 })).includes("LONG_VALIDITY:INFO"));
  assert.ok((await codes({ maxTimeoutSeconds: -1 })).includes("MALFORMED_REQUIREMENTS:HIGH"));
  // v1 field names and network names
  const v1 = await analyzeOption({ scheme: "exact", network: "base", maxAmountRequired: "2500000", asset: BASE_USDC, payTo: "0x" + "b2".repeat(20), resource: SITE, maxTimeoutSeconds: 60 }, 1, fc);
  assert.equal(v1.network.id, "eip155:8453");
  assert.equal(v1.amount.human, "2.5");
  // a Solana option: not screened, not read on-chain
  const sol = await analyzeOption({ scheme: "exact", network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", amount: "100000", asset: USDC["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"], payTo: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", maxTimeoutSeconds: 60 }, 2, fc);
  assert.equal(sol.asset.kind, "usdc");
  assert.ok(sol.findings.some((f) => f.code === "NOT_SCREENED"));
});

test("x402-check: a known non-USDC token gets a USD value from its Chainlink feed", async () => {
  const [, feed] = FEEDS.base.ETH;
  const round = "0x" + word("1") + word((3000n * 10n ** 8n).toString(16)) + word("0") + word((1_790_000_000).toString(16)) + word("1");
  const fc = new FakeChain({
    calls: { [`${k(feed)}:0x7284e416`]: abiString("ETH / USD"), [`${k(feed)}:0x313ce567`]: uintWord(8), [`${k(feed)}:0xfeaf968c`]: round },
  });
  fc.now = () => 1_790_000_100;
  const o = await analyzeOption({ scheme: "exact", network: "eip155:8453", amount: (2n * 10n ** 15n).toString(), asset: "0x4200000000000000000000000000000000000006", payTo: PAY, maxTimeoutSeconds: 60 }, 2, fc);
  assert.equal(o.asset.symbol, "WETH");
  assert.equal(o.amount.human, "0.002");
  assert.equal(o.amount.usd, "6");
  assert.ok(o.findings.some((f) => f.code === "NON_USDC_ASSET" && f.severity === "MEDIUM"));
});

test("usdValue: exact decimal arithmetic, rounded down to 6 decimals", () => {
  assert.equal(usdValue("1000000000000000000", 18, "2748.977965"), "2748.977965");
  assert.equal(usdValue("1", 18, "3000"), "0");
  assert.equal(usdValue("123456", 6, "1.0001"), "0.123468");
});

test("x402-check: v1/v2 disagreement, too many options, 402 without requirements, non-402, blocked redirect", async () => {
  let f = fakeFetch({ [SITE]: resp402({ v2: v2Requirements(), v1: v1Body({ network: "polygon" }) }) }, { facilitator: false });
  let r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.ok(r.findings.some((x) => x.code === "VERSION_MISMATCH"));
  f = fakeFetch({ [SITE]: resp402({ v2: v2Requirements(), v1: v1Body({ maxAmountRequired: "99999" }) }) }, { facilitator: false });
  r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.ok(r.findings.some((x) => x.code === "VERSION_MISMATCH" && /amounts/.test(x.message)));

  const six = Array.from({ length: 6 }, () => v2Requirements().accepts[0]);
  f = fakeFetch({ [SITE]: resp402({ v2: v2Requirements({}, six), v1: null }) }, { facilitator: false });
  r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.options.length, 5);
  assert.ok(r.findings.some((x) => x.code === "MANY_OPTIONS"));

  f = fakeFetch({ [SITE]: new Response("pay me", { status: 402 }) }, { facilitator: false });
  r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.verdict, "do not pay");
  assert.ok(r.findings.some((x) => x.code === "MALFORMED_REQUIREMENTS"));

  f = fakeFetch({ [SITE]: new Response("hello") }, { facilitator: false });
  r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.x402, false);
  assert.ok(r.findings.some((x) => x.code === "NOT_X402" && x.severity === "INFO"));

  f = fakeFetch({ [SITE]: new Response(null, { status: 302, headers: { Location: "https://elsewhere.net/pay" } }) }, { facilitator: false });
  r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.ok(r.findings.some((x) => x.code === "REDIRECT_NOT_FOLLOWED"));
});

test("x402-check: when GET isn't 402, tries the method the OpenAPI spec declares (POST)", async () => {
  const spec = { openapi: "3.1.0", paths: { "/data": { post: { summary: "x" } } } };
  const f = fakeFetch({
    "GET https://api.example.com/data": new Response("method not allowed", { status: 405 }),
    "POST https://api.example.com/data": resp402({ v1: null }),
    "https://api.example.com/openapi.json": Response.json(spec),
  }, { facilitator: false });
  const r = await x402Check(parseX402CheckTarget(SITE), new FakeChain(), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.method, "POST");
  assert.equal(r.x402, true);
  assert.equal(r.discovery.openapi, true);
  assert.equal(r.discovery.openapi_lists_path, true);
});

// ---------------------------------------------------------------- ENS / Basenames

test("namehash, dnsEncode and the Base reverse node match known values", () => {
  assert.equal(namehash(""), "0x" + "00".repeat(32));
  assert.equal(namehash("eth"), "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae");
  assert.equal(namehash("foo.eth"), "0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f");
  assert.equal(dnsEncode("foo.eth"), "03666f6f0365746800");
  // computed on-chain by the Basenames ReverseRegistrar.node(addr) on 2026-10-02
  assert.equal(reverseNode("0x2211d1D0020DAEA8039E46Cf1367962070d77DA9", 8453), "0x32ac9b4c5ef8d4742ed765a7e069ea31f043ee8d666b9009d74b2de6d02ff182");
  assert.equal(reverseNode("0xABC0000000000000000000000000000000000001", 1), namehash("abc0000000000000000000000000000000000001.addr.reverse"));
});

test("normalizeName: ASCII ENSIP-15 subset", () => {
  assert.equal(normalizeName("  Vitalik.ETH "), "vitalik.eth");
  assert.equal(normalizeName("_dmarc.example.eth"), "_dmarc.example.eth");
  for (const bad of ["vitalik", "vitalik..eth", ".eth", "vi talik.eth", "a_b.eth", "ab--cd.eth", "🦄.eth", "café.eth", ""]) {
    assert.throws(() => normalizeName(bad), undefined, bad);
  }
  assert.deepEqual(parseNameTarget("vitalik.eth", "0x" + "11".repeat(20)).error !== undefined, true);
  assert.ok(parseNameTarget(undefined, undefined).error);
  assert.ok(parseNameTarget(undefined, "0x123").error);
});

/** Fake chain for name lookups: eth_call answers keyed by "chainId:to:data". */
class FakeNames {
  constructor({ calls = {}, reverts = [], unknown = [] } = {}) { Object.assign(this, { calls, reverts: new Set(reverts), unknown: new Set(unknown) }); }
  key(c, to, data) { return `${c}:${to.toLowerCase()}:${data}`; }
  async ethCall(c, to, data) { const kk = this.key(c, to, data); if (this.unknown.has(kk)) return null; return this.calls[kk] ?? (this.reverts.has(kk) ? null : "0x" + "00".repeat(32)); }
  async ethCallStrict(c, to, data) {
    const kk = this.key(c, to, data);
    if (this.unknown.has(kk)) return { status: "unknown" };
    if (this.reverts.has(kk) || !(kk in this.calls)) return { status: "reverted" };
    return { status: "ok", data: this.calls[kk] };
  }
}
const aw = (a) => "0x" + word(a.slice(2).toLowerCase());
const RES = "0x" + "e5".repeat(20);
const ALICE = toChecksumAddress("0x" + "a7".repeat(20));
function namesFor({ chain = 1, registry = ENS_REGISTRY, name, address, primary = name, reverseResolver = RES }) {
  const node = namehash(name).slice(2);
  const rnode = reverseNode(address, chain).slice(2);
  return {
    [`${chain}:${registry.toLowerCase()}:0x0178b8bf${node}`]: aw(RES),
    [`${chain}:${RES.toLowerCase()}:0x3b3b57de${node}`]: aw(address),
    [`${chain}:${registry.toLowerCase()}:0x0178b8bf${rnode}`]: aw(reverseResolver),
    ...(primary ? { [`${chain}:${reverseResolver.toLowerCase()}:0x691f3431${rnode}`]: abiString(primary) } : {}),
  };
}

test("name -> address on ENS, with the reverse record checked", async () => {
  let r = await resolveName({ name: "alice.eth" }, new FakeNames({ calls: namesFor({ name: "alice.eth", address: ALICE }) }));
  assert.equal(r.found, true);
  assert.equal(r.address, ALICE);
  assert.equal(r.chain, "ethereum");
  assert.equal(r.verified_reverse, true);
  assert.match(r.source, /ENS registry/);
  r = await resolveName({ name: "alice.eth" }, new FakeNames({ calls: namesFor({ name: "alice.eth", address: ALICE, primary: "other.eth" }) }));
  assert.equal(r.verified_reverse, false);
  assert.ok(r.notes.some((n) => /primary name/.test(n)));
  r = await resolveName({ name: "nobody.eth" }, new FakeNames());
  assert.equal(r.found, false);
  assert.equal(r.address, null);
  assert.ok(r.notes.some((n) => /No resolver/.test(n)));
});

test("Basenames resolve on Base via the Basenames registry", async () => {
  const calls = namesFor({ chain: 8453, registry: BASENAMES.registry, name: "alice.base.eth", address: ALICE });
  const r = await resolveName({ name: "alice.base.eth" }, new FakeNames({ calls }));
  assert.equal(r.chain, "base");
  assert.equal(r.address, ALICE);
  assert.equal(r.verified_reverse, true);
  assert.match(r.source, /Basenames registry/);
});

test("ENSIP-10 wildcard: parent resolver answers resolve(); a revert is reported as off-chain (CCIP-Read)", async () => {
  const PR = "0x" + "c4".repeat(20);
  const parentNode = namehash("parent.eth").slice(2);
  const name = "sub.parent.eth";
  const node = namehash(name).slice(2);
  const dns = dnsEncode(name);
  const pad = (h) => h.padStart(64, "0");
  const bytes = (h) => pad((h.length / 2).toString(16)) + h.padEnd(Math.ceil(h.length / 64) * 64, "0");
  const inner = "3b3b57de" + node;
  const data = "0x9061b923" + pad("40") + pad((64 + bytes(dns).length / 2).toString(16)) + bytes(dns) + bytes(inner);
  const resolved = "0x" + pad("20") + pad("20") + word(ALICE.slice(2).toLowerCase());
  const base = {
    [`1:${k(ENS_REGISTRY)}:0x0178b8bf${parentNode}`]: aw(PR),
    [`1:${k(PR)}:0x01ffc9a79061b923${"0".repeat(56)}`]: uintWord(1),
  };
  let r = await resolveName({ name }, new FakeNames({ calls: { ...base, [`1:${k(PR)}:${data}`]: resolved } }));
  assert.equal(r.address, ALICE);
  assert.equal(r.wildcard, true);
  r = await resolveName({ name }, new FakeNames({ calls: base, reverts: [`1:${k(PR)}:${data}`] }));
  assert.equal(r.address, null);
  assert.ok(r.notes.some((n) => /off-chain/.test(n)));
});

test("address -> primary names on ENS and Basenames, each verified forward", async () => {
  const calls = {
    ...namesFor({ name: "alice.eth", address: ALICE }),
    ...namesFor({ chain: 8453, registry: BASENAMES.registry, name: "alice.base.eth", address: ALICE }),
  };
  let r = await resolveName({ address: ALICE }, new FakeNames({ calls }));
  assert.equal(r.name, "alice.eth");
  assert.equal(r.verified_reverse, true);
  assert.deepEqual(r.results.map((x) => [x.system, x.name, x.verified_reverse]), [["ens", "alice.eth", true], ["basenames", "alice.base.eth", true]]);
  // a reverse record claiming a name that resolves elsewhere is not verified
  const BOB = toChecksumAddress("0x" + "b0".repeat(20));
  const fake = { ...namesFor({ name: "alice.eth", address: ALICE }), [`1:${k(ENS_REGISTRY)}:0x0178b8bf${reverseNode(BOB, 1).slice(2)}`]: aw(RES), [`1:${k(RES)}:0x691f3431${reverseNode(BOB, 1).slice(2)}`]: abiString("alice.eth") };
  r = await resolveName({ address: BOB }, new FakeNames({ calls: fake }));
  assert.equal(r.results[0].verified_reverse, false);
  assert.match(r.results[0].note, /don't trust/);
});

test("name lookups that can't be read raise LookupUnavailable (a 503, never charged)", async () => {
  const kk = `1:${k(ENS_REGISTRY)}:0x0178b8bf${namehash("alice.eth").slice(2)}`;
  await assert.rejects(resolveName({ name: "alice.eth" }, new FakeNames({ unknown: [kk] })), LookupUnavailable);
});

// ---------------------------------------------------------------- robots.txt (RFC 9309)

const RFC_EXAMPLE = `User-Agent: *
Disallow: *.gif$
Disallow: /example/
Allow: /publications/

User-Agent: foobot
Disallow:/
Allow:/example/page.html
Allow:/example/allowed.gif

User-Agent: barbot
User-Agent: bazbot
Disallow: /example/page.html

User-Agent: quxbot

EOF`;

test("RFC 9309 5.1 example: groups, merging of consecutive user-agents, empty group, wildcard and $", () => {
  const p = parseRobots(RFC_EXAMPLE);
  const v = (agent, path) => evaluate(p, agent, path).verdict;
  assert.equal(v("*", "/image.gif"), "disallowed");
  assert.equal(v("*", "/a/b/image.gif"), "disallowed");
  assert.equal(v("*", "/image.gif?x=1"), "no rule");
  assert.equal(v("*", "/example/x"), "disallowed");
  assert.equal(v("*", "/publications/x"), "allowed");
  assert.equal(v("otherbot", "/example/x"), "disallowed");
  assert.equal(v("foobot", "/example/page.html"), "allowed");
  assert.equal(v("foobot", "/example/allowed.gif"), "allowed");
  assert.equal(v("foobot", "/other"), "disallowed");
  assert.equal(v("FooBot", "/other"), "disallowed");
  assert.equal(v("barbot", "/example/page.html"), "disallowed");
  assert.equal(v("bazbot", "/example/page.html"), "disallowed");
  assert.equal(v("bazbot", "/example/other.html"), "no rule");
  assert.equal(v("quxbot", "/example/x"), "no rule");
});

test("RFC 9309 5.2 longest match, Allow wins a tie, robots.txt always allowed, empty Disallow ignored", () => {
  let p = parseRobots("User-Agent: foobot\nAllow: /example/page/\nDisallow: /example/page/disallowed.gif\n");
  assert.equal(evaluate(p, "foobot", "/example/page/").verdict, "allowed");
  assert.equal(evaluate(p, "foobot", "/example/page/disallowed.gif").verdict, "disallowed");
  p = parseRobots("User-agent: *\nDisallow: /x\nAllow: /x\n");
  assert.equal(evaluate(p, "*", "/x").verdict, "allowed");
  p = parseRobots("User-agent: *\nDisallow: /\n");
  assert.equal(evaluate(p, "*", "/robots.txt").verdict, "allowed");
  p = parseRobots("User-agent: *\nDisallow:\n");
  assert.equal(evaluate(p, "*", "/anything").verdict, "no rule");
});

test("RFC 9309 2.2.2/2.2.3 percent-encoding and special characters", () => {
  assert.equal(normalizePath("/foo/bar/ツ"), "/foo/bar/%E3%83%84");
  assert.equal(normalizePath("/foo/bar/%62%61%7A"), "/foo/bar/baz");
  assert.equal(normalizePath("/foo/bar/%e3%83%84"), "/foo/bar/%E3%83%84");
  let p = parseRobots("User-agent: *\nDisallow: /foo/bar/%62%61%7A\nDisallow: /foo/bar/ツ\nDisallow: /path/file-with-a-%2A.html\nDisallow: /path/foo-%24\n");
  assert.equal(evaluate(p, "*", "/foo/bar/baz").verdict, "disallowed");
  assert.equal(evaluate(p, "*", "/foo/bar/%E3%83%84").verdict, "disallowed");
  assert.equal(evaluate(p, "*", "/path/file-with-a-*.html").verdict, "disallowed");
  assert.equal(evaluate(p, "*", "/path/foo-$").verdict, "disallowed");
  p = parseRobots("User-agent: *\nDisallow: /foo/bar?baz=quz\n");
  assert.equal(evaluate(p, "*", "/foo/bar?baz=quz").verdict, "disallowed");
  assert.equal(evaluate(p, "*", "/foo/bar").verdict, "no rule");
});

test("robots parsing: comments, CRLF, sitemaps, rules before any group ignored, matching groups merged", () => {
  const p = parseRobots("Disallow: /ignored\r\n# comment\r\nUser-agent: GPTBot # inline\r\nDisallow: /a\r\nSitemap: https://ex.com/s.xml\r\nUser-agent: *\r\nDisallow: /b\r\nUser-agent: gptbot\r\nDisallow: /c\r\n");
  assert.deepEqual(p.sitemaps, ["https://ex.com/s.xml"]);
  assert.equal(evaluate(p, "GPTBot", "/a").verdict, "disallowed");
  assert.equal(evaluate(p, "GPTBot", "/c").verdict, "disallowed");
  assert.equal(evaluate(p, "GPTBot", "/b").verdict, "no rule");
  assert.equal(evaluate(p, "ClaudeBot", "/b").verdict, "disallowed");
  assert.equal(evaluate(p, "ClaudeBot", "/ignored").verdict, "no rule");
});

test("checkRobots: 200, 404 (no restrictions), 5xx (assume disallow), blocked redirect, sidecars, custom agent", async () => {
  const site = "https://www.example.com";
  let f = fakeFetch({
    [`${site}/robots.txt`]: new Response("User-agent: GPTBot\nDisallow: /\nUser-agent: *\nAllow: /\nSitemap: https://www.example.com/sitemap.xml\n"),
    [`${site}/llms.txt`]: new Response("# Example\n", { headers: { "Content-Type": "text/plain" } }),
    [`${site}/ai.txt`]: new Response("<!doctype html><p>app</p>", { headers: { "Content-Type": "text/html" } }),
  }, { facilitator: false });
  let r = await checkRobots(parseRobotsTarget(`${site}/page?q=1`, "MyBot"), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.robots_found, true);
  assert.equal(r.path, "/page?q=1");
  assert.equal(r.results.GPTBot, "disallowed");
  assert.equal(r.results.ClaudeBot, "allowed");
  assert.equal(r.results.MyBot, "allowed");
  assert.deepEqual(Object.keys(r.results), [...AGENTS, "MyBot"]);
  assert.deepEqual(r.sitemaps, ["https://www.example.com/sitemap.xml"]);
  assert.equal(r.llms_txt.present, true);
  assert.equal(r.ai_txt.present, false);
  assert.match(r.notice, /isn't a terms-of-service/);

  f = fakeFetch({}, { facilitator: false });
  r = await checkRobots(parseRobotsTarget(`${site}/x`), new SafeFetcher({ fetchFn: f }));
  assert.equal(r.robots_found, false);
  assert.ok(Object.values(r.results).every((x) => x === "no rule"));

  f = fakeFetch({ [`${site}/robots.txt`]: new Response("oops", { status: 503 }) }, { facilitator: false });
  r = await checkRobots(parseRobotsTarget(`${site}/x`), new SafeFetcher({ fetchFn: f }));
  assert.ok(Object.values(r.results).every((x) => x === "disallowed"));
  assert.ok(r.notes.some((n) => /complete disallow/.test(n)));

  f = fakeFetch({ [`${site}/robots.txt`]: new Response(null, { status: 301, headers: { Location: "https://cdn.other.net/robots.txt" } }) }, { facilitator: false });
  r = await checkRobots(parseRobotsTarget(`${site}/x`), new SafeFetcher({ fetchFn: f }));
  assert.ok(Object.values(r.results).every((x) => x === "unknown"));

  assert.ok(parseRobotsTarget("https://example.com/", "bad agent!").error);
  assert.ok(parseRobotsTarget("http://example.com/").error);
});

// ---------------------------------------------------------------- HTTP routes

test("unpaid /x402-check, /name, /robots: 402 on GET, HEAD and POST with each route's description and Bazaar info", async () => {
  for (const p of ["/x402-check", "/name", "/robots"]) {
    for (const method of ["GET", "HEAD", "POST"]) {
      const r = await handle(req(p, { method }), {}, { fetch: fakeFetch() });
      assert.equal(r.status, 402, `${method} ${p}`);
      const pr = b64decodeJson(r.headers.get("PAYMENT-REQUIRED"));
      assert.equal(pr.resource.url, ORIGIN + p);
      assert.equal(pr.accepts[0].payTo, DEFAULTS.payTo);
      assert.ok(pr.extensions.bazaar.info && pr.extensions.bazaar.schema);
      assert.match(pr.resource.description, p === "/x402-check" ? /never pays/ : p === "/name" ? /ENS/ : /robots\.txt/);
    }
  }
});

test("paid /x402-check, /name, /robots: verify, run, settle", async () => {
  const f = fakeFetch({
    [SITE]: resp402(),
    "https://www.example.com/robots.txt": new Response("User-agent: *\nDisallow: /private\n"),
  });
  const fc = new FakeNames({ calls: namesFor({ name: "alice.eth", address: ALICE }) });
  fc.codeKind = async () => "none";
  const deps = { fetch: f, lookups: () => fc };
  let r = await handle(req(`/x402-check?url=${encodeURIComponent(SITE)}`, { pay: true }), {}, deps);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).options[0].asset.kind, "usdc");
  assert.ok(r.headers.get("PAYMENT-RESPONSE"));
  r = await handle(req("/name?name=Alice.eth", { pay: true }), {}, deps);
  assert.equal(r.status, 200);
  assert.equal((await r.json()).address, ALICE);
  r = await handle(req("/robots", { method: "POST", body: { url: "https://www.example.com/private/x", agent: "MyBot" }, pay: true }), {}, deps);
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.results.MyBot, "disallowed");
  assert.equal(f.calls.filter((c) => c.url.endsWith("/settle")).length, 3);
});

test("paid but bad input (unsafe URL, both name and address, bad agent): 400, facilitator never called", async () => {
  const f = fakeFetch();
  const deps = { fetch: f, lookups: () => new FakeNames() };
  for (const q of [
    "/x402-check?url=" + encodeURIComponent("https://127.0.0.1/pay"),
    "/x402-check?url=" + encodeURIComponent("http://example.com/"),
    "/x402-check",
    "/name?name=a.eth&address=0x" + "11".repeat(20),
    "/name?name=" + encodeURIComponent("🦄.eth"),
    "/robots?url=" + encodeURIComponent("https://localhost/"),
    "/robots?url=" + encodeURIComponent("https://example.com/") + "&agent=" + encodeURIComponent("a b"),
  ]) {
    const r = await handle(req(q, { pay: true }), {}, deps);
    assert.equal(r.status, 400, q);
  }
  assert.equal(f.calls.length, 0);
});

test("an unreachable target is a 503 and never settled", async () => {
  const f = fakeFetch({}, { fail: [SITE, "https://api.example.com/openapi.json", "https://api.example.com/llms.txt"] });
  const r = await handle(req(`/x402-check?url=${encodeURIComponent(SITE)}`, { pay: true }), {}, { fetch: f, lookups: () => new FakeChain() });
  assert.equal(r.status, 503);
  assert.ok(f.calls.some((c) => c.url.endsWith("/verify")));
  assert.ok(!f.calls.some((c) => c.url.endsWith("/settle")));
});

test("openapi and llms.txt describe the three new routes", async () => {
  const spec = openapi({ amount: "10000" }, ORIGIN);
  for (const p of ["/x402-check", "/name", "/robots"]) {
    assert.equal(spec.paths[p].get["x-payment-info"].price.amount, "0.01", p);
    assert.ok(spec.paths[p].post.requestBody);
    assert.ok(spec.paths[p].get.responses["402"]);
  }
  const t = await (await handle(new Request(ORIGIN + "/llms.txt"), {}, {})).text();
  for (const s of ["GET /x402-check", "GET /name", "GET /robots", "never pays"]) assert.ok(t.includes(s), s);
});
