import test from "node:test";
import assert from "node:assert/strict";
import { handle, openapi, _resetRateLimit } from "../src/worker.js";
import { FREE_PER_IP_PER_HOUR, SUPPORTED_VERSIONS, TOOLS, _resetMcpLimits, decodeHeaderValue } from "../src/mcp.js";
import { OFAC } from "../src/ofac-data.js";
import { FakeLookups } from "./fake.js";
import { FakeChain } from "./fakechain.js";

const BASE = "https://joi-presign.example.workers.dev";
const META = {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0.0" },
  "io.modelcontextprotocol/clientCapabilities": {},
};
test.beforeEach(() => {
  _resetRateLimit();
  _resetMcpLimits();
});

function req(body, headers = {}, method = "POST", ip = "203.0.113.7") {
  return new Request(BASE + "/mcp", {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "CF-Connecting-IP": ip, ...headers },
    body: method === "POST" ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
  });
}
function modern(method, params = {}, headers = {}, ip) {
  const h = { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method };
  if (method === "tools/call") h["Mcp-Name"] = params.name;
  return req({ jsonrpc: "2.0", id: 1, method, params: { ...params, _meta: META } }, { ...h, ...headers }, "POST", ip);
}
const legacy = (method, params = {}, headers = {}, ip) => req({ jsonrpc: "2.0", id: 7, method, params }, headers, "POST", ip);
const call = async (r, deps = {}) => {
  const res = await handle(r, {}, deps);
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
};

function fakeFetch(routes = {}) {
  const f = async (url) => {
    const r = routes[url];
    if (!r) return new Response("not found", { status: 404, headers: { "Content-Type": "text/plain" } });
    return r.clone();
  };
  return f;
}
const htmlRes = (body) => new Response(body, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
const textRes = (body) => new Response(body, { status: 200, headers: { "Content-Type": "text/plain" } });

// ---------------------------------------------------------------- lifecycle

test("legacy initialize negotiates a supported version, reports the server honestly, and initialized is accepted", async () => {
  let r = await call(legacy("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } }));
  assert.equal(r.status, 200);
  assert.equal(r.body.id, 7);
  assert.equal(r.body.result.protocolVersion, "2025-06-18");
  assert.deepEqual(r.body.result.capabilities, { tools: { listChanged: false } });
  assert.equal(r.body.result.serverInfo.name, "joi-presign");
  assert.match(r.body.result.instructions, /Joi, an autonomous AI agent/);
  assert.match(r.body.result.instructions, /x402/);
  assert.equal(r.body.result.resultType, undefined, "legacy results have no resultType");
  r = await call(legacy("initialize", { protocolVersion: "1999-01-01" }));
  assert.equal(r.body.result.protocolVersion, "2025-11-25");
  const n = await handle(req({ jsonrpc: "2.0", method: "notifications/initialized" }), {}, {});
  assert.equal(n.status, 202);
  assert.equal(await n.text(), "");
});

test("modern server/discover: complete result with versions, capabilities and serverInfo", async () => {
  const r = await call(modern("server/discover"));
  assert.equal(r.status, 200);
  const res = r.body.result;
  assert.equal(res.resultType, "complete");
  assert.deepEqual(res.supportedVersions, SUPPORTED_VERSIONS);
  assert.ok(res.supportedVersions.includes("2026-07-28") && res.supportedVersions.includes("2025-11-25"));
  assert.deepEqual(res.capabilities, { tools: {} });
  assert.equal(res._meta["io.modelcontextprotocol/serverInfo"].name, "joi-presign");
  assert.match(res.instructions, /AI agent/);
});

test("tools/list in both eras: the five free tools with valid input schemas, never /read or /x402-check", async () => {
  for (const r of [await call(modern("tools/list")), await call(legacy("tools/list"))]) {
    assert.equal(r.status, 200);
    const tools = r.body.result.tools;
    assert.deepEqual(tools.map((t) => t.name).sort(), ["contract_profile", "presign_check", "robots_check", "screen_address", "url_meta"]);
    for (const t of tools) {
      assert.ok(t.description.length > 40, t.name);
      assert.equal(t.inputSchema.type, "object");
      for (const k of t.inputSchema.required) assert.ok(k in t.inputSchema.properties, `${t.name}.${k}`);
      assert.equal(t.inputSchema.additionalProperties, false);
      assert.equal(t.annotations.readOnlyHint, true);
      assert.equal(t.annotations.destructiveHint, false);
      assert.ok(!/read_page|x402/.test(t.name));
    }
  }
  assert.equal((await call(modern("tools/list"))).body.result.resultType, "complete");
});

// ---------------------------------------------------------------- modern header validation

test("modern requests: missing or mismatched headers are rejected with 400 HeaderMismatch (-32020)", async () => {
  const cases = [
    modern("tools/list", {}, { "MCP-Protocol-Version": "" }),
    modern("tools/list", {}, { "MCP-Protocol-Version": "2025-11-25" }),
    modern("tools/list", {}, { "Mcp-Method": "tools/call" }),
    req({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }, { "Mcp-Method": "tools/list" }),
    req({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } }, { "MCP-Protocol-Version": "2026-07-28" }),
    modern("tools/call", { name: "screen_address", arguments: { address: "0x" + "12".repeat(20) } }, { "Mcp-Name": "url_meta" }),
    req({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "url_meta", arguments: {}, _meta: META } }, { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call" }),
  ];
  for (const c of cases) {
    const r = await call(c);
    assert.equal(r.status, 400);
    assert.equal(r.body.error.code, -32020, JSON.stringify(r.body));
  }
});

test("Mcp-Name may use the base64 sentinel; decodeHeaderValue handles plain, encoded and invalid values", async () => {
  const enc = "=?base64?" + btoa("screen_address") + "?=";
  const r = await call(modern("tools/call", { name: "screen_address", arguments: { address: "0x" + "12".repeat(20) } }, { "Mcp-Name": enc }), { lookups: () => new FakeChain() });
  assert.equal(r.status, 200);
  assert.equal(r.body.result.isError, false);
  assert.equal(decodeHeaderValue("abc"), "abc");
  assert.equal(decodeHeaderValue(null), null);
  assert.equal(decodeHeaderValue("=?base64?SGVsbG8sIOS4lueVjA==?="), "Hello, 世界");
  assert.equal(decodeHeaderValue("=?base64?/w==?="), undefined);
});

test("unsupported modern version: 400 with -32022 listing supported versions", async () => {
  const meta = { ...META, "io.modelcontextprotocol/protocolVersion": "2027-01-01" };
  const r = await call(req({ jsonrpc: "2.0", id: 3, method: "tools/list", params: { _meta: meta } }, { "MCP-Protocol-Version": "2027-01-01", "Mcp-Method": "tools/list" }));
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32022);
  assert.deepEqual(r.body.error.data, { supported: SUPPORTED_VERSIONS, requested: "2027-01-01" });
});

test("unknown methods: modern 404 / legacy 200, both -32601; legacy header checks", async () => {
  let r = await call(modern("resources/list"));
  assert.equal(r.status, 404);
  assert.equal(r.body.error.code, -32601);
  r = await call(legacy("prompts/list"));
  assert.equal(r.status, 200);
  assert.equal(r.body.error.code, -32601);
  r = await call(legacy("tools/list", {}, { "MCP-Protocol-Version": "1900-01-01" }));
  assert.equal(r.status, 400);
  r = await call(legacy("tools/list", {}, { "MCP-Protocol-Version": "2026-07-28" }));
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32020);
  r = await call(legacy("tools/list", {}, { "MCP-Protocol-Version": "2025-06-18" }));
  assert.equal(r.status, 200);
  r = await call(legacy("ping"));
  assert.deepEqual(r.body.result, {});
});

// ---------------------------------------------------------------- transport errors

test("malformed JSON-RPC, batches, GET, bad Origin, notifications and client responses", async () => {
  let r = await call(req("{nope"));
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32700);
  r = await call(req([{ jsonrpc: "2.0", id: 1, method: "ping" }]));
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32600);
  r = await call(req({ id: 1, method: "ping" }));
  assert.equal(r.status, 400);
  assert.equal(r.body.error.code, -32600);
  const g = await handle(req(null, {}, "GET"), {}, {});
  assert.equal(g.status, 405);
  assert.equal(g.headers.get("Allow"), "POST");
  r = await call(legacy("ping", {}, { Origin: "http://evil.example" }));
  assert.equal(r.status, 403);
  r = await call(legacy("ping", {}, { Origin: "https://claude.ai" }));
  assert.equal(r.status, 200);
  for (const body of [{ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } }, { jsonrpc: "2.0", id: 5, result: {} }]) {
    const n = await handle(req(body), {}, {});
    assert.equal(n.status, 202);
    assert.equal(await n.text(), "");
  }
  const big = await handle(req("{" + " ".repeat(70 * 1024) + "}"), {}, {});
  assert.equal(big.status, 413);
});

// ---------------------------------------------------------------- tools

const U256MAX = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const APPROVE_UNLIMITED_TO_EOA = {
  chainId: 8453,
  to: "0x" + "11".repeat(20),
  value: "0x0",
  data: "0x095ea7b3" + "44".repeat(20).padStart(64, "0") + BigInt(U256MAX).toString(16).padStart(64, "0"),
};

test("presign_check: structured + text output, HIGH for an unlimited approval to a plain wallet", async () => {
  const r = await call(modern("tools/call", { name: "presign_check", arguments: { payload: APPROVE_UNLIMITED_TO_EOA, chain: "base" } }), { lookups: () => new FakeLookups() });
  assert.equal(r.status, 200);
  const res = r.body.result;
  assert.equal(res.resultType, "complete");
  assert.equal(res.isError, false);
  assert.equal(res.structuredContent.risk, "HIGH");
  assert.ok(res.structuredContent.findings.some((f) => f.code === "APPROVAL_TO_EOA"));
  assert.deepEqual(JSON.parse(res.content[0].text), res.structuredContent);
  const bad = await call(legacy("tools/call", { name: "presign_check", arguments: { payload: { hello: 1 } } }), { lookups: () => new FakeLookups() });
  assert.equal(bad.body.result.isError, true);
  assert.match(bad.body.result.content[0].text, /Invalid input/);
  const badChain = await call(legacy("tools/call", { name: "presign_check", arguments: { payload: APPROVE_UNLIMITED_TO_EOA, chain: "solana" } }));
  assert.equal(badChain.body.result.isError, true);
});

test("contract_profile and screen_address with fake lookups; outages become tool errors", async () => {
  const TARGET = "0x" + "ab".repeat(20);
  let r = await call(legacy("tools/call", { name: "contract_profile", arguments: { address: TARGET, chain: "ethereum" } }),
    { lookups: () => new FakeChain({ code: { [TARGET]: "0x6080" }, nonce: { [TARGET]: 1 } }) });
  assert.equal(r.body.result.isError, false);
  assert.equal(r.body.result.structuredContent.kind, "contract");
  r = await call(legacy("tools/call", { name: "contract_profile", arguments: { address: TARGET } }), { lookups: () => new FakeChain({ unknown: ["code"] }) });
  assert.equal(r.body.result.isError, true);
  assert.match(r.body.result.content[0].text, /Temporarily unavailable/);
  r = await call(legacy("tools/call", { name: "contract_profile", arguments: { address: "0x1234" } }));
  assert.equal(r.body.result.isError, true);
  assert.match(r.body.result.content[0].text, /Invalid input/);

  const listed = Object.keys(OFAC)[0];
  r = await call(legacy("tools/call", { name: "screen_address", arguments: { address: listed } }), { lookups: () => new FakeChain() });
  assert.equal(r.body.result.structuredContent.sanctioned, true);
  r = await call(legacy("tools/call", { name: "screen_address", arguments: { address: "0x" + "12".repeat(20) } }), { lookups: () => new FakeChain() });
  assert.equal(r.body.result.structuredContent.sanctioned, false);
});

test("robots_check and url_meta use the safe fetcher (fake fetch)", async () => {
  const SITE = "https://site.example.com";
  const fetch = fakeFetch({
    [`${SITE}/robots.txt`]: textRes("User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nAllow: /"),
    [`${SITE}/page`]: htmlRes(`<html><head><title>Hello page</title><meta name="description" content="D"></head><body><p>x</p></body></html>`),
  });
  let r = await call(legacy("tools/call", { name: "robots_check", arguments: { url: `${SITE}/page` } }), { fetch });
  assert.equal(r.body.result.isError, false);
  assert.equal(r.body.result.structuredContent.results.GPTBot, "disallowed");
  r = await call(legacy("tools/call", { name: "url_meta", arguments: { url: `${SITE}/page` } }), { fetch });
  assert.equal(r.body.result.isError, false);
  assert.equal(r.body.result.structuredContent.title, "Hello page");
  r = await call(legacy("tools/call", { name: "url_meta", arguments: { url: "http://site.example.com/page" } }), { fetch });
  assert.equal(r.body.result.isError, true);
  assert.match(r.body.result.content[0].text, /Invalid input/);
});

test("unknown tool and non-object arguments are JSON-RPC errors (-32602)", async () => {
  let r = await call(legacy("tools/call", { name: "read_page", arguments: { url: "https://x.example.com" } }));
  assert.equal(r.body.error.code, -32602);
  r = await call(legacy("tools/call", { name: "x402_check", arguments: {} }));
  assert.equal(r.body.error.code, -32602);
  r = await call(legacy("tools/call", { name: "url_meta", arguments: "https://x.example.com" }));
  assert.equal(r.body.error.code, -32602);
});

test("free tier: 20 tool calls per IP per hour, then a tool error pointing to the paid endpoints; lists are free", async () => {
  const deps = { lookups: () => new FakeChain() };
  const args = { name: "screen_address", arguments: { address: "0x" + "12".repeat(20) } };
  for (let i = 0; i < FREE_PER_IP_PER_HOUR; i++) {
    const r = await call(legacy("tools/call", args, {}, "198.51.100.1"), deps);
    assert.equal(r.body.result.isError, false, `call ${i}`);
    _resetRateLimit(); // the HTTP-level 30/min limiter is separate
  }
  const over = await call(legacy("tools/call", args, {}, "198.51.100.1"), deps);
  assert.equal(over.body.result.isError, true);
  assert.match(over.body.result.content[0].text, /Free tier used up/);
  assert.match(over.body.result.content[0].text, /openapi\.json/);
  assert.match(over.body.result.content[0].text, /0\.005 USDC/);
  const list = await call(legacy("tools/list", {}, {}, "198.51.100.1"), deps);
  assert.equal(list.status, 200);
  const other = await call(legacy("tools/call", args, {}, "198.51.100.2"), deps);
  assert.equal(other.body.result.isError, false);
});

test("x402 routes are unchanged: unpaid -> 402, /mcp is not a paid route and not in openapi", async () => {
  for (const [method, path] of [["POST", "/check"], ["GET", "/contract"], ["HEAD", "/read"], ["GET", "/x402-check"]]) {
    const res = await handle(new Request(BASE + path, { method }), {}, {});
    assert.equal(res.status, 402, `${method} ${path}`);
  }
  assert.equal(openapi({ amount: "10000" }, BASE).paths["/mcp"], undefined);
  const about = await (await handle(new Request(BASE + "/llms.txt"), {}, {})).text();
  assert.match(about, /POST \/mcp/);
});

test("MCP logs carry only route and outcome, never arguments", async () => {
  const lines = [];
  const orig = console.log;
  console.log = (s) => lines.push(String(s));
  try {
    await call(legacy("tools/call", { name: "screen_address", arguments: { address: "0x" + "34".repeat(20) } }), { lookups: () => new FakeChain() });
  } finally {
    console.log = orig;
  }
  assert.ok(lines.length >= 1);
  for (const l of lines) {
    assert.deepEqual(Object.keys(JSON.parse(l)).sort(), ["outcome", "route"]);
    assert.ok(!l.includes("3434"), "no address in logs");
  }
  assert.equal(JSON.parse(lines[0]).outcome, "tool:screen_address:ok");
});

test("TOOLS export matches what tools/list serves", () => {
  assert.equal(TOOLS.length, 5);
});
