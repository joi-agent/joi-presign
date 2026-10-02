import test from "node:test";
import assert from "node:assert/strict";
import { NetLookups, endpointsFor, _clearFourbyteCache } from "../src/net.js";

// routes: [urlPart, bodyPart|null, response]; response: object (JSON 200), number (status), Error, or a function of the call count.
function fakeFetch(routes) {
  const calls = [];
  const f = async (url, init) => {
    assert.ok(init.signal, "every request must carry an abort signal (timeout)");
    const body = init.body || "";
    calls.push({ url, body });
    for (const [u, b, resp] of routes) {
      if (url.includes(u) && (b === null || body.includes(b))) {
        const r = typeof resp === "function" ? resp(calls.length) : resp;
        if (r instanceof Error) throw r;
        if (typeof r === "number") return new Response("{}", { status: r });
        return new Response(JSON.stringify(r), { status: 200 });
      }
    }
    throw new Error("no route");
  };
  f.calls = calls;
  return f;
}
const fast = (routes) => ({ fetchFn: fakeFetch(routes), retryDelaysMs: [0, 0] });

test("endpointsFor: tx history to the official Base/Arbitrum RPCs first, state reads to publicnode on Base", () => {
  assert.equal(endpointsFor(8453, "eth_getTransactionReceipt")[0], "https://mainnet.base.org");
  assert.equal(endpointsFor(8453, "eth_call")[0], "https://base-rpc.publicnode.com");
  assert.deepEqual(endpointsFor(42161, "eth_getTransactionByHash"), ["https://arb1.arbitrum.io/rpc"]);
  assert.equal(endpointsFor(1, "eth_getCode")[0], "https://ethereum-rpc.publicnode.com");
  assert.deepEqual(endpointsFor(999, "eth_call"), []);
});

test("rpc retries a 429 on the fallback endpoint, within the budget", async () => {
  const opts = fast([["base-rpc.publicnode", null, 429], ["mainnet.base.org", null, { jsonrpc: "2.0", id: 1, result: "0x1" }]]);
  const L = new NetLookups(opts);
  assert.equal(await L.rpc(8453, "eth_blockNumber", []), "0x1");
  assert.equal(opts.fetchFn.calls.length, 2);
});

test("rpc retries a non-revert JSON error (e.g. 'archive requests require a token') on the next endpoint", async () => {
  const opts = fast([
    ["mainnet.base.org", null, { jsonrpc: "2.0", id: 1, error: { code: -32602, message: "Archive requests require a personal token" } }],
    ["base-rpc.publicnode", null, { jsonrpc: "2.0", id: 1, result: { status: "0x1" } }],
  ]);
  const L = new NetLookups(opts);
  assert.deepEqual(await L.getReceipt(8453, "0x" + "ab".repeat(32)), { status: "0x1" });
});

test("a revert is an answer, not retried", async () => {
  const opts = fast([["publicnode", null, { jsonrpc: "2.0", id: 1, error: { code: 3, message: "execution reverted" } }]]);
  const L = new NetLookups(opts);
  assert.equal(await L.ethCall(1, "0x" + "11".repeat(20), "0x8da5cb5b"), null);
  assert.equal(opts.fetchFn.calls.length, 1);
});

test("no retry once the subrequest budget is spent", async () => {
  const opts = { fetchFn: fakeFetch([["", null, 429]]), retryDelaysMs: [0, 0], maxRequests: 1 };
  const L = new NetLookups(opts);
  assert.equal(await L.rpc(8453, "eth_blockNumber", []), null);
  assert.equal(opts.fetchFn.calls.length, 1);
});

test("getTransaction / getReceipt: object, false (node says none), null (lookup failed)", async () => {
  const H1 = "0x" + "01".repeat(32), H2 = "0x" + "02".repeat(32);
  const L = new NetLookups(fast([
    ["", H1, { jsonrpc: "2.0", id: 1, result: { hash: H1 } }],
    ["", H2, { jsonrpc: "2.0", id: 1, result: null }],
  ]));
  assert.deepEqual(await L.getTransaction(1, H1), { hash: H1 });
  assert.equal(await L.getTransaction(1, H2), false);
  assert.equal(await L.getReceipt(1, H2), false);
  assert.equal(await L.getTransaction(1, "0x" + "03".repeat(32)), null);
});

test("ethCallStrict: ok / reverted / unknown", async () => {
  const L = new NetLookups(fast([
    ["", "0x1626ba7eaa", { jsonrpc: "2.0", id: 1, result: "0x1626BA7E" + "0".repeat(56) }],
    ["", "0x1626ba7ebb", { jsonrpc: "2.0", id: 1, error: { code: -32000, message: "execution reverted: bad sig" } }],
    ["", "0x1626ba7ecc", 500],
  ]));
  const to = "0x" + "11".repeat(20);
  assert.deepEqual(await L.ethCallStrict(1, to, "0x1626ba7eaa"), { status: "ok", data: "0x1626ba7e" + "0".repeat(56) });
  assert.deepEqual(await L.ethCallStrict(1, to, "0x1626ba7ebb"), { status: "reverted" });
  assert.deepEqual(await L.ethCallStrict(1, to, "0x1626ba7ecc"), { status: "unknown" });
});

test("eventSignatures (cached) and sourcifyAbi (abi / 404 = false / error = null)", async () => {
  _clearFourbyteCache();
  const opts = fast([
    ["event-signatures", null, { results: [{ id: 9, text_signature: "Spam(uint256)" }, { id: 2, text_signature: "Swap(address,uint256)" }] }],
    ["/1/0xaaaa", "", { abi: [{ type: "function", name: "mint" }], match: "exact_match" }],
    ["/1/0xbbbb", "", 404],
    ["/1/0xcccc", "", 500],
  ]);
  const L = new NetLookups(opts);
  assert.deepEqual(await L.eventSignatures("0x" + "77".repeat(32)), ["Swap(address,uint256)", "Spam(uint256)"]);
  assert.deepEqual(await L.eventSignatures("0x" + "77".repeat(32)), ["Swap(address,uint256)", "Spam(uint256)"]);
  assert.equal(opts.fetchFn.calls.filter((c) => c.url.includes("event-signatures")).length, 1);
  const pad = (p) => p + "0".repeat(42 - p.length);
  assert.deepEqual(await L.sourcifyAbi(1, pad("0xaaaa")), [{ type: "function", name: "mint" }]);
  assert.ok(opts.fetchFn.calls.some((c) => c.url.includes("fields=abi")));
  assert.equal(await L.sourcifyAbi(1, pad("0xbbbb")), false);
  assert.equal(await L.sourcifyAbi(1, pad("0xcccc")), null);
});
