import test from "node:test";
import assert from "node:assert/strict";
import { NetLookups, _clearFourbyteCache } from "../src/net.js";

// routes: [urlPart, bodyPart|null, response] where response is an object (JSON 200), a number (HTTP status) or an Error.
function fakeFetch(routes) {
  const calls = [];
  const f = async (url, init) => {
    assert.ok(init.signal, "every request must carry an abort signal (timeout)");
    const body = init.body || "";
    calls.push({ url, body });
    for (const [u, b, resp] of routes) {
      if (url.includes(u) && (b === null || body.includes(b))) {
        if (resp instanceof Error) throw resp;
        if (typeof resp === "number") return new Response("{}", { status: resp });
        return new Response(JSON.stringify(resp), { status: 200 });
      }
    }
    throw new Error("no route");
  };
  f.calls = calls;
  return f;
}

const a = (p) => p + "0".repeat(42 - p.length);

test("codeKind variants and failures", async () => {
  const L = new NetLookups({ fetchFn: fakeFetch([
    ["publicnode", '"0xaaaa', { result: "0x" }],
    ["publicnode", '"0xbbbb', { result: "0xef0100" + "12".repeat(20) }],
    ["publicnode", '"0xcccc', { result: "0x6080604052" }],
  ]) });
  assert.equal(await L.codeKind(1, a("0xaaaa")), "none");
  assert.equal(await L.codeKind(1, a("0xbbbb")), "7702");
  assert.equal(await L.codeKind(1, a("0xcccc")), "contract");
  assert.equal(await L.codeKind(1, a("0xdddd")), null);
  assert.equal(await L.codeKind(999, a("0xaaaa")), null);
});

test("txCount and memoization", async () => {
  const f = fakeFetch([["arbitrum", null, { result: "0x1f" }]]);
  const L = new NetLookups({ fetchFn: f });
  assert.equal(await L.txCount(42161, a("0x1")), 31);
  assert.equal(await L.txCount(42161, a("0x1")), 31);
  assert.equal(f.calls.length, 1);
});

test("sourcify: match, 404 = not verified, 500 = unknown", async () => {
  const L = new NetLookups({ fetchFn: fakeFetch([
    ["/1/0xaaaa", null, { match: "exact_match" }],
    ["/1/0xbbbb", null, 404],
    ["/1/0xcccc", null, 500],
  ]) });
  assert.equal(await L.sourcifyVerified(1, a("0xaaaa")), true);
  assert.equal(await L.sourcifyVerified(1, a("0xbbbb")), false);
  assert.equal(await L.sourcifyVerified(1, a("0xcccc")), null);
});

test("4byte: oldest first, cached per isolate, down = null", async () => {
  _clearFourbyteCache();
  const f = fakeFetch([["4byte", null, { results: [{ id: 900, text_signature: "spam_x(uint256)" }, { id: 5, text_signature: "approve(address,uint256)" }] }]]);
  const L = new NetLookups({ fetchFn: f });
  assert.deepEqual(await L.selectorSignatures("0x095ea7b3"), ["approve(address,uint256)", "spam_x(uint256)"]);
  const L2 = new NetLookups({ fetchFn: fakeFetch([]) });
  assert.equal((await L2.selectorSignatures("0x095ea7b3"))[0], "approve(address,uint256)");
  assert.equal(f.calls.length, 1);
  const L3 = new NetLookups({ fetchFn: fakeFetch([["4byte", null, new Error("slow")]]) });
  assert.equal(await L3.selectorSignatures("0x12345678"), null);
});

test("subrequest budget: lookups beyond the cap answer unknown", async () => {
  const f = fakeFetch([["publicnode", null, { result: "0x" }]]);
  const L = new NetLookups({ fetchFn: f, maxRequests: 2 });
  assert.equal(await L.codeKind(1, a("0x01")), "none");
  assert.equal(await L.codeKind(1, a("0x02")), "none");
  assert.equal(await L.codeKind(1, a("0x03")), null);
  assert.equal(f.calls.length, 2);
});

test("timeout aborts a hanging request", async () => {
  const hang = (url, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted"))));
  const L = new NetLookups({ fetchFn: hang, timeoutMs: 20 });
  const t0 = Date.now();
  assert.equal(await L.codeKind(1, a("0x01")), null);
  assert.ok(Date.now() - t0 < 1000);
});
