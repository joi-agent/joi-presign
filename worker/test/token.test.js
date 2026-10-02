import test from "node:test";
import assert from "node:assert/strict";
import { tokenProfile, powersFromAbi } from "../src/token.js";
import { LookupUnavailable, SLOT_IMPLEMENTATION } from "../src/profile.js";
import { toChecksumAddress } from "../src/abi.js";
import { FakeChain, addrWord, uintWord, abiString } from "./fakechain.js";

const A = (b) => toChecksumAddress("0x" + b.repeat(20));
const [TOKEN, IMPL, OWNER] = ["c3", "d4", "e5"].map(A);
const k = (a) => a.toLowerCase();
const fn = (name, stateMutability = "nonpayable") => ({ type: "function", name, stateMutability, inputs: [], outputs: [] });
const erc20Calls = (t) => ({
  [`${k(t)}:0x06fdde03`]: abiString("Test Token"),
  [`${k(t)}:0x95d89b41`]: abiString("TST"),
  [`${k(t)}:0x313ce567`]: uintWord(18),
  [`${k(t)}:0x18160ddd`]: uintWord(10n ** 24n),
  [`${k(t)}:0x8da5cb5b`]: addrWord(OWNER),
});
const codes = (codeMap) => Object.fromEntries(Object.entries(codeMap).map(([a, c]) => [k(a), c]));

test("powersFromAbi: matches state-changing functions only", () => {
  const abi = [
    fn("mint"), fn("issue"), fn("pause"), fn("unpause"), fn("addToBlacklist"), fn("isBlacklisted", "view"),
    fn("setTaxFee"), fn("updateFees"), fn("upgradeTo"), fn("transfer"), fn("paused", "view"), { type: "event", name: "Paused" },
  ];
  const p = Object.fromEntries(powersFromAbi(abi).map((x) => [x.code, x.functions]));
  assert.deepEqual(p.MINT_FUNCTION, ["mint", "issue"]);
  assert.deepEqual(p.PAUSE_FUNCTION, ["pause", "unpause"]);
  assert.deepEqual(p.BLOCKLIST_FUNCTION, ["addToBlacklist"]);
  assert.deepEqual(p.FEE_FUNCTION, ["setTaxFee", "updateFees"]);
  assert.deepEqual(p.UPGRADE_FUNCTION, ["upgradeTo"]);
  assert.deepEqual(powersFromAbi([fn("transfer"), fn("approve")]), []);
});

test("verified token: metadata, owner powers from its ABI, owner is a single wallet, scope note", async () => {
  const chain = new FakeChain({
    code: codes({ [TOKEN]: "0x6080604052" }),
    calls: erc20Calls(TOKEN),
    sourcify: { [k(TOKEN)]: { verified: true, name: "TestToken" } },
    abi: { [k(TOKEN)]: [fn("mint"), fn("pause"), fn("transfer")] },
  });
  const r = await tokenProfile(8453, TOKEN, chain);
  assert.equal(r.kind, "token");
  assert.deepEqual(r.token, { address: TOKEN, name: "Test Token", symbol: "TST", decimals: 18, total_supply: (10n ** 24n).toString(), total_supply_formatted: "1000000" });
  assert.deepEqual(r.owner_powers.map((p) => p.code), ["MINT_FUNCTION", "PAUSE_FUNCTION"]);
  const mint = r.findings.find((f) => f.code === "MINT_FUNCTION");
  assert.equal(mint.severity, "MEDIUM");
  assert.match(mint.message, /single wallet/);
  assert.ok(r.findings.some((f) => f.code === "OWNER_IS_EOA"));
  assert.ok(r.findings.some((f) => f.code === "SCOPE" && /honeypots/.test(f.message)));
  assert.equal(r.risk, "MEDIUM");
});

test("proxy token: owner powers come from the implementation's ABI", async () => {
  const chain = new FakeChain({
    code: codes({ [TOKEN]: "0x6080604052", [IMPL]: "0x6080604052" }),
    storage: { [`${k(TOKEN)}:${SLOT_IMPLEMENTATION}`]: addrWord(IMPL) },
    calls: erc20Calls(TOKEN),
    sourcify: { [k(TOKEN)]: { verified: true, name: "Proxy" }, [k(IMPL)]: { verified: true, name: "TokenV2" } },
    abi: { [k(TOKEN)]: [fn("upgradeTo")], [k(IMPL)]: [fn("blacklist"), fn("setFee")] },
  });
  const r = await tokenProfile(1, TOKEN, chain);
  assert.deepEqual(r.owner_powers.map((p) => p.code), ["BLOCKLIST_FUNCTION", "FEE_FUNCTION"]);
  assert.ok(r.findings.some((f) => f.code === "UPGRADEABLE_PROXY"));
});

test("unverified token: owner powers can't be checked (MEDIUM); verified but no powers: INFO", async () => {
  let r = await tokenProfile(1, TOKEN, new FakeChain({ code: codes({ [TOKEN]: "0x60806040" }), calls: erc20Calls(TOKEN), sourcify: { [k(TOKEN)]: { verified: false, name: null } } }));
  assert.ok(r.findings.some((f) => f.code === "OWNER_POWERS_UNKNOWN" && f.severity === "MEDIUM"));
  r = await tokenProfile(1, TOKEN, new FakeChain({
    code: codes({ [TOKEN]: "0x60806040" }), calls: erc20Calls(TOKEN),
    sourcify: { [k(TOKEN)]: { verified: true, name: "T" } }, abi: { [k(TOKEN)]: [fn("transfer")] },
  }));
  assert.ok(r.findings.some((f) => f.code === "NO_OWNER_POWERS_FOUND"));
  r = await tokenProfile(1, TOKEN, new FakeChain({
    code: codes({ [TOKEN]: "0x60806040" }), calls: erc20Calls(TOKEN),
    sourcify: { [k(TOKEN)]: { verified: true, name: "T" } }, unknown: ["abi"],
  }));
  assert.ok(r.findings.some((f) => f.code === "LOOKUP_UNAVAILABLE" && /ABI/.test(f.message)));
});

test("not a token: an EOA or empty address is HIGH; a contract without ERC-20 calls is NOT_ERC20_LIKE", async () => {
  let r = await tokenProfile(1, OWNER, new FakeChain({ nonce: { [k(OWNER)]: 3 } }));
  assert.equal(r.kind, "eoa");
  assert.ok(r.findings.some((f) => f.code === "NOT_A_TOKEN" && f.severity === "HIGH"));
  r = await tokenProfile(1, TOKEN, new FakeChain({ code: codes({ [TOKEN]: "0x60806040" }), sourcify: { [k(TOKEN)]: { verified: false, name: null } } }));
  assert.ok(r.findings.some((f) => f.code === "NOT_ERC20_LIKE"));
  assert.equal(r.token.symbol, null);
});

test("legacy bytes32 symbol (e.g. MKR) is decoded", async () => {
  const calls = { ...erc20Calls(TOKEN), [`${k(TOKEN)}:0x95d89b41`]: "0x" + Buffer.from("MKR").toString("hex").padEnd(64, "0") };
  const r = await tokenProfile(1, TOKEN, new FakeChain({ code: codes({ [TOKEN]: "0x60806040" }), calls, sourcify: { [k(TOKEN)]: { verified: false, name: null } } }));
  assert.equal(r.token.symbol, "MKR");
});

test("unreadable code -> LookupUnavailable (503, never charged)", async () => {
  await assert.rejects(tokenProfile(1, TOKEN, new FakeChain({ unknown: ["code"] })), LookupUnavailable);
});
