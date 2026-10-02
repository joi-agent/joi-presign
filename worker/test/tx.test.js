import test from "node:test";
import assert from "node:assert/strict";
import { explainTx, parseTxTarget, formatUnits, TOPICS } from "../src/txexplain.js";
import { LookupUnavailable, NotFound } from "../src/profile.js";
import { toChecksumAddress } from "../src/abi.js";
import { FakeChain, addrWord, uintWord, abiString, word } from "./fakechain.js";

const A = (b) => toChecksumAddress("0x" + b.repeat(20));
const [ALICE, BOB, TOKEN, NFT, WETH, ROUTER, ITEMS, ODD] = ["a1", "b2", "c3", "d4", "e5", "f6", "17", "28"].map(A);
const H = "0x" + "ab".repeat(32);
const ZERO = "0x" + "00".repeat(20);
const MAX = (1n << 256n) - 1n;
const k = (a) => a.toLowerCase();

const meta = (token, sym, dec) => ({
  [`${k(token)}:0x95d89b41`]: abiString(sym),
  ...(dec === null ? {} : { [`${k(token)}:0x313ce567`]: uintWord(dec) }),
});
const log = (address, topics, data = "0x") => ({ address, topics, data });

function chain({ tx = {}, receipt = {}, extra = {} } = {}) {
  return new FakeChain({
    txs: { [H]: { from: ALICE, to: TOKEN, value: "0x0", nonce: "0x7", input: "0x", gasPrice: "0x1", ...tx } },
    receipts: { [H]: { status: "0x1", gasUsed: "0x5208", effectiveGasPrice: "0x3b9aca00", blockNumber: "0x10", logs: [], ...receipt } },
    blocks: { "0x10": { timestamp: "0x6553f100" } },
    calls: { ...meta(TOKEN, "USDC", 6), ...meta(NFT, "PUNK", null), ...meta(WETH, "WETH", 18) },
    ...extra,
  });
}

test("parseTxTarget: chain default, bad chain, bad hash", () => {
  assert.deepEqual(parseTxTarget(undefined, H.toUpperCase().replace("0X", "0x")), { chainId: 8453, hash: H });
  assert.match(parseTxTarget("solana", H).error, /unknown chain/);
  assert.match(parseTxTarget("base", "0x1234").error, /hash/);
  assert.match(parseTxTarget("base", null).error, /hash/);
});

test("formatUnits trims zeros and handles small values", () => {
  assert.equal(formatUnits(12000000n, 6), "12");
  assert.equal(formatUnits(180935n, 6), "0.180935");
  assert.equal(formatUnits(5n, 18), "0.000000000000000005");
  assert.equal(formatUnits(0n, 18), "0");
  assert.equal(formatUnits(123n, 0), "123");
});

test("ERC-20 transfer: decoded call, event with symbol/decimals, summary, fee and timestamp", async () => {
  const data = "0xa9059cbb" + word(BOB.slice(2).toLowerCase()) + word((12_000_000).toString(16));
  const r = await explainTx(8453, H, chain({
    tx: { input: data },
    receipt: { logs: [log(TOKEN, [TOPICS.T_TRANSFER, addrWord(ALICE), addrWord(BOB)], uintWord(12_000_000))] },
  }));
  assert.equal(r.status, "success");
  assert.equal(r.call.function, "transfer(address,uint256)");
  assert.deepEqual(r.call.args, [BOB, "12000000"]);
  assert.equal(r.events[0].type, "erc20_transfer");
  assert.equal(r.events[0].symbol, "USDC");
  assert.equal(r.events[0].amount, "12000000");
  assert.match(r.summary.join(" "), /sent 12 USDC to/);
  assert.equal(r.tx.fee_wei, (21000n * 1_000_000_000n).toString());
  assert.equal(r.tx.fee_eth, "0.000021");
  assert.equal(r.tx.timestamp, new Date(0x6553f100 * 1000).toISOString());
  assert.equal(r.risk, "LOW");
});

test("mint, burn, unknown decimals and an OP-stack l1Fee", async () => {
  const r = await explainTx(8453, H, chain({
    receipt: {
      l1Fee: "0x64",
      logs: [
        log(TOKEN, [TOPICS.T_TRANSFER, addrWord(ZERO), addrWord(BOB)], uintWord(5_000_000)),
        log(TOKEN, [TOPICS.T_TRANSFER, addrWord(BOB), addrWord(ZERO)], uintWord(1_000_000)),
        log(ODD, [TOPICS.T_TRANSFER, addrWord(ALICE), addrWord(BOB)], uintWord(77)),
      ],
    },
    extra: { calls: { ...meta(TOKEN, "USDC", 6) } },
  }));
  assert.match(r.summary.join(" "), /5 USDC minted to/);
  assert.match(r.summary.join(" "), /1 USDC burned from/);
  assert.match(r.summary.join(" "), /77 base units of the token/);
  assert.equal(r.tx.fee_wei, (21000n * 1_000_000_000n + 100n).toString());
});

test("unlimited approval and setApprovalForAll are flagged; a zero approval is a revoke", async () => {
  const r = await explainTx(1, H, chain({
    receipt: {
      logs: [
        log(TOKEN, [TOPICS.T_APPROVAL, addrWord(ALICE), addrWord(ROUTER)], "0x" + MAX.toString(16)),
        log(NFT, [TOPICS.T_APPROVAL_ALL, addrWord(ALICE), addrWord(ROUTER)], uintWord(1)),
        log(TOKEN, [TOPICS.T_APPROVAL, addrWord(ALICE), addrWord(BOB)], uintWord(0)),
      ],
    },
  }));
  assert.equal(r.risk, "MEDIUM");
  assert.deepEqual(r.findings.map((f) => f.code).sort(), ["APPROVAL_FOR_ALL_GRANTED", "UNLIMITED_APPROVAL_GRANTED"]);
  assert.match(r.summary.join(" "), /approved .* to spend unlimited USDC/);
  assert.match(r.summary.join(" "), /control of ALL their PUNK NFTs/);
  assert.match(r.summary.join(" "), /revoked .* allowance of USDC/);
});

test("ERC-721 transfer, ERC-1155 single and batch, WETH wrap/unwrap", async () => {
  const r = await explainTx(1, H, chain({
    receipt: {
      logs: [
        log(NFT, [TOPICS.T_TRANSFER, addrWord(ALICE), addrWord(BOB), uintWord(42)]),
        log(ITEMS, [TOPICS.T_1155_SINGLE, addrWord(ROUTER), addrWord(ALICE), addrWord(BOB)], uintWord(7) + word("3")),
        log(ITEMS, [TOPICS.T_1155_BATCH, addrWord(ROUTER), addrWord(ALICE), addrWord(BOB)],
          "0x" + word("40") + word("a0") + word("2") + word("1") + word("2") + word("2") + word("5") + word("6")),
        log(WETH, [TOPICS.T_DEPOSIT, addrWord(ALICE)], uintWord(10n ** 18n)),
        log(WETH, [TOPICS.T_WITHDRAWAL, addrWord(ALICE)], uintWord(5n * 10n ** 17n)),
      ],
    },
  }));
  const s = r.summary.join(" ");
  assert.match(s, /NFT #42 of PUNK moved from/);
  assert.match(s, /3 of item #7 of/);
  assert.match(s, /2 kinds of items of/);
  assert.match(s, /wrapped 1 into WETH/);
  assert.match(s, /unwrapped 0\.5 WETH/);
  assert.deepEqual(r.events.find((e) => e.type === "erc1155_transfer" && e.ids.length === 2).ids, ["1", "2"]);
});

test("unknown events get a 4byte guess; unknown selector gets a guessed function", async () => {
  const topic = "0x" + "99".repeat(32);
  const r = await explainTx(1, H, chain({
    tx: { to: ROUTER, input: "0xdeadbeef" + "00".repeat(32) },
    receipt: { logs: [log(ROUTER, [topic], "0x")] },
    extra: { events: { [topic]: ["Swapped(address,uint256)"] }, selectors: { "0xdeadbeef": ["claimAirdrop()"] } },
  }));
  assert.deepEqual(r.unknown_events, [{ address: ROUTER, topic0: topic, guess: "Swapped(address,uint256)" }]);
  assert.deepEqual([r.call.function, r.call.guessed], ["claimAirdrop()", true]);
  assert.match(r.summary.join(" "), /no token movements were logged/);
});

test("plain ETH transfer and contract creation", async () => {
  let r = await explainTx(1, H, chain({ tx: { to: BOB, value: "0xde0b6b3a7640000" } }));
  assert.match(r.summary.join(" "), /sent 1 ETH to/);
  r = await explainTx(1, H, chain({ tx: { to: null, input: "0x6080" }, receipt: { contractAddress: ROUTER } }));
  assert.match(r.summary.join(" "), new RegExp(`deployed a new contract at ${ROUTER}`));
});

test("failed and pending transactions", async () => {
  let r = await explainTx(1, H, chain({ receipt: { status: "0x0", logs: [log(TOKEN, [TOPICS.T_TRANSFER, addrWord(ALICE), addrWord(BOB)], uintWord(1))] } }));
  assert.equal(r.status, "failed");
  assert.match(r.summary[0], /Failed \(reverted\)/);
  assert.ok(r.findings.some((f) => f.code === "FAILED"));
  const pending = new FakeChain({ txs: { [H]: { from: ALICE, to: TOKEN, value: "0x0", input: "0x" } } });
  r = await explainTx(1, H, pending);
  assert.equal(r.status, "pending");
  assert.ok(r.findings.some((f) => f.code === "PENDING"));
});

test("unknown hash -> NotFound; failed lookups -> LookupUnavailable", async () => {
  await assert.rejects(explainTx(1, H, new FakeChain()), NotFound);
  await assert.rejects(explainTx(1, H, new FakeChain({ unknown: ["tx"] })), LookupUnavailable);
  await assert.rejects(explainTx(1, H, chain({ extra: { unknown: ["receipt"] } })), LookupUnavailable);
});

test("token metadata lookups are capped (subrequest budget)", async () => {
  const tokens = Array.from({ length: 20 }, (_, i) => A((i + 16).toString(16)));
  const c = chain({ receipt: { logs: tokens.map((t) => log(t, [TOPICS.T_TRANSFER, addrWord(ALICE), addrWord(BOB)], uintWord(1))) } });
  await explainTx(1, H, c);
  assert.ok(c.callLog.length <= 16, `metadata calls: ${c.callLog.length}`);
});
