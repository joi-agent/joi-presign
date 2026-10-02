// "What did this transaction do?": a read-only explainer of a mined (or pending) transaction.
// Every chain fact comes from `lookups`; anything may resolve to null (unknown).
import { decodeCall, decode, hexToBytes, toChecksumAddress, isAddress } from "./abi.js";
import { CHAINS, Report } from "./core.js";
import { keccak256, utf8, toHex } from "./keccak.js";
import { LookupUnavailable, NotFound } from "./profile.js";

const topicOf = (sig) => "0x" + toHex(keccak256(utf8(sig)));
const T_TRANSFER = topicOf("Transfer(address,address,uint256)");
const T_APPROVAL = topicOf("Approval(address,address,uint256)");
const T_APPROVAL_ALL = topicOf("ApprovalForAll(address,address,bool)");
const T_1155_SINGLE = topicOf("TransferSingle(address,address,address,uint256,uint256)");
const T_1155_BATCH = topicOf("TransferBatch(address,address,address,uint256[],uint256[])");
const T_DEPOSIT = topicOf("Deposit(address,uint256)");
const T_WITHDRAWAL = topicOf("Withdrawal(address,uint256)");
export const TOPICS = { T_TRANSFER, T_APPROVAL, T_APPROVAL_ALL, T_1155_SINGLE, T_1155_BATCH, T_DEPOSIT, T_WITHDRAWAL };

const SEL_SYMBOL = "0x95d89b41", SEL_DECIMALS = "0x313ce567";
const ZERO = "0x" + "00".repeat(20);
const UNLIMITED = 1n << 200n;
const MAX_TOKENS = 8, MAX_EVENT_GUESSES = 3, MAX_LOGS = 200, MAX_EVENTS_SHOWN = 50;
const CHAIN_NAMES = Object.fromEntries(Object.entries(CHAINS).map(([name, id]) => [id, name]));

export function parseTxTarget(chainRaw, hashRaw) {
  const chainName = chainRaw === undefined || chainRaw === null || chainRaw === "" ? "base" : String(chainRaw);
  const chainId = CHAINS[chainName];
  if (!chainId) return { error: `unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}` };
  if (typeof hashRaw !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(hashRaw)) return { error: "hash must be a 0x-prefixed 32-byte transaction hash" };
  return { chainId, hash: hashRaw.toLowerCase() };
}

const big = (h) => (typeof h === "string" && /^0x[0-9a-fA-F]*$/.test(h) ? BigInt(h === "0x" ? "0x0" : h) : null);
const topicAddr = (t) => (typeof t === "string" && /^0x0{24}[0-9a-fA-F]{40}$/.test(t) ? toChecksumAddress("0x" + t.slice(26)) : null);
const addrOrNull = (a) => (typeof a === "string" && isAddress(a) ? toChecksumAddress(a) : null);
const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "?");

/** Decimal string of `v / 10^decimals` with trailing zeros trimmed. */
export function formatUnits(v, decimals) {
  const neg = v < 0n;
  let s = (neg ? -v : v).toString();
  if (decimals > 0) {
    s = s.padStart(decimals + 1, "0");
    const i = s.length - decimals;
    s = `${s.slice(0, i)}.${s.slice(i)}`.replace(/\.?0+$/, "");
  }
  return (neg ? "-" : "") + s;
}

function decodeAbiString(hex) {
  if (typeof hex !== "string" || hex === "0x") return null;
  try {
    const b = hexToBytes(hex);
    if (b.length === 32) { // legacy bytes32 symbol (e.g. MKR)
      const end = b.indexOf(0);
      const s = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(0, end < 0 ? 32 : end));
      return s || null;
    }
    const [s] = decode(["string"], b);
    return s.length <= 64 ? s : s.slice(0, 64);
  } catch { return null; }
}

async function tokenMeta(chainId, token, lookups) {
  const [symHex, decHex] = await Promise.all([lookups.ethCall(chainId, token, SEL_SYMBOL), lookups.ethCall(chainId, token, SEL_DECIMALS)]);
  const decimals = big(decHex);
  return { symbol: decodeAbiString(symHex), decimals: decimals !== null && decimals <= 255n ? Number(decimals) : null };
}

function amountText(v, meta) {
  if (v >= UNLIMITED) return `unlimited ${meta.symbol || "tokens"}`;
  if (meta.decimals === null) return `${v.toString()} base units of ${meta.symbol || "the token"}`;
  return `${formatUnits(v, meta.decimals)} ${meta.symbol || "tokens"}`;
}

function parseLog(log) {
  const topics = Array.isArray(log.topics) ? log.topics.map((t) => String(t).toLowerCase()) : [];
  const address = addrOrNull(log.address);
  if (!address || !topics.length) return null;
  const data = typeof log.data === "string" && /^0x([0-9a-fA-F]{2})*$/.test(log.data) ? hexToBytes(log.data) : new Uint8Array(0);
  const t0 = topics[0];
  try {
    if (t0 === T_TRANSFER && topics.length === 3 && data.length === 32) {
      return { type: "erc20_transfer", token: address, from: topicAddr(topics[1]), to: topicAddr(topics[2]), amount: decode(["uint256"], data)[0] };
    }
    if (t0 === T_TRANSFER && topics.length === 4) {
      return { type: "erc721_transfer", token: address, from: topicAddr(topics[1]), to: topicAddr(topics[2]), token_id: BigInt(topics[3]) };
    }
    if (t0 === T_APPROVAL && topics.length === 3 && data.length === 32) {
      return { type: "erc20_approval", token: address, owner: topicAddr(topics[1]), spender: topicAddr(topics[2]), amount: decode(["uint256"], data)[0] };
    }
    if (t0 === T_APPROVAL && topics.length === 4) {
      return { type: "erc721_approval", token: address, owner: topicAddr(topics[1]), approved: topicAddr(topics[2]), token_id: BigInt(topics[3]) };
    }
    if (t0 === T_APPROVAL_ALL && topics.length === 3 && data.length === 32) {
      return { type: "approval_for_all", token: address, owner: topicAddr(topics[1]), operator: topicAddr(topics[2]), approved: decode(["bool"], data)[0] };
    }
    if (t0 === T_1155_SINGLE && topics.length === 4 && data.length === 64) {
      const [id, value] = decode(["uint256", "uint256"], data);
      return { type: "erc1155_transfer", token: address, operator: topicAddr(topics[1]), from: topicAddr(topics[2]), to: topicAddr(topics[3]), ids: [id], values: [value] };
    }
    if (t0 === T_1155_BATCH && topics.length === 4) {
      const [ids, values] = decode(["uint256[]", "uint256[]"], data);
      return { type: "erc1155_transfer", token: address, operator: topicAddr(topics[1]), from: topicAddr(topics[2]), to: topicAddr(topics[3]), ids, values };
    }
    if (t0 === T_DEPOSIT && topics.length === 2 && data.length === 32) {
      return { type: "wrap", token: address, account: topicAddr(topics[1]), amount: decode(["uint256"], data)[0] };
    }
    if (t0 === T_WITHDRAWAL && topics.length === 2 && data.length === 32) {
      return { type: "unwrap", token: address, account: topicAddr(topics[1]), amount: decode(["uint256"], data)[0] };
    }
  } catch { /* fall through: treat as unknown */ }
  return { type: "unknown", address, topic0: t0 };
}

function describe(ev, meta) {
  const m = meta || { symbol: null, decimals: null };
  const tokenName = m.symbol || short(ev.token);
  switch (ev.type) {
    case "erc20_transfer":
      if (ev.from === ZERO) return `${amountText(ev.amount, m)} minted to ${short(ev.to)}`;
      if (ev.to === ZERO) return `${amountText(ev.amount, m)} burned from ${short(ev.from)}`;
      return `${short(ev.from)} sent ${amountText(ev.amount, m)} to ${short(ev.to)}`;
    case "erc20_approval":
      if (ev.amount === 0n) return `${short(ev.owner)} revoked ${short(ev.spender)}'s allowance of ${tokenName}`;
      return `${short(ev.owner)} approved ${short(ev.spender)} to spend ${amountText(ev.amount, m)}`;
    case "erc721_transfer":
      if (ev.from === ZERO) return `NFT #${ev.token_id} of ${tokenName} minted to ${short(ev.to)}`;
      if (ev.to === ZERO) return `NFT #${ev.token_id} of ${tokenName} burned by ${short(ev.from)}`;
      return `NFT #${ev.token_id} of ${tokenName} moved from ${short(ev.from)} to ${short(ev.to)}`;
    case "erc721_approval":
      return `${short(ev.owner)} approved ${short(ev.approved)} to move NFT #${ev.token_id} of ${tokenName}`;
    case "approval_for_all":
      return ev.approved
        ? `${short(ev.owner)} gave ${short(ev.operator)} control of ALL their ${tokenName} NFTs`
        : `${short(ev.owner)} revoked ${short(ev.operator)}'s control of their ${tokenName} NFTs`;
    case "erc1155_transfer": {
      const what = ev.ids.length === 1 ? `${ev.values[0]} of item #${ev.ids[0]}` : `${ev.ids.length} kinds of items`;
      if (ev.from === ZERO) return `${what} of ${short(ev.token)} minted to ${short(ev.to)}`;
      if (ev.to === ZERO) return `${what} of ${short(ev.token)} burned from ${short(ev.from)}`;
      return `${what} of ${short(ev.token)} moved from ${short(ev.from)} to ${short(ev.to)}`;
    }
    case "wrap": return `${short(ev.account)} wrapped ${formatUnits(ev.amount, 18)} into ${tokenName}`;
    case "unwrap": return `${short(ev.account)} unwrapped ${formatUnits(ev.amount, 18)} ${tokenName}`;
    default: return null;
  }
}

// JSON-safe copy: bigints become decimal strings.
function plain(v) {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]));
  return v;
}

export async function explainTx(chainId, hash, lookups) {
  const chain = CHAIN_NAMES[chainId] || String(chainId);
  const tx = await lookups.getTransaction(chainId, hash);
  if (tx === null) throw new LookupUnavailable("could not read the transaction");
  if (tx === false) throw new NotFound(`no transaction with this hash on ${chain}`);
  const receipt = await lookups.getReceipt(chainId, hash);
  if (receipt === null) throw new LookupUnavailable("could not read the transaction receipt");

  const rep = new Report();
  const summary = [];
  const from = addrOrNull(tx.from);
  const to = addrOrNull(tx.to);
  const value = big(tx.value) ?? 0n;
  const status = receipt === false ? "pending" : (big(receipt.status) === 1n ? "success" : "failed");
  const out = {
    kind: "tx", chain_id: chainId, status, risk: "LOW", findings: [], summary,
    tx: { hash, from, to, value_wei: value.toString(), value_eth: formatUnits(value, 18), nonce: big(tx.nonce)?.toString() ?? null },
    call: null, events: [], unknown_events: [],
  };

  // the call
  let data = new Uint8Array(0);
  try { data = typeof tx.input === "string" ? hexToBytes(tx.input) : new Uint8Array(0); } catch { /* keep empty */ }
  if (data.length >= 4) {
    let call;
    try { call = decodeCall(data); } catch { call = { selector: "0x" + toHex(data.subarray(0, 4)), name: null, signature: null, args: null }; }
    out.call = { selector: call.selector, function: call.signature, args: call.args ? plain(call.args) : null, guessed: false };
    if (!call.signature) {
      const sigs = await lookups.selectorSignatures(call.selector);
      if (sigs && sigs.length) { out.call.function = sigs[0]; out.call.guessed = true; }
    }
  }

  if (status === "pending") {
    summary.push(`Pending: not mined yet. ${short(from)} is calling ${to ? short(to) : "contract creation"}${out.call?.function ? ` (${out.call.function})` : ""}.`);
    rep.add("PENDING", "INFO", "The transaction isn't mined yet, so it has had no effect so far.");
    out.findings = rep.findings;
    out.risk = rep.risk();
    return out;
  }

  // receipt facts
  const gasUsed = big(receipt.gasUsed) ?? 0n;
  const price = big(receipt.effectiveGasPrice) ?? big(tx.gasPrice) ?? 0n;
  const l1Fee = big(receipt.l1Fee) ?? 0n;
  const fee = gasUsed * price + l1Fee;
  Object.assign(out.tx, {
    block: big(receipt.blockNumber)?.toString() ?? null,
    gas_used: gasUsed.toString(),
    fee_wei: fee.toString(),
    fee_eth: formatUnits(fee, 18),
    contract_created: addrOrNull(receipt.contractAddress),
  });
  const block = receipt.blockNumber ? await lookups.getBlock(chainId, receipt.blockNumber) : null;
  const ts = block ? big(block.timestamp) : null;
  out.tx.timestamp = ts !== null ? new Date(Number(ts) * 1000).toISOString() : null;

  if (status === "failed") {
    summary.push(`Failed (reverted): nothing in it took effect, but ${short(from)} still paid the fee of ${out.tx.fee_eth} ETH.`);
    rep.add("FAILED", "INFO", "The transaction reverted: no transfers or approvals in it took effect. Only the fee was paid.");
  } else {
    if (!to && out.tx.contract_created) summary.push(`${short(from)} deployed a new contract at ${out.tx.contract_created}.`);
    if (value > 0n) summary.push(`${short(from)} sent ${formatUnits(value, 18)} ETH to ${short(to)}.`);
  }

  // events
  const logs = Array.isArray(receipt.logs) ? receipt.logs.slice(0, MAX_LOGS) : [];
  const parsed = logs.map(parseLog).filter(Boolean);
  const tokens = [...new Set(parsed.filter((e) => e.type !== "unknown").map((e) => e.token))].slice(0, MAX_TOKENS);
  const metas = Object.fromEntries(await Promise.all(tokens.map(async (t) => [t, await tokenMeta(chainId, t, lookups)])));
  const unknownTopics = [...new Set(parsed.filter((e) => e.type === "unknown").map((e) => e.topic0))];
  const guesses = {};
  for (const t of unknownTopics.slice(0, MAX_EVENT_GUESSES)) {
    const sigs = await lookups.eventSignatures(t);
    guesses[t] = sigs && sigs.length ? sigs[0] : null;
  }
  for (const ev of parsed) {
    if (ev.type === "unknown") {
      out.unknown_events.push({ address: ev.address, topic0: ev.topic0, guess: guesses[ev.topic0] ?? null });
      continue;
    }
    const meta = metas[ev.token] || null;
    const text = describe(ev, meta);
    if (out.events.length < MAX_EVENTS_SHOWN) {
      out.events.push({ ...plain(ev), symbol: meta?.symbol ?? null, decimals: meta?.decimals ?? null, text });
      if (text && summary.length < 25) summary.push(text + ".");
    }
    if (ev.type === "erc20_approval" && ev.amount >= UNLIMITED) {
      rep.add("UNLIMITED_APPROVAL_GRANTED", "MEDIUM",
        `This transaction gave ${ev.spender} an unlimited allowance on ${meta?.symbol || ev.token}. Revoke it if you don't need it.`);
    }
    if (ev.type === "approval_for_all" && ev.approved) {
      rep.add("APPROVAL_FOR_ALL_GRANTED", "MEDIUM",
        `This transaction gave ${ev.operator} control of all ${meta?.symbol || ev.token} NFTs of ${ev.owner}. Revoke it if you don't need it.`);
    }
  }
  if (logs.length > parsed.length) rep.add("UNPARSED_LOGS", "INFO", `${logs.length - parsed.length} log(s) couldn't be read.`);
  if (Array.isArray(receipt.logs) && receipt.logs.length > MAX_LOGS) rep.add("TRUNCATED", "INFO", `Only the first ${MAX_LOGS} of ${receipt.logs.length} logs were read.`);
  if (status === "success" && !summary.length) summary.push(`${short(from)} called ${short(to)}${out.call?.function ? ` (${out.call.function})` : ""}; no token movements were logged.`);
  out.findings = rep.findings;
  out.risk = rep.risk();
  return out;
}
