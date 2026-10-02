// Risk analysis of what a wallet is about to sign. Port of joi_presign/core.py.
// All chain facts come from a `lookups` object; any lookup may resolve to null (= unknown).
import { decodeCall, innerCalls, isAddress, toChecksumAddress, hexToBytes } from "./abi.js";
import { toHex } from "./keccak.js";

export const CHAINS = { ethereum: 1, arbitrum: 42161, base: 8453 };
export const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT160 = (1n << 160n) - 1n;
const UNLIMITED_THRESHOLD = 1n << 200n;
const LARGE_THRESHOLD = 10n ** 27n;
const LONG_WINDOW = 30n * 86400n;
const MAX_DEPTH = 3;
const SEVERITY = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
const PERMIT2_TYPES = new Set([
  "PermitSingle", "PermitBatch", "PermitTransferFrom", "PermitBatchTransferFrom",
  "PermitWitnessTransferFrom", "PermitBatchWitnessTransferFrom",
]);

class Report {
  constructor() { this.findings = []; }
  add(code, severity, message) {
    if (!this.findings.some((f) => f.code === code && f.severity === severity && f.message === message)) {
      this.findings.push({ code, severity, message });
    }
  }
  risk() {
    const worst = Math.max(0, ...this.findings.map((f) => SEVERITY[f.severity]));
    return worst >= 3 ? "HIGH" : worst === 2 ? "MEDIUM" : "LOW";
  }
}

export class BadInput extends Error {}

function int(v, dflt = 0n) {
  if (v === null || v === undefined) return dflt;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new BadInput(`not an integer: ${v}`);
    return BigInt(v);
  }
  const s = String(v).trim();
  try {
    if (/^-?0x[0-9a-f]+$/i.test(s)) return s.startsWith("-") ? -BigInt(s.slice(1)) : BigInt(s);
    if (/^[+-]?\d+$/.test(s)) return BigInt(s);
  } catch { /* fall through */ }
  throw new BadInput(`not an integer: ${JSON.stringify(v)}`);
}

function bytes(v) {
  if (v === null || v === undefined || v === "" || v === "0x") return new Uint8Array(0);
  if (typeof v !== "string") throw new Error("not valid hex");
  return hexToBytes(v);
}

const addr = (v) => (typeof v === "string" && isAddress(v) ? toChecksumAddress(v) : null);

// JSON-safe copy: bigints and bytes become strings.
function plain(v) {
  if (typeof v === "bigint") return v.toString();
  if (v instanceof Uint8Array) return toHex(v);
  if (Array.isArray(v)) return v.map(plain);
  return v;
}

const PRINTABLE = new Set(
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c",
);

// ---------------------------------------------------------------- input classification

export function classify(payload) {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return ["unknown", payload];
  const method = typeof payload.method === "string" ? payload.method : null;
  const params = Array.isArray(payload.params) ? payload.params : [];
  if ((method === "eth_sendTransaction" || method === "eth_signTransaction") && params.length) return ["tx", params[0]];
  if (method && method.startsWith("eth_signTypedData")) {
    for (let p of [...params, payload.typedData]) {
      if (typeof p === "string" && p.trim().startsWith("{")) {
        try { p = JSON.parse(p); } catch { throw new BadInput("typed data string is not valid JSON"); }
      }
      if (p && typeof p === "object" && "types" in p) return ["typed", p];
    }
    return ["unknown", payload];
  }
  if (method === "personal_sign" || method === "eth_sign") {
    const candidates = [...params, ...("message" in payload ? [payload.message] : [])];
    const msgs = candidates.filter((p) => typeof p === "string" && !(isAddress(p) && p.length === 42));
    return ["message", [method, msgs.length ? msgs[0] : ""]];
  }
  if ("types" in payload && "primaryType" in payload) return ["typed", payload];
  if ("to" in payload || "data" in payload || "input" in payload) return ["tx", payload];
  return ["unknown", payload];
}

export async function analyze(payload, chainId, lookups) {
  const rep = new Report();
  const [kind, obj] = classify(payload);
  let decoded;
  if (kind === "tx") decoded = await analyzeTx(obj, chainId, lookups, rep, 0, 0);
  else if (kind === "typed") decoded = await analyzeTyped(obj, chainId, lookups, rep);
  else if (kind === "message") decoded = analyzeMessage(obj, rep);
  else {
    decoded = null;
    rep.add("UNRECOGNIZED_INPUT", "MEDIUM", "Not a transaction, typed data or sign request this tool understands.");
  }
  return { kind, chain_id: chainId, risk: rep.risk(), findings: rep.findings, decoded };
}

// ---------------------------------------------------------------- address facts

async function addressStatus(chainId, a, lookups, rep, role) {
  const kind = await lookups.codeKind(chainId, a);
  if (kind === null) {
    rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not check whether the ${role} ${a} is a contract.`);
    return "unknown";
  }
  if (kind === "none") return "eoa";
  if (kind === "7702") {
    rep.add("DELEGATED_EOA", "MEDIUM", `The ${role} ${a} is an EOA with an EIP-7702 code delegation.`);
    return "eoa-7702";
  }
  const verified = await lookups.sourcifyVerified(chainId, a);
  if (verified === null) {
    rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not check source verification of the ${role} ${a}.`);
    return "unknown";
  }
  return verified ? "verified" : "unverified";
}

async function checkSpender(chainId, spender, lookups, rep, what) {
  const status = await addressStatus(chainId, spender, lookups, rep, "spender");
  if (status === "eoa" || status === "eoa-7702") {
    rep.add("APPROVAL_TO_EOA", "HIGH",
      `${what} goes to ${spender}, a plain wallet, not a contract. Classic phishing pattern: legitimate apps approve contracts.`);
  } else if (status === "unverified") {
    rep.add("SPENDER_UNVERIFIED", "MEDIUM", `${what} goes to ${spender}, a contract with no verified source on Sourcify.`);
  }
  return status;
}

function checkAmount(amount, uintMax, spenderStatus, rep, what) {
  if (amount === 0n) {
    rep.add("REVOKE", "INFO", `${what} sets the amount to 0 (a revoke).`);
    return;
  }
  const unlimited = amount >= (UNLIMITED_THRESHOLD < uintMax ? UNLIMITED_THRESHOLD : uintMax);
  if (unlimited) {
    rep.add("UNLIMITED_APPROVAL", spenderStatus === "verified" ? "MEDIUM" : "HIGH",
      `${what} is unlimited. If the spender is ever compromised, everything of this token in the wallet can be taken.`);
  } else if (amount >= LARGE_THRESHOLD) {
    rep.add("LARGE_APPROVAL", "MEDIUM", `${what} is very large (${amount} base units).`);
  }
}

async function checkRecipient(chainId, to, lookups, rep, what) {
  const kind = await lookups.codeKind(chainId, to);
  if (kind === "none") {
    const n = await lookups.txCount(chainId, to);
    if (n === 0) {
      rep.add("TRANSFER_TO_FRESH_ADDRESS", "MEDIUM",
        `${what} goes to ${to}, an address that has never sent a transaction. Double-check it isn't a look-alike.`);
    } else if (n === null) {
      rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not check the history of the recipient ${to}.`);
    }
  } else if (kind === null) {
    rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not check the recipient ${to}.`);
  }
}

function checkTime(ts, now, rep, code, what) {
  if (ts >= (1n << 48n) - 1n) rep.add(code, "MEDIUM", `${what} never expires.`);
  else if (ts > now + LONG_WINDOW) {
    rep.add(code, "MEDIUM", `${what} is valid for more than 30 days (${(ts - now) / 86400n} days).`);
  }
}

// ---------------------------------------------------------------- transactions

async function analyzeTx(tx, chainId, lookups, rep, depth, operation) {
  if (tx === null || typeof tx !== "object") throw new BadInput("transaction must be an object");
  if (depth === 0 && tx.chainId !== null && tx.chainId !== undefined && int(tx.chainId) !== BigInt(chainId)) {
    rep.add("CHAIN_MISMATCH", "HIGH", `The transaction is for chain ${int(tx.chainId)}, not chain ${chainId}.`);
  }
  const to = addr(tx.to);
  const value = int(tx.value);
  const decoded = { to, value: value.toString() };
  let data;
  try {
    data = bytes(tx.data || tx.input || "0x");
  } catch {
    rep.add("MALFORMED_CALLDATA", "MEDIUM", "Calldata is not valid hex.");
    return decoded;
  }
  if (operation === 1) {
    rep.add("DELEGATECALL_IN_BATCH", "HIGH",
      `A batched call DELEGATECALLs ${to}: that code runs with the wallet's own permissions and storage.`);
  }
  if (to === null) {
    if (tx.to === null || tx.to === undefined || tx.to === "" || tx.to === "0x") {
      rep.add("CONTRACT_CREATION", "MEDIUM", "This deploys a new contract from your account.");
    } else {
      const shown = typeof tx.to === "string" ? `'${tx.to}'` : JSON.stringify(tx.to);
      rep.add("MALFORMED_ADDRESS", "MEDIUM", `Invalid 'to' address: ${shown}.`);
    }
    return decoded;
  }
  if (data.length === 0) {
    if (value > 0n) await checkRecipient(chainId, to, lookups, rep, `A transfer of ${value} wei`);
    return decoded;
  }
  let call;
  try {
    call = decodeCall(data);
  } catch (e) {
    rep.add("MALFORMED_CALLDATA", "MEDIUM", e.message);
    return decoded;
  }
  if (call === null) {
    rep.add("MALFORMED_CALLDATA", "MEDIUM", "Calldata is shorter than a function selector.");
    return decoded;
  }
  decoded.selector = call.selector;
  if (call.name === null) {
    await unknownFunction(chainId, to, call.selector, lookups, rep, decoded);
    return decoded;
  }
  decoded.function = call.signature;
  decoded.args = plain(call.args);
  await knownFunction(chainId, to, call, tx, lookups, rep, decoded, depth);
  return decoded;
}

async function unknownFunction(chainId, to, sel, lookups, rep, decoded) {
  const sigs = await lookups.selectorSignatures(sel);
  if (sigs && sigs.length) {
    decoded.function_guesses = sigs.slice(0, 3);
    rep.add("UNKNOWN_FUNCTION_GUESSED", "LOW",
      `Function ${sel} is not in the built-in list; public database guesses: ${sigs.slice(0, 3).join(", ")} (guesses can be spoofed).`);
  } else if (sigs === null) {
    rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not look up function ${sel}.`);
    rep.add("UNKNOWN_FUNCTION", "MEDIUM", `Function ${sel} could not be identified.`);
  } else {
    rep.add("UNKNOWN_FUNCTION", "MEDIUM", `Function ${sel} is unknown to public databases: blind call.`);
  }
  const status = await addressStatus(chainId, to, lookups, rep, "target contract");
  if (status === "unverified") rep.add("TARGET_UNVERIFIED", "MEDIUM", `The target ${to} has no verified source on Sourcify.`);
}

async function knownFunction(chainId, to, call, tx, lookups, rep, decoded, depth) {
  const { name, args } = call;
  if (name === "approve" || name === "increaseAllowance") {
    const [spender, amount] = args;
    const what = `An allowance on token ${to} for ${spender}`;
    const status = amount ? await checkSpender(chainId, spender, lookups, rep, what) : "n/a";
    checkAmount(amount, MAX_UINT256, status, rep, what);
  } else if (name === "permit") {
    const [, spender, amount] = args;
    const what = `A permit on token ${to} for ${spender}`;
    const status = await checkSpender(chainId, spender, lookups, rep, what);
    checkAmount(amount, MAX_UINT256, status, rep, what);
  } else if (name === "permit2Approve") {
    const [token, spender, amount, expiration] = args;
    const what = `A Permit2 allowance on token ${token} for ${spender}`;
    const status = amount ? await checkSpender(chainId, spender, lookups, rep, what) : "n/a";
    checkAmount(amount, MAX_UINT160, status, rep, what);
    if (amount) checkTime(expiration, BigInt(lookups.now()), rep, "LONG_EXPIRATION", what);
  } else if (name === "setApprovalForAll") {
    const [operator, approved] = args;
    if (!approved) rep.add("REVOKE", "INFO", `Revokes operator ${operator} on collection ${to}.`);
    else {
      const what = `Approval for ALL items of collection ${to} to ${operator}`;
      const status = await checkSpender(chainId, operator, lookups, rep, what);
      rep.add("APPROVAL_FOR_ALL", status === "verified" ? "MEDIUM" : "HIGH",
        `${what}: the operator can move every item you own in this collection, now and later.`);
    }
  } else if (name === "transfer") {
    const [recipient, amount] = args;
    await checkRecipient(chainId, recipient, lookups, rep, `A transfer of ${amount} base units of ${to}`);
  } else if (["transferFrom", "safeTransferFrom721", "safeTransferFrom721Data", "safeTransferFrom1155",
    "safeBatchTransferFrom1155"].includes(name)) {
    const [sender, recipient] = args;
    const signer = addr(tx.from);
    if (signer && sender !== signer) rep.add("MOVES_OTHERS_ASSETS", "LOW", `Moves assets owned by ${sender}, not by the signer ${signer}.`);
    await checkRecipient(chainId, recipient, lookups, rep, `An asset transfer from ${to}`);
  } else if (["multicall", "multicallDeadline", "aggregate", "aggregate3", "tryAggregate", "multiSend"].includes(name)) {
    if (depth >= MAX_DEPTH) {
      rep.add("NESTING_TOO_DEEP", "MEDIUM", "Batches nested deeper than 3 levels were not analyzed.");
      return;
    }
    let calls;
    try {
      calls = innerCalls(call, to);
    } catch (e) {
      rep.add("MALFORMED_CALLDATA", "MEDIUM", e.message);
      return;
    }
    delete decoded.args;
    decoded.calls = [];
    for (const [t, v, d, op] of calls) {
      decoded.calls.push(await analyzeTx({ to: t, value: v, data: "0x" + toHex(d) }, chainId, lookups, rep, depth + 1, op));
    }
  }
}

// ---------------------------------------------------------------- typed data

async function analyzeTyped(td, chainId, lookups, rep) {
  const domain = td.domain && typeof td.domain === "object" ? td.domain : {};
  const pt = td.primaryType;
  const msg = td.message && typeof td.message === "object" ? td.message : {};
  if (domain.chainId !== null && domain.chainId !== undefined && int(domain.chainId) !== BigInt(chainId)) {
    rep.add("CHAIN_MISMATCH", "HIGH", `The signature is for chain ${int(domain.chainId)}, not chain ${chainId}.`);
  }
  const vc = addr(domain.verifyingContract);
  const pick = (k) => (domain[k] === undefined ? null : domain[k]);
  const decoded = { primaryType: pt ?? null, domain: { name: pick("name"), version: pick("version"), chainId: pick("chainId"), verifyingContract: pick("verifyingContract") } };
  const now = BigInt(lookups.now());
  if ((domain.name === "Permit2" || vc === PERMIT2) && PERMIT2_TYPES.has(pt)) {
    await permit2(chainId, pt, msg, now, lookups, rep, decoded);
    return decoded;
  }
  if (pt === "Permit" && "spender" in msg && "value" in msg) {
    const spender = addr(msg.spender);
    const what = `A signed permit on token ${vc} for ${spender}`;
    rep.add("PERMIT_SIGNATURE", "MEDIUM",
      "Gasless approval: anyone holding this signature can submit it on-chain to set the allowance.");
    const status = spender ? await checkSpender(chainId, spender, lookups, rep, what) : "unknown";
    checkAmount(int(msg.value), MAX_UINT256, status, rep, what);
    if ("deadline" in msg) checkTime(int(msg.deadline), now, rep, "LONG_DEADLINE", what);
    Object.assign(decoded, { spender, value: int(msg.value).toString(), deadline: int(msg.deadline).toString() });
    return decoded;
  }
  if (domain.name === "Seaport" && pt === "OrderComponents") {
    seaport(msg, rep, decoded);
    return decoded;
  }
  rep.add("UNKNOWN_TYPED_DATA", "LOW", `Typed data '${pt}' is not a known approval or order format; read it before signing.`);
  if (vc && (await lookups.codeKind(chainId, vc)) === "none") {
    rep.add("VERIFYING_CONTRACT_NOT_CONTRACT", "MEDIUM", `The domain's verifyingContract ${vc} has no code on this chain.`);
  }
  return decoded;
}

async function permit2(chainId, pt, msg, now, lookups, rep, decoded) {
  rep.add("PERMIT2_SIGNATURE", "MEDIUM", "Permit2 signature: it authorizes token movements without a further transaction.");
  const spender = addr(msg.spender);
  let amounts, uintMax, deadline;
  if (pt === "PermitSingle" || pt === "PermitBatch") {
    const details = Array.isArray(msg.details) ? msg.details : [msg.details || {}];
    amounts = details.map((d) => [addr(d.token), int(d.amount), int(d.expiration)]);
    uintMax = MAX_UINT160;
    deadline = int(msg.sigDeadline);
  } else {
    const permitted = Array.isArray(msg.permitted) ? msg.permitted : [msg.permitted || {}];
    amounts = permitted.map((p) => [addr(p.token), int(p.amount), null]);
    uintMax = MAX_UINT256;
    deadline = int(msg.deadline);
  }
  const status = spender ? await checkSpender(chainId, spender, lookups, rep, `A Permit2 signature for ${spender}`) : "unknown";
  for (const [token, amount, expiration] of amounts) {
    checkAmount(amount, uintMax, status, rep, `Permit2 amount for token ${token} to ${spender}`);
    if (expiration !== null && amount) checkTime(expiration, now, rep, "LONG_EXPIRATION", `The allowance for token ${token}`);
  }
  checkTime(deadline, now, rep, "LONG_DEADLINE", "The signature");
  Object.assign(decoded, {
    spender,
    tokens: amounts.map(([token, amount, expiration]) => ({ token, amount: amount.toString(), expiration: expiration === null ? null : expiration.toString() })),
    deadline: deadline.toString(),
  });
}

function seaport(msg, rep, decoded) {
  const offerer = addr(msg.offerer);
  const offer = Array.isArray(msg.offer) ? msg.offer : [];
  const consideration = Array.isArray(msg.consideration) ? msg.consideration : [];
  let toSigner = 0n;
  for (const c of consideration) {
    if (addr(c.recipient) === offerer) {
      const s = int(c.startAmount), e = int(c.endAmount);
      toSigner += s > e ? s : e;
    }
  }
  Object.assign(decoded, { offerer, offer_items: offer.length, consideration_items: consideration.length, paid_to_signer: toSigner.toString() });
  if (offer.length && toSigner <= 1000n) {
    rep.add("SEAPORT_GIVEAWAY", "HIGH",
      `This order hands over ${offer.length} item(s) and pays the signer ${toSigner === 0n ? "nothing" : "almost nothing"}. Typical NFT-drainer listing.`);
  } else {
    rep.add("SEAPORT_ORDER", "LOW", "Seaport order. This tool doesn't price assets: check the amounts you receive.");
  }
}

// ---------------------------------------------------------------- messages

function analyzeMessage([method, raw], rep) {
  let b;
  if (typeof raw !== "string") raw = String(raw ?? "");
  try {
    b = raw.startsWith("0x") ? hexToBytes(raw) : new TextEncoder().encode(raw);
  } catch {
    b = new TextEncoder().encode(raw);
  }
  let text = null;
  try {
    const t = new TextDecoder("utf-8", { fatal: true }).decode(b);
    if (t && [...t].every((ch) => PRINTABLE.has(ch))) text = t;
  } catch { /* not utf-8 */ }
  if (method === "eth_sign") {
    rep.add("BLIND_SIGNING", "HIGH",
      "eth_sign signs a raw hash: it can authorize a transaction or permit you cannot see. Legitimate apps almost never need it.");
  } else if (text === null) {
    rep.add("OPAQUE_MESSAGE", "MEDIUM",
      `personal_sign of ${b.length} unreadable bytes${b.length === 32 ? " (a 32-byte hash)" : ""}: you cannot read what you are approving.`);
  } else {
    rep.add("READABLE_MESSAGE", "LOW", "Readable message. Check it says what you expect (domain, nonce, purpose).");
  }
  return { method, text: text ? text.slice(0, 500) : null, length: b.length };
}
