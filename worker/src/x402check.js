// "Should my agent pay this 402?" Fetches a URL like a cautious x402 client (it never pays and never signs), reads
// the payment requirements (x402 v2 PAYMENT-REQUIRED header, v1 JSON body) and reports what paying would mean: the
// network, the asset and whether it's the real USDC, the amount in units and USD, and who gets paid (wallet or
// contract, verified, on the OFAC SDN list).
import { CHAINS, Report } from "./core.js";
import { isAddress, toChecksumAddress } from "./abi.js";
import { screenMatches } from "./screen.js";
import { formatUnits, parsePriceTarget, readPrice } from "./price.js";
import { checkUrl } from "./fetchsafe.js";
import { b64decodeJson } from "./x402.js";

export const X402CHECK_NOTICE =
  "This check never pays and never signs anything. It reads the 402 answer the way a careful client would and says " +
  "what paying would mean. A clean result is not an endorsement of the service behind the URL.";

// CAIP-2 ids used in x402 v2, with the names x402 v1 uses for the same networks.
export const NETWORKS = {
  "eip155:1": { name: "ethereum", testnet: false },
  "eip155:11155111": { name: "ethereum-sepolia", testnet: true },
  "eip155:8453": { name: "base", testnet: false },
  "eip155:84532": { name: "base-sepolia", testnet: true },
  "eip155:42161": { name: "arbitrum", testnet: false },
  "eip155:421614": { name: "arbitrum-sepolia", testnet: true },
  "eip155:10": { name: "optimism", testnet: false },
  "eip155:11155420": { name: "optimism-sepolia", testnet: true },
  "eip155:137": { name: "polygon", testnet: false },
  "eip155:80002": { name: "polygon-amoy", testnet: true },
  "eip155:43114": { name: "avalanche", testnet: false },
  "eip155:43113": { name: "avalanche-fuji", testnet: true },
  "eip155:1329": { name: "sei", testnet: false },
  "eip155:1328": { name: "sei-testnet", testnet: true },
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": { name: "solana", testnet: false },
  "solana:EtWTRABZaYq6iMfeYKouRu166VPAZGDO": { name: "solana-devnet", testnet: true },
};
export const V1_NETWORKS = Object.fromEntries(Object.entries(NETWORKS).map(([id, n]) => [n.name, id]));

// Native USDC issued by Circle, per network. Source: https://developers.circle.com/stablecoins/usdc-contract-addresses
// (checked 2026-10-02; on ethereum/base/arbitrum also checked on-chain: symbol USDC, 6 decimals).
export const USDC = {
  "eip155:1": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "eip155:11155111": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  "eip155:42161": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
  "eip155:421614": "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
  "eip155:10": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
  "eip155:11155420": "0x5fd84259d66Cd46123540766Be93DFE6D43130D7",
  "eip155:137": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
  "eip155:80002": "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582",
  "eip155:43114": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
  "eip155:43113": "0x5425890298aed601595a70AB815c96711a31Bc65",
  "eip155:1329": "0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392",
  "eip155:1328": "0x4fCF1784B31630811181f670Aea7A7bEF803eaED",
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "solana:EtWTRABZaYq6iMfeYKouRu166VPAZGDO": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
};

// Other tokens worth naming, on the chains this service can read. Each checked on-chain 2026-10-02 (symbol, decimals).
// [symbol, decimals, Chainlink feed asset (see price.js) or null]
export const KNOWN_TOKENS = {
  "eip155:1": {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ["USDT", 6, "USDT"], // Tether, tether.to/en/supported-protocols
    "0x6b175474e89094c44da98b954eedeac495271d0f": ["DAI", 18, "DAI"], // Sky/MakerDAO Dai
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ["WETH", 18, "ETH"], // canonical WETH9
  },
  "eip155:8453": {
    "0x4200000000000000000000000000000000000006": ["WETH", 18, "ETH"], // OP Stack predeploy, docs.base.org
    "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": ["DAI", 18, "DAI"],
    "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": ["USDT", 6, "USDT"],
  },
  "eip155:42161": {
    "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": ["WETH", 18, "ETH"],
    "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": ["USDT0", 6, "USDT"], // on-chain symbol "USD₮0"
    "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": ["DAI", 18, "DAI"],
  },
};

const CHAIN_BY_ID = Object.fromEntries(Object.entries(CHAINS).map(([name, id]) => [`eip155:${id}`, { name, id }]));
const MAX_OPTIONS = 5;
const SEV = { INFO: 0, LOW: 0, MEDIUM: 1, HIGH: 2 };

export function parseX402CheckTarget(urlRaw) {
  try {
    return { url: checkUrl(urlRaw).toString() };
  } catch (e) {
    return { error: e.message };
  }
}

/** {version, accepts[], resource, description} from a v2 PAYMENT-REQUIRED header value, or null. */
export function parseV2Header(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  try {
    const d = b64decodeJson(value);
    return d && typeof d === "object" && Array.isArray(d.accepts) ? d : null;
  } catch {
    return null;
  }
}

/** The JSON body of a 402, or null. */
export function parseBody(text) {
  if (typeof text !== "string" || !text.trim().startsWith("{")) return null;
  try {
    const d = JSON.parse(text);
    return d && typeof d === "object" && Array.isArray(d.accepts) ? d : null;
  } catch {
    return null;
  }
}

function caipOf(network) {
  if (typeof network !== "string") return null;
  if (NETWORKS[network] || /^(eip155|solana):/.test(network)) return network;
  return V1_NETWORKS[network] || null;
}

const isDigits = (v) => (typeof v === "string" && /^\d+$/.test(v)) || (Number.isSafeInteger(v) && v >= 0);

/** Decimal-string multiply of a token amount by a USD price, rounded down to 6 decimals. */
export function usdValue(atomic, decimals, priceStr) {
  const [w, f = ""] = String(priceStr).split(".");
  const pDec = f.length;
  const p = BigInt(w + f);
  const v = (BigInt(atomic) * p * 10n ** 6n) / 10n ** BigInt(decimals + pDec);
  return formatUnits(v, 6);
}

async function payToFacts(chainId, payTo, lookups) {
  const kind = await lookups.codeKind(chainId, payTo);
  if (kind === "contract") {
    const src = await lookups.sourcifyInfo(chainId, payTo);
    return { kind: "contract", verified: src ? src.verified : null, name: src ? src.name : null };
  }
  return { kind: kind === "none" ? "eoa" : kind === "7702" ? "eoa-7702" : "unknown", verified: null, name: null };
}

async function tokenFacts(chainId, asset, lookups) {
  const [symHex, decHex] = await Promise.all([lookups.ethCall(chainId, asset, "0x95d89b41"), lookups.ethCall(chainId, asset, "0x313ce567")]);
  let symbol = null;
  if (symHex && symHex.length >= 130) {
    try {
      const off = Number(BigInt("0x" + symHex.slice(2, 66))) * 2 + 2;
      const len = Number(BigInt("0x" + symHex.slice(off, off + 64)));
      const bytes = symHex.slice(off + 64, off + 64 + len * 2);
      symbol = new TextDecoder().decode(Uint8Array.from(bytes.match(/../g) || [], (b) => parseInt(b, 16)));
    } catch { symbol = null; }
  }
  const decimals = decHex && decHex.length >= 66 ? Number(BigInt("0x" + decHex.slice(2, 66))) : null;
  return { symbol, decimals: decimals !== null && decimals <= 36 ? decimals : null };
}

export async function analyzeOption(opt, version, lookups) {
  const rep = new Report();
  const o = opt && typeof opt === "object" ? opt : {};
  const amountRaw = version === 2 ? o.amount : o.maxAmountRequired;
  const missing = [];
  for (const [k, v] of [["scheme", o.scheme], ["network", o.network], [version === 2 ? "amount" : "maxAmountRequired", amountRaw], ["asset", o.asset], ["payTo", o.payTo], ["maxTimeoutSeconds", o.maxTimeoutSeconds]]) {
    if (v === undefined || v === null || v === "") missing.push(k);
  }
  if (missing.length) rep.add("MALFORMED_REQUIREMENTS", "HIGH", `The payment option is missing ${missing.join(", ")}. A correct client can't pay it safely.`);

  const caip = caipOf(o.network);
  const net = caip ? NETWORKS[caip] : null;
  const network = { id: caip, given: o.network ?? null, name: net ? net.name : null, testnet: net ? net.testnet : null, recognized: !!net };
  if (o.network && !net) rep.add("UNKNOWN_NETWORK", "MEDIUM", `Network '${o.network}' isn't one this check recognizes, so the asset and recipient can't be judged.`);
  if (net && net.testnet) rep.add("TESTNET", "INFO", `${net.name} is a test network: the tokens have no value. Fine for testing, not a paid service.`);

  if (o.scheme !== undefined && o.scheme !== "exact") {
    rep.add("NOT_EXACT_SCHEME", "MEDIUM",
      `Scheme '${o.scheme}' isn't 'exact'. With 'exact' you authorize precisely the amount shown; other schemes (such as 'upto') ` +
      "let the server settle a variable amount up to a limit, so read that scheme's rules before signing.");
  }

  const isEvm = caip ? caip.startsWith("eip155:") : typeof o.payTo === "string" && o.payTo.startsWith("0x");
  const chain = caip ? CHAIN_BY_ID[caip] : null;

  // asset
  const usdc = caip ? USDC[caip] : null;
  let asset = { address: o.asset ?? null, symbol: null, decimals: null, kind: "unknown" };
  if (typeof o.asset === "string" && isEvm && !/^0x[0-9a-fA-F]{40}$/.test(o.asset)) {
    rep.add("MALFORMED_REQUIREMENTS", "HIGH", `The asset '${String(o.asset).slice(0, 80)}' isn't a valid token address.`);
  } else if (typeof o.asset === "string") {
    const known = caip && KNOWN_TOKENS[caip] ? KNOWN_TOKENS[caip][o.asset.toLowerCase()] : null;
    if (usdc && o.asset.toLowerCase() === usdc.toLowerCase()) {
      asset = { address: o.asset, symbol: "USDC", decimals: 6, kind: "usdc" };
    } else if (known) {
      asset = { address: o.asset, symbol: known[0], decimals: known[1], kind: "known", feed_asset: known[2] };
      rep.add("NON_USDC_ASSET", "MEDIUM", `The asset is ${known[0]}, not USDC. Check you mean to pay in ${known[0]}.`);
    } else {
      if (chain && isEvm) {
        const t = await tokenFacts(chain.id, o.asset, lookups);
        asset = { address: o.asset, symbol: t.symbol, decimals: t.decimals, kind: "unknown" };
      }
      rep.add("NON_USDC_ASSET", "MEDIUM",
        `The asset ${o.asset}${asset.symbol ? ` (calls itself ${asset.symbol})` : ""} isn't the canonical USDC${net ? ` on ${net.name}` : ""}` +
        `${usdc ? ` (${usdc})` : ""}. A token can name itself anything: be sure you know what you'd be paying.`);
    }
  }

  // amount
  const amount = { atomic: null, human: null, usd: null };
  if (amountRaw !== undefined && amountRaw !== null && amountRaw !== "") {
    if (!isDigits(amountRaw)) {
      rep.add("MALFORMED_REQUIREMENTS", "HIGH", `The amount '${String(amountRaw).slice(0, 40)}' isn't a whole number of token base units.`);
    } else {
      amount.atomic = String(amountRaw);
      if (asset.decimals !== null) amount.human = formatUnits(BigInt(amount.atomic), asset.decimals);
      if (asset.kind === "usdc") amount.usd = amount.human;
      else if (asset.feed_asset && chain) {
        try {
          const p = await readPrice(parsePriceTarget(chain.name, asset.feed_asset), lookups);
          amount.usd = usdValue(amount.atomic, asset.decimals, p.price);
          amount.usd_price_source = `Chainlink ${p.description} (${p.feed})`;
        } catch { /* no USD value */ }
      }
      if (amount.atomic === "0") rep.add("ZERO_AMOUNT", "INFO", "The amount is zero.");
    }
  }

  // who gets paid
  let payTo = { address: o.payTo ?? null, kind: null, verified: null, name: null, sanctioned: false, matches: [] };
  if (typeof o.payTo === "string" && isEvm) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(o.payTo)) {
      rep.add("MALFORMED_REQUIREMENTS", "HIGH", `payTo '${o.payTo.slice(0, 80)}' isn't a valid address.`);
    } else {
      if (!isAddress(o.payTo)) rep.add("PAYTO_BAD_CHECKSUM", "MEDIUM", "payTo's mixed-case spelling isn't a valid checksum: it may be mistyped.");
      const lower = o.payTo.toLowerCase();
      const matches = screenMatches(lower);
      payTo = { address: toChecksumAddress(lower), kind: null, verified: null, name: null, sanctioned: matches.length > 0, matches };
      if (matches.length) {
        rep.add("PAYTO_SANCTIONED", "HIGH",
          `payTo ${payTo.address} is on the OFAC SDN list (${[...new Set(matches.map((m) => m.entity))].join("; ")}). Paying it may be illegal for you. Don't.`);
      }
      if (chain) {
        const f = await payToFacts(chain.id, payTo.address, lookups);
        Object.assign(payTo, f);
        if (f.kind === "contract" && f.verified === false) {
          rep.add("PAYTO_UNVERIFIED_CONTRACT", "MEDIUM", "payTo is a contract whose source isn't verified on Sourcify, so nobody can easily check where the money goes next.");
        } else if (f.kind === "contract" && f.verified === null) {
          rep.add("LOOKUP_UNAVAILABLE", "INFO", "Could not check whether payTo's source is verified.");
        } else if (f.kind === "eoa-7702") {
          rep.add("PAYTO_DELEGATED", "INFO", "payTo is a wallet with an EIP-7702 delegation: its code is set by the wallet owner.");
        } else if (f.kind === "unknown") {
          rep.add("LOOKUP_UNAVAILABLE", "INFO", "Could not read payTo on-chain.");
        }
      } else if (net) {
        rep.add("CHAIN_NOT_READ", "INFO", `This service doesn't read ${net.name} on-chain, so payTo wasn't profiled there (the sanctions list was still checked).`);
      }
    }
  } else if (typeof o.payTo === "string" && caip && caip.startsWith("solana:")) {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(o.payTo)) rep.add("MALFORMED_REQUIREMENTS", "HIGH", "payTo isn't a valid Solana address.");
    rep.add("NOT_SCREENED", "INFO", "Solana recipients aren't screened: the bundled OFAC data covers EVM addresses only.");
  }

  // time window
  const timeout = Number.isFinite(Number(o.maxTimeoutSeconds)) ? Number(o.maxTimeoutSeconds) : null;
  if (o.maxTimeoutSeconds !== undefined && (timeout === null || timeout <= 0)) {
    rep.add("MALFORMED_REQUIREMENTS", "HIGH", "maxTimeoutSeconds isn't a positive number.");
  } else if (timeout !== null && timeout > 3600) {
    rep.add("LONG_VALIDITY", "INFO", `A signed payment would stay valid for up to ${timeout} seconds (over an hour).`);
  }

  return {
    version, scheme: o.scheme ?? null, network, asset, amount, pay_to: payTo, max_timeout_seconds: timeout,
    description: typeof o.description === "string" ? o.description : null,
    risk: rep.risk(), findings: rep.findings,
  };
}

async function present(fetcher, url) {
  try {
    const r = await fetcher.fetch(url, { maxBytes: 64 * 1024 });
    if (r.blocked || r.status !== 200) return { present: false, status: r.status };
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    return { present: !ct.includes("text/html") && !/^\s*<(!doctype|html)/i.test(r.text), status: r.status, text: r.text };
  } catch {
    return { present: null, status: null };
  }
}

export async function x402Check(target, lookups, fetcher) {
  const rep = new Report();
  const url = new URL(target.url);
  const origin = url.origin;

  // discovery hints first: the OpenAPI spec also says which method the route declares
  const [spec, llms] = await Promise.all([present(fetcher, origin + "/openapi.json"), present(fetcher, origin + "/llms.txt")]);
  let declared = [];
  let specListsPath = null;
  if (spec.present && spec.text) {
    try {
      const d = JSON.parse(spec.text);
      const p = d && d.paths && d.paths[url.pathname];
      specListsPath = !!p;
      if (p) declared = Object.keys(p).map((m) => m.toUpperCase()).filter((m) => ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(m));
    } catch { spec.present = false; }
  }

  let r = await fetcher.fetch(target.url, { method: "GET" });
  let method = "GET";
  if (r.status !== 402 && !r.blocked) {
    const allow = (r.headers.get("allow") || "").toUpperCase();
    const alt = declared.find((m) => m !== "GET") || (allow.includes("POST") || r.status === 405 ? "POST" : null);
    if (alt) {
      r = await fetcher.fetch(target.url, { method: alt, body: "{}", headers: { "Content-Type": "application/json" } });
      method = alt;
    }
  }

  const discovery = {
    openapi: spec.present === null ? null : !!spec.present,
    openapi_lists_path: specListsPath,
    llms_txt: llms.present === null ? null : !!llms.present,
  };
  const base = { url: target.url, final_url: r.url, http_status: r.status, method, discovery, notice: X402CHECK_NOTICE };

  if (r.blocked) {
    rep.add("REDIRECT_NOT_FOLLOWED", "MEDIUM", `The URL redirects and the redirect wasn't followed: ${r.blocked}. A paid endpoint normally answers 402 directly.`);
    return { ...base, x402: false, verdict: "not checked: redirect", risk: rep.risk(), findings: rep.findings, options: [] };
  }
  if (r.status !== 402) {
    rep.add("NOT_X402", "INFO", `The URL answered HTTP ${r.status} to ${method}, not 402 Payment Required, so it isn't asking for an x402 payment there.`);
    return { ...base, x402: false, verdict: "not an x402 payment request", risk: rep.risk(), findings: rep.findings, options: [] };
  }

  const v2 = parseV2Header(r.headers.get("payment-required"));
  const bodyJson = parseBody(r.text);
  const v1 = bodyJson && bodyJson.x402Version !== 2 ? bodyJson : null;
  const v2b = v2 || (bodyJson && bodyJson.x402Version === 2 ? bodyJson : null);
  if (!v2b && !v1) {
    rep.add("MALFORMED_REQUIREMENTS", "HIGH", "The URL answers 402 but with no readable x402 payment requirements (no PAYMENT-REQUIRED header, no x402 JSON body).");
    return { ...base, x402: true, versions: [], verdict: "do not pay", risk: rep.risk(), findings: rep.findings, options: [] };
  }

  const versions = [...(v2b ? [2] : []), ...(v1 ? [1] : [])];
  const primary = v2b ? { v: 2, d: v2b } : { v: 1, d: v1 };
  const accepts = primary.d.accepts.slice(0, MAX_OPTIONS);
  if (primary.d.accepts.length > MAX_OPTIONS) rep.add("MANY_OPTIONS", "INFO", `${primary.d.accepts.length} payment options offered; the first ${MAX_OPTIONS} were checked.`);
  if (!accepts.length) rep.add("MALFORMED_REQUIREMENTS", "HIGH", "The 402 lists no payment options.");

  // v1 and v2 should describe the same payment
  if (v2b && v1) {
    const nets = (d, v) => new Set(d.accepts.map((a) => caipOf(a && a.network)).filter(Boolean));
    const a = nets(v2b, 2);
    const b = nets(v1, 1);
    const same = a.size === b.size && [...a].every((x) => b.has(x));
    if (!same) rep.add("VERSION_MISMATCH", "MEDIUM", `The v2 header and the v1 body offer different networks (${[...a].join(", ") || "none"} vs ${[...b].join(", ") || "none"}). A well-built server keeps them identical.`);
    else {
      for (const o2 of v2b.accepts) {
        const o1 = v1.accepts.find((x) => x && caipOf(x.network) === caipOf(o2 && o2.network));
        if (o1 && o2 && String(o1.maxAmountRequired) !== String(o2.amount)) {
          rep.add("VERSION_MISMATCH", "MEDIUM", `The v2 header and the v1 body ask different amounts on ${caipOf(o2.network)} (${o2.amount} vs ${o1.maxAmountRequired}).`);
        }
      }
    }
  }

  const options = [];
  for (const opt of accepts) options.push(await analyzeOption(opt, primary.v, lookups));
  const all = [...rep.findings, ...options.flatMap((o) => o.findings)];
  const worst = all.reduce((m, f) => Math.max(m, SEV[f.severity] ?? 0), 0);
  const risk = ["LOW", "MEDIUM", "HIGH"][worst];
  const verdict = risk === "HIGH" ? "do not pay" : risk === "MEDIUM" ? "check the findings before paying" : "no red flags found";
  const resource = primary.v === 2 ? (primary.d.resource || null) : (accepts[0] && accepts[0].resource ? { url: accepts[0].resource, description: accepts[0].description ?? null } : null);
  return { ...base, x402: true, versions, resource, verdict, risk, findings: rep.findings, options };
}
