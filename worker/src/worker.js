// Cloudflare Worker: pre-sign risk check and contract profile, paid per call over x402.
// Flow for POST /check and GET|POST /contract: validate input (free) -> 402 if unpaid -> verify payment
// -> run -> settle -> return the report. Nothing is charged for bad input or an internal error.
// Request bodies are never stored or logged.
import { analyze, classify, CHAINS, BadInput } from "./core.js";
import { NetLookups } from "./net.js";
import { LookupUnavailable, parseTarget, profileAddress } from "./profile.js";
import { parseJsonLossless } from "./json.js";
import {
  BAZAAR, BAZAAR_CONTRACT, CONTRACT_DESCRIPTION, DEFAULTS, DESCRIPTION, PaymentError, b64encodeJson, checkPaymentMatches, paymentRequired,
  paymentRequiredV1Body, readPayment, settlePayment, verifyPayment,
} from "./x402.js";

const MAX_BODY = 64 * 1024;
const RATE_LIMIT = 30; // requests per IP per minute, per isolate (best effort)
const hits = new Map();

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, PAYMENT-SIGNATURE, X-PAYMENT",
  "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE",
};

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body, null, 1), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS, ...headers },
  });
}

function config(env = {}) {
  return {
    ...DEFAULTS,
    facilitatorUrl: env.FACILITATOR_URL || DEFAULTS.facilitatorUrl,
    payTo: env.PAY_TO || DEFAULTS.payTo,
    amount: env.PRICE_ATOMIC || DEFAULTS.amount,
  };
}

export function rateLimited(ip, now = Date.now()) {
  const minute = Math.floor(now / 60000);
  if (hits.size > 10000) hits.clear();
  const h = hits.get(ip);
  if (!h || h.minute !== minute) {
    hits.set(ip, { minute, count: 1 });
    return false;
  }
  h.count++;
  return h.count > RATE_LIMIT;
}

export function _resetRateLimit() {
  hits.clear();
}

function about(cfg) {
  const price = (Number(cfg.amount) / 1e6).toFixed(6).replace(/0+$/, "");
  return `joi-presign: a pre-sign risk check and contract profile for wallets and agents.

${DESCRIPTION}
${CONTRACT_DESCRIPTION}

POST /check?chain=base|ethereum|arbitrum  (JSON body)
  Body: an unsigned transaction {chainId, from, to, value, data} (type-4 with authorizationList included),
  EIP-712 typed data, an EIP-7702 authorization {chainId, address, nonce}, or a JSON-RPC request
  (eth_sendTransaction, eth_signTypedData_v4, personal_sign, eth_sign).
  Returns {kind, chain_id, risk: LOW|MEDIUM|HIGH, findings[], decoded}. Large integers are decimal strings.
GET /contract?chain=base|ethereum|arbitrum&address=0x...  (or POST /contract with JSON {chain, address})
  Returns {kind: eoa|eoa-7702|contract|none, chain_id, risk, findings[], profile}: code size, Sourcify
  verification and name, EIP-1967 / beacon / EIP-1167 proxy and its implementation, the proxy admin,
  and owner()/admin()/getOwner() with whether that's a single wallet or a contract.
Price: ${price} USDC per call (either endpoint) on Base, paid with x402 (v2 PAYMENT-SIGNATURE or v1
  X-PAYMENT header). Without payment you get HTTP 402 with the payment requirements. Bad input is
  rejected for free, and failed lookups are never charged.
GET /health, GET /openapi.json, GET /llms.txt

It's a second opinion, not a guarantee. LOW means none of the checks fired, not that a transaction
or contract is safe. A contract profile describes who can change or control a contract; it doesn't
audit its code. Limitations: no simulation (a malicious verified contract passes), no asset pricing, amount
thresholds ignore token decimals, 4byte guesses can be spoofed, public RPCs can rate-limit.

Run by Joi, an autonomous AI agent. Contact: joi-ai@agentmail.to
Request bodies are not stored.
`;
}

export function openapi(cfg, origin) {
  const price = (Number(cfg.amount) / 1e6).toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
  return {
    openapi: "3.1.0",
    info: {
      title: "joi-presign",
      version: "0.1.0",
      description: `${DESCRIPTION} ${CONTRACT_DESCRIPTION} A second opinion, not a guarantee: no simulation, no asset pricing, no code audit. Request bodies are not stored.`,
      contact: { name: "Joi (AI agent)", email: "joi-ai@agentmail.to" },
    },
    servers: [{ url: origin }],
    "x-agentcash-guidance": { llmsTxtUrl: `${origin}/llms.txt` },
    paths: {
      "/contract": {
        get: {
          summary: "Profile an address before interacting with it",
          description: "Wallet, EIP-7702-delegated wallet or contract; Sourcify verification and name; EIP-1967/beacon/EIP-1167 proxy, implementation and admin; owner()/admin()/getOwner() and whether it's a single wallet.",
          security: [],
          "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: price }, protocols: [{ x402: {} }] },
          parameters: [
            { name: "chain", in: "query", required: false, schema: { type: "string", enum: Object.keys(CHAINS), default: "base" } },
            { name: "address", in: "query", required: true, schema: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } },
          ],
          responses: {
            "200": { description: "Address profile", content: { "application/json": { example: BAZAAR_CONTRACT.info.output.example } } },
            "400": { description: "Invalid address or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
        post: {
          summary: "Profile an address before interacting with it (JSON body)",
          description: "Same as GET /contract with the parameters in a JSON body.",
          security: [],
          "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: price }, protocols: [{ x402: {} }] },
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["address"],
                  properties: {
                    chain: { type: "string", enum: Object.keys(CHAINS), default: "base" },
                    address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  },
                },
                example: BAZAAR_CONTRACT.info.input.queryParams,
              },
            },
          },
          responses: {
            "200": { description: "Address profile", content: { "application/json": { example: BAZAAR_CONTRACT.info.output.example } } },
            "400": { description: "Invalid address or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
      },
      "/check": {
        post: {
          summary: "Risk-check what a wallet is about to sign",
          description: "Decodes an unsigned transaction, EIP-712 typed data or a sign request and returns LOW/MEDIUM/HIGH with findings.",
          security: [],
          "x-payment-info": {
            price: { mode: "fixed", currency: "USD", amount: price },
            protocols: [{ x402: {} }],
          },
          parameters: [{
            name: "chain", in: "query", required: false,
            schema: { type: "string", enum: Object.keys(CHAINS), default: "base" },
          }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  description: "An unsigned transaction {chainId, from, to, value, data}, EIP-712 typed data, or a JSON-RPC request (eth_sendTransaction, eth_signTypedData_v4, personal_sign, eth_sign).",
                },
                example: BAZAAR.info.input.body,
              },
            },
          },
          responses: {
            "200": {
              description: "Risk report",
              content: { "application/json": { example: BAZAAR.info.output.example } },
            },
            "400": { description: "Input not understood (never charged)" },
            "402": { description: "Payment Required (x402)" },
          },
        },
      },
    },
  };
}

async function handleCheck(request, env, deps) {
  const cfg = config(env);
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const chainName = url.searchParams.get("chain") || "base";
  const chainId = CHAINS[chainName];
  if (!chainId) return json(400, { error: `unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}` });

  const text = await request.text();
  if (text.length > MAX_BODY) return json(413, { error: `body larger than ${MAX_BODY} bytes` });
  let payload;
  try {
    payload = parseJsonLossless(text);
    if (classify(payload)[0] === "unknown") {
      return json(400, { error: "not a transaction, typed data or sign request this service understands" });
    }
  } catch (e) {
    return json(400, { error: e instanceof BadInput ? e.message : "body is not valid JSON" });
  }

  return paidFlow(request, cfg, resourceUrl, deps, (lookups) => analyze(payload, chainId, lookups));
}

// Payment is verified before running and settled only after a successful run, so failures are never charged.
async function paidFlow(request, cfg, resourceUrl, deps, run) {
  const required = (error) => json(402, paymentRequiredV1Body(cfg, resourceUrl, error), {
    "PAYMENT-REQUIRED": b64encodeJson(paymentRequired(cfg, resourceUrl, error)),
  });

  let payment;
  try {
    payment = readPayment(request.headers);
    if (!payment) return required("PAYMENT-SIGNATURE header is required");
    checkPaymentMatches(cfg, payment);
    await verifyPayment(cfg, resourceUrl, payment, deps.fetch);
  } catch (e) {
    if (!(e instanceof PaymentError)) throw e;
    if (e.status === 402) return required(e.reason);
    return json(e.status, { error: e.reason });
  }

  let report;
  try {
    report = await run(deps.lookups ? deps.lookups() : new NetLookups({ fetchFn: deps.fetch }));
  } catch (e) {
    // Not settled, so the payer is not charged.
    if (e instanceof BadInput) return json(400, { error: e.message });
    if (e instanceof LookupUnavailable) return json(503, { error: `${e.message}; you were not charged, try again later` });
    return json(500, { error: "internal error while checking; you were not charged" });
  }

  const settlement = await settlePayment(cfg, resourceUrl, payment, deps.fetch);
  const responseHeader = payment.version === 2 ? "PAYMENT-RESPONSE" : "X-PAYMENT-RESPONSE";
  if (settlement.success !== true) {
    return json(402, { error: settlement.errorReason || "settlement failed" }, { [responseHeader]: b64encodeJson(settlement) });
  }
  return json(200, report, { [responseHeader]: b64encodeJson(settlement) });
}

async function handleContract(request, env, deps) {
  const cfg = { ...config(env), description: CONTRACT_DESCRIPTION, bazaar: BAZAAR_CONTRACT };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  let chainRaw = url.searchParams.get("chain");
  let addressRaw = url.searchParams.get("address");
  if (request.method === "POST") {
    const text = await request.text();
    if (text.length > MAX_BODY) return json(413, { error: `body larger than ${MAX_BODY} bytes` });
    let body;
    try {
      body = text.trim() === "" ? {} : parseJsonLossless(text);
    } catch {
      return json(400, { error: "body is not valid JSON" });
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return json(400, { error: "body must be a JSON object {chain, address}" });
    if (body.chain !== undefined) chainRaw = body.chain;
    if (body.address !== undefined) addressRaw = body.address;
  }
  const target = parseTarget(chainRaw, addressRaw);
  if (target.error) return json(400, { error: target.error });
  return paidFlow(request, cfg, resourceUrl, deps, (lookups) => profileAddress(target.chainId, target.address, lookups));
}

export async function handle(request, env = {}, deps = {}) {
  deps = { fetch: deps.fetch || ((...a) => fetch(...a)), lookups: deps.lookups };
  const url = new URL(request.url);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (rateLimited(ip)) return json(429, { error: "too many requests, slow down" }, { "Retry-After": "60" });
  if (request.method === "GET" && url.pathname === "/") {
    return new Response(about(config(env)), { headers: { "Content-Type": "text/plain; charset=utf-8", ...CORS } });
  }
  if (request.method === "GET" && url.pathname === "/health") return json(200, { ok: true });
  if (request.method === "GET" && url.pathname === "/openapi.json") return json(200, openapi(config(env), url.origin));
  if (request.method === "GET" && url.pathname === "/llms.txt") {
    return new Response(about(config(env)), { headers: { "Content-Type": "text/plain; charset=utf-8", ...CORS } });
  }
  if (request.method === "POST" && url.pathname === "/check") return handleCheck(request, env, deps);
  if ((request.method === "GET" || request.method === "POST") && url.pathname === "/contract") return handleContract(request, env, deps);
  return json(404, { error: "not found. See GET /" });
}

export default {
  fetch: (request, env) => handle(request, env),
};
