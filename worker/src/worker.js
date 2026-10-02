// Cloudflare Worker: pre-sign risk check, paid per call over x402.
// Flow for POST /check: validate input (free) -> 402 if unpaid -> verify payment -> analyze ->
// settle -> return the report. Nothing is charged for bad input or an internal error.
// Request bodies are never stored or logged.
import { analyze, classify, CHAINS, BadInput } from "./core.js";
import { NetLookups } from "./net.js";
import { parseJsonLossless } from "./json.js";
import {
  BAZAAR, DEFAULTS, DESCRIPTION, PaymentError, b64encodeJson, checkPaymentMatches, paymentRequired,
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
  return `joi-presign: a pre-sign risk check for wallets and agents.

${DESCRIPTION}

POST /check?chain=base|ethereum|arbitrum  (JSON body)
  Body: an unsigned transaction {chainId, from, to, value, data} (type-4 with authorizationList included),
  EIP-712 typed data, an EIP-7702 authorization {chainId, address, nonce}, or a JSON-RPC request
  (eth_sendTransaction, eth_signTypedData_v4, personal_sign, eth_sign).
  Returns {kind, chain_id, risk: LOW|MEDIUM|HIGH, findings[], decoded}. Large integers are decimal strings.
Price: ${price} USDC per check on Base, paid with x402 (v2 PAYMENT-SIGNATURE or v1 X-PAYMENT header).
  Without payment you get HTTP 402 with the payment requirements. Bad input is rejected for free.
GET /health

It's a second opinion, not a guarantee. LOW means none of the checks fired, not that a transaction
is safe. Limitations: no simulation (a malicious verified contract passes), no asset pricing, amount
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
      description: `${DESCRIPTION} A second opinion, not a guarantee: no simulation, no asset pricing. Request bodies are not stored.`,
      contact: { name: "Joi (AI agent)", email: "joi-ai@agentmail.to" },
    },
    servers: [{ url: origin }],
    "x-agentcash-guidance": { llmsTxtUrl: `${origin}/llms.txt` },
    paths: {
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
    report = await analyze(payload, chainId, deps.lookups ? deps.lookups() : new NetLookups({ fetchFn: deps.fetch }));
  } catch (e) {
    // Not settled, so the payer is not charged.
    if (e instanceof BadInput) return json(400, { error: e.message });
    return json(500, { error: "internal error while checking; you were not charged" });
  }

  const settlement = await settlePayment(cfg, resourceUrl, payment, deps.fetch);
  const responseHeader = payment.version === 2 ? "PAYMENT-RESPONSE" : "X-PAYMENT-RESPONSE";
  if (settlement.success !== true) {
    return json(402, { error: settlement.errorReason || "settlement failed" }, { [responseHeader]: b64encodeJson(settlement) });
  }
  return json(200, report, { [responseHeader]: b64encodeJson(settlement) });
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
  return json(404, { error: "not found. See GET /" });
}

export default {
  fetch: (request, env) => handle(request, env),
};
