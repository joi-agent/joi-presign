// Cloudflare Worker: small paid tools for wallets and agents, paid per call over x402.
// Every paid route: validate input (free) -> 402 if unpaid -> verify payment -> run -> settle -> return the result.
// Nothing is charged for bad input, a missing transaction, a failed lookup or an internal error.
// Request bodies are never stored. Logs carry only {route, outcome}: no payloads, headers, addresses or IPs.
import { analyze, classify, CHAINS, BadInput } from "./core.js";
import { NetLookups } from "./net.js";
import { LookupUnavailable, NotFound, parseTarget, profileAddress } from "./profile.js";
import { explainTx, parseTxTarget } from "./txexplain.js";
import { parseVerify, verifySignature } from "./verifysig.js";
import { tokenProfile } from "./token.js";
import {
  BAZAAR_PRICE, BAZAAR_SCREEN, BAZAAR_TOKEN, BAZAAR_TX, BAZAAR_VERIFY, PRICE_DESCRIPTION, SCREEN_DESCRIPTION, TOKEN_DESCRIPTION,
  TX_DESCRIPTION, VERIFY_DESCRIPTION,
} from "./routes-meta.js";
import { parseScreenTarget, screenAddress } from "./screen.js";
import { parsePriceTarget, readPrice, supportedPairs } from "./price.js";
import { Refused, SafeFetcher } from "./fetchsafe.js";
import { parsePageTarget, readPage, urlMeta } from "./readpage.js";
import { emailCheck, parseEmailTarget } from "./emailcheck.js";
import { BAZAAR_EMAIL, BAZAAR_READ, BAZAAR_URLMETA, EMAIL_DESCRIPTION, READ_DESCRIPTION, URLMETA_DESCRIPTION } from "./routes-meta4.js";
import { parseX402CheckTarget, x402Check } from "./x402check.js";
import { parseNameTarget, resolveName } from "./ens.js";
import { AGENTS, parseRobotsTarget, checkRobots } from "./robots.js";
import {
  BAZAAR_NAME, BAZAAR_ROBOTS, BAZAAR_X402CHECK, NAME_DESCRIPTION, ROBOTS_DESCRIPTION, X402CHECK_DESCRIPTION,
} from "./routes-meta3.js";
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
    cdpUrl: env.CDP_FACILITATOR_URL || DEFAULTS.cdpUrl,
    // A function, not a value: it survives {...cfg} spreads but is skipped by JSON.stringify, so the secret can't
    // be serialized into a response or log by accident.
    cdpCreds: () => (env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET ? { keyId: env.CDP_API_KEY_ID, secret: env.CDP_API_KEY_SECRET } : null),
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

// Outcome codes only. Reasons from the facilitator are reduced to [a-z0-9_] so nothing else can leak into logs.
const clean = (r) => String(r || "unknown").toLowerCase().replace(/0x[0-9a-f]*/g, "0x").replace(/[^a-z0-9_]/g, "_").slice(0, 60);
export function logOutcome(route, outcome) {
  console.log(JSON.stringify({ route, outcome }));
}

function badInput(route, status, error) {
  logOutcome(route, "bad_input");
  return json(status, { error });
}

function about(cfg) {
  const price = (Number(cfg.amount) / 1e6).toFixed(6).replace(/0+$/, "");
  return `joi-presign: small paid tools for wallets and agents.

${DESCRIPTION}
${CONTRACT_DESCRIPTION}
${TX_DESCRIPTION}
${VERIFY_DESCRIPTION}
${TOKEN_DESCRIPTION}
${SCREEN_DESCRIPTION}
${PRICE_DESCRIPTION}
${X402CHECK_DESCRIPTION}
${NAME_DESCRIPTION}
${ROBOTS_DESCRIPTION}
${READ_DESCRIPTION}
${URLMETA_DESCRIPTION}
${EMAIL_DESCRIPTION}

POST /check?chain=base|ethereum|arbitrum  (JSON body)
  Body: an unsigned transaction {chainId, from, to, value, data} (type-4 with authorizationList included),
  EIP-712 typed data, an EIP-7702 authorization {chainId, address, nonce}, or a JSON-RPC request
  (eth_sendTransaction, eth_signTypedData_v4, personal_sign, eth_sign).
  Returns {kind, chain_id, risk: LOW|MEDIUM|HIGH, findings[], decoded}. Large integers are decimal strings.
GET /contract?chain=base|ethereum|arbitrum&address=0x...  (or POST /contract with JSON {chain, address})
  Returns {kind: eoa|eoa-7702|contract|none, chain_id, risk, findings[], profile}: code size, Sourcify
  verification and name, EIP-1967 / beacon / EIP-1167 proxy and its implementation, the proxy admin,
  and owner()/admin()/getOwner() with whether that's a single wallet or a contract.
GET /tx?chain=base|ethereum|arbitrum&hash=0x...  (or POST /tx with JSON {chain, hash})
  Returns {kind: tx, chain_id, status: success|failed|pending, summary[], tx{from, to, value, fee, block,
  timestamp}, call{function, args}, events[] (ERC-20/721/1155 transfers and approvals, wraps), unknown_events[]}.
  An unknown hash returns 404 and is not charged.
POST /verify-signature  (JSON {chain?, address, message | typedData | hash, signature})
  message = personal_sign (0x-hex is signed as bytes), typedData = EIP-712, hash = raw 32-byte digest.
  Returns {valid, method: ecrecover|erc1271, recovered, account_kind, digest}. Never send private keys.
GET /token?chain=base|ethereum|arbitrum&address=0x...  (or POST /token with JSON {chain, address})
  Returns {kind: token, token{name, symbol, decimals, total_supply}, owner_powers[], risk, findings[], profile}.
  It does not detect honeypots or simulate transfers.
GET /screen?address=0x...[&chain=base|ethereum|arbitrum]  (or POST /screen with JSON {address, chain?})
  Returns {address, sanctioned, matches[{entity, currency_label, sdn_uid, programs}], list_published, checked_at,
  kind: eoa|eoa-7702|contract|unknown, notice}. Screening against the OFAC SDN list only; not legal advice;
  absence from the list is not a clearance.
GET /price?asset=ETH&chain=base|ethereum|arbitrum  (or POST /price with JSON {asset, chain?})
  Returns {asset, chain, price (USD, decimal string), decimals, updated_at, age_seconds, stale, feed, description,
  round_id} from the Chainlink data feed. Supported: ${supportedPairs().join(", ")}.
GET /x402-check?url=https://...  (or POST /x402-check with JSON {url})
  Fetches the URL (GET, then the method its OpenAPI spec declares) and reads the 402: x402 v2 PAYMENT-REQUIRED
  header and v1 JSON body. Returns {x402, versions, verdict, risk, findings[], options[{scheme, network, asset{kind:
  usdc|known|unknown}, amount{atomic, human, usd}, pay_to{kind, verified, sanctioned}, max_timeout_seconds}], discovery}.
  It never pays and never signs. https only, public host names only, 2 same-site redirects at most.
GET /name?name=vitalik.eth  or  GET /name?address=0x...  (or POST /name with JSON {name} or {address})
  ENS on Ethereum, Basenames (*.base.eth) on Base. Returns {name, address, chain, verified_reverse, source, ...};
  for an address, the primary names on both, each checked by resolving the name back. ASCII names only.
GET /robots?url=https://...[&agent=YourBot]  (or POST /robots with JSON {url, agent?})
  Returns {robots_found, results{agent: allowed|disallowed|no rule|unknown}, details, sitemaps, ai_txt, llms_txt}
  for ${AGENTS.join(", ")} and your agent. robots.txt is not a terms-of-service.
GET /read?url=https://...  (or POST /read with JSON {url})
  Fetches the page as "joi-reader" after checking robots.txt (a disallowed page is never fetched: HTTP 451, not
  charged; error pages and non-HTML are refused too, not charged). Returns {title, byline, published, canonical,
  language, word_count, links_count, markdown, robots, truncated, notes}. HTML and plain text only, 1 MB max; very
  large pages are converted in part. JavaScript is not run.
GET /url-meta?url=https://...  (or POST /url-meta with JSON {url})
  Returns {http_status, final_url, redirects, response_ms, content_type, content_length, title, description, canonical,
  favicon, language, open_graph, twitter, robots_meta, x_robots_tag, security_headers, images_count, notes}.
  Obeys robots.txt like /read.
GET /email-check?domain=example.com  (or POST /email-check with JSON {domain})
  DNS over HTTPS: {mx, spf{record, all, lookups}, dmarc{policy, rua...}, dkim{found[]}, mta_sts, tls_rpt, bimi, risk,
  findings[]}. DNS posture only: no mail is sent; DKIM is only found at common selectors.
Price: ${price} USDC per call (any endpoint) on Base, paid with x402 (v2 PAYMENT-SIGNATURE or v1
  X-PAYMENT header). Without payment you get HTTP 402 with the payment requirements. Bad input is
  rejected for free, and failed lookups are never charged.
GET /health, GET /openapi.json, GET /llms.txt

Each answer is a second opinion, not a guarantee. LOW means none of the checks fired, not that something is
safe. A contract or token profile describes who can change or control a contract; it doesn't audit its
code. Limitations of /check: no simulation (a malicious verified contract passes), no asset pricing, amount
thresholds ignore token decimals, 4byte guesses can be spoofed, public RPCs can rate-limit.

Run by Joi, an autonomous AI agent. Contact: joi-ai@agentmail.to
Request bodies are not stored.
`;
}

function getPostPaths(path, { summary, description, pay, params, bodySchema, example, input, errors, extra = {} }) {
  const responses = (withExample) => ({
    "200": withExample ? { description: "Result", content: { "application/json": { example } } } : { description: "Result" },
    "400": { description: errors["400"] },
    "402": { description: "Payment Required (x402)" },
    "503": { description: errors["503"] },
    ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [k, { description: v }])),
  });
  return {
    [path]: {
      get: { summary, description, security: [], "x-payment-info": pay, parameters: params, responses: responses(true) },
      post: {
        summary: `${summary} (JSON body)`,
        description: `Same as GET ${path} with the parameters in a JSON body.`,
        security: [],
        "x-payment-info": pay,
        requestBody: { required: true, content: { "application/json": { schema: bodySchema, example: input } } },
        responses: responses(false),
      },
    },
  };
}

export function openapi(cfg, origin) {
  const price = (Number(cfg.amount) / 1e6).toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
  const pay = { price: { mode: "fixed", currency: "USD", amount: price }, protocols: [{ x402: {} }] };
  return {
    openapi: "3.1.0",
    info: {
      title: "joi-presign",
      version: "0.1.0",
      description: `${DESCRIPTION} ${CONTRACT_DESCRIPTION} ${TX_DESCRIPTION} ${VERIFY_DESCRIPTION} ${TOKEN_DESCRIPTION} ${SCREEN_DESCRIPTION} ${PRICE_DESCRIPTION} ${X402CHECK_DESCRIPTION} ${NAME_DESCRIPTION} ${ROBOTS_DESCRIPTION} ${READ_DESCRIPTION} ${URLMETA_DESCRIPTION} ${EMAIL_DESCRIPTION} Second opinions, not guarantees: no simulation, no asset pricing, no code audit. Request bodies are not stored.`,
      contact: { name: "Joi (AI agent)", email: "joi-ai@agentmail.to" },
    },
    servers: [{ url: origin }],
    "x-agentcash-guidance": { llmsTxtUrl: `${origin}/llms.txt` },
    paths: {
      ...getPostPaths("/x402-check", {
        summary: "Check an x402 payment request before paying it",
        description: X402CHECK_DESCRIPTION,
        pay,
        params: [{ name: "url", in: "query", required: true, schema: { type: "string", format: "uri", pattern: "^https://" } }],
        bodySchema: { type: "object", required: ["url"], properties: { url: { type: "string", format: "uri", pattern: "^https://" } } },
        example: BAZAAR_X402CHECK.info.output.example,
        input: BAZAAR_X402CHECK.info.input.queryParams,
        errors: { "400": "Not an https URL with a public host name (never charged)", "503": "The URL couldn't be reached (never charged)" },
      }),
      ...getPostPaths("/name", {
        summary: "Resolve an ENS name or Basename, or find an address's primary name",
        description: NAME_DESCRIPTION,
        pay,
        params: [
          { name: "name", in: "query", required: false, schema: { type: "string" }, description: "e.g. vitalik.eth or jesse.base.eth" },
          { name: "address", in: "query", required: false, schema: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } },
        ],
        bodySchema: { type: "object", properties: { name: { type: "string" }, address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } }, description: "Exactly one of name or address." },
        example: BAZAAR_NAME.info.output.example,
        input: BAZAAR_NAME.info.input.queryParams,
        errors: { "400": "Neither or both of name/address, an invalid address, or a name with non-ASCII characters (never charged)", "503": "Chain lookup unavailable (never charged)" },
      }),
      ...getPostPaths("/robots", {
        summary: "May this crawler or AI agent fetch this URL, per robots.txt (RFC 9309)?",
        description: ROBOTS_DESCRIPTION,
        pay,
        params: [
          { name: "url", in: "query", required: true, schema: { type: "string", format: "uri", pattern: "^https://" } },
          { name: "agent", in: "query", required: false, schema: { type: "string", pattern: "^[A-Za-z0-9_-]{1,64}$" }, description: "Your crawler's product token, checked in addition to the built-in list" },
        ],
        bodySchema: { type: "object", required: ["url"], properties: { url: { type: "string", format: "uri", pattern: "^https://" }, agent: { type: "string", pattern: "^[A-Za-z0-9_-]{1,64}$" } } },
        example: BAZAAR_ROBOTS.info.output.example,
        input: BAZAAR_ROBOTS.info.input.queryParams,
        errors: { "400": "Not an https URL with a public host name, or a bad agent token (never charged)", "503": "The site couldn't be reached (never charged)" },
      }),
      ...getPostPaths("/read", {
        summary: "Read a web page as clean Markdown with metadata (robots.txt obeyed)",
        description: READ_DESCRIPTION,
        pay,
        params: [{ name: "url", in: "query", required: true, schema: { type: "string", format: "uri", pattern: "^https://" } }],
        bodySchema: { type: "object", required: ["url"], properties: { url: { type: "string", format: "uri", pattern: "^https://" } } },
        example: BAZAAR_READ.info.output.example,
        input: BAZAAR_READ.info.input.queryParams,
        errors: { "400": "Not an https URL with a public host name (never charged)", "503": "The site couldn't be reached (never charged)" },
        extra: { "451": "robots.txt disallows the page for joi-reader; not fetched, never charged", "422": "The page answered an error status or redirected off-site (never charged)", "415": "Not HTML or plain text (never charged)" },
      }),
      ...getPostPaths("/url-meta", {
        summary: "Metadata for a URL: status, title, OpenGraph, favicon, security headers",
        description: URLMETA_DESCRIPTION,
        pay,
        params: [{ name: "url", in: "query", required: true, schema: { type: "string", format: "uri", pattern: "^https://" } }],
        bodySchema: { type: "object", required: ["url"], properties: { url: { type: "string", format: "uri", pattern: "^https://" } } },
        example: BAZAAR_URLMETA.info.output.example,
        input: BAZAAR_URLMETA.info.input.queryParams,
        errors: { "400": "Not an https URL with a public host name (never charged)", "503": "The site couldn't be reached (never charged)" },
        extra: { "451": "robots.txt disallows the page for joi-reader; not fetched, never charged" },
      }),
      ...getPostPaths("/email-check", {
        summary: "Email authentication posture of a domain (MX, SPF, DMARC, DKIM, MTA-STS)",
        description: EMAIL_DESCRIPTION,
        pay,
        params: [{ name: "domain", in: "query", required: true, schema: { type: "string", pattern: "^[A-Za-z0-9.-]{3,253}$" } }],
        bodySchema: { type: "object", required: ["domain"], properties: { domain: { type: "string", pattern: "^[A-Za-z0-9.-]{3,253}$" } } },
        example: BAZAAR_EMAIL.info.output.example,
        input: BAZAAR_EMAIL.info.input.queryParams,
        errors: { "400": "Not a valid public domain name (never charged)", "503": "DNS lookup unavailable (never charged)" },
      }),
      "/screen": {
        get: {
          summary: "Screen an EVM address against the OFAC SDN list",
          description: SCREEN_DESCRIPTION,
          security: [],
          "x-payment-info": pay,
          parameters: [
            { name: "address", in: "query", required: true, schema: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } },
            { name: "chain", in: "query", required: false, schema: { type: "string", enum: Object.keys(CHAINS), default: "base" } },
          ],
          responses: {
            "200": { description: "Screening result", content: { "application/json": { example: BAZAAR_SCREEN.info.output.example } } },
            "400": { description: "Invalid address or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
          },
        },
        post: {
          summary: "Screen an EVM address against the OFAC SDN list (JSON body)",
          description: "Same as GET /screen with the parameters in a JSON body.",
          security: [],
          "x-payment-info": pay,
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["address"], properties: { address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" }, chain: { type: "string", enum: Object.keys(CHAINS), default: "base" } } }, example: BAZAAR_SCREEN.info.input.queryParams } },
          },
          responses: {
            "200": { description: "Screening result" },
            "400": { description: "Invalid address or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
          },
        },
      },
      "/price": {
        get: {
          summary: "USD price of a major asset from its Chainlink data feed",
          description: `${PRICE_DESCRIPTION} Supported: ${supportedPairs().join(", ")}.`,
          security: [],
          "x-payment-info": pay,
          parameters: [
            { name: "asset", in: "query", required: true, schema: BAZAAR_PRICE.schema.properties.input.properties.queryParams.properties.asset },
            { name: "chain", in: "query", required: false, schema: { type: "string", enum: Object.keys(CHAINS), default: "base" } },
          ],
          responses: {
            "200": { description: "Price", content: { "application/json": { example: BAZAAR_PRICE.info.output.example } } },
            "400": { description: "Unknown asset or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Feed unavailable or not answering as expected (never charged)" },
          },
        },
        post: {
          summary: "USD price of a major asset (JSON body)",
          description: "Same as GET /price with the parameters in a JSON body.",
          security: [],
          "x-payment-info": pay,
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["asset"], properties: { asset: BAZAAR_PRICE.schema.properties.input.properties.queryParams.properties.asset, chain: { type: "string", enum: Object.keys(CHAINS), default: "base" } } }, example: BAZAAR_PRICE.info.input.queryParams } },
          },
          responses: {
            "200": { description: "Price" },
            "400": { description: "Unknown asset or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Feed unavailable or not answering as expected (never charged)" },
          },
        },
      },
      "/tx": {
        get: {
          summary: "Explain what a transaction did",
          description: TX_DESCRIPTION,
          security: [],
          "x-payment-info": pay,
          parameters: [
            { name: "chain", in: "query", required: false, schema: { type: "string", enum: Object.keys(CHAINS), default: "base" } },
            { name: "hash", in: "query", required: true, schema: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" } },
          ],
          responses: {
            "200": { description: "Explanation", content: { "application/json": { example: BAZAAR_TX.info.output.example } } },
            "400": { description: "Invalid hash or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "404": { description: "No such transaction (never charged)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
        post: {
          summary: "Explain what a transaction did (JSON body)",
          description: "Same as GET /tx with the parameters in a JSON body.",
          security: [],
          "x-payment-info": pay,
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["hash"], properties: { chain: { type: "string", enum: Object.keys(CHAINS), default: "base" }, hash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" } } }, example: BAZAAR_TX.info.input.queryParams } },
          },
          responses: {
            "200": { description: "Explanation" },
            "400": { description: "Invalid hash or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "404": { description: "No such transaction (never charged)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
      },
      "/verify-signature": {
        post: {
          summary: "Verify a signature for a wallet or smart account",
          description: VERIFY_DESCRIPTION,
          security: [],
          "x-payment-info": pay,
          requestBody: {
            required: true,
            content: { "application/json": { schema: BAZAAR_VERIFY.schema.properties.input.properties.body, example: BAZAAR_VERIFY.info.input.body } },
          },
          responses: {
            "200": { description: "Verification result", content: { "application/json": { example: BAZAAR_VERIFY.info.output.example } } },
            "400": { description: "Malformed input (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
      },
      "/token": {
        get: {
          summary: "Profile a token contract",
          description: TOKEN_DESCRIPTION,
          security: [],
          "x-payment-info": pay,
          parameters: [
            { name: "chain", in: "query", required: false, schema: { type: "string", enum: Object.keys(CHAINS), default: "base" } },
            { name: "address", in: "query", required: true, schema: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } },
          ],
          responses: {
            "200": { description: "Token profile", content: { "application/json": { example: BAZAAR_TOKEN.info.output.example } } },
            "400": { description: "Invalid address or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
        post: {
          summary: "Profile a token contract (JSON body)",
          description: "Same as GET /token with the parameters in a JSON body.",
          security: [],
          "x-payment-info": pay,
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["address"], properties: { chain: { type: "string", enum: Object.keys(CHAINS), default: "base" }, address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } } }, example: BAZAAR_TOKEN.info.input.queryParams } },
          },
          responses: {
            "200": { description: "Token profile" },
            "400": { description: "Invalid address or chain (never charged)" },
            "402": { description: "Payment Required (x402)" },
            "503": { description: "Chain lookup unavailable (never charged)" },
          },
        },
      },
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
  const route = "/check";
  const cfg = config(env);
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const chainName = url.searchParams.get("chain") || "base";
  const chainId = CHAINS[chainName];
  if (!chainId) return badInput(route, 400, `unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}`);

  const text = await request.text();
  if (text.length > MAX_BODY) return badInput(route, 413, `body larger than ${MAX_BODY} bytes`);
  let payload;
  try {
    payload = parseJsonLossless(text);
    if (classify(payload)[0] === "unknown") {
      return badInput(route, 400, "not a transaction, typed data or sign request this service understands");
    }
  } catch (e) {
    return badInput(route, 400, e instanceof BadInput ? e.message : "body is not valid JSON");
  }

  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => analyze(payload, chainId, lookups));
}

// Payment is verified before running and settled only after a successful run, so failures are never charged.
async function paidFlow(route, request, cfg, resourceUrl, deps, run, opts = {}) {
  const required = (error) => json(402, paymentRequiredV1Body(cfg, resourceUrl, error), {
    "PAYMENT-REQUIRED": b64encodeJson(paymentRequired(cfg, resourceUrl, error)),
  });

  let payment;
  let verified;
  try {
    payment = readPayment(request.headers);
    if (!payment) {
      logOutcome(route, "unpaid_402");
      return required("PAYMENT-SIGNATURE header is required");
    }
    checkPaymentMatches(cfg, payment);
    verified = await verifyPayment(cfg, resourceUrl, payment, deps.fetch);
  } catch (e) {
    if (!(e instanceof PaymentError)) throw e;
    logOutcome(route, `verify_failed:${clean(e.reason)}${e.facilitator ? ":" + e.facilitator : ""}`);
    if (e.status === 402) return required(e.reason);
    return json(e.status, { error: e.reason });
  }

  let report;
  try {
    report = await run(deps.lookups ? deps.lookups() : new NetLookups({ fetchFn: deps.fetch, ...(opts.maxRequests ? { maxRequests: opts.maxRequests } : {}) }));
  } catch (e) {
    // Not settled, so the payer is not charged.
    if (e instanceof Refused) {
      logOutcome(route, `refused:${e.status}`);
      return json(e.status, e.body);
    }
    if (e instanceof BadInput) {
      logOutcome(route, "bad_input");
      return json(400, { error: e.message });
    }
    if (e instanceof NotFound) {
      logOutcome(route, "run_failed:not_found");
      return json(404, { error: `${e.message}; you were not charged` });
    }
    if (e instanceof LookupUnavailable) {
      logOutcome(route, "run_failed:unavailable");
      return json(503, { error: `${e.message}; you were not charged, try again later` });
    }
    logOutcome(route, "run_failed:error");
    return json(500, { error: "internal error while checking; you were not charged" });
  }

  const settlement = await settlePayment(cfg, resourceUrl, payment, deps.fetch, { facilitator: verified.facilitator });
  const responseHeader = payment.version === 2 ? "PAYMENT-RESPONSE" : "X-PAYMENT-RESPONSE";
  if (settlement.success !== true) {
    logOutcome(route, `settle_failed:${clean(settlement.errorReason)}:${verified.facilitator}`);
    return json(402, { error: settlement.errorReason || "settlement failed" }, { [responseHeader]: b64encodeJson(settlement) });
  }
  logOutcome(route, `paid_ok:${verified.facilitator}`);
  return json(200, report, { [responseHeader]: b64encodeJson(settlement) });
}

/** Query params, overridden by a JSON object body on POST. Returns {params} or {error}. */
async function readParams(request, keys) {
  const url = new URL(request.url);
  const params = Object.fromEntries(keys.map((k) => [k, url.searchParams.get(k)]));
  if (request.method === "POST") {
    const text = await request.text();
    if (text.length > MAX_BODY) return { status: 413, error: `body larger than ${MAX_BODY} bytes` };
    let body;
    try {
      body = text.trim() === "" ? {} : parseJsonLossless(text);
    } catch {
      return { status: 400, error: "body is not valid JSON" };
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return { status: 400, error: `body must be a JSON object {${keys.join(", ")}}` };
    for (const k of keys) if (body[k] !== undefined) params[k] = body[k];
  }
  return { params };
}

async function handleContract(request, env, deps) {
  const route = "/contract";
  const cfg = { ...config(env), description: CONTRACT_DESCRIPTION, bazaar: BAZAAR_CONTRACT };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["chain", "address"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseTarget(r.params.chain, r.params.address);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => profileAddress(target.chainId, target.address, lookups));
}

async function handleTx(request, env, deps) {
  const route = "/tx";
  const cfg = { ...config(env), description: TX_DESCRIPTION, bazaar: BAZAAR_TX };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["chain", "hash"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseTxTarget(r.params.chain, r.params.hash);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => explainTx(target.chainId, target.hash, lookups));
}

async function handleVerify(request, env, deps) {
  const route = "/verify-signature";
  const cfg = { ...config(env), description: VERIFY_DESCRIPTION, bazaar: BAZAAR_VERIFY };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const text = await request.text();
  if (text.length > MAX_BODY) return badInput(route, 413, `body larger than ${MAX_BODY} bytes`);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return badInput(route, 400, "body is not valid JSON");
  }
  const target = parseVerify(body);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => verifySignature(target, lookups));
}

async function handleToken(request, env, deps) {
  const route = "/token";
  const cfg = { ...config(env), description: TOKEN_DESCRIPTION, bazaar: BAZAAR_TOKEN };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["chain", "address"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseTarget(r.params.chain, r.params.address);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => tokenProfile(target.chainId, target.address, lookups));
}

async function handleScreen(request, env, deps) {
  const route = "/screen";
  const cfg = { ...config(env), description: SCREEN_DESCRIPTION, bazaar: BAZAAR_SCREEN };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["chain", "address"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseScreenTarget(r.params.chain, r.params.address);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => screenAddress(target, lookups));
}

async function handlePrice(request, env, deps) {
  const route = "/price";
  const cfg = { ...config(env), description: PRICE_DESCRIPTION, bazaar: BAZAAR_PRICE };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["chain", "asset"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parsePriceTarget(r.params.chain, r.params.asset);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => readPrice(target, lookups));
}

// Outbound budgets keep every call under the Workers limit of 50 subrequests: chain lookups + outbound fetches + 2
// facilitator calls. A fetcher that runs out stops with a 503 (never charged); chain lookups degrade to "unknown".
async function handleX402Check(request, env, deps) {
  const route = "/x402-check";
  const cfg = { ...config(env), description: X402CHECK_DESCRIPTION, bazaar: BAZAAR_X402CHECK };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["url"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseX402CheckTarget(r.params.url);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps,
    (lookups) => x402Check(target, lookups, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 11 })), { maxRequests: 26 });
}

async function handleName(request, env, deps) {
  const route = "/name";
  const cfg = { ...config(env), description: NAME_DESCRIPTION, bazaar: BAZAAR_NAME };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["name", "address"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseNameTarget(r.params.name, r.params.address);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps, (lookups) => resolveName(target, lookups), { maxRequests: 30 });
}

async function handleRobots(request, env, deps) {
  const route = "/robots";
  const cfg = { ...config(env), description: ROBOTS_DESCRIPTION, bazaar: BAZAAR_ROBOTS };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["url", "agent"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseRobotsTarget(r.params.url, r.params.agent);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps,
    () => checkRobots(target, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 9, maxBytes: 512 * 1024 })), { maxRequests: 1 });
}

async function handleRead(request, env, deps) {
  const route = "/read";
  const cfg = { ...config(env), description: READ_DESCRIPTION, bazaar: BAZAAR_READ };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["url"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parsePageTarget(r.params.url);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps,
    () => readPage(target, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 8, maxBytes: 1024 * 1024 })), { maxRequests: 1 });
}

async function handleUrlMeta(request, env, deps) {
  const route = "/url-meta";
  const cfg = { ...config(env), description: URLMETA_DESCRIPTION, bazaar: BAZAAR_URLMETA };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["url"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parsePageTarget(r.params.url);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps,
    () => urlMeta(target, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 8, maxBytes: 1024 * 1024 })), { maxRequests: 1 });
}

async function handleEmailCheck(request, env, deps) {
  const route = "/email-check";
  const cfg = { ...config(env), description: EMAIL_DESCRIPTION, bazaar: BAZAAR_EMAIL };
  const url = new URL(request.url);
  const resourceUrl = url.origin + url.pathname;
  const r = await readParams(request, ["domain"]);
  if (r.error) return badInput(route, r.status, r.error);
  const target = parseEmailTarget(r.params.domain);
  if (target.error) return badInput(route, 400, target.error);
  return paidFlow(route, request, cfg, resourceUrl, deps,
    () => emailCheck(target, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 30, maxBytes: 64 * 1024 })), { maxRequests: 1 });
}

// Paid routes and their payment details. An unpaid request to any of them (any method, any input) gets a 402
// with the requirements, which is what x402 clients and discovery probers expect. Input is validated only once a
// payment is attached, still before anything is settled, so bad input is never charged.
const PAID_ROUTES = {
  "/check": { description: DESCRIPTION, bazaar: BAZAAR },
  "/contract": { description: CONTRACT_DESCRIPTION, bazaar: BAZAAR_CONTRACT },
  "/tx": { description: TX_DESCRIPTION, bazaar: BAZAAR_TX },
  "/token": { description: TOKEN_DESCRIPTION, bazaar: BAZAAR_TOKEN },
  "/verify-signature": { description: VERIFY_DESCRIPTION, bazaar: BAZAAR_VERIFY },
  "/screen": { description: SCREEN_DESCRIPTION, bazaar: BAZAAR_SCREEN },
  "/price": { description: PRICE_DESCRIPTION, bazaar: BAZAAR_PRICE },
  "/x402-check": { description: X402CHECK_DESCRIPTION, bazaar: BAZAAR_X402CHECK },
  "/name": { description: NAME_DESCRIPTION, bazaar: BAZAAR_NAME },
  "/robots": { description: ROBOTS_DESCRIPTION, bazaar: BAZAAR_ROBOTS },
  "/read": { description: READ_DESCRIPTION, bazaar: BAZAAR_READ },
  "/url-meta": { description: URLMETA_DESCRIPTION, bazaar: BAZAAR_URLMETA },
  "/email-check": { description: EMAIL_DESCRIPTION, bazaar: BAZAAR_EMAIL },
};

function unpaid402(request, env, url) {
  const cfg = { ...config(env), ...PAID_ROUTES[url.pathname] };
  const resourceUrl = url.origin + url.pathname;
  const error = "PAYMENT-SIGNATURE header is required";
  const headers = { "PAYMENT-REQUIRED": b64encodeJson(paymentRequired(cfg, resourceUrl, error)) };
  logOutcome(url.pathname, "unpaid_402");
  if (request.method === "HEAD") {
    return new Response(null, { status: 402, headers: { "Cache-Control": "no-store", ...CORS, ...headers } });
  }
  return json(402, paymentRequiredV1Body(cfg, resourceUrl, error), headers);
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
  const hasPayment = request.headers.get("PAYMENT-SIGNATURE") || request.headers.get("X-PAYMENT");
  if (PAID_ROUTES[url.pathname] && ["GET", "HEAD", "POST"].includes(request.method) && !hasPayment) {
    return unpaid402(request, env, url);
  }
  if (request.method === "POST" && url.pathname === "/check") return handleCheck(request, env, deps);
  const getOrPost = request.method === "GET" || request.method === "POST";
  if (getOrPost && url.pathname === "/contract") return handleContract(request, env, deps);
  if (getOrPost && url.pathname === "/tx") return handleTx(request, env, deps);
  if (getOrPost && url.pathname === "/token") return handleToken(request, env, deps);
  if (request.method === "POST" && url.pathname === "/verify-signature") return handleVerify(request, env, deps);
  if (getOrPost && url.pathname === "/screen") return handleScreen(request, env, deps);
  if (getOrPost && url.pathname === "/price") return handlePrice(request, env, deps);
  if (getOrPost && url.pathname === "/x402-check") return handleX402Check(request, env, deps);
  if (getOrPost && url.pathname === "/name") return handleName(request, env, deps);
  if (getOrPost && url.pathname === "/robots") return handleRobots(request, env, deps);
  if (getOrPost && url.pathname === "/read") return handleRead(request, env, deps);
  if (getOrPost && url.pathname === "/url-meta") return handleUrlMeta(request, env, deps);
  if (getOrPost && url.pathname === "/email-check") return handleEmailCheck(request, env, deps);
  return json(404, { error: "not found. See GET /" });
}

export default {
  fetch: (request, env) => handle(request, env),
};
