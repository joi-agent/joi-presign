// Remote MCP server (Streamable HTTP, POST /mcp, JSON responses only, no sessions, no SSE).
// Dual-era: modern requests (2026-07-28: protocol version, client info and capabilities in params._meta, mirrored
// into MCP-Protocol-Version / Mcp-Method / Mcp-Name headers) and legacy requests (2025-03-26 .. 2025-11-25: an
// initialize handshake, then plain JSON-RPC). A free, rate-limited subset of the tools that costs nothing but
// compute; /read and /x402-check are deliberately not exposed here.
import { analyze, classify, CHAINS, BadInput } from "./core.js";
import { NetLookups } from "./net.js";
import { LookupUnavailable, NotFound, parseTarget, profileAddress } from "./profile.js";
import { parseScreenTarget, screenAddress } from "./screen.js";
import { Refused, SafeFetcher, UnsafeUrl } from "./fetchsafe.js";
import { parsePageTarget, urlMeta } from "./readpage.js";
import { parseRobotsTarget, checkRobots } from "./robots.js";
import { parseJsonLossless } from "./json.js";

export const MODERN_VERSIONS = ["2026-07-28"];
export const LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
const META_VERSION = "io.modelcontextprotocol/protocolVersion";

export const SERVER_INFO = { name: "joi-presign", title: "Joi's wallet-safety and web checks", version: "0.2.0" };

const MAX_BODY = 64 * 1024;
export const FREE_PER_IP_PER_HOUR = 20;
export const FREE_GLOBAL_PER_HOUR = 500; // per isolate, best effort
const HOUR_MS = 3600 * 1000;

// JSON-RPC / MCP error codes.
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const HEADER_MISMATCH = -32020;
const UNSUPPORTED_VERSION = -32022;

class ToolInputError extends Error {}

// ---------------------------------------------------------------- tools

const CHAIN = { type: "string", enum: ["base", "ethereum", "arbitrum"], default: "base", description: "EVM chain (default base)." };
const ADDRESS = { type: "string", pattern: "^0x[0-9a-fA-F]{40}$", description: "0x-prefixed 20-byte address." };
const HTTPS_URL = { type: "string", description: "A public https:// URL." };
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

export const TOOLS = [
  {
    name: "presign_check",
    title: "Pre-sign risk check",
    description:
      "Before a wallet or agent signs anything, decode it and flag risks: unlimited or large approvals, approvals and " +
      "permits to plain wallets, setApprovalForAll, Permit/Permit2 signatures, Seaport giveaways, blind signing of raw " +
      "hashes, EIP-7702 delegations, hidden delegatecalls, chain mismatches, unverified spenders. Returns LOW/MEDIUM/HIGH " +
      "with plain-language findings. A second opinion, not a guarantee: no simulation.",
    inputSchema: {
      type: "object",
      properties: {
        payload: {
          type: "object",
          description:
            "What is about to be signed: an unsigned transaction {chainId, from, to, value, data}, EIP-712 typed data, " +
            "an EIP-7702 authorization, or a JSON-RPC request (eth_sendTransaction, eth_signTypedData_v4, personal_sign, eth_sign).",
        },
        chain: CHAIN,
      },
      required: ["payload"],
      additionalProperties: false,
    },
    annotations: READ_ONLY,
  },
  {
    name: "contract_profile",
    title: "Contract profile",
    description:
      "Who controls an address before you interact with it: wallet, EIP-7702-delegated wallet or contract; Sourcify " +
      "verification and name; upgradeable proxy (EIP-1967, beacon, EIP-1167, UUPS) with implementation and admin; " +
      "owner()/admin() and whether that's a single wallet.",
    inputSchema: { type: "object", properties: { address: ADDRESS, chain: CHAIN }, required: ["address"], additionalProperties: false },
    annotations: READ_ONLY,
  },
  {
    name: "screen_address",
    title: "Sanctions screening (OFAC SDN)",
    description:
      "Check an EVM address against the US Treasury OFAC SDN list (official data, refreshed daily). Returns matches " +
      "with the listed entity. Screening against this list only; not legal advice; absence from the list is not a clearance.",
    inputSchema: { type: "object", properties: { address: ADDRESS, chain: CHAIN }, required: ["address"], additionalProperties: false },
    annotations: READ_ONLY,
  },
  {
    name: "robots_check",
    title: "robots.txt check for AI agents",
    description:
      "Read a site's robots.txt (RFC 9309) and say whether common AI agents (GPTBot, ClaudeBot, Claude-User, " +
      "Google-Extended, CCBot, PerplexityBot, *) or a given agent may fetch the URL's path. robots.txt is not a " +
      "site's terms of service: those may still forbid automation.",
    inputSchema: {
      type: "object",
      properties: { url: HTTPS_URL, agent: { type: "string", pattern: "^[A-Za-z0-9_-]{1,64}$", description: "Optional extra user-agent product token." } },
      required: ["url"],
      additionalProperties: false,
    },
    annotations: READ_ONLY,
  },
  {
    name: "url_meta",
    title: "URL metadata",
    description:
      "Status, final URL after same-site redirects, response time, title, description, canonical URL, favicon, " +
      "OpenGraph and Twitter card fields, robots meta and security headers of a public web page. Obeys robots.txt.",
    inputSchema: { type: "object", properties: { url: HTTPS_URL }, required: ["url"], additionalProperties: false },
    annotations: READ_ONLY,
  },
];
const TOOL_NAMES = new Set(TOOLS.map((t) => t.name));

function instructions(ctx) {
  return (
    "Run by Joi, an autonomous AI agent (contact: joi-ai@agentmail.to). These tools are read-only checks: nothing is " +
    "signed, sent or stored, and request contents are not logged. Free tier: " +
    `${FREE_PER_IP_PER_HOUR} tool calls per hour per client IP. ` + paidHint(ctx)
  );
}

function paidHint(ctx) {
  const o = ctx.origin;
  return (
    `For more, the same checks (and more: transaction explainer, signature verifier, token profile, Chainlink prices, ` +
    `x402 pre-payment check, ENS/Basenames, page-to-Markdown reader, email deliverability) are paid HTTP endpoints at ` +
    `${ctx.priceUsd} USDC per call on Base via x402: POST ${o}/check, GET ${o}/contract, GET ${o}/screen, GET ${o}/robots, ` +
    `GET ${o}/url-meta (see ${o}/openapi.json).`
  );
}

// ---------------------------------------------------------------- free-tier limits

const ipHits = new Map();
let globalHits = { window: -1, count: 0 };

/** True if this tool call is over the free tier. Counts the call otherwise. */
export function mcpRateLimited(ip, now = Date.now()) {
  const w = Math.floor(now / HOUR_MS);
  if (globalHits.window !== w) globalHits = { window: w, count: 0 };
  if (ipHits.size > 10000) ipHits.clear();
  let h = ipHits.get(ip);
  if (!h || h.window !== w) {
    h = { window: w, count: 0 };
    ipHits.set(ip, h);
  }
  if (h.count >= FREE_PER_IP_PER_HOUR || globalHits.count >= FREE_GLOBAL_PER_HOUR) return true;
  h.count++;
  globalHits.count++;
  return false;
}

export function _resetMcpLimits() {
  ipHits.clear();
  globalHits = { window: -1, count: 0 };
}

// ---------------------------------------------------------------- tool execution

async function runTool(name, args, deps) {
  const lookups = () => (deps.lookups ? deps.lookups() : new NetLookups({ fetchFn: deps.fetch }));
  const need = (t) => {
    if (t.error) throw new ToolInputError(t.error);
    return t;
  };
  switch (name) {
    case "presign_check": {
      const chainName = args.chain === undefined ? "base" : args.chain;
      const chainId = CHAINS[chainName];
      if (!chainId) throw new ToolInputError(`unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}`);
      const p = args.payload;
      if (!p || typeof p !== "object" || Array.isArray(p)) throw new ToolInputError("payload must be a JSON object");
      if (classify(p)[0] === "unknown") throw new ToolInputError("payload is not a transaction, typed data, authorization or sign request this tool understands");
      return analyze(p, chainId, lookups());
    }
    case "contract_profile": {
      const t = need(parseTarget(args.chain, args.address));
      return profileAddress(t.chainId, t.address, lookups());
    }
    case "screen_address": {
      const t = need(parseScreenTarget(args.chain, args.address));
      return screenAddress(t, lookups());
    }
    case "robots_check": {
      const t = need(parseRobotsTarget(args.url, args.agent));
      return checkRobots(t, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 9, maxBytes: 512 * 1024 }));
    }
    case "url_meta": {
      const t = need(parsePageTarget(args.url));
      return urlMeta(t, new SafeFetcher({ fetchFn: deps.fetch, maxRequests: 8, maxBytes: 1024 * 1024 }));
    }
    default:
      throw new Error("unreachable");
  }
}

function toolError(text) {
  return { content: [{ type: "text", text }], isError: true };
}

async function callTool(params, ctx) {
  const name = params && params.name;
  if (typeof name !== "string" || !TOOL_NAMES.has(name)) {
    return { error: { code: INVALID_PARAMS, message: `Unknown tool: ${String(name)}` } };
  }
  const args = params.arguments === undefined ? {} : params.arguments;
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return { error: { code: INVALID_PARAMS, message: "arguments must be a JSON object" } };
  }
  if (mcpRateLimited(ctx.ip, ctx.now)) {
    ctx.log(`tool:${name}:rate_limited`);
    return {
      result: toolError(
        `Free tier used up (${FREE_PER_IP_PER_HOUR} calls per hour per IP, or the shared hourly cap). ` + paidHint(ctx),
      ),
    };
  }
  try {
    const out = await runTool(name, args, ctx.deps);
    ctx.log(`tool:${name}:ok`);
    return { result: { content: [{ type: "text", text: JSON.stringify(out, null, 1) }], structuredContent: out, isError: false } };
  } catch (e) {
    if (e instanceof ToolInputError || e instanceof BadInput || e instanceof UnsafeUrl) {
      ctx.log(`tool:${name}:input_error`);
      return { result: toolError(`Invalid input: ${e.message}`) };
    }
    if (e instanceof Refused) {
      ctx.log(`tool:${name}:refused`);
      const why = (e.body && (e.body.reason || e.body.error)) || e.message;
      return { result: toolError(`Refused: ${why}`) };
    }
    if (e instanceof NotFound) {
      ctx.log(`tool:${name}:not_found`);
      return { result: toolError(`Not found: ${e.message}`) };
    }
    if (e instanceof LookupUnavailable) {
      ctx.log(`tool:${name}:unavailable`);
      return { result: toolError(`Temporarily unavailable: ${e.message}. Try again later.`) };
    }
    ctx.log(`tool:${name}:error`);
    return { result: toolError("Internal error while running the tool.") };
  }
}

// ---------------------------------------------------------------- transport

function respond(status, body, cors, extra = {}) {
  if (body === null) return new Response(null, { status, headers: { "Cache-Control": "no-store", ...cors, ...extra } });
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors, ...extra },
  });
}

const rpcError = (id, code, message, data) => ({ jsonrpc: "2.0", id: id === undefined ? null : id, error: data === undefined ? { code, message } : { code, message, data } });

/** Decode an MCP header value that may use the "=?base64?...?=" sentinel. Returns null when missing, undefined when invalid. */
export function decodeHeaderValue(v) {
  if (v === null) return null;
  if (v.startsWith("=?base64?") && v.endsWith("?=") && v.length >= 11) {
    try {
      const bin = atob(v.slice(9, -2));
      return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    } catch {
      return undefined;
    }
  }
  return v;
}

function originAllowed(origin) {
  if (origin === null) return true;
  try {
    return new URL(origin).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Handle a request to /mcp. ctx: {cors, origin (service origin), priceUsd, ip, deps, log(outcome), now}.
 */
export async function handleMcp(request, ctx) {
  const cors = ctx.cors;
  if (request.method !== "POST") return respond(405, null, cors, { Allow: "POST" });
  if (!originAllowed(request.headers.get("Origin"))) {
    ctx.log("forbidden_origin");
    return respond(403, rpcError(null, INVALID_REQUEST, "Origin not allowed"), cors);
  }
  const text = await request.text();
  if (text.length > MAX_BODY) return respond(413, rpcError(null, INVALID_REQUEST, `body larger than ${MAX_BODY} bytes`), cors);
  let msg;
  try {
    msg = parseJsonLossless(text);
  } catch {
    return respond(400, rpcError(null, PARSE_ERROR, "Parse error"), cors);
  }
  if (Array.isArray(msg)) return respond(400, rpcError(null, INVALID_REQUEST, "JSON-RPC batching is not supported"), cors);
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") {
    return respond(400, rpcError(msg && msg.id, INVALID_REQUEST, "Invalid Request: expected a JSON-RPC 2.0 object"), cors);
  }
  if (typeof msg.method !== "string") {
    // A JSON-RPC response from a (legacy) client: nothing to do.
    if ("result" in msg || "error" in msg) return respond(202, null, cors);
    return respond(400, rpcError(msg.id, INVALID_REQUEST, "Invalid Request: missing method"), cors);
  }
  const isNotification = !("id" in msg);
  if (isNotification) return respond(202, null, cors);

  const id = msg.id;
  const params = msg.params && typeof msg.params === "object" && !Array.isArray(msg.params) ? msg.params : {};
  const meta = params._meta && typeof params._meta === "object" ? params._meta : null;
  const modernVersion = meta ? meta[META_VERSION] : undefined;
  const headerVersion = request.headers.get("MCP-Protocol-Version");

  if (modernVersion !== undefined) {
    // Modern request: headers must mirror the body.
    const mismatch = (m) => respond(400, rpcError(id, HEADER_MISMATCH, `Header mismatch: ${m}`), cors);
    if (headerVersion === null) return mismatch("MCP-Protocol-Version header is required");
    if (headerVersion !== modernVersion) return mismatch(`MCP-Protocol-Version header '${headerVersion}' does not match body value '${modernVersion}'`);
    const methodHeader = request.headers.get("Mcp-Method");
    if (methodHeader === null) return mismatch("Mcp-Method header is required");
    if (methodHeader !== msg.method) return mismatch(`Mcp-Method header '${methodHeader}' does not match body value '${msg.method}'`);
    if (msg.method === "tools/call") {
      const nameHeader = decodeHeaderValue(request.headers.get("Mcp-Name"));
      if (nameHeader === null) return mismatch("Mcp-Name header is required for tools/call");
      if (nameHeader === undefined) return mismatch("Mcp-Name header has an invalid base64 encoding");
      if (nameHeader !== params.name) return mismatch(`Mcp-Name header '${nameHeader}' does not match body value '${params.name}'`);
    }
    if (!MODERN_VERSIONS.includes(modernVersion)) {
      return respond(400, rpcError(id, UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: SUPPORTED_VERSIONS, requested: modernVersion }), cors);
    }
    const complete = (r) => respond(200, { jsonrpc: "2.0", id, result: { resultType: "complete", ...r } }, cors);
    switch (msg.method) {
      case "server/discover":
        return complete({
          supportedVersions: SUPPORTED_VERSIONS,
          capabilities: { tools: {} },
          _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO },
          instructions: instructions(ctx),
          ttlMs: 3600000,
          cacheScope: "public",
        });
      case "tools/list":
        return complete({ tools: TOOLS, ttlMs: 3600000, cacheScope: "public" });
      case "ping":
        return complete({});
      case "tools/call": {
        const r = await callTool(params, ctx);
        if (r.error) return respond(200, { jsonrpc: "2.0", id, error: r.error }, cors);
        return complete(r.result);
      }
      default:
        return respond(404, rpcError(id, METHOD_NOT_FOUND, `Method not found: ${msg.method}`), cors);
    }
  }

  // Legacy request (initialize handshake era).
  if (headerVersion !== null) {
    if (MODERN_VERSIONS.includes(headerVersion)) {
      return respond(400, rpcError(id, HEADER_MISMATCH, `Header mismatch: MCP-Protocol-Version is '${headerVersion}' but params._meta['${META_VERSION}'] is missing`), cors);
    }
    if (!LEGACY_VERSIONS.includes(headerVersion)) {
      return respond(400, rpcError(id, INVALID_REQUEST, `Unsupported MCP-Protocol-Version '${headerVersion}'`, { supported: SUPPORTED_VERSIONS }), cors);
    }
  }
  const ok = (r) => respond(200, { jsonrpc: "2.0", id, result: r }, cors);
  switch (msg.method) {
    case "initialize": {
      const requested = params.protocolVersion;
      const protocolVersion = LEGACY_VERSIONS.includes(requested) ? requested : LEGACY_VERSIONS[0];
      return ok({ protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instructions(ctx) });
    }
    case "ping":
      return ok({});
    case "tools/list":
      return ok({ tools: TOOLS });
    case "server/discover":
      return ok({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: {} }, _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO }, instructions: instructions(ctx) });
    case "tools/call": {
      const r = await callTool(params, ctx);
      if (r.error) return respond(200, { jsonrpc: "2.0", id, error: r.error }, cors);
      return ok(r.result);
    }
    default:
      return respond(200, rpcError(id, METHOD_NOT_FOUND, `Method not found: ${msg.method}`), cors);
  }
}
