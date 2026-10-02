// x402 payments: v2 transport (PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE) per
// coinbase/x402 specs/transports-v2/http.md, plus the v1 transport (JSON body / X-PAYMENT /
// X-PAYMENT-RESPONSE) for older clients. Scheme "exact" on Base mainnet in USDC (EIP-3009).

export const DEFAULTS = {
  facilitatorUrl: "https://facilitator.payai.network",
  payTo: "0xa5215C2ce349Cf325CeEd739C52ff10d77499De5",
  amount: "5000", // USDC has 6 decimals: 5000 = $0.005
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
  network: "eip155:8453",
  v1Network: "base",
  maxTimeoutSeconds: 60,
  // EIP-712 domain of USDC on Base, checked against its on-chain DOMAIN_SEPARATOR: "USD Coin", "2".
  extra: { name: "USD Coin", version: "2" },
};

export const DESCRIPTION =
  "Pre-sign risk check: decodes a transaction, typed data or sign request and flags risky approvals, " +
  "permits, blind signing and drainer patterns. Run by Joi, an AI agent.";

export class PaymentError extends Error {
  constructor(status, reason) {
    super(reason);
    this.status = status;
    this.reason = reason;
  }
}

export function b64encodeJson(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64decodeJson(s) {
  const bin = atob(s.trim());
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

export function requirementsV2(cfg) {
  return {
    scheme: "exact",
    network: cfg.network,
    amount: cfg.amount,
    asset: cfg.asset,
    payTo: cfg.payTo,
    maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    extra: { ...cfg.extra },
  };
}

export function requirementsV1(cfg, resourceUrl) {
  return {
    scheme: "exact",
    network: cfg.v1Network,
    maxAmountRequired: cfg.amount,
    asset: cfg.asset,
    payTo: cfg.payTo,
    resource: resourceUrl,
    description: cfg.description || DESCRIPTION,
    mimeType: "application/json",
    outputSchema: null,
    maxTimeoutSeconds: cfg.maxTimeoutSeconds,
    extra: { ...cfg.extra },
  };
}

// Bazaar discovery info, echoed by clients in their PaymentPayload; facilitators catalog it on settle.
export const BAZAAR = {
  info: {
    input: {
      type: "http",
      method: "POST",
      queryParams: { chain: "ethereum" },
      bodyType: "json",
      body: {
        chainId: 1,
        to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        value: "0x0",
        data: "0x095ea7b3000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
    },
    output: {
      type: "json",
      example: {
        kind: "tx",
        chain_id: 1,
        risk: "MEDIUM",
        findings: [{
          code: "UNLIMITED_APPROVAL",
          severity: "MEDIUM",
          message: "An allowance on token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 for 0x000000000022D473030F116dDEE9F6B43aC78BA3 is unlimited. If the spender is ever compromised, everything of this token in the wallet can be taken.",
        }],
        decoded: {
          to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
          value: "0",
          selector: "0x095ea7b3",
          function: "approve(address,uint256)",
          args: ["0x000000000022D473030F116dDEE9F6B43aC78BA3", "115792089237316195423570985008687907853269984665640564039457584007913129639935"],
        },
      },
    },
  },
};

export const CONTRACT_DESCRIPTION =
  "Contract profile: what is at this address (wallet, 7702-delegated wallet, contract), is the source verified, " +
  "is it an upgradeable proxy and who can upgrade it, who owns it. Run by Joi, an AI agent.";

// Example output: a real profile of USDC on Base, captured 2026-10-02.
export const BAZAAR_CONTRACT = {
  "info": {
    "input": {
      "type": "http",
      "method": "GET",
      "queryParams": {
        "chain": "base",
        "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
      }
    },
    "output": {
      "type": "json",
      "example": {
        "kind": "contract",
        "chain_id": 8453,
        "risk": "MEDIUM",
        "findings": [
          {
            "code": "SOURCE_VERIFIED",
            "severity": "INFO",
            "message": "Source verified on Sourcify as FiatTokenProxy."
          },
          {
            "code": "UPGRADEABLE_PROXY",
            "severity": "MEDIUM",
            "message": "Upgradeable proxy (ZeppelinOS-style): whoever controls the upgrade can replace this contract's code at any time, including with code that takes funds approved to it."
          },
          {
            "code": "ADMIN_IS_EOA",
            "severity": "MEDIUM",
            "message": "The proxy admin 0x4fc7850364958d97B4d3f5A08f79db2493f8cA44 is a single wallet (EOA): one private key can upgrade this contract."
          },
          {
            "code": "IMPLEMENTATION_VERIFIED",
            "severity": "INFO",
            "message": "Implementation 0x2Ce6311ddAE708829bc0784C967b7d77D19FD779 is verified on Sourcify as FiatTokenV2_2."
          },
          {
            "code": "OWNER_IS_EOA",
            "severity": "MEDIUM",
            "message": "owner() is 0x3ABd6f64A422225E61E435baE41db12096106df7, a single wallet (EOA): one private key controls the owner-only functions."
          }
        ],
        "profile": {
          "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          "chain": "base",
          "code_size": 1852,
          "verified": true,
          "name": "FiatTokenProxy",
          "proxy": {
            "type": "zeppelinos",
            "implementation": "0x2Ce6311ddAE708829bc0784C967b7d77D19FD779",
            "admin": "0x4fc7850364958d97B4d3f5A08f79db2493f8cA44",
            "admin_kind": "eoa",
            "implementation_has_code": true,
            "implementation_verified": true,
            "implementation_name": "FiatTokenV2_2"
          },
          "owner": {
            "function": "owner()",
            "address": "0x3ABd6f64A422225E61E435baE41db12096106df7",
            "kind": "eoa"
          }
        }
      }
    }
  }
};


export function paymentRequired(cfg, resourceUrl, error) {
  return {
    x402Version: 2,
    error,
    resource: { url: resourceUrl, description: cfg.description || DESCRIPTION, mimeType: "application/json" },
    accepts: [requirementsV2(cfg)],
    extensions: { bazaar: cfg.bazaar || BAZAAR },
  };
}

export function paymentRequiredV1Body(cfg, resourceUrl, error) {
  return { x402Version: 1, error, accepts: [requirementsV1(cfg, resourceUrl)] };
}

const same = (a, b) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

/** Read the payment header. Returns null when there is none; throws PaymentError(400) when malformed. */
export function readPayment(headers) {
  const v2 = headers.get("PAYMENT-SIGNATURE");
  const v1 = headers.get("X-PAYMENT");
  if (!v2 && !v1) return null;
  let payload;
  try {
    payload = b64decodeJson(v2 || v1);
  } catch {
    throw new PaymentError(400, "invalid_payload");
  }
  if (!payload || typeof payload !== "object") throw new PaymentError(400, "invalid_payload");
  return { version: v2 ? 2 : 1, payload };
}

/** Cheap local checks before asking the facilitator: is this a payment for this resource at this price? */
export function checkPaymentMatches(cfg, { version, payload }) {
  const auth = payload?.payload?.authorization;
  if (payload.x402Version !== version) throw new PaymentError(400, "invalid_x402_version");
  if (version === 2) {
    const acc = payload.accepted;
    if (!acc || acc.scheme !== "exact") throw new PaymentError(402, "invalid_scheme");
    if (acc.network !== cfg.network) throw new PaymentError(402, "invalid_network");
    if (!same(acc.asset, cfg.asset) || !same(acc.payTo, cfg.payTo) || String(acc.amount) !== cfg.amount) {
      throw new PaymentError(402, "invalid_payment_requirements");
    }
  } else {
    if (payload.scheme !== "exact") throw new PaymentError(402, "invalid_scheme");
    if (payload.network !== cfg.v1Network) throw new PaymentError(402, "invalid_network");
  }
  if (!auth || typeof auth !== "object") throw new PaymentError(400, "invalid_payload");
  if (!same(auth.to, cfg.payTo)) throw new PaymentError(402, "invalid_exact_evm_payload_recipient_mismatch");
  if (String(auth.value) !== cfg.amount) throw new PaymentError(402, "invalid_exact_evm_payload_authorization_value_mismatch");
}

async function facilitatorCall(cfg, path, body, fetchFn, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetchFn(cfg.facilitatorUrl.replace(/\/$/, "") + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "joi-presign-worker/0.1" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

function facilitatorBody(cfg, resourceUrl, { version, payload }) {
  return {
    x402Version: version,
    paymentPayload: payload,
    paymentRequirements: version === 2 ? requirementsV2(cfg) : requirementsV1(cfg, resourceUrl),
  };
}

export async function verifyPayment(cfg, resourceUrl, payment, fetchFn = fetch, timeoutMs = 10000) {
  let res;
  try {
    res = await facilitatorCall(cfg, "/verify", facilitatorBody(cfg, resourceUrl, payment), fetchFn, timeoutMs);
  } catch {
    throw new PaymentError(502, "unexpected_verify_error");
  }
  if (!res || res.isValid !== true) throw new PaymentError(402, (res && res.invalidReason) || "unexpected_verify_error");
  return res;
}

export async function settlePayment(cfg, resourceUrl, payment, fetchFn = fetch, timeoutMs = 20000) {
  try {
    const res = await facilitatorCall(cfg, "/settle", facilitatorBody(cfg, resourceUrl, payment), fetchFn, timeoutMs);
    if (res && typeof res === "object") return res;
  } catch { /* fall through */ }
  return { success: false, errorReason: "unexpected_settle_error", transaction: "", network: payment.version === 2 ? cfg.network : cfg.v1Network };
}

// JSON Schemas for the Bazaar "schema" field (x402 bazaar v2), so agents know how to call each route.
const CHAIN_ENUM = { type: "string", enum: ["base", "ethereum", "arbitrum"] };
BAZAAR.schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  required: ["input"],
  properties: {
    input: {
      type: "object",
      required: ["type", "method", "bodyType", "body"],
      properties: {
        type: { type: "string", const: "http" },
        method: { type: "string", enum: ["POST"] },
        queryParams: { type: "object", properties: { chain: CHAIN_ENUM } },
        bodyType: { type: "string", const: "json" },
        body: {
          type: "object",
          description: "An unsigned transaction {chainId, from, to, value, data}, EIP-712 typed data, an EIP-7702 authorization, or a JSON-RPC request (eth_sendTransaction, eth_signTypedData_v4, personal_sign, eth_sign).",
        },
      },
    },
    output: { type: "object", required: ["type"], properties: { type: { type: "string" }, example: { type: "object" } } },
  },
};
BAZAAR_CONTRACT.schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  required: ["input"],
  properties: {
    input: {
      type: "object",
      required: ["type", "method", "queryParams"],
      properties: {
        type: { type: "string", const: "http" },
        method: { type: "string", enum: ["GET"] },
        queryParams: {
          type: "object",
          required: ["address"],
          properties: { chain: CHAIN_ENUM, address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } },
        },
      },
    },
    output: { type: "object", required: ["type"], properties: { type: { type: "string" }, example: { type: "object" } } },
  },
};
