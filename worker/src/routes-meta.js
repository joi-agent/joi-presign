// Descriptions, Bazaar discovery info and input schemas for /tx, /verify-signature and /token.
// Example outputs are real responses captured from live read-only runs (see tools/capture-examples.mjs).
import EXAMPLES from "./examples.js";

const CHAIN_ENUM = { type: "string", enum: ["base", "ethereum", "arbitrum"] };
const ADDRESS = { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" };
const OUTPUT_SCHEMA = { type: "object", required: ["type"], properties: { type: { type: "string" }, example: { type: "object" } } };
const SCHEMA = "https://json-schema.org/draft/2020-12/schema";

export const TX_DESCRIPTION =
  "Transaction explainer: what a transaction did in plain words (status, fee, decoded call, token transfers, " +
  "approvals, NFT moves, wraps), with symbols and decimals. Run by Joi, an AI agent.";
export const VERIFY_DESCRIPTION =
  "Signature verifier: checks a personal_sign message, EIP-712 typed data or raw digest against an address, " +
  "for wallets (ecrecover) and smart accounts (ERC-1271), including EIP-7702 wallets. Run by Joi, an AI agent.";
export const TOKEN_DESCRIPTION =
  "Token profile: name, symbol, decimals, supply, who controls the contract, and owner powers found in the " +
  "verified code (mint, pause, blocklist, fees, upgrades). No honeypot detection. Run by Joi, an AI agent.";

export const BAZAAR_TX = {
  info: {
    input: { type: "http", method: "GET", queryParams: EXAMPLES.tx.input },
    output: { type: "json", example: EXAMPLES.tx.output },
  },
  schema: {
    $schema: SCHEMA, type: "object", required: ["input"],
    properties: {
      input: {
        type: "object", required: ["type", "method", "queryParams"],
        properties: {
          type: { type: "string", const: "http" },
          method: { type: "string", enum: ["GET"] },
          queryParams: {
            type: "object", required: ["hash"],
            properties: { chain: CHAIN_ENUM, hash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" } },
          },
        },
      },
      output: OUTPUT_SCHEMA,
    },
  },
};

export const BAZAAR_VERIFY = {
  info: {
    input: { type: "http", method: "POST", bodyType: "json", body: EXAMPLES.verify.input },
    output: { type: "json", example: EXAMPLES.verify.output },
  },
  schema: {
    $schema: SCHEMA, type: "object", required: ["input"],
    properties: {
      input: {
        type: "object", required: ["type", "method", "bodyType", "body"],
        properties: {
          type: { type: "string", const: "http" },
          method: { type: "string", enum: ["POST"] },
          bodyType: { type: "string", const: "json" },
          body: {
            type: "object", required: ["address", "signature"],
            description: "Exactly one of message (personal_sign; 0x-hex is signed as bytes), typedData (EIP-712) or hash (32-byte digest).",
            properties: {
              chain: CHAIN_ENUM, address: ADDRESS,
              message: { type: "string" }, typedData: { type: "object" },
              hash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
              signature: { type: "string", pattern: "^0x([0-9a-fA-F]{2})+$" },
            },
          },
        },
      },
      output: OUTPUT_SCHEMA,
    },
  },
};

export const BAZAAR_TOKEN = {
  info: {
    input: { type: "http", method: "GET", queryParams: EXAMPLES.token.input },
    output: { type: "json", example: EXAMPLES.token.output },
  },
  schema: {
    $schema: SCHEMA, type: "object", required: ["input"],
    properties: {
      input: {
        type: "object", required: ["type", "method", "queryParams"],
        properties: {
          type: { type: "string", const: "http" },
          method: { type: "string", enum: ["GET"] },
          queryParams: { type: "object", required: ["address"], properties: { chain: CHAIN_ENUM, address: ADDRESS } },
        },
      },
      output: OUTPUT_SCHEMA,
    },
  },
};
