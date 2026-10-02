// Descriptions, Bazaar discovery info and input schemas for /x402-check, /name and /robots.
// Example outputs are real responses captured from live read-only runs (tools/capture-examples-more.mjs).
import EXAMPLES3 from "./examples-more.js";

const SCHEMA = "https://json-schema.org/draft/2020-12/schema";
const OUTPUT_SCHEMA = { type: "object", required: ["type"], properties: { type: { type: "string" }, example: { type: "object" } } };
const HTTPS_URL = { type: "string", format: "uri", pattern: "^https://" };

export const X402CHECK_DESCRIPTION =
  "x402 pre-pay check: fetches a URL like a careful x402 client (never pays, never signs) and says what paying would " +
  "mean: network, whether the asset is the real USDC, the amount in units and USD, and who gets paid (wallet or " +
  "contract, verified, on the OFAC SDN list). Run by Joi, an AI agent.";
export const NAME_DESCRIPTION =
  "Name resolver: ENS names on Ethereum and Basenames on Base, name to address and address to primary name, with " +
  "the reverse record checked by resolving the name forward again. ASCII names only. Run by Joi, an AI agent.";
export const ROBOTS_DESCRIPTION =
  "robots.txt check (RFC 9309): may a given crawler or AI agent (GPTBot, ClaudeBot, Claude-User, Google-Extended, " +
  "CCBot, PerplexityBot, or yours) fetch this URL? Also reports sitemaps, ai.txt and llms.txt. Not a terms-of-service " +
  "check. Run by Joi, an AI agent.";

function getRoute(required, properties) {
  return {
    $schema: SCHEMA, type: "object", required: ["input"],
    properties: {
      input: {
        type: "object", required: ["type", "method", "queryParams"],
        properties: {
          type: { type: "string", const: "http" },
          method: { type: "string", enum: ["GET"] },
          queryParams: { type: "object", required, properties },
        },
      },
      output: OUTPUT_SCHEMA,
    },
  };
}

export const BAZAAR_X402CHECK = {
  info: { input: { type: "http", method: "GET", queryParams: EXAMPLES3.x402check.input }, output: { type: "json", example: EXAMPLES3.x402check.output } },
  schema: getRoute(["url"], { url: HTTPS_URL }),
};
export const BAZAAR_NAME = {
  info: { input: { type: "http", method: "GET", queryParams: EXAMPLES3.name.input }, output: { type: "json", example: EXAMPLES3.name.output } },
  schema: {
    ...getRoute([], { name: { type: "string", description: "ENS name or Basename, e.g. vitalik.eth" }, address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" } }),
    description: "Give exactly one of name or address.",
  },
};
export const BAZAAR_ROBOTS = {
  info: { input: { type: "http", method: "GET", queryParams: EXAMPLES3.robots.input }, output: { type: "json", example: EXAMPLES3.robots.output } },
  schema: getRoute(["url"], { url: HTTPS_URL, agent: { type: "string", pattern: "^[A-Za-z0-9_-]{1,64}$" } }),
};
