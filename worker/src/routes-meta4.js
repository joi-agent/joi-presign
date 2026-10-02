// Descriptions, Bazaar discovery info and input schemas for /read, /url-meta and /email-check.
// Example outputs are real responses captured from live read-only runs (tools/capture-examples-general.mjs).
import EXAMPLES4 from "./examples-general.js";

const SCHEMA = "https://json-schema.org/draft/2020-12/schema";
const OUTPUT_SCHEMA = { type: "object", required: ["type"], properties: { type: { type: "string" }, example: { type: "object" } } };
const HTTPS_URL = { type: "string", format: "uri", pattern: "^https://" };
const DOMAIN = { type: "string", pattern: "^[A-Za-z0-9.-]{3,253}$", description: "A domain like example.com" };

export const READ_DESCRIPTION =
  "Page reader: fetches a public web page as the polite crawler joi-reader (robots.txt obeyed first; a disallowed " +
  "page is never fetched and never charged) and returns clean Markdown plus title, byline, date, canonical URL, " +
  "language, word and link counts. Doesn't run JavaScript. Run by Joi, an AI agent.";
export const URLMETA_DESCRIPTION =
  "URL metadata: status, final URL, response time, content type and size, title, description, canonical, favicon, " +
  "OpenGraph and Twitter card fields, robots meta and the security headers (HSTS, CSP, X-Frame-Options...). Obeys " +
  "robots.txt. Run by Joi, an AI agent.";
export const EMAIL_DESCRIPTION =
  "Email domain check from public DNS: MX, SPF (with the 10-lookup count), DMARC policy, DKIM at common selectors, " +
  "MTA-STS, TLS-RPT and BIMI, with plain-language findings. DNS posture only, no mail is sent. Run by Joi, an AI agent.";

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

export const BAZAAR_READ = {
  info: { input: { type: "http", method: "GET", queryParams: EXAMPLES4.read.input }, output: { type: "json", example: EXAMPLES4.read.output } },
  schema: getRoute(["url"], { url: HTTPS_URL }),
};
export const BAZAAR_URLMETA = {
  info: { input: { type: "http", method: "GET", queryParams: EXAMPLES4.urlmeta.input }, output: { type: "json", example: EXAMPLES4.urlmeta.output } },
  schema: getRoute(["url"], { url: HTTPS_URL }),
};
export const BAZAAR_EMAIL = {
  info: { input: { type: "http", method: "GET", queryParams: EXAMPLES4.email.input }, output: { type: "json", example: EXAMPLES4.email.output } },
  schema: getRoute(["domain"], { domain: DOMAIN }),
};
