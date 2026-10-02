// Capture real example outputs for /read, /url-meta and /email-check from live read-only runs.
// Run: node tools/capture-examples-general.mjs  (writes src/examples-general.js)
import fs from "node:fs";
import { SafeFetcher } from "../src/fetchsafe.js";
import { parsePageTarget, readPage, urlMeta } from "../src/readpage.js";
import { emailCheck, parseEmailTarget } from "../src/emailcheck.js";

const fetcher = (maxBytes) => new SafeFetcher({ fetchFn: fetch, maxRequests: 30, maxBytes });
const read = { input: { url: "https://example.com/" } };
read.output = await readPage(parsePageTarget(read.input.url), fetcher(2 * 1024 * 1024));
const urlmeta = { input: { url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/402" } };
urlmeta.output = await urlMeta(parsePageTarget(urlmeta.input.url), fetcher(1024 * 1024));
const email = { input: { domain: "gmail.com" } };
email.output = await emailCheck(parseEmailTarget(email.input.domain), fetcher(64 * 1024));
const emailSmall = { input: { domain: "example.com" } };
emailSmall.output = await emailCheck(parseEmailTarget(emailSmall.input.domain), fetcher(64 * 1024));
const out = `// Real outputs captured ${new Date().toISOString().slice(0, 10)} from live read-only runs (tools/capture-examples-general.mjs).\nexport default ${JSON.stringify({ read, urlmeta, email, email_small: emailSmall }, null, 1)};\n`;
fs.writeFileSync(new URL("../src/examples-general.js", import.meta.url), out);
console.log("wrote src/examples-general.js", out.length, "bytes");
