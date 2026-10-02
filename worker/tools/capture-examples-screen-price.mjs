// Capture real example outputs for /screen and /price from live READ-ONLY calls, then write src/examples-screen-price.js.
// Usage: node tools/capture-examples-screen-price.mjs
import fs from "node:fs";
import { NetLookups } from "../src/net.js";
import { parseScreenTarget, screenAddress } from "../src/screen.js";
import { parsePriceTarget, readPrice } from "../src/price.js";

const L = () => new NetLookups({});
// A listed address (OFAC SDN, entity LAZARUS GROUP): public data, shown so the example demonstrates a match.
const SCREEN_IN = { chain: "ethereum", address: "0x08723392Ed15743cc38513C4925f5e6be5c17243" };
const PRICE_IN = { chain: "base", asset: "ETH" };
const screen = await screenAddress(parseScreenTarget(SCREEN_IN.chain, SCREEN_IN.address), L());
const price = await readPrice(parsePriceTarget(PRICE_IN.chain, PRICE_IN.asset), L());
fs.writeFileSync(new URL("../src/examples-screen-price.js", import.meta.url),
  `// Real outputs captured ${new Date().toISOString().slice(0, 10)} from live read-only runs (tools/capture-examples-screen-price.mjs).\n` +
  `export default ${JSON.stringify({ screen: { input: SCREEN_IN, output: screen }, price: { input: PRICE_IN, output: price } }, null, 1)};\n`);
console.log("screen", screen.address, screen.sanctioned, screen.matches.map((m) => m.entity), screen.kind);
console.log("price", price.asset, price.chain, price.price, price.age_seconds, price.stale);
