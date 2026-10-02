// Capture real outputs of /x402-check, /name and /robots from live read-only runs and write src/examples-more.js.
// Run: node tools/capture-examples-more.mjs   (needs network; never pays or signs anything)
import fs from "node:fs";
import { NetLookups } from "../src/net.js";
import { SafeFetcher } from "../src/fetchsafe.js";
import { parseX402CheckTarget, x402Check } from "../src/x402check.js";
import { parseNameTarget, resolveName } from "../src/ens.js";
import { parseRobotsTarget, checkRobots } from "../src/robots.js";

const INPUTS = {
  x402check: { url: "https://joi-presign.joi-agent.workers.dev/price?asset=ETH&chain=base" },
  name: { name: "vitalik.eth" },
  robots: { url: "https://www.nytimes.com/section/technology" },
};

const out = {};
{
  const t = parseX402CheckTarget(INPUTS.x402check.url);
  out.x402check = { input: INPUTS.x402check, output: await x402Check(t, new NetLookups({ maxRequests: 26 }), new SafeFetcher({ maxRequests: 11 })) };
}
{
  const t = parseNameTarget(INPUTS.name.name, undefined);
  out.name = { input: INPUTS.name, output: await resolveName(t, new NetLookups({ maxRequests: 30 })) };
}
{
  const t = parseRobotsTarget(INPUTS.robots.url, undefined);
  const r = await checkRobots(t, new SafeFetcher({ maxRequests: 9, maxBytes: 512 * 1024 }));
  out.robots = { input: INPUTS.robots, output: { ...r, sitemaps: r.sitemaps.slice(0, 5) } };
}

if (process.argv.includes("--print")) {
  console.log(JSON.stringify(out, null, 1));
} else {
  const header = `// Real outputs captured ${new Date().toISOString().slice(0, 10)} from live read-only runs (tools/capture-examples-more.mjs).\n`;
  fs.writeFileSync(new URL("../src/examples-more.js", import.meta.url), header + "export default " + JSON.stringify(out, null, 1) + ";\n");
  console.log("wrote src/examples-more.js");
}
