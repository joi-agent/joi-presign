// Capture real example outputs for the Bazaar/OpenAPI docs from live READ-ONLY calls, then write src/examples.js.
// Usage: node tools/capture-examples.mjs [txHashOnBase]
import fs from "node:fs";
import { NetLookups } from "../src/net.js";
import { explainTx } from "../src/txexplain.js";
import { tokenProfile } from "../src/token.js";
import { parseVerify, verifySignature } from "../src/verifysig.js";

const BASE = 8453, USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const L = () => new NetLookups({});

async function findUsdcTransfer() {
  const l = L();
  const head = BigInt(await l.rpc(BASE, "eth_blockNumber", []));
  for (let n = head - 5n; n > head - 40n; n--) {
    const b = await new NetLookups({ maxRequests: 2 }).rpc(BASE, "eth_getBlockByNumber", ["0x" + n.toString(16), true]);
    for (const tx of (b && b.transactions) || []) {
      if (tx.to && tx.to.toLowerCase() === USDC.toLowerCase() && tx.input.startsWith("0xa9059cbb")) return tx.hash;
    }
  }
  throw new Error("no USDC transfer found");
}

const hash = process.argv[2] || await findUsdcTransfer();
const tx = await explainTx(BASE, hash.toLowerCase(), L());
const token = await tokenProfile(BASE, USDC, L());
const vec = JSON.parse(fs.readFileSync(new URL("../test/sig-vectors.json", import.meta.url), "utf8")).typed[0];
const vInput = { chain: "ethereum", address: vec.address, typedData: vec.typedData, signature: vec.signature };
const ver = await verifySignature(parseVerify(vInput), L());
const examples = {
  tx: { input: { chain: "base", hash: hash.toLowerCase() }, output: tx },
  verify: { input: vInput, output: ver },
  token: { input: { chain: "base", address: USDC }, output: token },
};
fs.writeFileSync(new URL("../src/examples.js", import.meta.url),
  `// Real outputs captured ${new Date().toISOString().slice(0, 10)} from live read-only runs (tools/capture-examples.mjs).\n` +
  `// The /verify-signature example is the EIP-712 spec's "Ether Mail" test vector.\nexport default ${JSON.stringify(examples, null, 1)};\n`);
console.log("tx", hash, tx.status, tx.summary);
console.log("token", token.token, token.risk, token.findings.map((f) => f.code));
console.log("verify", ver.valid, ver.method, ver.recovered);
