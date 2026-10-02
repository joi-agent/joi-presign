// Token profile: the contract profile plus name/symbol/decimals/supply, and owner powers read from the
// verified ABI (mint, pause, blocklists, fee changes, upgrades). Read-only. It doesn't detect honeypots
// or simulate transfers.
import { decode, hexToBytes } from "./abi.js";
import { Report } from "./core.js";
import { profileAddress } from "./profile.js";
import { formatUnits } from "./txexplain.js";

const SEL = { name: "0x06fdde03", symbol: "0x95d89b41", decimals: "0x313ce567", totalSupply: "0x18160ddd" };

// Function-name patterns -> owner power. Checked against non-view functions of the verified ABI only.
export const POWERS = [
  ["MINT_FUNCTION", /^(mint|mintTo|mintFor|batchMint|mintTokens|issue)$|^_?mint[A-Z]/,
    "can create new tokens (a mint function), which dilutes holders"],
  ["PAUSE_FUNCTION", /^(pause|unpause|setPaused|setPause|togglePause|pauseTransfers)$/i,
    "can pause transfers, freezing everyone's tokens"],
  ["BLOCKLIST_FUNCTION", /(black|block|deny)list|^(freeze|freezeAccount|addToBlocked|blockAccount|setBlocked|setBot|setBots|addBots?)$/i,
    "can block specific addresses from moving their tokens (a blocklist)"],
  ["FEE_FUNCTION", /^(set|update|change)\w*(fee|tax)\w*$|^(setfees?|settaxes?)$/i,
    "can change transfer fees or taxes"],
  ["UPGRADE_FUNCTION", /^(upgradeTo|upgradeToAndCall)$/,
    "can replace the token's code (an upgrade function)"],
];

function readString(hex) {
  if (typeof hex !== "string" || hex === "0x") return null;
  try {
    const b = hexToBytes(hex);
    if (b.length === 32) {
      const end = b.indexOf(0);
      const s = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(0, end < 0 ? 32 : end));
      return s || null;
    }
    const [s] = decode(["string"], b);
    return s.length <= 100 ? s : s.slice(0, 100);
  } catch { return null; }
}

function readUint(hex) {
  if (typeof hex !== "string" || !/^0x[0-9a-f]{64}$/i.test(hex)) return null;
  return BigInt(hex);
}

/** Owner powers from an ABI: [{code, functions}] using only state-changing functions. */
export function powersFromAbi(abi) {
  const fns = abi.filter((x) => x && x.type === "function" && typeof x.name === "string" && !["view", "pure"].includes(x.stateMutability) && x.constant !== true);
  const out = [];
  for (const [code, re, text] of POWERS) {
    const hits = [...new Set(fns.filter((f) => re.test(f.name)).map((f) => f.name))];
    if (hits.length) out.push({ code, text, functions: hits });
  }
  return out;
}

export async function tokenProfile(chainId, address, lookups) {
  const base = await profileAddress(chainId, address, lookups);
  const rep = new Report();
  for (const f of base.findings) rep.add(f.code, f.severity, f.message);
  const out = { kind: "token", chain_id: chainId, risk: "LOW", findings: [], token: null, owner_powers: [], profile: base.profile };

  if (base.kind !== "contract") {
    rep.add("NOT_A_TOKEN", "HIGH", `There's no token contract at ${address}: it's ${base.kind === "none" ? "an empty address" : "a wallet, not a contract"}.`);
    out.kind = base.kind;
    out.findings = rep.findings;
    out.risk = rep.risk();
    return out;
  }

  const [nameHex, symHex, decHex, supHex] = await Promise.all(Object.values(SEL).map((s) => lookups.ethCall(chainId, address, s)));
  const decimals = readUint(decHex);
  const supply = readUint(supHex);
  const token = {
    address,
    name: readString(nameHex),
    symbol: readString(symHex),
    decimals: decimals !== null && decimals <= 255n ? Number(decimals) : null,
    total_supply: supply === null ? null : supply.toString(),
  };
  token.total_supply_formatted = supply !== null && token.decimals !== null ? formatUnits(supply, token.decimals) : null;
  out.token = token;
  if (token.symbol === null && token.decimals === null && supply === null) {
    rep.add("NOT_ERC20_LIKE", "MEDIUM", "The contract doesn't answer the standard ERC-20 calls (symbol, decimals, totalSupply): it may not be a fungible token.");
  }

  // owner powers, from the verified ABI of the code that actually runs (the implementation behind a proxy)
  const proxy = base.profile.proxy;
  const codeAddr = proxy && proxy.implementation ? proxy.implementation : address;
  const codeVerified = proxy && proxy.implementation ? proxy.implementation_verified : base.profile.verified;
  if (codeVerified === true) {
    const abi = await lookups.sourcifyAbi(chainId, codeAddr);
    if (Array.isArray(abi)) {
      out.owner_powers = powersFromAbi(abi);
      const holder = base.profile.owner && base.profile.owner.kind === "eoa" ? ` The owner, ${base.profile.owner.address}, is a single wallet.` : "";
      for (const p of out.owner_powers) {
        rep.add(p.code, "MEDIUM", `Someone (usually the owner or an admin role) ${p.text}: ${p.functions.join(", ")}.${holder}`);
      }
      if (!out.owner_powers.length) rep.add("NO_OWNER_POWERS_FOUND", "INFO", "The verified code has no mint, pause, blocklist, fee or upgrade functions by name.");
    } else {
      rep.add("LOOKUP_UNAVAILABLE", "INFO", "Could not read the verified ABI to check for owner powers.");
    }
  } else if (codeVerified === false) {
    rep.add("OWNER_POWERS_UNKNOWN", "MEDIUM", "The source isn't verified, so its owner powers (mint, pause, blocklist, fees) can't be checked.");
  }
  rep.add("SCOPE", "INFO", "This profile doesn't detect honeypots or simulate transfers: a token can still block selling or take hidden fees in ways a read-only check can't see.");
  out.findings = rep.findings;
  out.risk = rep.risk();
  return out;
}
