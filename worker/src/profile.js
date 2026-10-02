// "Know what you're interacting with": a read-only profile of an address. Every chain fact comes from
// `lookups` (getCode, getStorageAt, ethCall, sourcifyInfo, codeKind, txCount); any may resolve to null.
import { isAddress, toChecksumAddress } from "./abi.js";
import { CHAINS, KNOWN_DELEGATES, Report } from "./core.js";

export class LookupUnavailable extends Error {}

// EIP-1967 slots: keccak256("eip1967.proxy.implementation" / "eip1967.proxy.admin" / "eip1967.proxy.beacon") - 1.
export const SLOT_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
export const SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
// Older proxies, still behind major tokens (e.g. USDC's FiatTokenProxy): ZeppelinOS keccak256("org.zeppelinos.proxy.implementation"
// / ".admin"), and EIP-1822 (UUPS) keccak256("PROXIABLE"). All values computed and checked 2026-10-02.
export const SLOT_ZOS_IMPLEMENTATION = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
export const SLOT_ZOS_ADMIN = "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b";
export const SLOT_PROXIABLE = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7";
// EIP-1167 minimal proxy runtime code around the 20-byte implementation address.
const MINIMAL_PREFIX = "363d3d373d3d3d363d73";
const MINIMAL_SUFFIX = "5af43d82803e903d91602b57fd5bf3";
const SEL_IMPLEMENTATION = "0x5c60da1b"; // implementation() on a beacon
const OWNER_GETTERS = [["owner()", "0x8da5cb5b"], ["admin()", "0xf851a440"], ["getOwner()", "0x893d20e8"]];
const ZERO = "0x" + "00".repeat(20);

const CHAIN_NAMES = Object.fromEntries(Object.entries(CHAINS).map(([name, id]) => [id, name]));

/** A 32-byte word holding an address (upper 12 bytes zero) -> checksum address, else null. */
function wordToAddress(word) {
  if (typeof word !== "string") return null;
  const h = word.replace(/^0x/, "").padStart(64, "0");
  if (h.length !== 64 || !/^0{24}/.test(h)) return null;
  return toChecksumAddress("0x" + h.slice(24));
}

export function parseTarget(chainRaw, addressRaw) {
  const chainName = chainRaw === undefined || chainRaw === null || chainRaw === "" ? "base" : String(chainRaw);
  const chainId = CHAINS[chainName];
  if (!chainId) return { error: `unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}` };
  if (typeof addressRaw !== "string" || !isAddress(addressRaw) || !addressRaw.startsWith("0x")) {
    return { error: "address must be a 0x-prefixed 20-byte hex address (mixed case must be a valid EIP-55 checksum)" };
  }
  return { chainId, address: toChecksumAddress(addressRaw) };
}

async function describeCode(chainId, a, lookups) {
  const [code, src] = await Promise.all([lookups.getCode(chainId, a), lookups.sourcifyInfo(chainId, a)]);
  return { code, verified: src ? src.verified : null, name: src ? src.name : null };
}

async function classifyHolder(chainId, a, lookups) {
  if (a === ZERO) return "zero";
  const kind = await lookups.codeKind(chainId, a);
  if (kind === "none" || kind === "7702") return "eoa";
  if (kind === "contract") return "contract";
  return null;
}

export async function profileAddress(chainId, address, lookups) {
  const rep = new Report();
  const chain = CHAIN_NAMES[chainId] || String(chainId);
  const code = await lookups.getCode(chainId, address);
  if (code === null) throw new LookupUnavailable("could not read the code at this address");
  const profile = { address, chain, code_size: (code.length - 2) / 2 };

  // ---- no code: a wallet or an unused address
  if (code === "0x") {
    const [n, bal] = await Promise.all([lookups.txCount(chainId, address), lookups.balance(chainId, address)]);
    const facts = { tx_count: n, balance_wei: bal === null ? null : bal.toString() };
    if (n === 0 && bal === 0n) {
      rep.add("NO_CODE", "MEDIUM",
        `No code, no transactions and no balance at ${address} on ${chain}. If you expected a contract, check the address and the chain.`);
      return { kind: "none", chain_id: chainId, risk: rep.risk(), findings: rep.findings, profile: { ...profile, ...facts } };
    }
    if (n === null || bal === null) rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not fully read the activity of ${address}.`);
    rep.add("EOA", "INFO", `${address} is a regular wallet (EOA), not a contract.`);
    if (n === 0) rep.add("NEVER_SENT", "INFO", `${address} has never sent a transaction on ${chain}.`);
    return { kind: "eoa", chain_id: chainId, risk: rep.risk(), findings: rep.findings, profile: { ...profile, ...facts } };
  }

  // ---- EIP-7702 delegated wallet
  if (code.startsWith("0xef0100") && code.length === 2 + 46) {
    const delegate = toChecksumAddress("0x" + code.slice(8));
    const d = await lookups.sourcifyInfo(chainId, delegate);
    const known = KNOWN_DELEGATES[delegate] || null;
    rep.add("DELEGATED_EOA", "MEDIUM",
      `${address} is a wallet (EOA) that delegates its code to ${delegate}${known ? ` (${known})` : ""} via EIP-7702: ` +
      "calls to it run that contract's code, and that code controls the account.");
    if (d && d.verified === false) rep.add("DELEGATE_UNVERIFIED", "MEDIUM", `The delegate ${delegate}'s source isn't verified on Sourcify.`);
    else if (!d || d.verified === null) rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not check source verification of the delegate ${delegate}.`);
    return {
      kind: "eoa-7702", chain_id: chainId, risk: rep.risk(), findings: rep.findings,
      profile: { ...profile, delegate, delegate_known_as: known, delegate_verified: d ? d.verified : null, delegate_name: d ? d.name : null },
    };
  }

  // ---- contract
  const src = await lookups.sourcifyInfo(chainId, address);
  profile.verified = src ? src.verified : null;
  profile.name = src ? src.name : null;
  if (profile.verified === true) rep.add("SOURCE_VERIFIED", "INFO", `Source verified on Sourcify${profile.name ? ` as ${profile.name}` : ""}.`);
  else if (profile.verified === false) rep.add("UNVERIFIED_SOURCE", "MEDIUM", "The source code isn't verified on Sourcify, so nobody can easily check what this contract does.");
  else rep.add("LOOKUP_UNAVAILABLE", "INFO", "Could not check source verification on Sourcify.");

  // proxies
  let proxy = null;
  const body = code.slice(2);
  if (body.length === 90 && body.startsWith(MINIMAL_PREFIX) && body.endsWith(MINIMAL_SUFFIX)) {
    const impl = toChecksumAddress("0x" + body.slice(MINIMAL_PREFIX.length, MINIMAL_PREFIX.length + 40));
    proxy = { type: "eip1167", implementation: impl };
    rep.add("MINIMAL_PROXY", "INFO", `A minimal proxy (EIP-1167): every call runs the code at ${impl}. It can't be upgraded.`);
  } else {
    const [implWord, adminWord, beaconWord] = await Promise.all([
      lookups.getStorageAt(chainId, address, SLOT_IMPLEMENTATION),
      lookups.getStorageAt(chainId, address, SLOT_ADMIN),
      lookups.getStorageAt(chainId, address, SLOT_BEACON),
    ]);
    if (implWord === null || adminWord === null || beaconWord === null) {
      rep.add("LOOKUP_UNAVAILABLE", "INFO", "Could not read the EIP-1967 proxy slots.");
    }
    const impl = wordToAddress(implWord);
    const admin = wordToAddress(adminWord);
    const beacon = wordToAddress(beaconWord);
    if (beacon && beacon !== ZERO) {
      const ret = await lookups.ethCall(chainId, beacon, SEL_IMPLEMENTATION);
      const bImpl = wordToAddress(ret);
      proxy = { type: "eip1967-beacon", beacon, implementation: bImpl && bImpl !== ZERO ? bImpl : null };
      rep.add("UPGRADEABLE_BEACON", "MEDIUM",
        `Upgradeable beacon proxy (EIP-1967): its code comes from the beacon ${beacon}, and whoever controls that beacon can change it at any time.`);
      if (!proxy.implementation) rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not read the implementation from the beacon ${beacon}.`);
    } else if (impl && impl !== ZERO) {
      proxy = { type: "eip1967", implementation: impl, admin: admin && admin !== ZERO ? admin : null };
      rep.add("UPGRADEABLE_PROXY", "MEDIUM",
        "Upgradeable proxy (EIP-1967): whoever controls the upgrade can replace this contract's code at any time, " +
        "including with code that takes funds approved to it.");
      if (proxy.admin) {
        const adminKind = await classifyHolder(chainId, proxy.admin, lookups);
        proxy.admin_kind = adminKind;
        if (adminKind === "eoa") {
          rep.add("ADMIN_IS_EOA", "MEDIUM", `The proxy admin ${proxy.admin} is a single wallet (EOA): one private key can upgrade this contract.`);
        } else if (adminKind === "contract") {
          rep.add("ADMIN_IS_CONTRACT", "INFO", `The proxy admin ${proxy.admin} is a contract (possibly a multisig or timelock; not analyzed).`);
        }
      } else {
        rep.add("UPGRADE_VIA_IMPLEMENTATION", "INFO", "No EIP-1967 admin is set: upgrades are probably controlled by the implementation's own logic (UUPS), usually its owner.");
      }
    }
    if (!proxy) {
      const [zImplWord, zAdminWord, uupsWord] = await Promise.all([
        lookups.getStorageAt(chainId, address, SLOT_ZOS_IMPLEMENTATION),
        lookups.getStorageAt(chainId, address, SLOT_ZOS_ADMIN),
        lookups.getStorageAt(chainId, address, SLOT_PROXIABLE),
      ]);
      const zImpl = wordToAddress(zImplWord);
      const zAdmin = wordToAddress(zAdminWord);
      const uImpl = wordToAddress(uupsWord);
      if (zImpl && zImpl !== ZERO) {
        proxy = { type: "zeppelinos", implementation: zImpl, admin: zAdmin && zAdmin !== ZERO ? zAdmin : null };
      } else if (uImpl && uImpl !== ZERO) {
        proxy = { type: "eip1822", implementation: uImpl, admin: null };
      }
      if (proxy) {
        rep.add("UPGRADEABLE_PROXY", "MEDIUM",
          `Upgradeable proxy (${proxy.type === "zeppelinos" ? "ZeppelinOS-style" : "EIP-1822 UUPS"}): whoever controls the upgrade can ` +
          "replace this contract's code at any time, including with code that takes funds approved to it.");
        if (proxy.admin) {
          const adminKind = await classifyHolder(chainId, proxy.admin, lookups);
          proxy.admin_kind = adminKind;
          if (adminKind === "eoa") {
            rep.add("ADMIN_IS_EOA", "MEDIUM", `The proxy admin ${proxy.admin} is a single wallet (EOA): one private key can upgrade this contract.`);
          } else if (adminKind === "contract") {
            rep.add("ADMIN_IS_CONTRACT", "INFO", `The proxy admin ${proxy.admin} is a contract (possibly a multisig or timelock; not analyzed).`);
          }
        } else if (proxy.type === "eip1822") {
          rep.add("UPGRADE_VIA_IMPLEMENTATION", "INFO", "Upgrades are controlled by the implementation's own logic (UUPS), usually its owner.");
        }
      }
    }
  }

  // the implementation behind a proxy
  if (proxy && proxy.implementation) {
    const im = await describeCode(chainId, proxy.implementation, lookups);
    proxy.implementation_has_code = im.code === null ? null : im.code !== "0x";
    proxy.implementation_verified = im.verified;
    proxy.implementation_name = im.name;
    if (im.code === "0x") {
      rep.add("IMPLEMENTATION_NO_CODE", "HIGH", `The proxy points at ${proxy.implementation}, which has no code: calls to it will fail or do nothing.`);
    } else if (im.verified === false) {
      rep.add("IMPLEMENTATION_UNVERIFIED", "MEDIUM", `The implementation ${proxy.implementation}'s source isn't verified on Sourcify.`);
    } else if (im.verified === true) {
      rep.add("IMPLEMENTATION_VERIFIED", "INFO", `Implementation ${proxy.implementation} is verified on Sourcify${im.name ? ` as ${im.name}` : ""}.`);
    } else {
      rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not fully check the implementation ${proxy.implementation}.`);
    }
  }
  profile.proxy = proxy;

  // owner-style getters (reverts and non-address answers are ignored)
  let owner = null;
  for (const [fn, sel] of OWNER_GETTERS) {
    const a = wordToAddress(await lookups.ethCall(chainId, address, sel));
    if (a) { owner = { function: fn, address: a }; break; }
  }
  if (owner) {
    if (owner.address === ZERO) {
      owner.kind = "zero";
      rep.add("OWNERSHIP_RENOUNCED", "INFO", `${owner.function} returns the zero address: ownership looks renounced.`);
    } else {
      owner.kind = await classifyHolder(chainId, owner.address, lookups);
      if (owner.kind === "eoa") {
        rep.add("OWNER_IS_EOA", "MEDIUM", `${owner.function} is ${owner.address}, a single wallet (EOA): one private key controls the owner-only functions.`);
      } else if (owner.kind === "contract") {
        rep.add("OWNER_IS_CONTRACT", "INFO", `${owner.function} is ${owner.address}, a contract (possibly a multisig or timelock; not analyzed).`);
      } else {
        rep.add("LOOKUP_UNAVAILABLE", "INFO", `Could not check what kind of account the owner ${owner.address} is.`);
      }
    }
  }
  profile.owner = owner;

  return { kind: "contract", chain_id: chainId, risk: rep.risk(), findings: rep.findings, profile };
}
