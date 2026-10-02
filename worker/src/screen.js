// Sanctions screening of an EVM address against the OFAC SDN list's digital-currency addresses.
// The list is bundled at build time by tools/gen_ofac.py (refreshed by joi-ofac-refresh); no lookup can make a
// screen fail, so this route never answers 503. The optional account kind comes from `lookups.codeKind`.
import { isAddress, toChecksumAddress } from "./abi.js";
import { CHAINS } from "./core.js";
import { OFAC, OFAC_META, OFAC_GENERATED_AT } from "./ofac-data.js";

export const SCREEN_NOTICE =
  "Screening against the OFAC SDN list only; not legal advice; absence from the list is not a clearance.";

const HEX40 = /^0x[0-9a-fA-F]{40}$/;

/** {chainId, address (lowercase), checksumOk} or {error}. Any case is accepted; a bad checksum only warns. */
export function parseScreenTarget(chainRaw, addressRaw) {
  const chainName = chainRaw === undefined || chainRaw === null || chainRaw === "" ? "base" : String(chainRaw);
  const chainId = CHAINS[chainName];
  if (!chainId) return { error: `unknown chain '${chainName}'. Use one of: ${Object.keys(CHAINS).join(", ")}` };
  if (typeof addressRaw !== "string" || !HEX40.test(addressRaw.trim())) {
    return { error: "address must be a 0x-prefixed 20-byte hex address" };
  }
  const a = addressRaw.trim();
  const mixed = /[a-f]/.test(a.slice(2)) && /[A-F]/.test(a.slice(2));
  return { chainId, address: a.toLowerCase(), checksumOk: !mixed || isAddress(a) };
}

/** Pure lookup in the bundled list. */
export function screenMatches(addressLower) {
  return (OFAC[addressLower] || []).map(([entity, label, uid, programs]) => ({
    entity, currency_label: label, sdn_uid: uid, programs,
  }));
}

export async function screenAddress(target, lookups) {
  const matches = screenMatches(target.address);
  let kind = "unknown";
  try {
    const k = lookups && typeof lookups.codeKind === "function" ? await lookups.codeKind(target.chainId, target.address) : null;
    kind = k === "none" ? "eoa" : k === "7702" ? "eoa-7702" : k === "contract" ? "contract" : "unknown";
  } catch { /* kind stays unknown; the screen itself doesn't depend on it */ }
  const now = lookups && typeof lookups.now === "function" ? lookups.now() : Math.floor(Date.now() / 1000);
  const warnings = target.checksumOk ? [] : ["The mixed-case input is not a valid EIP-55 checksum: check the address for a typo."];
  return {
    address: toChecksumAddress(target.address),
    sanctioned: matches.length > 0,
    matches,
    list_published: OFAC_META.published,
    list: { name: "OFAC SDN (digital currency addresses)", source: OFAC_META.source, published: OFAC_META.published, evm_address_count: OFAC_META.evm_address_count, generated_at: OFAC_GENERATED_AT },
    checked_at: new Date(now * 1000).toISOString(),
    chain_id: target.chainId,
    kind,
    warnings,
    notice: SCREEN_NOTICE,
  };
}
