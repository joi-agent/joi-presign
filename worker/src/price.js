// USD prices from Chainlink data feeds (latestRoundData), for a small explicit set of assets per chain.
// Feed proxies, pairs and heartbeats come from Chainlink's official data-feeds directory, the JSON behind
// https://docs.chain.link/data-feeds/price-feeds/addresses (one file per network, URLs below). Each entry was checked
// on-chain on 2026-10-02 with tools/check_feeds.py: description() matches the pair and decimals() matches.
// The standard feed (path "<asset>-usd") is used where it exists; on Base only the SVR variant is listed for ETH and BTC.
import { CHAINS } from "./core.js";
import { LookupUnavailable } from "./profile.js";

export const FEED_DIRECTORY = {
  ethereum: "https://reference-data-directory.vercel.app/feeds-mainnet.json",
  base: "https://reference-data-directory.vercel.app/feeds-ethereum-mainnet-base-1.json",
  arbitrum: "https://reference-data-directory.vercel.app/feeds-ethereum-mainnet-arbitrum-1.json",
};

// asset -> [pair, proxy address, heartbeat seconds, directory path]
export const FEEDS = {
  // Source: FEED_DIRECTORY.ethereum
  ethereum: {
    ETH: ["ETH / USD", "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", 3600, "eth-usd"],
    BTC: ["BTC / USD", "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c", 3600, "btc-usd"],
    USDC: ["USDC / USD", "0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6", 82800, "usdc-usd"],
    USDT: ["USDT / USD", "0x3E7d1eAB13ad0104d2750B8863b489D65364e32D", 86400, "usdt-usd"],
    DAI: ["DAI / USD", "0xAed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9", 3600, "dai-usd"],
    LINK: ["LINK / USD", "0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c", 3600, "link-usd"],
    STETH: ["STETH / USD", "0xCfE54B5cD566aB89272946F602D76Ea879CAb4a8", 3600, "steth-usd"],
  },
  // Source: FEED_DIRECTORY.base
  base: {
    ETH: ["ETH / USD", "0xa4250cE1aA15Ff4cb5E5a8655293b65694e436Ed", 1200, "eth-usd-svr"],
    BTC: ["BTC / USD", "0x32F587986D3fb47601157c19615d568BeD0BCabc", 1200, "btc-usd-svr"],
    CBBTC: ["cbBTC / USD", "0x07DA0E54543a844a80ABE69c8A12F22B3aA59f9D", 1200, "cbbtc-usd"],
    CBETH: ["CBETH / USD", "0xd7818272B9e248357d13057AAb0B417aF31E817d", 1200, "cbeth-usd"],
    USDC: ["USDC / USD", "0x7e860098F58bBFC8648a4311b374B1D669a2bc6B", 86400, "usdc-usd"],
    USDT: ["USDT / USD", "0xf19d560eB8d2ADf07BD6D13ed03e1D11215721F9", 86400, "usdt-usd"],
    DAI: ["DAI / USD", "0x591e79239a7d679378eC8c847e5038150364C78F", 86400, "dai-usd"],
    LINK: ["LINK / USD", "0x17CAb8FE31E32f08326e5E27412894e49B0f9D65", 86400, "link-usd"],
  },
  // Source: FEED_DIRECTORY.arbitrum
  arbitrum: {
    ETH: ["ETH / USD", "0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612", 1755, "eth-usd"],
    BTC: ["BTC / USD", "0x6ce185860a4963106506C203335A2910413708e9", 1755, "btc-usd"],
    USDC: ["USDC / USD", "0x50834F3163758fcC1Df9973b6e91f0F0F0434aD3", 255, "usdc-usd"],
    USDT: ["USDT / USD", "0x3f3f5dF88dC9F13eac63DF89EC16ef6e7E25DdE7", 255, "usdt-usd"],
    DAI: ["DAI / USD", "0xc5C8E77B397E531B8EC06BFb0048328B30E9eCfB", 86400, "dai-usd"],
    LINK: ["LINK / USD", "0x86E53CF1B870786351Da77A57575e79CB55812CB", 1755, "link-usd"],
  },
};

export const SEL = { description: "0x7284e416", decimals: "0x313ce567", latestRoundData: "0xfeaf968c" };
// A feed counts as stale when its last update is older than its heartbeat plus 10% (1 hour if no heartbeat is known).
export const STALE_GRACE = 1.1;

/** Supported "chain:ASSET" pairs, for docs and error messages. */
export function supportedPairs() {
  return Object.entries(FEEDS).flatMap(([chain, m]) => Object.keys(m).map((asset) => `${chain}:${asset}`));
}

export function parsePriceTarget(chainRaw, assetRaw) {
  const chain = chainRaw === undefined || chainRaw === null || chainRaw === "" ? "base" : String(chainRaw);
  if (!CHAINS[chain] || !FEEDS[chain]) return { error: `unknown chain '${chain}'. Use one of: ${Object.keys(FEEDS).join(", ")}` };
  if (typeof assetRaw !== "string" || assetRaw.trim() === "") return { error: "asset is required (e.g. ETH)" };
  const asset = assetRaw.trim().toUpperCase();
  const f = FEEDS[chain][asset];
  if (!f) return { error: `no feed for ${asset} on ${chain}. Supported on ${chain}: ${Object.keys(FEEDS[chain]).join(", ")}` };
  const [pair, feed, heartbeat, path] = f;
  return { chain, chainId: CHAINS[chain], asset, pair, feed, heartbeat, path };
}

const norm = (s) => String(s).replace(/\s+/g, " ").trim().toUpperCase();

function word(hex, i) {
  return BigInt("0x" + (hex.slice(2 + i * 64, 2 + (i + 1) * 64) || "0"));
}

export function decodeString(hex) {
  if (typeof hex !== "string" || hex.length < 2 + 128) return null;
  try {
    const off = Number(word(hex, 0)) * 2 + 2;
    const len = Number(BigInt("0x" + hex.slice(off, off + 64)));
    const bytes = hex.slice(off + 64, off + 64 + len * 2);
    if (bytes.length !== len * 2) return null;
    return new TextDecoder().decode(Uint8Array.from(bytes.match(/../g) || [], (b) => parseInt(b, 16)));
  } catch {
    return null;
  }
}

/** Decimal string of a scaled integer: formatUnits(274897796500n, 8) = "2748.977965". */
export function formatUnits(v, decimals) {
  const neg = v < 0n;
  const s = (neg ? -v : v).toString().padStart(decimals + 1, "0");
  const whole = s.slice(0, s.length - decimals);
  const frac = s.slice(s.length - decimals).replace(/0+$/, "");
  return (neg ? "-" : "") + whole + (frac ? "." + frac : "");
}

export async function readPrice(t, lookups) {
  const [desc, dec, round] = await Promise.all([
    lookups.ethCall(t.chainId, t.feed, SEL.description),
    lookups.ethCall(t.chainId, t.feed, SEL.decimals),
    lookups.ethCall(t.chainId, t.feed, SEL.latestRoundData),
  ]);
  if (desc === null || dec === null || round === null) throw new LookupUnavailable("could not read the price feed");
  const description = decodeString(desc);
  if (description === null || norm(description) !== norm(t.pair)) {
    throw new LookupUnavailable(`price feed description mismatch (expected '${t.pair}', got '${description}')`);
  }
  if (dec.length < 66 || round.length < 2 + 5 * 64) throw new LookupUnavailable("unexpected price feed response");
  const decimals = Number(word(dec, 0));
  const roundId = word(round, 0);
  let answer = word(round, 1);
  if (answer >= 1n << 255n) answer -= 1n << 256n; // int256
  const updatedAt = Number(word(round, 3));
  if (answer <= 0n || updatedAt === 0 || decimals > 36) throw new LookupUnavailable("the price feed returned no usable answer");
  const now = typeof lookups.now === "function" ? lookups.now() : Math.floor(Date.now() / 1000);
  const age = Math.max(0, now - updatedAt);
  const limit = t.heartbeat ? Math.round(t.heartbeat * STALE_GRACE) : 3600;
  return {
    asset: t.asset,
    chain: t.chain,
    chain_id: t.chainId,
    price: formatUnits(answer, decimals),
    currency: "USD",
    decimals,
    updated_at: new Date(updatedAt * 1000).toISOString(),
    age_seconds: age,
    stale: age > limit,
    heartbeat_seconds: t.heartbeat,
    feed: t.feed,
    description,
    round_id: roundId.toString(),
    source: "Chainlink data feed (latestRoundData)",
  };
}
