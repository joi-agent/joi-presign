#!/usr/bin/env python3
"""Verify src/price.js FEEDS against Chainlink's official data-feeds directory and on-chain (stdlib only).

For each entry: the proxy must be listed in the network's directory JSON (the data behind
docs.chain.link/data-feeds/price-feeds/addresses) with the same path, and on-chain description() must equal the pair
and decimals() must match the directory. Heartbeat differences are reported. Exit code 1 on any mismatch.
"""
import json
import re
import sys
import urllib.request

DIRS = {
    "ethereum": "https://reference-data-directory.vercel.app/feeds-mainnet.json",
    "base": "https://reference-data-directory.vercel.app/feeds-ethereum-mainnet-base-1.json",
    "arbitrum": "https://reference-data-directory.vercel.app/feeds-ethereum-mainnet-arbitrum-1.json",
}
RPCS = {"ethereum": "https://ethereum-rpc.publicnode.com", "base": "https://base-rpc.publicnode.com", "arbitrum": "https://arb1.arbitrum.io/rpc"}


def get_json(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                 headers={"User-Agent": "joi-presign-feeds/1.0", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def eth_call(chain, to, data):
    return get_json(RPCS[chain], {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": to, "data": data}, "latest"]}).get("result")


def decode_string(h):
    b = bytes.fromhex(h[2:])
    off = int.from_bytes(b[:32], "big")
    n = int.from_bytes(b[off:off + 32], "big")
    return b[off + 32:off + 32 + n].decode()


def load_feeds(path="src/price.js"):
    src = open(path, encoding="utf-8").read()
    body = src[src.index("export const FEEDS"):src.index("};", src.index("export const FEEDS"))]
    feeds, chain = {}, None
    for line in body.splitlines():
        m = re.match(r"\s*(ethereum|base|arbitrum): \{", line)
        if m:
            chain = m.group(1)
            feeds[chain] = {}
            continue
        m = re.match(r'\s*([A-Z0-9]+): \["([^"]+)", "(0x[0-9a-fA-F]{40})", (\d+), "([^"]+)"\]', line)
        if m and chain:
            feeds[chain][m.group(1)] = (m.group(2), m.group(3), int(m.group(4)), m.group(5))
    return feeds


def main():
    feeds, bad = load_feeds(), 0
    for chain, assets in feeds.items():
        directory = {e.get("proxyAddress", "").lower(): e for e in get_json(DIRS[chain]) if e.get("proxyAddress")}
        for asset, (pair, proxy, hb, path) in assets.items():
            e = directory.get(proxy.lower())
            problems = []
            if not e:
                problems.append("proxy not in the official directory")
            else:
                if e.get("path") != path:
                    problems.append(f"directory path {e.get('path')!r} != {path!r}")
                if e.get("heartbeat") is not None and int(e["heartbeat"]) != hb:
                    problems.append(f"directory heartbeat {e.get('heartbeat')} != {hb}")
            desc = decode_string(eth_call(chain, proxy, "0x7284e416"))
            dec = int(eth_call(chain, proxy, "0x313ce567"), 16)
            if desc.strip().upper() != pair.upper():
                problems.append(f"on-chain description {desc!r} != {pair!r}")
            if e and e.get("decimals") is not None and int(e["decimals"]) != dec:
                problems.append(f"on-chain decimals {dec} != directory {e.get('decimals')}")
            status = "OK" if not problems else "MISMATCH: " + "; ".join(problems)
            bad += bool(problems)
            print(f"{chain:9s} {asset:6s} {proxy} {desc!r:18s} dec={dec} hb={hb}  {status}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
