"""Network lookups with timeouts. Every method returns None when the answer is unknown."""
import json
import os
import time
import urllib.error
import urllib.request

RPCS = {
    1: "https://ethereum-rpc.publicnode.com",
    42161: "https://arb1.arbitrum.io/rpc",
    8453: "https://mainnet.base.org",
}
SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{addr}"
FOURBYTE = "https://www.4byte.directory/api/v1/signatures/?hex_signature={sel}"


class NetLookups:
    def __init__(self, timeout=8, cache_dir=None, opener=None, clock=time.time):
        self.timeout = timeout
        self.cache_dir = cache_dir or os.path.expanduser("~/.cache/joi-presign")
        self.opener = opener or urllib.request.urlopen
        self.clock = clock
        self._memo = {}

    def now(self):
        return int(self.clock())

    def _request(self, url, body=None):
        headers = {"User-Agent": "joi-presign/0.1", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        return self.opener(req, timeout=self.timeout)

    def _rpc(self, chain_id, method, params):
        url = RPCS.get(chain_id)
        if not url:
            return None
        key = (chain_id, method, json.dumps(params))
        if key in self._memo:
            return self._memo[key]
        try:
            with self._request(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}) as r:
                result = json.load(r).get("result")
        except (urllib.error.URLError, OSError, ValueError, AttributeError, TypeError):
            result = None
        self._memo[key] = result
        return result

    def code_kind(self, chain_id, addr):
        """'none' (no code), '7702' (EOA with delegation), 'contract', or None if unknown."""
        code = self._rpc(chain_id, "eth_getCode", [addr, "latest"])
        if not isinstance(code, str):
            return None
        if code in ("0x", "0x0"):
            return "none"
        if code.lower().startswith("0xef0100") and len(code) == 2 + 46:
            return "7702"
        return "contract"

    def tx_count(self, chain_id, addr):
        n = self._rpc(chain_id, "eth_getTransactionCount", [addr, "latest"])
        try:
            return int(n, 16) if isinstance(n, str) else None
        except ValueError:
            return None

    def sourcify_verified(self, chain_id, addr):
        key = ("sourcify", chain_id, addr.lower())
        if key in self._memo:
            return self._memo[key]
        try:
            with self._request(SOURCIFY.format(chain=chain_id, addr=addr)) as r:
                result = json.load(r).get("match") in ("match", "exact_match", "partial", "perfect")
        except urllib.error.HTTPError as e:
            result = False if e.code == 404 else None
        except (urllib.error.URLError, OSError, ValueError, AttributeError, TypeError):
            result = None
        self._memo[key] = result
        return result

    def selector_signatures(self, sel):
        """Text signatures for a 4-byte selector, oldest registration first (newer ones are often spam)."""
        cache_file = os.path.join(self.cache_dir, "4byte.json")
        cache = {}
        try:
            with open(cache_file) as f:
                cache = json.load(f)
        except (OSError, ValueError):
            pass
        if sel in cache:
            return cache[sel]
        try:
            with self._request(FOURBYTE.format(sel=sel)) as r:
                results = json.load(r).get("results", [])
        except (urllib.error.URLError, OSError, ValueError, AttributeError, TypeError):
            return None
        sigs = [x["text_signature"] for x in sorted(results, key=lambda x: x.get("id", 0)) if "text_signature" in x]
        cache[sel] = sigs
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(cache, f)
        except OSError:
            pass
        return sigs
