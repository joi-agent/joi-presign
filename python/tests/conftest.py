import os
import sys

import pytest
from eth_abi import encode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from joi_presign.abi import selector  # noqa: E402

NOW = 1_790_000_000
TOKEN = "0x" + "11" * 20
ROUTER = "0x" + "22" * 20        # verified contract
SHADY = "0x" + "33" * 20         # unverified contract
EOA = "0x" + "44" * 20           # wallet with history
FRESH = "0x" + "55" * 20         # wallet with no history
DELEGATED = "0x" + "66" * 20     # EIP-7702 EOA
SIGNER = "0x" + "77" * 20
UNKNOWN_ADDR = "0x" + "88" * 20  # lookups fail


class FakeLookups:
    def __init__(self, signatures=None):
        self.code = {ROUTER: "contract", SHADY: "contract", TOKEN: "contract", EOA: "none", FRESH: "none",
                     DELEGATED: "7702", SIGNER: "none"}
        self.verified = {ROUTER: True, SHADY: False, TOKEN: True}
        self.counts = {EOA: 12, FRESH: 0, SIGNER: 5}
        self.signatures = signatures if signatures is not None else {}

    def now(self):
        return NOW

    def code_kind(self, chain_id, addr):
        return self.code.get(addr.lower())

    def tx_count(self, chain_id, addr):
        return self.counts.get(addr.lower())

    def sourcify_verified(self, chain_id, addr):
        return self.verified.get(addr.lower())

    def selector_signatures(self, sel):
        return self.signatures.get(sel, [])


@pytest.fixture
def L():
    return FakeLookups()


def calldata(sig, types, values):
    return selector(sig) + encode(types, values).hex()


def codes(report):
    return {f["code"]: f["severity"] for f in report["findings"]}
