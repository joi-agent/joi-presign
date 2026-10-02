from eth_abi import encode

from joi_presign.abi import selector
from joi_presign.core import analyze

from conftest import (DELEGATED, EOA, FRESH, NOW, ROUTER, SHADY, SIGNER, TOKEN, UNKNOWN_ADDR,
                      FakeLookups, calldata, codes)

MAX = 2**256 - 1


def tx(data, to=TOKEN, value=0, **kw):
    return {"chainId": 1, "from": SIGNER, "to": to, "value": hex(value), "data": data, **kw}


def test_unlimited_approve_to_verified_router_is_medium(L):
    r = analyze(tx(calldata("approve(address,uint256)", ["address", "uint256"], [ROUTER, MAX])), 1, L)
    assert codes(r) == {"UNLIMITED_APPROVAL": "MEDIUM"}
    assert r["risk"] == "MEDIUM"
    assert r["decoded"]["function"] == "approve(address,uint256)"


def test_unlimited_approve_to_unverified_contract_is_high(L):
    r = analyze(tx(calldata("approve(address,uint256)", ["address", "uint256"], [SHADY, MAX])), 1, L)
    assert codes(r) == {"SPENDER_UNVERIFIED": "MEDIUM", "UNLIMITED_APPROVAL": "HIGH"}
    assert r["risk"] == "HIGH"


def test_approve_to_eoa_is_high_even_when_small(L):
    r = analyze(tx(calldata("approve(address,uint256)", ["address", "uint256"], [EOA, 10**18])), 1, L)
    assert codes(r) == {"APPROVAL_TO_EOA": "HIGH"}


def test_approve_to_7702_delegated_eoa(L):
    r = analyze(tx(calldata("approve(address,uint256)", ["address", "uint256"], [DELEGATED, 5])), 1, L)
    assert codes(r)["DELEGATED_EOA"] == "MEDIUM"
    assert codes(r)["APPROVAL_TO_EOA"] == "HIGH"


def test_large_but_finite_approve(L):
    r = analyze(tx(calldata("increaseAllowance(address,uint256)", ["address", "uint256"], [ROUTER, 10**28])), 1, L)
    assert codes(r) == {"LARGE_APPROVAL": "MEDIUM"}


def test_revoke_is_low(L):
    r = analyze(tx(calldata("approve(address,uint256)", ["address", "uint256"], [EOA, 0])), 1, L)
    assert codes(r) == {"REVOKE": "INFO"}
    assert r["risk"] == "LOW"


def test_set_approval_for_all(L):
    r = analyze(tx(calldata("setApprovalForAll(address,bool)", ["address", "bool"], [SHADY, True])), 1, L)
    assert codes(r) == {"SPENDER_UNVERIFIED": "MEDIUM", "APPROVAL_FOR_ALL": "HIGH"}
    r = analyze(tx(calldata("setApprovalForAll(address,bool)", ["address", "bool"], [ROUTER, True])), 1, L)
    assert codes(r) == {"APPROVAL_FOR_ALL": "MEDIUM"}
    r = analyze(tx(calldata("setApprovalForAll(address,bool)", ["address", "bool"], [SHADY, False])), 1, L)
    assert codes(r) == {"REVOKE": "INFO"}


def test_transfer_to_fresh_address(L):
    r = analyze(tx(calldata("transfer(address,uint256)", ["address", "uint256"], [FRESH, 100])), 1, L)
    assert codes(r) == {"TRANSFER_TO_FRESH_ADDRESS": "MEDIUM"}
    r = analyze(tx(calldata("transfer(address,uint256)", ["address", "uint256"], [EOA, 100])), 1, L)
    assert codes(r) == {}


def test_transfer_from_someone_else(L):
    r = analyze(tx(calldata("transferFrom(address,address,uint256)", ["address", "address", "uint256"], [EOA, FRESH, 1])), 1, L)
    assert codes(r) == {"MOVES_OTHERS_ASSETS": "LOW", "TRANSFER_TO_FRESH_ADDRESS": "MEDIUM"}


def test_erc1155_safe_transfer(L):
    data = calldata("safeTransferFrom(address,address,uint256,uint256,bytes)",
                    ["address", "address", "uint256", "uint256", "bytes"], [SIGNER, FRESH, 7, 1, b""])
    assert codes(analyze(tx(data), 1, L)) == {"TRANSFER_TO_FRESH_ADDRESS": "MEDIUM"}


def test_native_value_transfer(L):
    assert codes(analyze(tx("0x", to=FRESH, value=10**18), 1, L)) == {"TRANSFER_TO_FRESH_ADDRESS": "MEDIUM"}
    assert codes(analyze(tx("0x", to=EOA, value=10**18), 1, L)) == {}


def test_permit2_onchain_approve(L):
    data = calldata("approve(address,address,uint160,uint48)", ["address", "address", "uint160", "uint48"],
                    [TOKEN, SHADY, 2**160 - 1, NOW + 365 * 86400])
    r = analyze(tx(data, to="0x000000000022D473030F116dDEE9F6B43aC78BA3"), 1, L)
    assert codes(r) == {"SPENDER_UNVERIFIED": "MEDIUM", "UNLIMITED_APPROVAL": "HIGH", "LONG_EXPIRATION": "MEDIUM"}


def test_onchain_permit_call(L):
    data = calldata("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                    ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
                    [SIGNER, EOA, MAX, NOW + 60, 27, b"\x01" * 32, b"\x02" * 32])
    assert codes(analyze(tx(data), 1, L)) == {"APPROVAL_TO_EOA": "HIGH", "UNLIMITED_APPROVAL": "HIGH"}


def test_multicall_inner_approve_is_found(L):
    inner = bytes.fromhex(calldata("approve(address,uint256)", ["address", "uint256"], [EOA, 5])[2:])
    data = selector("multicall(bytes[])") + encode(["bytes[]"], [[inner]]).hex()
    r = analyze(tx(data, to=ROUTER), 1, L)
    assert codes(r) == {"APPROVAL_TO_EOA": "HIGH"}
    assert r["decoded"]["calls"][0]["function"] == "approve(address,uint256)"


def test_aggregate3_inner_targets(L):
    inner = bytes.fromhex(calldata("approve(address,uint256)", ["address", "uint256"], [SHADY, MAX])[2:])
    data = selector("aggregate3((address,bool,bytes)[])") + encode(["(address,bool,bytes)[]"], [[(TOKEN, False, inner)]]).hex()
    r = analyze(tx(data, to=ROUTER), 1, L)
    assert r["decoded"]["calls"][0]["to"].lower() == TOKEN
    assert codes(r)["UNLIMITED_APPROVAL"] == "HIGH"


def test_safe_multisend_delegatecall_and_inner(L):
    inner = bytes.fromhex(calldata("approve(address,uint256)", ["address", "uint256"], [EOA, 5])[2:])
    entry1 = bytes([0]) + bytes.fromhex(TOKEN[2:]) + (0).to_bytes(32, "big") + len(inner).to_bytes(32, "big") + inner
    entry2 = bytes([1]) + bytes.fromhex(SHADY[2:]) + (0).to_bytes(32, "big") + (0).to_bytes(32, "big")
    data = selector("multiSend(bytes)") + encode(["bytes"], [entry1 + entry2]).hex()
    r = analyze(tx(data, to=ROUTER), 1, L)
    assert codes(r) == {"APPROVAL_TO_EOA": "HIGH", "DELEGATECALL_IN_BATCH": "HIGH"}
    assert len(r["decoded"]["calls"]) == 2


def test_truncated_multisend(L):
    data = selector("multiSend(bytes)") + encode(["bytes"], [bytes([0]) + b"\x00" * 30]).hex()
    assert codes(analyze(tx(data, to=ROUTER), 1, L)) == {"MALFORMED_CALLDATA": "MEDIUM"}


def test_unknown_selector_guessed_vs_blind():
    L = FakeLookups(signatures={"0xdeadbeef": ["claimAirdrop()"]})
    r = analyze(tx("0xdeadbeef", to=ROUTER), 1, L)
    assert codes(r) == {"UNKNOWN_FUNCTION_GUESSED": "LOW"}
    assert r["decoded"]["function_guesses"] == ["claimAirdrop()"]
    r = analyze(tx("0xcafebabe", to=SHADY), 1, L)
    assert codes(r) == {"UNKNOWN_FUNCTION": "MEDIUM", "TARGET_UNVERIFIED": "MEDIUM"}


def test_chain_mismatch(L):
    r = analyze(tx("0x", to=EOA, value=1, chainId=8453), 1, L)
    assert codes(r)["CHAIN_MISMATCH"] == "HIGH"


def test_contract_creation_and_bad_input(L):
    assert codes(analyze({"to": None, "data": "0x6000"}, 1, L)) == {"CONTRACT_CREATION": "MEDIUM"}
    assert codes(analyze(tx("0x12"), 1, L)) == {"MALFORMED_CALLDATA": "MEDIUM"}
    assert codes(analyze(tx("0xzz"), 1, L)) == {"MALFORMED_CALLDATA": "MEDIUM"}
    assert codes(analyze(tx("0x" + selector("approve(address,uint256)")[2:] + "00"), 1, L)) == {"MALFORMED_CALLDATA": "MEDIUM"}


def test_lookups_failing_degrades_to_info(L):
    r = analyze(tx(calldata("approve(address,uint256)", ["address", "uint256"], [UNKNOWN_ADDR, MAX])), 1, L)
    assert codes(r) == {"LOOKUP_UNAVAILABLE": "INFO", "UNLIMITED_APPROVAL": "HIGH"}


def test_jsonrpc_wrapper(L):
    req = {"method": "eth_sendTransaction", "params": [tx(calldata("approve(address,uint256)", ["address", "uint256"], [EOA, 1]))]}
    assert analyze(req, 1, L)["kind"] == "tx"
