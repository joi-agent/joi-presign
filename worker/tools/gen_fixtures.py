"""Generate test/fixtures.json: every case run through the Python joi_presign.analyze with a fake
lookups object, so the Worker port can be checked for identical findings.
Run: python3 tools/gen_fixtures.py (needs the python/ package importable)"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = os.path.expanduser("~/joi-presign")
sys.path.insert(0, PY)
sys.path.insert(0, os.path.join(PY, "tests"))

from eth_abi import encode  # noqa: E402

from conftest import (DELEGATED, EOA, FRESH, MM_DELEGATOR, NOW, ROUTER, SHADY, SIGNER, SIMPLE7702, TOKEN,  # noqa: E402
                      UNKNOWN_ADDR, FakeLookups, calldata)
from joi_presign.abi import selector  # noqa: E402
from joi_presign.core import PERMIT2, analyze  # noqa: E402

MAX = 2**256 - 1
SIGS = {"0xdeadbeef": ["claimAirdrop()"]}


def tx(data, to=TOKEN, value=0, **kw):
    return {"chainId": 1, "from": SIGNER, "to": to, "value": hex(value), "data": data, **kw}


def eip2612(spender, value, deadline, chain=1):
    return {"types": {"EIP712Domain": [], "Permit": []}, "primaryType": "Permit",
            "domain": {"name": "USD Coin", "version": "2", "chainId": chain, "verifyingContract": TOKEN},
            "message": {"owner": SIGNER, "spender": spender, "value": str(value), "nonce": 0, "deadline": deadline}}


def permit2(primary, message):
    return {"types": {"EIP712Domain": []}, "primaryType": primary,
            "domain": {"name": "Permit2", "chainId": 8453, "verifyingContract": PERMIT2}, "message": message}


def seaport(offerer, consideration):
    return {"types": {"EIP712Domain": []}, "primaryType": "OrderComponents",
            "domain": {"name": "Seaport", "version": "1.6", "chainId": 1,
                       "verifyingContract": "0x0000000000000068F116a894984e2DB1123eB395"},
            "message": {"offerer": offerer,
                        "offer": [{"itemType": 2, "token": TOKEN, "identifierOrCriteria": "7", "startAmount": "1", "endAmount": "1"}],
                        "consideration": consideration}}


def type4(*auths, chain=1):
    return {"type": "0x4", "chainId": chain, "from": SIGNER, "to": SIGNER, "value": "0x0", "data": "0x",
            "authorizationList": list(auths)}


def auth(address, chain=1, nonce=0, key="address"):
    return {key: address, "chainId": chain, "nonce": nonce, "yParity": "0x0", "r": "0x01", "s": "0x02"}


A = lambda to, amt: calldata("approve(address,uint256)", ["address", "uint256"], [to, amt])  # noqa: E731
inner_eoa = bytes.fromhex(A(EOA, 5)[2:])
inner_shady = bytes.fromhex(A(SHADY, MAX)[2:])
entry1 = bytes([0]) + bytes.fromhex(TOKEN[2:]) + (0).to_bytes(32, "big") + len(inner_eoa).to_bytes(32, "big") + inner_eoa
entry2 = bytes([1]) + bytes.fromhex(SHADY[2:]) + (0).to_bytes(32, "big") + (0).to_bytes(32, "big")
nested = bytes.fromhex((selector("multicall(bytes[])") + encode(["bytes[]"], [[inner_eoa]]).hex())[2:])
for _ in range(3):
    nested = bytes.fromhex((selector("multicall(bytes[])") + encode(["bytes[]"], [[nested]]).hex())[2:])

CASES = {
    "unlimited_approve_verified": (tx(A(ROUTER, MAX)), 1),
    "unlimited_approve_unverified": (tx(A(SHADY, MAX)), 1),
    "approve_eoa_small": (tx(A(EOA, 10**18)), 1),
    "approve_7702": (tx(A(DELEGATED, 5)), 1),
    "large_finite": (tx(calldata("increaseAllowance(address,uint256)", ["address", "uint256"], [ROUTER, 10**28])), 1),
    "revoke": (tx(A(EOA, 0)), 1),
    "approval_for_all_shady": (tx(calldata("setApprovalForAll(address,bool)", ["address", "bool"], [SHADY, True])), 1),
    "approval_for_all_router": (tx(calldata("setApprovalForAll(address,bool)", ["address", "bool"], [ROUTER, True])), 1),
    "approval_for_all_revoke": (tx(calldata("setApprovalForAll(address,bool)", ["address", "bool"], [SHADY, False])), 1),
    "transfer_fresh": (tx(calldata("transfer(address,uint256)", ["address", "uint256"], [FRESH, 100])), 1),
    "transfer_known": (tx(calldata("transfer(address,uint256)", ["address", "uint256"], [EOA, 100])), 1),
    "transfer_from_other": (tx(calldata("transferFrom(address,address,uint256)", ["address", "address", "uint256"], [EOA, FRESH, 1])), 1),
    "erc1155_transfer": (tx(calldata("safeTransferFrom(address,address,uint256,uint256,bytes)",
                                     ["address", "address", "uint256", "uint256", "bytes"], [SIGNER, FRESH, 7, 1, b""])), 1),
    "erc1155_batch": (tx(calldata("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
                                  ["address", "address", "uint256[]", "uint256[]", "bytes"], [SIGNER, FRESH, [1, 2], [3, 4], b"\x01\x02"])), 1),
    "native_fresh": (tx("0x", to=FRESH, value=10**18), 1),
    "native_known": (tx("0x", to=EOA, value=10**18), 1),
    "permit2_onchain": (tx(calldata("approve(address,address,uint160,uint48)", ["address", "address", "uint160", "uint48"],
                                    [TOKEN, SHADY, 2**160 - 1, NOW + 365 * 86400]), to=PERMIT2), 1),
    "permit_call": (tx(calldata("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                                ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
                                [SIGNER, EOA, MAX, NOW + 60, 27, b"\x01" * 32, b"\x02" * 32])), 1),
    "multicall_inner": (tx(selector("multicall(bytes[])") + encode(["bytes[]"], [[inner_eoa]]).hex(), to=ROUTER), 1),
    "multicall_deadline": (tx(selector("multicall(uint256,bytes[])") + encode(["uint256", "bytes[]"], [NOW, [inner_eoa, inner_shady]]).hex(), to=ROUTER), 1),
    "aggregate": (tx(selector("aggregate((address,bytes)[])") + encode(["(address,bytes)[]"], [[(TOKEN, inner_eoa)]]).hex(), to=ROUTER), 1),
    "aggregate3": (tx(selector("aggregate3((address,bool,bytes)[])") + encode(["(address,bool,bytes)[]"], [[(TOKEN, False, inner_shady)]]).hex(), to=ROUTER), 1),
    "try_aggregate": (tx(selector("tryAggregate(bool,(address,bytes)[])") + encode(["bool", "(address,bytes)[]"], [True, [(TOKEN, inner_shady)]]).hex(), to=ROUTER), 1),
    "multisend": (tx(selector("multiSend(bytes)") + encode(["bytes"], [entry1 + entry2]).hex(), to=ROUTER), 1),
    "multisend_truncated": (tx(selector("multiSend(bytes)") + encode(["bytes"], [bytes([0]) + b"\x00" * 30]).hex(), to=ROUTER), 1),
    "nesting_too_deep": (tx("0x" + nested.hex(), to=ROUTER), 1),
    "unknown_guessed": (tx("0xdeadbeef", to=ROUTER), 1),
    "unknown_blind": (tx("0xcafebabe", to=SHADY), 1),
    "chain_mismatch": (tx("0x", to=EOA, value=1, chainId=8453), 1),
    "contract_creation": ({"to": None, "data": "0x6000"}, 1),
    "short_calldata": (tx("0x12"), 1),
    "bad_hex": (tx("0xzz"), 1),
    "truncated_args": (tx("0x" + selector("approve(address,uint256)")[2:] + "00"), 1),
    "bad_to": (tx("0x", to="0x1234", value=1), 1),
    "lookups_fail": (tx(A(UNKNOWN_ADDR, MAX)), 1),
    "jsonrpc_tx": ({"method": "eth_sendTransaction", "params": [tx(A(EOA, 1))]}, 1),
    "eip2612_benign": (eip2612(ROUTER, 10**6, NOW + 600), 1),
    "eip2612_drainer": (eip2612(EOA, MAX, MAX), 1),
    "typed_chain_mismatch": (eip2612(ROUTER, 1, NOW + 60, chain=8453), 1),
    "permit2_single": (permit2("PermitSingle", {"details": {"token": TOKEN, "amount": str(2**160 - 1), "expiration": NOW + 400 * 86400, "nonce": 0},
                                                "spender": SHADY, "sigDeadline": NOW + 1800}), 8453),
    "permit2_batch_transfer": (permit2("PermitBatchTransferFrom", {"permitted": [{"token": TOKEN, "amount": "1000"}, {"token": ROUTER, "amount": str(MAX)}],
                                                                   "spender": ROUTER, "nonce": 1, "deadline": NOW + 60}), 8453),
    "seaport_giveaway": (seaport(SIGNER, [{"itemType": 0, "token": "0x" + "00" * 20, "startAmount": "1", "endAmount": "1", "recipient": EOA}]), 1),
    "seaport_normal": (seaport(SIGNER, [{"itemType": 0, "token": "0x" + "00" * 20, "startAmount": str(10**18), "endAmount": str(10**18), "recipient": SIGNER}]), 1),
    "unknown_typed": ({"types": {"EIP712Domain": []}, "primaryType": "Mail",
                       "domain": {"name": "Ether Mail", "chainId": 1, "verifyingContract": EOA}, "message": {"contents": "hi"}}, 1),
    "typed_via_jsonrpc_string": ({"method": "eth_signTypedData_v4", "params": [SIGNER, json.dumps(eip2612(ROUTER, 1, NOW + 60))]}, 1),
    "eth_sign": ({"method": "eth_sign", "params": [SIGNER, "0x" + "ab" * 32]}, 1),
    "personal_sign_readable": ({"method": "personal_sign", "params": ["0x" + "Sign in to example.com\nNonce: 42".encode().hex(), SIGNER]}, 1),
    "personal_sign_opaque": ({"method": "personal_sign", "params": ["0x" + "ff" * 32, SIGNER]}, 1),
    "personal_sign_plain": ({"method": "personal_sign", "params": ["hello world", SIGNER]}, 1),
    "unrecognized_object": ({"hello": 1}, 1),
    "unrecognized_list": ([1, 2], 1),
    "7702_known_verified": (type4(auth(MM_DELEGATOR, nonce=5)), 1),
    "7702_unverified": (type4(auth(SHADY)), 1),
    "7702_verified_not_listed": (type4(auth(ROUTER)), 1),
    "7702_listed_unverified": (type4(auth(SIMPLE7702)), 1),
    "7702_chain_zero": (type4(auth(MM_DELEGATOR, chain=0)), 1),
    "7702_revoke": (type4(auth("0x" + "00" * 20)), 1),
    "7702_nocode_and_delegated": (type4(auth(EOA), auth(DELEGATED)), 1),
    "7702_other_chain": (type4(auth(MM_DELEGATOR, chain=8453)), 1),
    "7702_lookups_fail": (type4(auth(UNKNOWN_ADDR)), 1),
    "7702_standalone_object": ({"address": SHADY, "chainId": "0x1", "nonce": "0x0"}, 1),
    "7702_request": ({"method": "wallet_signAuthorization", "params": [auth(MM_DELEGATOR, nonce=3, key="contractAddress")]}, 1),
    "7702_in_jsonrpc_tx": ({"method": "eth_sendTransaction", "params": [type4(auth(SHADY))]}, 1),
    "7702_missing_fields": (type4({"address": SHADY}), 1),
    "7702_negative_nonce": (type4(auth(SHADY, nonce=-1)), 1),
    "7702_null_chain": (type4({"address": SHADY, "chainId": None, "nonce": 0}), 1),
    "7702_bool_chain": (type4(auth(SHADY, chain=True)), 1),
    "7702_list_not_list": ({**type4(), "authorizationList": "nope"}, 1),
    "7702_bad_delegate": (type4(auth("0x1234")), 1),
    "7702_hex_negative_chain": (type4(auth(SHADY, chain="-0x1")), 1),
    "7702_request_without_auth": ({"method": "wallet_signAuthorization", "params": ["0x1234"]}, 1),
}

for name in sorted(os.listdir(os.path.join(PY, "examples"))):
    with open(os.path.join(PY, "examples", name)) as f:
        CASES["example_" + name[:-5]] = (json.load(f), 8453)


def stringify_ints(v):
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (bytes, bytearray)):
        return v.hex()  # the Python tool leaves nested bytes raw (its --json would crash here)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return [stringify_ints(x) for x in v]
    if isinstance(v, dict):
        return {k: stringify_ints(x) for k, x in v.items()}
    return v


out = []
for name, (payload, chain) in CASES.items():
    rep = analyze(payload, chain, FakeLookups(signatures=SIGS))
    out.append({"name": name, "chain": chain, "payload": payload, "expected": {
        "kind": rep["kind"], "risk": rep["risk"], "findings": rep["findings"], "decoded": stringify_ints(rep["decoded"])}})

with open(os.path.join(HERE, "..", "test", "fixtures.json"), "w") as f:
    json.dump({"now": NOW, "cases": out}, f, indent=1)
print(f"wrote {len(out)} cases")
