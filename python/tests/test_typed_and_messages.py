import json

from joi_presign.core import PERMIT2, analyze

from conftest import EOA, NOW, ROUTER, SHADY, SIGNER, TOKEN, codes

MAX = 2**256 - 1


def eip2612(spender, value, deadline, chain=1):
    return {
        "types": {"EIP712Domain": [], "Permit": []},
        "primaryType": "Permit",
        "domain": {"name": "USD Coin", "version": "2", "chainId": chain, "verifyingContract": TOKEN},
        "message": {"owner": SIGNER, "spender": spender, "value": str(value), "nonce": 0, "deadline": deadline},
    }


def test_eip2612_permit_benign(L):
    r = analyze(eip2612(ROUTER, 10**6, NOW + 600), 1, L)
    assert codes(r) == {"PERMIT_SIGNATURE": "MEDIUM"}


def test_eip2612_permit_drainer_shape(L):
    r = analyze(eip2612(EOA, MAX, MAX), 1, L)
    assert codes(r) == {"PERMIT_SIGNATURE": "MEDIUM", "APPROVAL_TO_EOA": "HIGH",
                        "UNLIMITED_APPROVAL": "HIGH", "LONG_DEADLINE": "MEDIUM"}
    assert r["risk"] == "HIGH"


def test_typed_chain_mismatch(L):
    assert codes(analyze(eip2612(ROUTER, 1, NOW + 60, chain=8453), 1, L))["CHAIN_MISMATCH"] == "HIGH"


def permit2(primary, message):
    return {"types": {"EIP712Domain": []}, "primaryType": primary,
            "domain": {"name": "Permit2", "chainId": 8453, "verifyingContract": PERMIT2}, "message": message}


def test_permit2_single_unlimited_long(L):
    td = permit2("PermitSingle", {
        "details": {"token": TOKEN, "amount": str(2**160 - 1), "expiration": NOW + 400 * 86400, "nonce": 0},
        "spender": SHADY, "sigDeadline": NOW + 1800})
    r = analyze(td, 8453, L)
    assert codes(r) == {"PERMIT2_SIGNATURE": "MEDIUM", "SPENDER_UNVERIFIED": "MEDIUM",
                        "UNLIMITED_APPROVAL": "HIGH", "LONG_EXPIRATION": "MEDIUM"}


def test_permit2_batch_transfer_from(L):
    td = permit2("PermitBatchTransferFrom", {
        "permitted": [{"token": TOKEN, "amount": "1000"}, {"token": ROUTER, "amount": str(MAX)}],
        "spender": ROUTER, "nonce": 1, "deadline": NOW + 60})
    r = analyze(td, 8453, L)
    assert codes(r) == {"PERMIT2_SIGNATURE": "MEDIUM", "UNLIMITED_APPROVAL": "MEDIUM"}
    assert len(r["decoded"]["tokens"]) == 2


def seaport(offerer, consideration):
    return {"types": {"EIP712Domain": []}, "primaryType": "OrderComponents",
            "domain": {"name": "Seaport", "version": "1.6", "chainId": 1,
                       "verifyingContract": "0x0000000000000068F116a894984e2DB1123eB395"},
            "message": {"offerer": offerer,
                        "offer": [{"itemType": 2, "token": TOKEN, "identifierOrCriteria": "7", "startAmount": "1", "endAmount": "1"}],
                        "consideration": consideration}}


def test_seaport_giveaway(L):
    to_attacker = [{"itemType": 0, "token": "0x" + "00" * 20, "startAmount": "1", "endAmount": "1", "recipient": EOA}]
    assert codes(analyze(seaport(SIGNER, to_attacker), 1, L)) == {"SEAPORT_GIVEAWAY": "HIGH"}


def test_seaport_normal_listing(L):
    paid = [{"itemType": 0, "token": "0x" + "00" * 20, "startAmount": str(10**18), "endAmount": str(10**18), "recipient": SIGNER}]
    assert codes(analyze(seaport(SIGNER, paid), 1, L)) == {"SEAPORT_ORDER": "LOW"}


def test_unknown_typed_data(L):
    td = {"types": {"EIP712Domain": []}, "primaryType": "Mail",
          "domain": {"name": "Ether Mail", "chainId": 1, "verifyingContract": EOA}, "message": {"contents": "hi"}}
    assert codes(analyze(td, 1, L)) == {"UNKNOWN_TYPED_DATA": "LOW", "VERIFYING_CONTRACT_NOT_CONTRACT": "MEDIUM"}


def test_typed_data_via_jsonrpc_string(L):
    req = {"method": "eth_signTypedData_v4", "params": [SIGNER, json.dumps(eip2612(ROUTER, 1, NOW + 60))]}
    r = analyze(req, 1, L)
    assert r["kind"] == "typed" and codes(r) == {"PERMIT_SIGNATURE": "MEDIUM"}


def test_eth_sign_is_blind(L):
    r = analyze({"method": "eth_sign", "params": [SIGNER, "0x" + "ab" * 32]}, 1, L)
    assert codes(r) == {"BLIND_SIGNING": "HIGH"}


def test_personal_sign_readable_and_opaque(L):
    msg = "0x" + "Sign in to example.com\nNonce: 42".encode().hex()
    r = analyze({"method": "personal_sign", "params": [msg, SIGNER]}, 1, L)
    assert codes(r) == {"READABLE_MESSAGE": "LOW"}
    assert r["decoded"]["text"].startswith("Sign in")
    r = analyze({"method": "personal_sign", "params": ["0x" + "ff" * 32, SIGNER]}, 1, L)
    assert codes(r) == {"OPAQUE_MESSAGE": "MEDIUM"}


def test_unrecognized_input(L):
    assert codes(analyze({"hello": 1}, 1, L)) == {"UNRECOGNIZED_INPUT": "MEDIUM"}
    assert codes(analyze([1, 2], 1, L)) == {"UNRECOGNIZED_INPUT": "MEDIUM"}
