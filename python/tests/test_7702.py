from eth_utils import to_checksum_address

from joi_presign.core import KNOWN_DELEGATES, analyze

from conftest import DELEGATED, EOA, MM_DELEGATOR, ROUTER, SHADY, SIGNER, SIMPLE7702, UNKNOWN_ADDR, codes

ZERO = "0x" + "00" * 20


def type4(*auths, chain=1):
    return {"type": "0x4", "chainId": chain, "from": SIGNER, "to": SIGNER, "value": "0x0", "data": "0x",
            "authorizationList": list(auths)}


def auth(address, chain=1, nonce=0, key="address"):
    return {key: address, "chainId": chain, "nonce": nonce, "yParity": "0x0", "r": "0x01", "s": "0x02"}


def test_allowlist_is_checksummed():
    assert all(to_checksum_address(a) == a for a in KNOWN_DELEGATES)


def test_known_verified_delegate_is_medium(L):
    r = analyze(type4(auth(MM_DELEGATOR, nonce=5)), 1, L)
    assert codes(r) == {"EIP7702_DELEGATION": "MEDIUM"}
    assert "full control of your account on chain 1" in r["findings"][0]["message"]
    a = r["decoded"]["authorizations"][0]
    assert a == {"delegate": to_checksum_address(MM_DELEGATOR), "chainId": 1, "nonce": 5,
                 "known_as": "MetaMask EIP7702StatelessDeleGator"}


def test_unverified_delegate_is_high(L):
    r = analyze(type4(auth(SHADY)), 1, L)
    assert codes(r) == {"EIP7702_DELEGATION": "HIGH"}
    assert "not verified on Sourcify" in r["findings"][0]["message"]
    assert r["risk"] == "HIGH"


def test_verified_but_not_allowlisted_is_high(L):
    r = analyze(type4(auth(ROUTER)), 1, L)
    assert codes(r) == {"EIP7702_DELEGATION": "HIGH"}
    assert "not one of the widely used wallet implementations" in r["findings"][0]["message"]


def test_allowlisted_but_unverified_is_high(L):
    r = analyze(type4(auth(SIMPLE7702)), 1, L)
    assert codes(r) == {"EIP7702_DELEGATION": "HIGH"}
    assert "but unconfirmed" in r["findings"][0]["message"]


def test_chain_id_zero_is_its_own_high(L):
    r = analyze(type4(auth(MM_DELEGATOR, chain=0)), 1, L)
    assert codes(r) == {"AUTH_ALL_CHAINS": "HIGH", "EIP7702_DELEGATION": "MEDIUM"}
    assert "on every chain" in r["findings"][1]["message"]
    assert r["risk"] == "HIGH"


def test_zero_address_is_a_revoke(L):
    r = analyze(type4(auth(ZERO)), 1, L)
    assert codes(r) == {"DELEGATION_REVOKE": "INFO"}
    assert r["risk"] == "LOW"


def test_delegate_without_code_and_delegated_eoa_are_high(L):
    r = analyze(type4(auth(EOA), auth(DELEGATED)), 1, L)
    msgs = [f["message"] for f in r["findings"]]
    assert codes(r) == {"EIP7702_DELEGATION": "HIGH"}
    assert any("no code on that chain" in m for m in msgs) and any("It is not a contract." in m for m in msgs)
    assert len(r["decoded"]["authorizations"]) == 2


def test_authorization_for_another_chain(L):
    r = analyze(type4(auth(MM_DELEGATOR, chain=8453)), 1, L)
    assert codes(r) == {"CHAIN_MISMATCH": "HIGH", "EIP7702_DELEGATION": "MEDIUM"}


def test_lookups_failing(L):
    r = analyze(type4(auth(UNKNOWN_ADDR)), 1, L)
    assert codes(r) == {"LOOKUP_UNAVAILABLE": "INFO", "EIP7702_DELEGATION": "HIGH"}


def test_standalone_authorization_object(L):
    r = analyze({"address": SHADY, "chainId": "0x1", "nonce": "0x0"}, 1, L)
    assert r["kind"] == "authorization"
    assert codes(r) == {"EIP7702_DELEGATION": "HIGH"}
    assert r["decoded"]["chainId"] == 1


def test_authorization_request_from_a_site(L):
    req = {"method": "wallet_signAuthorization", "params": [auth(MM_DELEGATOR, nonce=3, key="contractAddress")]}
    r = analyze(req, 1, L)
    assert r["kind"] == "authorization"
    assert codes(r) == {"NONSTANDARD_AUTH_REQUEST": "MEDIUM", "EIP7702_DELEGATION": "MEDIUM"}


def test_type4_inside_eth_send_transaction(L):
    r = analyze({"method": "eth_sendTransaction", "params": [type4(auth(SHADY))]}, 1, L)
    assert r["kind"] == "tx" and codes(r) == {"EIP7702_DELEGATION": "HIGH"}


def test_malformed_authorizations(L):
    bad = [
        type4({"address": SHADY}),
        type4(auth(SHADY, nonce=-1)),
        type4({"address": SHADY, "chainId": None, "nonce": 0}),
        type4(auth(SHADY, chain=True)),
        {**type4(), "authorizationList": "nope"},
    ]
    for tx in bad:
        assert codes(analyze(tx, 1, L)) == {"MALFORMED_AUTHORIZATION": "MEDIUM"}, tx
    r = analyze(type4(auth("0x1234")), 1, L)
    assert codes(r) == {"MALFORMED_ADDRESS": "MEDIUM"}
