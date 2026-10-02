"""Risk analysis of what a wallet is about to sign. Pure logic: all network facts come from a
`lookups` object (see net.NetLookups; tests use a fake). Any lookup may return None = unknown."""
import json
import string

from eth_utils import is_address, to_checksum_address

from .abi import decode_call, inner_calls

CHAINS = {"ethereum": 1, "arbitrum": 42161, "base": 8453}
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
MAX_UINT256 = 2**256 - 1
MAX_UINT160 = 2**160 - 1
UNLIMITED_THRESHOLD = 2**200  # anything this large is effectively unlimited for a uint256 amount
LARGE_THRESHOLD = 10**27  # 1e9 tokens at 18 decimals
LONG_WINDOW = 30 * 86400
MAX_DEPTH = 3
SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
PERMIT2_TYPES = {
    "PermitSingle", "PermitBatch", "PermitTransferFrom", "PermitBatchTransferFrom",
    "PermitWitnessTransferFrom", "PermitBatchWitnessTransferFrom",
}
ZERO_ADDRESS = "0x" + "00" * 20
# Widely used EIP-7702 delegate implementations. Sources: the "known implementations" table on
# ethereum.org/roadmap/pectra/7702 (checked 2026-10-02), except Coinbase's proxy, from the
# base/eip-7702-proxy README. Being listed is not enough: the delegate must also be verified on Sourcify.
KNOWN_DELEGATES = {
    "0x000000009B1D0aF20D8C6d0A44e162d11F9b8f00": "Uniswap Calibur",
    "0x69007702764179f14F51cdce752f4f775d74E139": "Alchemy Modular Account",
    "0x5A7FC11397E9a8AD41BF10bf13F22B0a63f96f6d": "Ambire account",
    "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B": "MetaMask EIP7702StatelessDeleGator",
    "0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9": "Simple7702Account (Ethereum Foundation AA team)",
    "0x17c11FDdADac2b341F2455aFe988fec4c3ba26e3": "Luganodes Pectra batch contract",
    "0x7702cb554e6bFb442cb743A7dF23154544a7176C": "Coinbase EIP7702Proxy",
}


class Report:
    def __init__(self):
        self.findings = []

    def add(self, code, severity, message):
        f = {"code": code, "severity": severity, "message": message}
        if f not in self.findings:
            self.findings.append(f)

    def risk(self):
        worst = max((SEVERITY[f["severity"]] for f in self.findings), default=0)
        return {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[worst]


def _int(v, default=0):
    if v is None:
        return default
    if isinstance(v, int):
        return v
    s = str(v).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _bytes(v):
    if v in (None, "", "0x"):
        return b""
    s = v[2:] if v.startswith("0x") else v
    return bytes.fromhex(s)


def _addr(v):
    return to_checksum_address(v) if isinstance(v, str) and is_address(v) else None


# ---------------------------------------------------------------- input classification


def classify(payload):
    """Return (kind, obj) with kind in tx | typed | message | unknown."""
    if not isinstance(payload, dict):
        return "unknown", payload
    method = payload.get("method")
    params = payload.get("params") or []
    if method in ("eth_sendTransaction", "eth_signTransaction") and params:
        return "tx", params[0]
    if method and method.startswith("eth_signTypedData"):
        for p in params + [payload.get("typedData")]:
            if isinstance(p, str) and p.strip().startswith("{"):
                p = json.loads(p)
            if isinstance(p, dict) and "types" in p:
                return "typed", p
        return "unknown", payload
    if method in ("personal_sign", "eth_sign"):
        candidates = params + ([payload["message"]] if "message" in payload else [])
        msgs = [p for p in candidates if isinstance(p, str) and not (is_address(p) and len(p) == 42)]
        return "message", (method, msgs[0] if msgs else "")
    if method and method.startswith(("eth_", "wallet_")) and "authorization" in method.lower():
        for p in params + [payload.get("authorization")]:
            if _is_authorization(p):
                return "authorization", ("request", p)
        return "unknown", payload
    if "types" in payload and "primaryType" in payload:
        return "typed", payload
    if _is_authorization(payload) and not any(k in payload for k in ("to", "data", "input")):
        return "authorization", ("object", payload)
    if "to" in payload or "data" in payload or "input" in payload:
        return "tx", payload
    return "unknown", payload


def _is_authorization(p):
    """An EIP-7702 authorization: {chainId, address (viem: contractAddress), nonce, ...signature}."""
    return isinstance(p, dict) and ("address" in p or "contractAddress" in p) and "chainId" in p and "nonce" in p


def analyze(payload, chain_id, lookups):
    rep = Report()
    kind, obj = classify(payload)
    if kind == "tx":
        decoded = _analyze_tx(obj, chain_id, lookups, rep, depth=0)
        if isinstance(obj, dict) and "authorizationList" in obj:
            auths = obj["authorizationList"]
            if isinstance(auths, list):
                decoded["authorizations"] = [_authorization(a, chain_id, lookups, rep) for a in auths]
            else:
                rep.add("MALFORMED_AUTHORIZATION", "MEDIUM", "The transaction's authorizationList is not a list.")
    elif kind == "authorization":
        source, auth = obj
        if source == "request":
            rep.add("NONSTANDARD_AUTH_REQUEST", "MEDIUM",
                    "There is no standard way for a website to ask for an EIP-7702 authorization signature. "
                    "Legitimate wallets only create one inside their own account-upgrade flow.")
        decoded = _authorization(auth, chain_id, lookups, rep)
    elif kind == "typed":
        decoded = _analyze_typed(obj, chain_id, lookups, rep)
    elif kind == "message":
        decoded = _analyze_message(obj, rep)
    else:
        decoded = None
        rep.add("UNRECOGNIZED_INPUT", "MEDIUM", "Not a transaction, typed data or sign request this tool understands.")
    return {"kind": kind, "chain_id": chain_id, "risk": rep.risk(), "findings": rep.findings, "decoded": decoded}


# ---------------------------------------------------------------- address facts


def _address_status(chain_id, addr, lookups, rep, role):
    """Classify an address: eoa | eoa-7702 | verified | unverified | unknown, adding findings."""
    kind = lookups.code_kind(chain_id, addr)
    if kind is None:
        rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not check whether the {role} {addr} is a contract.")
        return "unknown"
    if kind == "none":
        return "eoa"
    if kind == "7702":
        rep.add("DELEGATED_EOA", "MEDIUM", f"The {role} {addr} is an EOA with an EIP-7702 code delegation.")
        return "eoa-7702"
    verified = lookups.sourcify_verified(chain_id, addr)
    if verified is None:
        rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not check source verification of the {role} {addr}.")
        return "unknown"
    return "verified" if verified else "unverified"


def _check_spender(chain_id, spender, lookups, rep, what):
    status = _address_status(chain_id, spender, lookups, rep, "spender")
    if status in ("eoa", "eoa-7702"):
        rep.add("APPROVAL_TO_EOA", "HIGH",
                f"{what} goes to {spender}, a plain wallet, not a contract. Classic phishing pattern: legitimate apps approve contracts.")
    elif status == "unverified":
        rep.add("SPENDER_UNVERIFIED", "MEDIUM", f"{what} goes to {spender}, a contract with no verified source on Sourcify.")
    return status


def _check_amount(amount, uint_max, spender_status, rep, what):
    if amount == 0:
        rep.add("REVOKE", "INFO", f"{what} sets the amount to 0 (a revoke).")
        return
    unlimited = amount >= min(UNLIMITED_THRESHOLD, uint_max)
    trusted = spender_status == "verified"
    if unlimited:
        rep.add("UNLIMITED_APPROVAL", "MEDIUM" if trusted else "HIGH",
                f"{what} is unlimited. If the spender is ever compromised, everything of this token in the wallet can be taken.")
    elif amount >= LARGE_THRESHOLD:
        rep.add("LARGE_APPROVAL", "MEDIUM", f"{what} is very large ({amount} base units).")


def _check_recipient(chain_id, to, lookups, rep, what):
    kind = lookups.code_kind(chain_id, to)
    if kind == "none":
        n = lookups.tx_count(chain_id, to)
        if n == 0:
            rep.add("TRANSFER_TO_FRESH_ADDRESS", "MEDIUM",
                    f"{what} goes to {to}, an address that has never sent a transaction. Double-check it isn't a look-alike.")
        elif n is None:
            rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not check the history of the recipient {to}.")
    elif kind is None:
        rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not check the recipient {to}.")


def _check_time(ts, now, rep, code, what):
    if ts >= 2**48 - 1:
        rep.add(code, "MEDIUM", f"{what} never expires.")
    elif ts > now + LONG_WINDOW:
        rep.add(code, "MEDIUM", f"{what} is valid for more than 30 days ({(ts - now) // 86400} days).")


# ---------------------------------------------------------------- EIP-7702 authorizations

_DELEGATE_REASON = {
    "nocode": " It has no code on that chain, so the delegation points at nothing, or at whatever gets deployed there later.",
    "eoa": " It is not a contract.",
    "unverified": " Its source is not verified on Sourcify.",
    "unknown": "",
    "verified": " It is not one of the widely used wallet implementations.",
}


def _authorization(a, chain_id, lookups, rep):
    if not _is_authorization(a):
        rep.add("MALFORMED_AUTHORIZATION", "MEDIUM", "An EIP-7702 authorization entry is missing chainId, address or nonce.")
        return None
    raw = a.get("address", a.get("contractAddress"))
    delegate = _addr(raw)
    try:
        if any(a.get(k) is None or isinstance(a.get(k), bool) for k in ("chainId", "nonce")):
            raise ValueError
        auth_chain, nonce = _int(a["chainId"]), _int(a["nonce"])
        if not (0 <= auth_chain <= MAX_UINT256 and 0 <= nonce < 2**64):
            raise ValueError
    except (TypeError, ValueError):
        rep.add("MALFORMED_AUTHORIZATION", "MEDIUM", "An EIP-7702 authorization has a chainId or nonce that is not a valid number.")
        return {"delegate": delegate, "chainId": None, "nonce": None, "known_as": None}
    entry = {"delegate": delegate, "chainId": auth_chain, "nonce": nonce, "known_as": KNOWN_DELEGATES.get(delegate)}
    if delegate is None:
        rep.add("MALFORMED_ADDRESS", "MEDIUM", f"Invalid delegate address in an EIP-7702 authorization: {raw!r}.")
        return entry
    if auth_chain == 0:
        rep.add("AUTH_ALL_CHAINS", "HIGH",
                "This authorization has chainId 0, so it is valid on every EVM chain: whoever holds it can install "
                "the same delegation everywhere your account exists.")
    elif auth_chain != chain_id:
        rep.add("CHAIN_MISMATCH", "HIGH", f"The authorization is for chain {auth_chain}, not chain {chain_id}.")
    if delegate == to_checksum_address(ZERO_ADDRESS):
        rep.add("DELEGATION_REVOKE", "INFO", "Delegates to the zero address: this clears your account's EIP-7702 delegation (a revoke).")
        return entry
    where = "every chain" if auth_chain == 0 else f"chain {auth_chain}"
    lookup_chain = chain_id if auth_chain == 0 else auth_chain
    kind = lookups.code_kind(lookup_chain, delegate)
    if kind is None:
        rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not check whether the delegate {delegate} is a contract.")
        status = "unknown"
    elif kind == "none":
        status = "nocode"
    elif kind == "7702":
        status = "eoa"
    else:
        verified = lookups.sourcify_verified(lookup_chain, delegate)
        if verified is None:
            rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not check source verification of the delegate {delegate}.")
            status = "unknown"
        else:
            status = "verified" if verified else "unverified"
    known = entry["known_as"]
    if known and status == "verified":
        rep.add("EIP7702_DELEGATION", "MEDIUM",
                f"Delegates your account to {known} ({delegate}), a widely used wallet implementation. This gives that "
                f"contract full control of your account on {where}. Only sign this inside your wallet's own upgrade flow.")
    else:
        name = f" ({known}, but unconfirmed)" if known else ""
        rep.add("EIP7702_DELEGATION", "HIGH",
                f"Delegates your account to {delegate}{name}. This gives the contract full control of your account on "
                f"{where}: it can move all your assets at any time.{_DELEGATE_REASON[status]} Wallet drainers use exactly this.")
    return entry


# ---------------------------------------------------------------- transactions


def _analyze_tx(tx, chain_id, lookups, rep, depth, operation=0):
    if depth == 0 and tx.get("chainId") is not None and _int(tx["chainId"]) != chain_id:
        rep.add("CHAIN_MISMATCH", "HIGH", f"The transaction is for chain {_int(tx['chainId'])}, not chain {chain_id}.")
    to = _addr(tx.get("to"))
    value = _int(tx.get("value"))
    try:
        data = _bytes(tx.get("data") or tx.get("input") or "0x")
    except ValueError:
        rep.add("MALFORMED_CALLDATA", "MEDIUM", "Calldata is not valid hex.")
        return {"to": to, "value": value}
    decoded = {"to": to, "value": value}
    if operation == 1:
        rep.add("DELEGATECALL_IN_BATCH", "HIGH",
                f"A batched call DELEGATECALLs {to}: that code runs with the wallet's own permissions and storage.")
    if to is None:
        if tx.get("to") in (None, "", "0x"):
            rep.add("CONTRACT_CREATION", "MEDIUM", "This deploys a new contract from your account.")
        else:
            rep.add("MALFORMED_ADDRESS", "MEDIUM", f"Invalid 'to' address: {tx.get('to')!r}.")
        return decoded
    if not data:
        if value > 0:
            _check_recipient(chain_id, to, lookups, rep, f"A transfer of {value} wei")
        return decoded
    try:
        call = decode_call(data)
    except ValueError as e:
        rep.add("MALFORMED_CALLDATA", "MEDIUM", str(e))
        return decoded
    if call is None:
        rep.add("MALFORMED_CALLDATA", "MEDIUM", "Calldata is shorter than a function selector.")
        return decoded
    decoded["selector"] = call["selector"]
    if call["name"] is None:
        _unknown_function(chain_id, to, call["selector"], lookups, rep, decoded)
        return decoded
    decoded["function"] = call["signature"]
    decoded["args"] = [a.hex() if isinstance(a, bytes) else a for a in call["args"]]
    _known_function(chain_id, to, value, call, tx, lookups, rep, decoded, depth)
    return decoded


def _unknown_function(chain_id, to, sel, lookups, rep, decoded):
    sigs = lookups.selector_signatures(sel)
    if sigs:
        decoded["function_guesses"] = sigs[:3]
        rep.add("UNKNOWN_FUNCTION_GUESSED", "LOW",
                f"Function {sel} is not in the built-in list; public database guesses: {', '.join(sigs[:3])} (guesses can be spoofed).")
    elif sigs is None:
        rep.add("LOOKUP_UNAVAILABLE", "INFO", f"Could not look up function {sel}.")
        rep.add("UNKNOWN_FUNCTION", "MEDIUM", f"Function {sel} could not be identified.")
    else:
        rep.add("UNKNOWN_FUNCTION", "MEDIUM", f"Function {sel} is unknown to public databases: blind call.")
    status = _address_status(chain_id, to, lookups, rep, "target contract")
    if status == "unverified":
        rep.add("TARGET_UNVERIFIED", "MEDIUM", f"The target {to} has no verified source on Sourcify.")


def _known_function(chain_id, to, value, call, tx, lookups, rep, decoded, depth):
    name, args = call["name"], call["args"]
    if name in ("approve", "increaseAllowance"):
        spender, amount = args
        what = f"An allowance on token {to} for {spender}"
        status = _check_spender(chain_id, spender, lookups, rep, what) if amount else "n/a"
        _check_amount(amount, MAX_UINT256, status, rep, what)
    elif name == "permit":
        spender, amount = args[1], args[2]
        what = f"A permit on token {to} for {spender}"
        status = _check_spender(chain_id, spender, lookups, rep, what)
        _check_amount(amount, MAX_UINT256, status, rep, what)
    elif name == "permit2Approve":
        token, spender, amount, expiration = args
        what = f"A Permit2 allowance on token {token} for {spender}"
        status = _check_spender(chain_id, spender, lookups, rep, what) if amount else "n/a"
        _check_amount(amount, MAX_UINT160, status, rep, what)
        if amount:
            _check_time(expiration, lookups.now(), rep, "LONG_EXPIRATION", what)
    elif name == "setApprovalForAll":
        operator, approved = args
        if not approved:
            rep.add("REVOKE", "INFO", f"Revokes operator {operator} on collection {to}.")
        else:
            what = f"Approval for ALL items of collection {to} to {operator}"
            status = _check_spender(chain_id, operator, lookups, rep, what)
            rep.add("APPROVAL_FOR_ALL", "MEDIUM" if status == "verified" else "HIGH",
                    f"{what}: the operator can move every item you own in this collection, now and later.")
    elif name == "transfer":
        recipient, amount = args
        _check_recipient(chain_id, recipient, lookups, rep, f"A transfer of {amount} base units of {to}")
    elif name in ("transferFrom", "safeTransferFrom721", "safeTransferFrom721Data",
                  "safeTransferFrom1155", "safeBatchTransferFrom1155"):
        sender, recipient = args[0], args[1]
        signer = _addr(tx.get("from"))
        if signer and sender != signer:
            rep.add("MOVES_OTHERS_ASSETS", "LOW", f"Moves assets owned by {sender}, not by the signer {signer}.")
        _check_recipient(chain_id, recipient, lookups, rep, f"An asset transfer from {to}")
    elif name in ("multicall", "multicallDeadline", "aggregate", "aggregate3", "tryAggregate", "multiSend"):
        if depth >= MAX_DEPTH:
            rep.add("NESTING_TOO_DEEP", "MEDIUM", "Batches nested deeper than 3 levels were not analyzed.")
            return
        try:
            calls = inner_calls(call, to)
        except ValueError as e:
            rep.add("MALFORMED_CALLDATA", "MEDIUM", str(e))
            return
        decoded.pop("args", None)
        decoded["calls"] = [
            _analyze_tx({"to": t, "value": v, "data": "0x" + d.hex()}, chain_id, lookups, rep, depth + 1, op)
            for t, v, d, op in calls
        ]


# ---------------------------------------------------------------- typed data


def _analyze_typed(td, chain_id, lookups, rep):
    domain = td.get("domain") or {}
    pt = td.get("primaryType")
    msg = td.get("message") or {}
    if domain.get("chainId") is not None and _int(domain["chainId"]) != chain_id:
        rep.add("CHAIN_MISMATCH", "HIGH", f"The signature is for chain {_int(domain['chainId'])}, not chain {chain_id}.")
    vc = _addr(domain.get("verifyingContract"))
    decoded = {"primaryType": pt, "domain": {k: domain.get(k) for k in ("name", "version", "chainId", "verifyingContract")}}
    now = lookups.now()
    if domain.get("name") == "Permit2" or vc == PERMIT2:
        if pt in PERMIT2_TYPES:
            _permit2(chain_id, pt, msg, now, lookups, rep, decoded)
            return decoded
    if pt == "Permit" and "spender" in msg and "value" in msg:
        spender = _addr(msg["spender"])
        what = f"A signed permit on token {vc} for {spender}"
        rep.add("PERMIT_SIGNATURE", "MEDIUM",
                "Gasless approval: anyone holding this signature can submit it on-chain to set the allowance.")
        status = _check_spender(chain_id, spender, lookups, rep, what) if spender else "unknown"
        _check_amount(_int(msg["value"]), MAX_UINT256, status, rep, what)
        if "deadline" in msg:
            _check_time(_int(msg["deadline"]), now, rep, "LONG_DEADLINE", what)
        decoded.update(spender=spender, value=_int(msg["value"]), deadline=_int(msg.get("deadline")))
        return decoded
    if domain.get("name") == "Seaport" and pt == "OrderComponents":
        _seaport(msg, rep, decoded)
        return decoded
    rep.add("UNKNOWN_TYPED_DATA", "LOW", f"Typed data '{pt}' is not a known approval or order format; read it before signing.")
    if vc and lookups.code_kind(chain_id, vc) == "none":
        rep.add("VERIFYING_CONTRACT_NOT_CONTRACT", "MEDIUM", f"The domain's verifyingContract {vc} has no code on this chain.")
    return decoded


def _permit2(chain_id, pt, msg, now, lookups, rep, decoded):
    rep.add("PERMIT2_SIGNATURE", "MEDIUM", "Permit2 signature: it authorizes token movements without a further transaction.")
    spender = _addr(msg.get("spender"))
    if pt in ("PermitSingle", "PermitBatch"):
        details = msg.get("details")
        details = details if isinstance(details, list) else [details or {}]
        amounts = [(_addr(d.get("token")), _int(d.get("amount")), _int(d.get("expiration"))) for d in details]
        uint_max = MAX_UINT160
        deadline = _int(msg.get("sigDeadline"))
    else:
        permitted = msg.get("permitted")
        permitted = permitted if isinstance(permitted, list) else [permitted or {}]
        amounts = [(_addr(p.get("token")), _int(p.get("amount")), None) for p in permitted]
        uint_max = MAX_UINT256
        deadline = _int(msg.get("deadline"))
    status = _check_spender(chain_id, spender, lookups, rep, f"A Permit2 signature for {spender}") if spender else "unknown"
    for token, amount, expiration in amounts:
        what = f"Permit2 amount for token {token} to {spender}"
        _check_amount(amount, uint_max, status, rep, what)
        if expiration is not None and amount:
            _check_time(expiration, now, rep, "LONG_EXPIRATION", f"The allowance for token {token}")
    _check_time(deadline, now, rep, "LONG_DEADLINE", "The signature")
    decoded.update(spender=spender, tokens=[{"token": t, "amount": a, "expiration": e} for t, a, e in amounts], deadline=deadline)


def _seaport(msg, rep, decoded):
    offerer = _addr(msg.get("offerer"))
    offer = msg.get("offer") or []
    consideration = msg.get("consideration") or []
    to_signer = sum(
        max(_int(c.get("startAmount")), _int(c.get("endAmount")))
        for c in consideration if _addr(c.get("recipient")) == offerer
    )
    decoded.update(offerer=offerer, offer_items=len(offer), consideration_items=len(consideration), paid_to_signer=to_signer)
    if offer and to_signer <= 1000:
        rep.add("SEAPORT_GIVEAWAY", "HIGH",
                f"This order hands over {len(offer)} item(s) and pays the signer {'nothing' if to_signer == 0 else 'almost nothing'}. Typical NFT-drainer listing.")
    else:
        rep.add("SEAPORT_ORDER", "LOW", "Seaport order. This tool doesn't price assets: check the amounts you receive.")


# ---------------------------------------------------------------- messages


def _analyze_message(obj, rep):
    method, raw = obj
    try:
        b = _bytes(raw) if isinstance(raw, str) and raw.startswith("0x") else raw.encode()
    except ValueError:
        b = raw.encode()
    text = None
    try:
        t = b.decode("utf-8")
        if t and all(ch in string.printable for ch in t):
            text = t
    except UnicodeDecodeError:
        pass
    if method == "eth_sign":
        rep.add("BLIND_SIGNING", "HIGH",
                "eth_sign signs a raw hash: it can authorize a transaction or permit you cannot see. Legitimate apps almost never need it.")
    elif text is None:
        rep.add("OPAQUE_MESSAGE", "MEDIUM",
                f"personal_sign of {len(b)} unreadable bytes{' (a 32-byte hash)' if len(b) == 32 else ''}: you cannot read what you are approving.")
    else:
        rep.add("READABLE_MESSAGE", "LOW", "Readable message. Check it says what you expect (domain, nonce, purpose).")
    return {"method": method, "text": text[:500] if text else None, "length": len(b)}
