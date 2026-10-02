"""Selector table and calldata decoding. Pure functions, no network."""
from eth_abi import decode
from eth_utils import keccak, to_checksum_address


def selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


_SIGNATURES = {
    "approve": "approve(address,uint256)",
    "increaseAllowance": "increaseAllowance(address,uint256)",
    "transfer": "transfer(address,uint256)",
    "transferFrom": "transferFrom(address,address,uint256)",
    "setApprovalForAll": "setApprovalForAll(address,bool)",
    "safeTransferFrom721": "safeTransferFrom(address,address,uint256)",
    "safeTransferFrom721Data": "safeTransferFrom(address,address,uint256,bytes)",
    "safeTransferFrom1155": "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "safeBatchTransferFrom1155": "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    "permit": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "permit2Approve": "approve(address,address,uint160,uint48)",
    "multicall": "multicall(bytes[])",
    "multicallDeadline": "multicall(uint256,bytes[])",
    "aggregate": "aggregate((address,bytes)[])",
    "aggregate3": "aggregate3((address,bool,bytes)[])",
    "tryAggregate": "tryAggregate(bool,(address,bytes)[])",
    "multiSend": "multiSend(bytes)",
}

KNOWN = {}
for _name, _sig in _SIGNATURES.items():
    _types = _sig[_sig.index("(") + 1 : -1]
    KNOWN[selector(_sig)] = (_name, _sig, _types)


def _split_types(types: str) -> list:
    out, depth, cur = [], 0, ""
    for ch in types:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur:
        out.append(cur)
    return out


def _norm(value):
    if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
        return to_checksum_address(value)
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    return value


def decode_call(data: bytes):
    """Return {selector, name, signature, args} or None if data is shorter than a selector.
    `name` is None for unknown selectors. Raises ValueError on malformed arguments."""
    if len(data) < 4:
        return None
    sel = "0x" + data[:4].hex()
    if sel not in KNOWN:
        return {"selector": sel, "name": None, "signature": None, "args": None}
    name, sig, types = KNOWN[sel]
    try:
        args = decode(_split_types(types), data[4:])
    except Exception as e:  # eth_abi raises several error types
        raise ValueError(f"cannot decode {sig}: {e}") from e
    return {"selector": sel, "name": name, "signature": sig, "args": [_norm(a) for a in args]}


def inner_calls(call: dict, outer_to: str):
    """For batching functions, return [(target, value, data, operation)]; operation 1 = delegatecall."""
    name, args = call["name"], call["args"]
    if name == "multicall":
        return [(outer_to, 0, bytes(d), 0) for d in args[0]]
    if name == "multicallDeadline":
        return [(outer_to, 0, bytes(d), 0) for d in args[1]]
    if name == "aggregate":
        return [(to_checksum_address(t), 0, bytes(d), 0) for t, d in args[0]]
    if name == "aggregate3":
        return [(to_checksum_address(t), 0, bytes(d), 0) for t, _allow, d in args[0]]
    if name == "tryAggregate":
        return [(to_checksum_address(t), 0, bytes(d), 0) for t, d in args[1]]
    if name == "multiSend":
        return decode_multisend(bytes(args[0]))
    return []


def decode_multisend(blob: bytes):
    """Safe MultiSend packed encoding: operation(1) | to(20) | value(32) | dataLength(32) | data."""
    out, i = [], 0
    while i < len(blob):
        if i + 85 > len(blob):
            raise ValueError("truncated multiSend entry header")
        op = blob[i]
        to = to_checksum_address("0x" + blob[i + 1 : i + 21].hex())
        value = int.from_bytes(blob[i + 21 : i + 53], "big")
        length = int.from_bytes(blob[i + 53 : i + 85], "big")
        if i + 85 + length > len(blob):
            raise ValueError("truncated multiSend entry data")
        out.append((to, value, blob[i + 85 : i + 85 + length], op))
        i += 85 + length
    return out
