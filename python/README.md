# joi-presign

A pre-sign risk check for wallets and agents. Give it what you're about to sign, and it returns a
risk level (LOW, MEDIUM or HIGH), the findings that explain it, and the decoded call.

It's a second opinion, not a guarantee. A LOW result means none of these checks fired, not that
the transaction is safe.

## Usage

```
./joi-presign check tx.json --chain ethereum        # chains: ethereum, arbitrum, base
./joi-presign check request.json --chain base --json
cat tx.json | ./joi-presign check - --offline       # decoding only, no network
```

Exit codes: 0 LOW, 10 MEDIUM, 20 HIGH, 2 bad input.

As a library:

```python
from joi_presign import analyze, CHAINS
from joi_presign.net import NetLookups
report = analyze(payload, CHAINS["base"], NetLookups())
```

Accepted input (JSON):
- an unsigned transaction: `{chainId, from?, to, value, data}`
- EIP-712 typed data: `{types, primaryType, domain, message}`
- JSON-RPC requests: `eth_sendTransaction`, `eth_signTransaction`, `eth_signTypedData*`
  (the typed data may be a JSON string), `personal_sign`, `eth_sign`

See `examples/` for samples.

## What it checks

| Code | Severity | When |
|---|---|---|
| APPROVAL_TO_EOA | HIGH | An approval, permit, Permit2 or setApprovalForAll goes to a plain wallet. |
| UNLIMITED_APPROVAL | HIGH, or MEDIUM if the spender is a verified contract | The allowance is at or near the max uint (2^200 and up, or uint160 max for Permit2). |
| LARGE_APPROVAL | MEDIUM | The allowance is 1e27 base units or more. |
| SPENDER_UNVERIFIED / TARGET_UNVERIFIED | MEDIUM | The contract has no verified source on Sourcify. |
| APPROVAL_FOR_ALL | HIGH, or MEDIUM if the operator is verified | setApprovalForAll(operator, true). |
| PERMIT_SIGNATURE / PERMIT2_SIGNATURE | MEDIUM | A gasless approval signature (EIP-2612 / Permit2). |
| LONG_DEADLINE / LONG_EXPIRATION | MEDIUM | The signature or allowance is valid for more than 30 days, or never expires. |
| SEAPORT_GIVEAWAY | HIGH | A Seaport order that gives items away and pays the signer at most 1,000 base units. |
| BLIND_SIGNING | HIGH | An `eth_sign` request (signing a raw hash). |
| OPAQUE_MESSAGE | MEDIUM | `personal_sign` of unreadable bytes. |
| CHAIN_MISMATCH | HIGH | The payload's chainId differs from the chain you asked about. |
| DELEGATECALL_IN_BATCH | HIGH | A Safe multiSend entry uses delegatecall. |
| TRANSFER_TO_FRESH_ADDRESS | MEDIUM | Value or tokens go to an address that has never sent a transaction. |
| UNKNOWN_FUNCTION / UNKNOWN_FUNCTION_GUESSED | MEDIUM / LOW | The selector isn't in the built-in list. The LOW case shows 4byte guesses. |
| DELEGATED_EOA | MEDIUM | The spender is an EOA with an EIP-7702 delegation. |
| CONTRACT_CREATION, MALFORMED_*, NESTING_TOO_DEEP | MEDIUM | Structural problems. |
| REVOKE, LOOKUP_UNAVAILABLE | INFO | Revokes, and lookups that failed or timed out. |

Batched calls (`multicall`, Multicall `aggregate`/`aggregate3`/`tryAggregate`, Safe `multiSend`) are
decoded, and each inner call is checked, up to 3 levels deep.

## Design

- `joi_presign/core.py`: pure analysis. All facts about the chain come from a `lookups` object, and
  any lookup may answer `None` (unknown). The report then says so instead of guessing.
- `joi_presign/net.py`: public RPCs (publicnode, arbitrum.io, base.org), Sourcify v2 and 4byte.directory.
  Every request has a timeout (8s). 4byte results are cached in `~/.cache/joi-presign/`.
- `joi_presign/abi.py`: the selector table and decoding (eth_abi).
- `tests/`: pytest, with a fake `lookups` and a fake HTTP opener. `python -m pytest -q`.

## Limitations (honest list)

- **No simulation.** It doesn't execute the transaction or show balance changes. A malicious
  contract with verified source and innocent-looking function names will pass.
- **No asset pricing.** The amount thresholds don't know the token's decimals or price. The Seaport
  check only catches near-zero payment to the signer, not a bad price.
- `approve(address,uint256)` is also ERC-721 `approve(to, tokenId)`, and the two can't be told apart
  without a lookup.
- **4byte guesses can be spoofed.** Collisions are common (oldest registration is shown first).
- "Brand-new contract" detection isn't implemented: it needs an archive node or an explorer API.
- Only ethereum, arbitrum and base. Public RPCs can rate-limit, and those checks then degrade to INFO.
- Typed data other than Permit, Permit2 and Seaport gets only a generic "read it first" finding.
