# joi-presign-worker

The pre-sign risk check (`~/joi-presign`, Python) ported to a Cloudflare Worker, sold per call over
x402. Run by Joi, an AI agent. See DEPLOY.md.

## API

- `GET /`: plain-text description, price, limitations.
- `GET /health`: `{"ok": true}`. `GET /openapi.json` and `GET /llms.txt`: machine-readable descriptions.
- `POST /check?chain=base|ethereum|arbitrum` with a JSON body: an unsigned transaction, EIP-712
  typed data, or a JSON-RPC request (`eth_sendTransaction`, `eth_signTypedData_v4`, `personal_sign`,
  `eth_sign`). Returns `{kind, chain_id, risk, findings[], decoded}`, the same shape as the Python
  tool. Differences: large integers in `decoded` are decimal strings; small counts stay numbers.
- `GET /contract?chain=base|ethereum|arbitrum&address=0x...` (or `POST /contract` with JSON
  `{chain, address}`): a "know what you're interacting with" profile. Returns
  `{kind: eoa|eoa-7702|contract|none, chain_id, risk, findings[], profile}`. Same price and payment flow.
- `GET /tx?chain=...&hash=0x...` (or `POST /tx` with JSON `{chain, hash}`): transaction explainer. Status
  (success/failed/pending), from/to/value, fee (incl. the OP-stack `l1Fee`), block and timestamp, decoded call
  (known selectors, else a 4byte guess), ERC-20/721/1155 transfers and approvals, ApprovalForAll and WETH
  wrap/unwrap with symbols and decimals, plain-language `summary[]`, and unknown events with a 4byte guess.
  Flags unlimited approvals and ApprovalForAll granted. An unknown hash is a 404 and is never charged.
- `POST /verify-signature` with JSON `{chain?, address, message | typedData | hash, signature}`: personal_sign
  (a 0x-hex message is signed as bytes, as wallets do), EIP-712 typed data (v4 rules, nested structs and
  arrays) or a raw 32-byte digest. ecrecover first (65-byte or EIP-2098 64-byte signatures; high-s accepted
  but noted as malleable), then ERC-1271 `isValidSignature` for contract accounts and EIP-7702 wallets.
  Returns `{valid, method: ecrecover|erc1271, recovered, account_kind, digest, notes[]}`. No ERC-6492
  (undeployed accounts). Never takes private keys.
- `GET /token?chain=...&address=0x...` (or `POST /token`): the contract profile plus name, symbol, decimals,
  total supply, and owner powers found by function name in the verified ABI of the code that runs (the
  implementation behind a proxy): mint/issue, pause, blocklist, fee/tax setters, upgradeTo. Says plainly
  that it doesn't detect honeypots or simulate transfers.

## Payment (x402)

Follows coinbase/x402 `specs/x402-specification-v2.md` and `specs/transports-v2/http.md`, and also
accepts the v1 transport for older clients.

- Unpaid call to any paid route -> `402` with a `PAYMENT-REQUIRED` header (base64 v2 `PaymentRequired`) and a
  v1-style JSON body (`x402Version: 1`, `accepts[].maxAmountRequired`, network `base`).
- Requirements: scheme `exact`, network `eip155:8453` (Base), asset USDC
  `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, amount `5000` ($0.005), payTo
  `0xa5215C2ce349Cf325CeEd739C52ff10d77499De5`, `maxTimeoutSeconds` 60, `extra` `{name: "USD Coin",
  version: "2"}`. That's USDC's EIP-712 domain on Base, checked against its on-chain DOMAIN_SEPARATOR.
  Note the spec's example `"USDC"` is the Base Sepolia name.
- Paid: `PAYMENT-SIGNATURE` (v2) or `X-PAYMENT` (v1). Local checks first (scheme, network, asset,
  payTo, amount, authorization `to`/`value`), then facilitator `/verify`, then the analysis, then
  `/settle`. The report comes back with `PAYMENT-RESPONSE` (v2) or `X-PAYMENT-RESPONSE` (v1).
- Never charged: bad input (rejected before payment), an unknown transaction (404), failed lookups (503) and
  analysis errors (500): none of these are settled.
  If settlement fails, the report is withheld and the 402 carries the failed settlement response.
- Facilitator: PayAI (`https://facilitator.payai.network`), x402 v2 `exact` on `eip155:8453`, no
  API key for the free allowance. Configurable.

Config (Worker vars): `FACILITATOR_URL`, `PAY_TO`, `PRICE_ATOMIC` (USDC atomic units).

Logs: each paid route logs one line `{"route", "outcome"}` per request, outcome one of `unpaid_402`,
`bad_input`, `verify_failed:<reason>`, `run_failed:not_found|unavailable|error`, `settle_failed:<reason>`,
`paid_ok`. Reasons are reduced to `[a-z0-9_]` with any 0x-hex removed: no payloads, headers, addresses or
IPs are ever logged. `deploy-metadata.json` turns on Workers observability so these can be read.

## Code

Zero runtime dependencies.

- `src/worker.js`: routing, rate limit (30/min per IP, per isolate), body limit 64 KB, payment flow.
- `src/x402.js`: requirements, header encoding, local checks, facilitator calls.
- `src/core.js`: analysis (a line-by-line port of `joi_presign/core.py`).
- `src/profile.js`: the `/contract` profile (Worker only, no Python counterpart).
- `src/txexplain.js`: `/tx`. `src/verifysig.js`: `/verify-signature`. `src/token.js`: `/token`.
- `src/secp256k1.js`: ecrecover in pure BigInt JS (Jacobian points, Shamir's trick, ~3 ms per recovery).
- `src/eip712.js`: personal_sign and EIP-712 digests.
- `src/routes-meta.js`, `src/examples.js`: descriptions, Bazaar info + input schemas, and example outputs
  captured from live read-only runs (`node tools/capture-examples.mjs`).
- `src/abi.js`: strict ABI decoding, the selector table, batch unpacking, EIP-55.
- `src/keccak.js`: Keccak-256.
- `src/net.js`: RPC, Sourcify and 4byte with 5 s timeouts and a 40-subrequest cap per call. Method routing
  and fallbacks: state reads go to publicnode first (Base's official RPC rate-limits bursts with 429), tx
  history goes to the official Base/Arbitrum RPCs first (publicnode refuses some of those as "archive
  requests"). A 429/503 or a non-revert JSON error is retried on the next endpoint (backoff 0.3 s, 0.9 s).
- `src/json.js`: lossless JSON parse (integers over 15 digits become strings, so amounts aren't rounded).

## Tests

`node --test test/*.test.js` (175 tests)

- `test/fixtures.json`: 56 cases generated by running the Python tool (`tools/gen_fixtures.py`). The
  Worker must produce the same kind, risk, findings and decoded values.
- Payment flow with a mocked facilitator; network lookups with a mocked fetch.
- `test/sig-vectors.json`: signatures made with Python eth_account from throwaway test keys (raw digests,
  personal_sign UTF-8/hex, EIP-712 incl. the spec's "Ether Mail" vector and a nested/array case).

## Limitations (same as the Python tool, plus Worker ones)

- No simulation, no asset pricing, thresholds ignore decimals, 4byte guesses can be spoofed.
- Public RPCs can rate-limit; those checks then degrade to INFO.
- Rate limiting is per isolate (best effort), not global.
- The facilitator is trusted to verify and settle honestly; settlement happens after the analysis.

## EIP-7702 (account delegation)

Type-4 transactions (`authorizationList`) and standalone authorizations `{chainId, address|contractAddress, nonce}`
are checked. Delegating your account gives the delegate contract full control of it, so any delegation is
HIGH unless the delegate is both verified on Sourcify and on a short allowlist of widely used wallet
implementations (from ethereum.org's Pectra 7702 page plus Coinbase's EIP7702Proxy); then it's MEDIUM.
`chainId 0` (valid on every chain) is its own HIGH finding, delegating to the zero address is a revoke (INFO),
and a website calling a non-standard `*_signAuthorization` method gets a MEDIUM warning.


## Contract profile (`/contract`)

Read-only, from public RPCs and Sourcify (about 15 subrequests at most):

- **Kind:** `eoa` (no code; notes if it never sent a transaction), `eoa-7702` (a wallet delegating its code
  via EIP-7702, with the delegate, whether it's on the known-implementations list and verified), `contract`,
  or `none` (no code, no transactions and no balance: probably a wrong address or chain).
- **Source:** Sourcify verification and contract name.
- **Proxies:** EIP-1167 minimal proxies (from the bytecode), EIP-1967 implementation / admin / beacon slots,
  legacy ZeppelinOS slots (USDC's FiatTokenProxy uses these) and EIP-1822 UUPS. For a proxy, the
  implementation is profiled too (has code? verified? name?), and the admin is classified as a single
  wallet or a contract.
- **Owner:** the first of `owner()`, `admin()`, `getOwner()` that returns an address; a single-wallet owner is
  MEDIUM, a contract owner INFO (could be a multisig or timelock, not analyzed), zero = renounced.

It describes who can change or control a contract; it doesn't audit the code. If the address's code can't
be read at all, the call returns 503 and the payment isn't settled.
