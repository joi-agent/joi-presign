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
- `GET /screen?address=0x...[&chain=...]` (or `POST /screen` with JSON `{address, chain?}`): sanctions
  screening against the OFAC SDN list's digital-currency addresses that are EVM addresses (ETH, plus USDT,
  USDC, ARB, BSC and ETC entries with 0x addresses). Returns `{address, sanctioned, matches[{entity,
  currency_label, sdn_uid, programs}], list_published, checked_at, kind, warnings, notice}`. Any case is
  accepted; a mixed-case address with a bad EIP-55 checksum is screened and warned about. "Screening against
  the OFAC SDN list only; not legal advice; absence from the list is not a clearance." Never answers 503:
  the list is bundled, and only the optional account kind needs a lookup.
- `GET /price?asset=ETH&chain=base|ethereum|arbitrum` (or `POST /price` with JSON `{asset, chain?}`): the
  USD price from the asset's Chainlink data feed (`latestRoundData`, `decimals`, `description`). Returns
  `{asset, chain, price (exact decimal string), decimals, updated_at, age_seconds, stale, heartbeat_seconds,
  feed, description, round_id}`. `stale` = last update older than the feed's heartbeat plus 10%. A
  description that doesn't match the expected pair, a failed read or a non-positive answer is a 503 and
  never charged. Supported: ETH, BTC, USDC, USDT, DAI, LINK and stETH on Ethereum; ETH, BTC, cbBTC, cbETH,
  USDC, USDT, DAI and LINK on Base; ETH, BTC, USDC, USDT, DAI and LINK on Arbitrum.
- `GET /x402-check?url=https://...` (or `POST /x402-check` with JSON `{url}`): "should my agent pay this
  402?". Fetches the URL like a careful x402 client (GET, then the method the origin's OpenAPI spec declares
  for that path, or POST after a 405) and reads the x402 v2 `PAYMENT-REQUIRED` header and the v1 JSON body.
  For each payment option (first 5): network (CAIP-2 and v1 names), whether the asset is Circle's USDC on
  that network or a known token (WETH, USDT, DAI on Ethereum/Base/Arbitrum), the amount in base units, token
  units and USD (USDC = 1; known tokens via their Chainlink feed), payTo (OFAC SDN screen; wallet, EIP-7702
  wallet or contract and Sourcify verification on Ethereum/Base/Arbitrum), maxTimeoutSeconds. Findings:
  PAYTO_SANCTIONED (HIGH), MALFORMED_REQUIREMENTS (HIGH), NON_USDC_ASSET, NOT_EXACT_SCHEME, UNKNOWN_NETWORK,
  PAYTO_UNVERIFIED_CONTRACT, VERSION_MISMATCH (v1 and v2 disagree on networks or amounts),
  REDIRECT_NOT_FOLLOWED (MEDIUM), TESTNET, LONG_VALIDITY, NOT_X402 (INFO). Verdict: "do not pay" / "check the
  findings before paying" / "no red flags found". Also reports whether /openapi.json (and whether it lists the
  path) and /llms.txt exist. It never pays and never signs.
- `GET /name?name=vitalik.eth` or `GET /name?address=0x...` (or `POST /name` with JSON `{name}` / `{address}`):
  ENS on Ethereum (registry `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`, resolver `addr()`, ENSIP-10
  wildcard through the parent's `resolve()`; off-chain CCIP-Read answers aren't followed) and Basenames
  (`*.base.eth`) on Base (registry `0xb94704422c2a1e396835a571837aa5ae53285a95`, reverse node
  `keccak256(namehash("80002105.reverse"), keccak256(hex address))`). A name returns `{name, address, found,
  chain, resolver, wildcard, verified_reverse, source, notes}`; an address returns its primary names on both
  systems, each verified by resolving the name forward again (`verified_reverse`). Only ASCII names are
  accepted (lowercased, ENSIP-15 label rules); anything else is a 400 rather than a wrong normalization.
- `GET /robots?url=https://...&agent=YourBot` (or `POST /robots` with JSON `{url, agent?}`): RFC 9309
  robots.txt evaluation of the URL's path for `*`, GPTBot, ClaudeBot, Claude-User, Google-Extended, CCBot,
  PerplexityBot and your agent: `allowed` / `disallowed` (the most specific matching rule), `no rule`
  (nothing matches: allowed), `unknown` (robots.txt couldn't be read). 4xx robots.txt = no restrictions,
  5xx/429 = assume complete disallow (RFC 9309 2.3.1). Also sitemaps, ai.txt and llms.txt presence (an HTML
  page served at those paths doesn't count). robots.txt is not a terms-of-service.
- `GET /read?url=https://...` (or `POST /read` with JSON `{url}`): a public web page as clean Markdown plus
  `{title, byline, published, canonical, language, description, site_name, word_count, links_count, robots,
  truncated, notes}`. It behaves like a polite crawler: User-Agent `joi-reader/0.1 (AI agent; +https://joi-presign.joi-agent.workers.dev)`,
  robots.txt is read first and evaluated for `joi-reader` (falling back to the `*` group, RFC 9309); a
  disallowed page is never fetched and answers **451** `{allowed: false, reason, rule}` without settling. Also
  refused without charge: error statuses and off-site redirects (422), content that isn't HTML or plain text
  (415). The page is the biggest `<article>`, else `<main>`, else `[role=main]`, else `<body>`; navigation,
  headers, footers, asides, forms, cookie/share/ad blocks and hidden elements are dropped. Kept: headings,
  paragraphs, lists (nested, `start=`), code blocks (with `language-*`), blockquotes, simple tables, images and
  links (resolved against `<base>`; in-page `#` links become plain text). JavaScript isn't run. Up to 1 MB is
  read; scripts/styles/SVG/comments are stripped first and at most 100 KB of HTML is converted (CPU budget).
- `GET /url-meta?url=https://...` (or `POST /url-meta` with JSON `{url}`): `{http_status, final_url, redirects,
  response_ms, content_type, content_length, bytes_read, title, description, canonical, favicon{url, source},
  language, open_graph, twitter, robots_meta{noindex, nofollow, ...}, x_robots_tag, security_headers{hsts, csp,
  x_frame_options, x_content_type_options, referrer_policy, permissions_policy}, images_count, notes}`. Obeys
  robots.txt like `/read` (451, not charged); error statuses are reported, not refused. Only the `<head>` is
  parsed, so it's cheap on big pages.
- `GET /email-check?domain=example.com` (or `POST /email-check` with JSON `{domain}`): email authentication
  posture from public DNS, queried over HTTPS at `cloudflare-dns.com`: MX (incl. RFC 7505 null MX), SPF (record,
  `all` qualifier, DNS lookups counted through includes/redirects against the RFC 7208 limit of 10, ptr use,
  broken includes), DMARC (policy, sp, pct, rua; falls back to the organizational domain), DKIM keys at the
  common selectors google/selector1/selector2/default/k1 (revoked keys flagged), MTA-STS, TLS-RPT and BIMI.
  Findings: `+all` HIGH, multiple SPF or DMARC records HIGH, more than 10 lookups HIGH, no SPF/DMARC MEDIUM,
  `p=none` LOW, and so on. A domain that doesn't exist is reported (`exists: false`); a resolver failure on a
  core lookup is a 503 and never charged. DNS posture only: no mail is sent.

Outbound fetches for `/x402-check`, `/robots`, `/read`, `/url-meta` and `/email-check` (`src/fetchsafe.js`): https only, public DNS names only (no IP
literals, no localhost/.local/.internal-style names), port 443, no credentials, `redirect: "manual"` with at
most 2 redirects inside the same site (registrable domain; shared hosts like workers.dev or github.io count as
separate sites), an 8 s overall limit and a size cap. A target that can't be reached is a 503 and never charged.
Per call the subrequests stay under the Workers limit of 50: `/x402-check` 26 chain lookups + 11 fetches + 2
facilitator calls, `/name` 30 + 2, `/robots` 9 + 2, `/read` and `/url-meta` 8 + 2 (robots.txt, the page, its
redirects, robots.txt of a redirect target), `/email-check` 30 + 2 (DNS over HTTPS: 11 base queries + up to 12
for SPF includes + DMARC fallback).

## Free MCP server (`POST /mcp`)

A remote MCP server (Streamable HTTP) so AI assistants can discover and call a free, rate-limited subset of the
tools. JSON responses only (no SSE), no sessions.

- Protocol versions: `2026-07-28` (modern: version, client info and capabilities in `params._meta`, mirrored in the
  `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers; mismatches get `400` / `-32020`; unknown versions
  `400` / `-32022`; `server/discover` implemented; results carry `resultType: "complete"`) and the legacy
  `initialize`-handshake versions `2025-11-25`, `2025-06-18`, `2025-03-26`.
- Methods: `server/discover`, `initialize`, `ping`, `tools/list`, `tools/call`. Notifications and client responses
  get `202`. `GET /mcp` is `405`. Batches are refused. An `Origin` header must be `https://`.
- Tools: `presign_check`, `contract_profile`, `screen_address`, `robots_check`, `url_meta` (read-only annotations,
  structured + text output, tool errors as `isError: true`). `/read` and `/x402-check` are deliberately not exposed:
  they fetch arbitrary pages and stay paid-only.
- Free tier: 20 tool calls per hour per client IP and a shared hourly cap per isolate (best effort). Over the limit,
  the tool returns an error that points to the paid x402 endpoints.
- Logs: route and outcome only (e.g. `tool:screen_address:ok`), never arguments.
- `tools/server.json` is a draft for the official MCP registry (`io.github.joi-agent/joi-presign`); not published yet.

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
- `src/screen.js` + `src/ofac-data.js`: `/screen`. The data file is generated by `tools/gen_ofac.py` (Python
  stdlib) from the official OFAC Sanctions List Service export
  (`https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML`, the file
  `treasury.gov/ofac/downloads/sdn.xml` redirects to). It refuses to write when it finds fewer than 50 EVM
  addresses, so a format change can't publish an empty list. `~/bin/joi-ofac-refresh` (for cron) regenerates
  it and deploys only if the data changed and the tests pass, restoring the previous file otherwise.
- `src/price.js`: `/price`. Feed proxies, pairs and heartbeats come from Chainlink's official data-feeds
  directory (the JSON behind docs.chain.link/data-feeds/price-feeds/addresses). `tools/check_feeds.py`
  verifies every entry against that directory (address, path, heartbeat, decimals) and on-chain
  (`description()`, `decimals()`). The standard `<asset>-usd` feed is used where it exists; on Base only the
  SVR variant is listed for ETH and BTC.
- `src/examples-screen-price.js`: example outputs for the two routes (`node tools/capture-examples-screen-price.mjs`).
- `src/fetchsafe.js`: the outbound fetch guard (URL checks, same-site redirects, time limit, size cap, budget).
- `src/x402check.js`: `/x402-check`. USDC addresses from Circle's list
  (developers.circle.com/stablecoins/usdc-contract-addresses, checked 2026-10-02); known tokens checked on-chain.
- `src/ens.js`: `/name`. Addresses from docs.ens.domains (registry) and the base/basenames README (Base
  Mainnet table), checked on-chain on 2026-10-02.
- `src/robots.js`: `/robots`, RFC 9309 parsing and matching (rules capped at 5,000 to stay inside the CPU limit).
- `src/routes-meta3.js` + `src/examples-more.js`: descriptions, Bazaar info/schemas and live-captured
  examples for the three routes (`node tools/capture-examples-more.mjs`).
- `src/html.js`: a small tolerant HTML parser (quote-aware tag ends, entities, implicit closes, raw-text
  elements), boilerplate removal, content selection, Markdown rendering and page metadata (one-pass head scan).
- `src/readpage.js`: `/read` and `/url-meta` (robots.txt first, as `joi-reader`; refusals via `Refused`, never
  settled).
- `src/emailcheck.js`: `/email-check` (DNS over HTTPS, SPF/DMARC/DKIM parsing).
- `src/routes-meta4.js` + `src/examples-general.js`: descriptions, Bazaar info/schemas and live-captured
  examples for the three routes (`node tools/capture-examples-general.mjs`).
- `src/json.js`: lossless JSON parse (integers over 15 digits become strings, so amounts aren't rounded).
- `src/mcp.js`: the free MCP server on `/mcp` (dual-era Streamable HTTP, five read-only tools, free-tier limits).

## Tests

`node --test test/*.test.js` (271 tests)

- `test/fixtures.json`: 56 cases generated by running the Python tool (`tools/gen_fixtures.py`). The
  Worker must produce the same kind, risk, findings and decoded values.
- Payment flow with a mocked facilitator; network lookups with a mocked fetch.
- `test/sig-vectors.json`: signatures made with Python eth_account from throwaway test keys (raw digests,
  personal_sign UTF-8/hex, EIP-712 incl. the spec's "Ether Mail" vector and a nested/array case).
- `test/fixtures/sdn-sample.xml`: a made-up list in the official SDN.XML format, for the generator test
  (needs `python3` on PATH).
- `test/more.test.js`: the fetch guard (SSRF cases, redirects, size cap, budget), x402-check findings and
  verdicts, ENS namehash vectors (EIP-137) and a Basenames reverse node computed on-chain, wildcard and
  reverse verification, RFC 9309's own examples (5.1, 5.2, 2.2.2, 2.2.3), and the HTTP flow of the three routes.
- `test/general.test.js`: the HTML parser and Markdown renderer on a realistic article fixture, content
  selection, robots refusals (the page is never fetched, the payment never settled), redirects into disallowed
  paths, error pages, content types, size caps, `/url-meta` fields, DNS-over-HTTPS parsing (TXT strings and
  escapes), SPF lookup counting, DMARC parsing and fallback, NXDOMAIN/SERVFAIL, and the HTTP flow.
- `test/mcp.test.js`: MCP lifecycle in both eras, `server/discover`, tool schemas, modern header validation
  (incl. the base64 `Mcp-Name` sentinel), unsupported versions, unknown methods, malformed JSON-RPC, Origin,
  notifications, each tool with fakes, the free-tier limit, unchanged x402 routes, and argument-free logs.

## Limitations (same as the Python tool, plus Worker ones)

- No simulation, no asset pricing, thresholds ignore decimals, 4byte guesses can be spoofed.
- Public RPCs can rate-limit; those checks then degrade to INFO.
- Rate limiting is per isolate (best effort), not global.
- The facilitator is trusted to verify and settle honestly; settlement happens after the analysis.
- `/name` handles ASCII names only and doesn't follow off-chain (CCIP-Read) resolution.
- `/x402-check` reads what the server says; it can't know whether the service will deliver after payment.
- `/robots` reads robots.txt only; a site's terms of service may still forbid automated access.
- `/read` doesn't run JavaScript (app-like pages come back empty, with a note), keeps simple tables only, and
  converts at most 100 KB of HTML. HTML parsing is the most CPU-heavy work in the service: on the Workers free plan
  (10 ms CPU per request) very large pages can exceed the limit on a cold isolate; such a request fails before
  settlement, so it isn't charged. `/url-meta` parses only the `<head>`.
- `/email-check` finds DKIM only at common selectors and can't test delivery or reputation; DMARC fallback uses
  an approximate organizational domain (a short public-suffix list).

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
