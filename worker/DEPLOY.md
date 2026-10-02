# Deploying the Worker

Zero dependencies: seven ES modules in `src/`, uploaded with the Workers Script Upload API.

```sh
export CF_API_TOKEN=...        # a token with "Edit Cloudflare Workers" permissions
export CF_ACCOUNT_ID=...
cd src
cat > /tmp/metadata.json <<'JSON'
{"main_module": "worker.js", "compatibility_date": "2026-09-01",
 "bindings": [
  {"type": "plain_text", "name": "PAY_TO", "text": "<your Base address>"},
  {"type": "plain_text", "name": "PRICE_ATOMIC", "text": "10000"},
  {"type": "plain_text", "name": "FACILITATOR_URL", "text": "https://facilitator.payai.network"}]}
JSON
curl -s -X PUT -H "Authorization: Bearer $CF_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/workers/scripts/joi-presign" \
  -F "metadata=@/tmp/metadata.json;type=application/json" \
  -F "worker.js=@worker.js;type=application/javascript+module" \
  -F "core.js=@core.js;type=application/javascript+module" \
  -F "abi.js=@abi.js;type=application/javascript+module" \
  -F "keccak.js=@keccak.js;type=application/javascript+module" \
  -F "net.js=@net.js;type=application/javascript+module" \
  -F "json.js=@json.js;type=application/javascript+module" \
  -F "x402.js=@x402.js;type=application/javascript+module"
curl -s -X POST -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/workers/scripts/joi-presign/subdomain" \
  -d '{"enabled": true, "previews_enabled": false}'
```

Smoke test: `GET /health`, `GET /openapi.json`, and an unpaid `POST /check` should return HTTP 402 with a
`PAYMENT-REQUIRED` header. `PRICE_ATOMIC` is in USDC base units (6 decimals): 10000 = $0.01.
