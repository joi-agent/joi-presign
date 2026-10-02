// Real outputs captured 2026-10-02 from live read-only runs (tools/capture-examples-more.mjs).
export default {
 "x402check": {
  "input": {
   "url": "https://joi-presign.joi-agent.workers.dev/price?asset=ETH&chain=base"
  },
  "output": {
   "url": "https://joi-presign.joi-agent.workers.dev/price?asset=ETH&chain=base",
   "final_url": "https://joi-presign.joi-agent.workers.dev/price?asset=ETH&chain=base",
   "http_status": 402,
   "method": "GET",
   "discovery": {
    "openapi": true,
    "openapi_lists_path": true,
    "llms_txt": true
   },
   "notice": "This check never pays and never signs anything. It reads the 402 answer the way a careful client would and says what paying would mean. A clean result is not an endorsement of the service behind the URL.",
   "x402": true,
   "versions": [
    2,
    1
   ],
   "resource": {
    "url": "https://joi-presign.joi-agent.workers.dev/price",
    "description": "Price: the USD price of a major asset from its Chainlink data feed on Base, Ethereum or Arbitrum, with the feed's update time and a staleness flag. Run by Joi, an AI agent.",
    "mimeType": "application/json"
   },
   "verdict": "no red flags found",
   "risk": "LOW",
   "findings": [],
   "options": [
    {
     "version": 2,
     "scheme": "exact",
     "network": {
      "id": "eip155:8453",
      "given": "eip155:8453",
      "name": "base",
      "testnet": false,
      "recognized": true
     },
     "asset": {
      "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "symbol": "USDC",
      "decimals": 6,
      "kind": "usdc"
     },
     "amount": {
      "atomic": "10000",
      "human": "0.01",
      "usd": "0.01"
     },
     "pay_to": {
      "address": "0xa5215C2ce349Cf325CeEd739C52ff10d77499De5",
      "kind": "eoa",
      "verified": null,
      "name": null,
      "sanctioned": false,
      "matches": []
     },
     "max_timeout_seconds": 60,
     "description": null,
     "risk": "LOW",
     "findings": []
    }
   ]
  }
 },
 "name": {
  "input": {
   "name": "vitalik.eth"
  },
  "output": {
   "query": {
    "name": "vitalik.eth"
   },
   "name": "vitalik.eth",
   "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
   "found": true,
   "chain": "ethereum",
   "chain_id": 1,
   "resolver": "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63",
   "wildcard": false,
   "verified_reverse": true,
   "source": "ENS registry 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e on Ethereum",
   "notes": []
  }
 },
 "robots": {
  "input": {
   "url": "https://www.nytimes.com/section/technology"
  },
  "output": {
   "url": "https://www.nytimes.com/section/technology",
   "origin": "https://www.nytimes.com",
   "path": "/section/technology",
   "robots_url": "https://www.nytimes.com/robots.txt",
   "robots_found": true,
   "http_status": 200,
   "results": {
    "*": "no rule",
    "GPTBot": "disallowed",
    "ClaudeBot": "disallowed",
    "Claude-User": "disallowed",
    "Google-Extended": "disallowed",
    "CCBot": "disallowed",
    "PerplexityBot": "disallowed"
   },
   "details": {
    "*": {
     "verdict": "no rule",
     "group": "*",
     "rule": null
    },
    "GPTBot": {
     "verdict": "disallowed",
     "group": "GPTBot",
     "rule": "Disallow: /"
    },
    "ClaudeBot": {
     "verdict": "disallowed",
     "group": "ClaudeBot",
     "rule": "Disallow: /"
    },
    "Claude-User": {
     "verdict": "disallowed",
     "group": "Claude-User",
     "rule": "Disallow: /"
    },
    "Google-Extended": {
     "verdict": "disallowed",
     "group": "Google-Extended",
     "rule": "Disallow: /"
    },
    "CCBot": {
     "verdict": "disallowed",
     "group": "CCBot",
     "rule": "Disallow: /"
    },
    "PerplexityBot": {
     "verdict": "disallowed",
     "group": "PerplexityBot",
     "rule": "Disallow: /"
    }
   },
   "sitemaps": [
    "https://www.nytimes.com/sitemaps/new/news.xml.gz",
    "https://www.nytimes.com/sitemaps/new/sitemap.xml.gz",
    "https://www.nytimes.com/sitemaps/new/collections.xml.gz",
    "https://www.nytimes.com/sitemaps/new/video.xml.gz",
    "https://www.nytimes.com/sitemaps/new/cooking.xml.gz"
   ],
   "ai_txt": {
    "present": false,
    "status": 404
   },
   "llms_txt": {
    "present": false,
    "status": 404
   },
   "legend": {
    "allowed": "an Allow rule is the most specific match",
    "disallowed": "a Disallow rule is the most specific match",
    "no rule": "nothing matches this path: allowed by default",
    "unknown": "robots.txt couldn't be read"
   },
   "notes": [],
   "notice": "robots.txt states a site's crawling preferences (RFC 9309). It isn't a terms-of-service or a license: a site's terms may still forbid automated access, and robots.txt doesn't grant permission to use the content."
  }
 }
};
