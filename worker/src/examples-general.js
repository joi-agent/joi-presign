// Real outputs captured 2026-10-02 from live read-only runs (tools/capture-examples-general.mjs).
export default {
 "read": {
  "input": {
   "url": "https://example.com/"
  },
  "output": {
   "url": "https://example.com/",
   "final_url": "https://example.com/",
   "http_status": 200,
   "allowed": true,
   "robots": {
    "verdict": "allowed",
    "rule": null,
    "group": null,
    "note": "robots.txt unavailable (HTTP 404): no restrictions apply"
   },
   "title": "Example Domain",
   "byline": null,
   "published": null,
   "canonical": null,
   "language": "en",
   "description": null,
   "site_name": null,
   "word_count": 25,
   "links_count": 0,
   "content_type": "text/html",
   "truncated": false,
   "markdown": "This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.",
   "notes": [],
   "user_agent": "joi-reader/0.1 (AI agent; +https://joi-presign.joi-agent.workers.dev)",
   "fetched_at": "2026-10-02T20:52:36.455Z"
  }
 },
 "urlmeta": {
  "input": {
   "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/402"
  },
  "output": {
   "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/402",
   "final_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/402",
   "redirects": [],
   "http_status": 200,
   "response_ms": 225,
   "content_type": "text/html",
   "content_length": 21034,
   "bytes_read": 209295,
   "truncated": false,
   "title": "402 Payment Required - HTTP | MDN",
   "description": "The HTTP 402 Payment Required client error response status code is a nonstandard response status code reserved for future use.",
   "canonical": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/402",
   "favicon": {
    "url": "https://developer.mozilla.org/favicon.svg",
    "source": "link"
   },
   "language": "en-US",
   "open_graph": {
    "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/402",
    "title": "402 Payment Required - HTTP | MDN",
    "locale": "en_US",
    "description": "The HTTP 402 Payment Required client error response status code is a nonstandard response status code reserved for future use.",
    "image": "https://developer.mozilla.org/mdn-social-image.46ac2375.png",
    "image:type": "image/png",
    "image:height": "1024",
    "image:width": "1024",
    "image:alt": "The MDN logo",
    "site_name": "MDN Web Docs"
   },
   "twitter": {
    "card": "summary",
    "creator": "MozDevNet"
   },
   "robots_meta": {
    "raw": null,
    "noindex": false,
    "nofollow": false,
    "noarchive": false,
    "nosnippet": false,
    "noai": false,
    "googlebot": null
   },
   "x_robots_tag": null,
   "security_headers": {
    "hsts": {
     "present": true,
     "value": "max-age=63072000"
    },
    "csp": {
     "present": true,
     "value": "default-src 'self'; script-src 'report-sample' 'self' 'wasm-unsafe-eval' assets.codepen.io production-assets.codepen.io https://js.stripe.com transcend-cdn.com 'sha256-XNBp89FG76amD8BqrJzyflxOF9PaWPqPqvJfKZPCv7M=' 'sha256-YCNoU9DNiinACbd8n6UPyB/8vj0kXvhkOni9/06SuYw=' 'sha256-PZjP7OR6mBEtnvXIZfCZ5PuOlxoDF1LDZL8aj8c42rw='; script-src-elem 'report-sample' 'self' 'wasm-unsafe-eval' assets.codepen.io production-assets.codepen.io https://js.stripe.com transcend-cdn.com 'sha256-XNBp89FG76amD8BqrJzyflxO"
    },
    "x_frame_options": {
     "present": true,
     "value": "DENY"
    },
    "x_content_type_options": {
     "present": true,
     "value": "nosniff"
    },
    "referrer_policy": {
     "present": true,
     "value": "strict-origin-when-cross-origin"
    },
    "permissions_policy": {
     "present": false
    }
   },
   "server": "Google Frontend",
   "robots": {
    "verdict": "allowed",
    "rule": null,
    "group": "*"
   },
   "notes": [],
   "user_agent": "joi-reader/0.1 (AI agent; +https://joi-presign.joi-agent.workers.dev)",
   "fetched_at": "2026-10-02T20:52:36.937Z",
   "images_count": 0
  }
 },
 "email": {
  "input": {
   "domain": "gmail.com"
  },
  "output": {
   "domain": "gmail.com",
   "exists": true,
   "mx": {
    "records": [
     {
      "priority": 5,
      "host": "gmail-smtp-in.l.google.com"
     },
     {
      "priority": 10,
      "host": "alt1.gmail-smtp-in.l.google.com"
     },
     {
      "priority": 20,
      "host": "alt2.gmail-smtp-in.l.google.com"
     },
     {
      "priority": 30,
      "host": "alt3.gmail-smtp-in.l.google.com"
     },
     {
      "priority": 40,
      "host": "alt4.gmail-smtp-in.l.google.com"
     }
    ],
    "null_mx": false
   },
   "spf": {
    "record": "v=spf1 redirect=_spf.google.com",
    "all": "~",
    "lookups": 1,
    "lookups_capped": false,
    "includes": [],
    "redirect": "_spf.google.com",
    "mechanisms": [],
    "problems": [],
    "notes": []
   },
   "dmarc": {
    "record": "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com",
    "source_domain": "gmail.com",
    "policy": "none",
    "subdomain_policy": "quarantine",
    "pct": 100,
    "rua": "mailto:mailauth-reports@google.com",
    "ruf": null,
    "adkim": "r",
    "aspf": "r"
   },
   "dkim": {
    "checked": [
     "google",
     "selector1",
     "selector2",
     "default",
     "k1"
    ],
    "found": []
   },
   "mta_sts": {
    "record": "v=STSv1; id=20190429T010101;",
    "present": true
   },
   "tls_rpt": {
    "record": "v=TLSRPTv1;rua=mailto:sts-reports@google.com",
    "present": true
   },
   "bimi": {
    "present": false
   },
   "risk": "LOW",
   "findings": [
    {
     "code": "SPF_SOFTFAIL",
     "severity": "INFO",
     "message": "SPF ends in ~all (soft fail): unlisted senders are marked, not rejected; -all is stricter."
    },
    {
     "code": "DMARC_MONITOR_ONLY",
     "severity": "LOW",
     "message": "DMARC p=none: monitoring only, failing mail is still delivered."
    },
    {
     "code": "DKIM_NOT_FOUND",
     "severity": "INFO",
     "message": "No DKIM key at the common selectors (google, selector1, selector2, default, k1); the domain may still sign with another selector."
    }
   ],
   "notice": "DNS posture only: this doesn't send mail, test delivery or check sender reputation, and DKIM can only be found for the common selectors tried.",
   "resolver": "cloudflare-dns.com (DNS over HTTPS)",
   "checked_at": "2026-10-02T20:52:36.988Z"
  }
 },
 "email_small": {
  "input": {
   "domain": "example.com"
  },
  "output": {
   "domain": "example.com",
   "exists": true,
   "mx": {
    "records": [
     {
      "priority": 0,
      "host": ""
     }
    ],
    "null_mx": true
   },
   "spf": {
    "record": "v=spf1 -all",
    "all": "-",
    "lookups": 0,
    "lookups_capped": false,
    "includes": [],
    "redirect": null,
    "mechanisms": [
     "-all"
    ],
    "problems": [],
    "notes": []
   },
   "dmarc": {
    "record": "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s",
    "source_domain": "example.com",
    "policy": "reject",
    "subdomain_policy": "reject",
    "pct": 100,
    "rua": null,
    "ruf": null,
    "adkim": "s",
    "aspf": "s"
   },
   "dkim": {
    "checked": [
     "google",
     "selector1",
     "selector2",
     "default",
     "k1"
    ],
    "found": [
     {
      "selector": "google",
      "key_type": "rsa",
      "revoked": true
     },
     {
      "selector": "selector1",
      "key_type": "rsa",
      "revoked": true
     },
     {
      "selector": "selector2",
      "key_type": "rsa",
      "revoked": true
     },
     {
      "selector": "default",
      "key_type": "rsa",
      "revoked": true
     },
     {
      "selector": "k1",
      "key_type": "rsa",
      "revoked": true
     }
    ]
   },
   "mta_sts": {
    "present": false
   },
   "tls_rpt": {
    "present": false
   },
   "bimi": {
    "present": false
   },
   "risk": "LOW",
   "findings": [
    {
     "code": "NULL_MX",
     "severity": "INFO",
     "message": "example.com publishes a null MX (RFC 7505): it explicitly doesn't accept email."
    },
    {
     "code": "DMARC_NO_REPORTS",
     "severity": "INFO",
     "message": "DMARC has no rua= address, so the owner gets no aggregate reports."
    }
   ],
   "notice": "DNS posture only: this doesn't send mail, test delivery or check sender reputation, and DKIM can only be found for the common selectors tried.",
   "resolver": "cloudflare-dns.com (DNS over HTTPS)",
   "checked_at": "2026-10-02T20:52:37.037Z"
  }
 }
};
