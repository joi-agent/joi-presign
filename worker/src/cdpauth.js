// Coinbase Developer Platform (CDP) API authentication: a short-lived Ed25519 JWT per request, bound to the
// request's method and path. The secret is base64 of 64 bytes (32-byte Ed25519 seed + 32-byte public key).
// The secret never leaves this module: only the signed token is returned.

const enc = new TextEncoder();

function b64ToBytes(b64) {
  const bin = atob(String(b64).trim());
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const b64urlJson = (obj) => b64url(enc.encode(JSON.stringify(obj)));

function randomHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// Imported keys per isolate, keyed by key id (the secret itself is never used as a map key).
const keyCache = new Map();

/** Import the Ed25519 signing key from the CDP secret format. */
export async function importCdpKey(secretB64) {
  const raw = b64ToBytes(secretB64);
  if (raw.length !== 64) throw new Error("CDP secret must be 64 bytes (Ed25519 seed + public key)");
  const jwk = { kty: "OKP", crv: "Ed25519", d: b64url(raw.slice(0, 32)), x: b64url(raw.slice(32)), ext: false };
  return crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
}

async function signingKey(keyId, secretB64) {
  let p = keyCache.get(keyId);
  if (!p) {
    p = importCdpKey(secretB64);
    keyCache.set(keyId, p);
    p.catch(() => keyCache.delete(keyId));
  }
  return p;
}

export function _clearCdpKeyCache() {
  keyCache.clear();
}

/**
 * A Bearer JWT for one CDP API call. `url` is the full request URL; the token's `uri` claim binds it to
 * "<METHOD> <host><path>" and it is valid for 120 seconds.
 */
export async function cdpJwt({ keyId, secret, method, url, now = Math.floor(Date.now() / 1000), nonce = randomHex(16) }) {
  const u = new URL(url);
  const header = { alg: "EdDSA", kid: keyId, typ: "JWT", nonce };
  const payload = { sub: keyId, iss: "cdp", nbf: now, exp: now + 120, uri: `${method.toUpperCase()} ${u.host}${u.pathname}` };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const key = await signingKey(keyId, secret);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, enc.encode(signingInput)));
  return `${signingInput}.${b64url(sig)}`;
}
