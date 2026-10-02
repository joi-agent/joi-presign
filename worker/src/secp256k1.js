// secp256k1 public-key recovery (what the ecrecover precompile does), BigInt only, no dependencies.
// Verification only: this module never handles private keys.
import { keccak256, toHex } from "./keccak.js";
import { toChecksumAddress } from "./abi.js";

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
export const HALF_N = N >> 1n;

const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };

function powMod(b, e, m) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

function inv(a, m) {
  // Extended Euclid; a must be non-zero mod m.
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return mod(s0, m);
}

// Jacobian points [X, Y, Z]; Z = 0n is the point at infinity.
const INF = [0n, 1n, 0n];

function dbl([X, Y, Z]) {
  if (Z === 0n || Y === 0n) return INF;
  const YY = (Y * Y) % P;
  const S = (4n * X * YY) % P;
  const M = (3n * X * X) % P; // a = 0
  const X3 = mod(M * M - 2n * S);
  const Y3 = mod(M * (S - X3) - 8n * YY * YY);
  const Z3 = (2n * Y * Z) % P;
  return [X3, Y3, Z3];
}

function add(p1, p2) {
  const [X1, Y1, Z1] = p1, [X2, Y2, Z2] = p2;
  if (Z1 === 0n) return p2;
  if (Z2 === 0n) return p1;
  const Z1Z1 = (Z1 * Z1) % P, Z2Z2 = (Z2 * Z2) % P;
  const U1 = (X1 * Z2Z2) % P, U2 = (X2 * Z1Z1) % P;
  const S1 = (Y1 * Z2 * Z2Z2) % P, S2 = (Y2 * Z1 * Z1Z1) % P;
  if (U1 === U2) return S1 === S2 ? dbl(p1) : INF;
  const H = mod(U2 - U1), R = mod(S2 - S1);
  const HH = (H * H) % P, HHH = (H * HH) % P, V = (U1 * HH) % P;
  const X3 = mod(R * R - HHH - 2n * V);
  const Y3 = mod(R * (V - X3) - S1 * HHH);
  const Z3 = (H * Z1 * Z2) % P;
  return [X3, Y3, Z3];
}

function toAffine([X, Y, Z]) {
  if (Z === 0n) return null;
  const zi = inv(Z, P), zi2 = (zi * zi) % P;
  return [(X * zi2) % P, (Y * zi2 * zi) % P];
}

// a*A + b*B in one pass (Shamir's trick).
function mulAdd(a, A, b, B) {
  const AB = add(A, B);
  let R = INF;
  const bits = Math.max(a.toString(2).length, b.toString(2).length);
  for (let i = bits - 1; i >= 0; i--) {
    R = dbl(R);
    const ia = (a >> BigInt(i)) & 1n, ib = (b >> BigInt(i)) & 1n;
    if (ia && ib) R = add(R, AB);
    else if (ia) R = add(R, A);
    else if (ib) R = add(R, B);
  }
  return R;
}

/**
 * Recover the signer address of a 32-byte digest. v may be 27/28 or 0/1 (recovery id).
 * Returns a checksum address, or null for any invalid signature (like ecrecover returning zero).
 * High-s signatures are accepted, as ecrecover does; callers can check s > HALF_N themselves.
 */
export function recoverAddress(digest, r, s, v) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) return null;
  let recid = typeof v === "bigint" ? Number(v) : v;
  if (recid === 27 || recid === 28) recid -= 27;
  if (recid !== 0 && recid !== 1) return null;
  if (r <= 0n || r >= N || s <= 0n || s >= N) return null;
  const x = r; // recid 2/3 (x = r + n) can't occur for secp256k1 in practice and isn't accepted by ecrecover
  const alpha = mod(x * x * x + 7n);
  const beta = powMod(alpha, (P + 1n) / 4n, P);
  if ((beta * beta) % P !== alpha) return null; // r isn't the x of a curve point
  const y = (beta & 1n) === BigInt(recid) ? beta : P - beta;
  const e = BigInt("0x" + (toHex(digest) || "0")) % N;
  const rInv = inv(r, N);
  const u1 = mod(-e * rInv, N), u2 = mod(s * rInv, N);
  const Q = toAffine(mulAdd(u1, [GX, GY, 1n], u2, [x, y, 1n]));
  if (!Q) return null;
  const pub = new Uint8Array(64);
  const hx = Q[0].toString(16).padStart(64, "0"), hy = Q[1].toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) {
    pub[i] = parseInt(hx.slice(2 * i, 2 * i + 2), 16);
    pub[32 + i] = parseInt(hy.slice(2 * i, 2 * i + 2), 16);
  }
  return toChecksumAddress(toHex(keccak256(pub)).slice(24));
}

/**
 * Split a 65-byte (r|s|v) or 64-byte EIP-2098 compact (r|yParityAndS) signature.
 * Returns {r, s, v} with v as 27/28, or null if the length is neither.
 */
export function splitSignature(sig) {
  if (!(sig instanceof Uint8Array)) return null;
  const big = (b) => BigInt("0x" + (toHex(b) || "0"));
  if (sig.length === 65) {
    let v = sig[64];
    if (v === 0 || v === 1) v += 27;
    return { r: big(sig.subarray(0, 32)), s: big(sig.subarray(32, 64)), v };
  }
  if (sig.length === 64) {
    const vs = big(sig.subarray(32, 64));
    return { r: big(sig.subarray(0, 32)), s: vs & ((1n << 255n) - 1n), v: Number(vs >> 255n) + 27 };
  }
  return null;
}
