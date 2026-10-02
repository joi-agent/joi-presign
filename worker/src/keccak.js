// Keccak-256 (the Ethereum variant, not SHA3-256) on 32-bit lane halves. No dependencies.

const RC = [
  [0x00000001, 0x00000000], [0x00008082, 0x00000000], [0x0000808a, 0x80000000], [0x80008000, 0x80000000],
  [0x0000808b, 0x00000000], [0x80000001, 0x00000000], [0x80008081, 0x80000000], [0x00008009, 0x80000000],
  [0x0000008a, 0x00000000], [0x00000088, 0x00000000], [0x80008009, 0x00000000], [0x8000000a, 0x00000000],
  [0x8000808b, 0x00000000], [0x0000008b, 0x80000000], [0x00008089, 0x80000000], [0x00008003, 0x80000000],
  [0x00008002, 0x80000000], [0x00000080, 0x80000000], [0x0000800a, 0x00000000], [0x8000000a, 0x80000000],
  [0x80008081, 0x80000000], [0x00008080, 0x80000000], [0x80000001, 0x00000000], [0x80008008, 0x80000000],
]; // [lo, hi]

// Rotation offset of lane x + 5y.
const R = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

function rot(lo, hi, n) {
  if (n === 0) return [lo, hi];
  if (n === 32) return [hi, lo];
  if (n > 32) { [lo, hi] = [hi, lo]; n -= 32; }
  return [((lo << n) | (hi >>> (32 - n))) >>> 0, ((hi << n) | (lo >>> (32 - n))) >>> 0];
}

function keccakF(s) {
  const C = new Uint32Array(10), B = new Uint32Array(50);
  for (const [rcLo, rcHi] of RC) {
    for (let x = 0; x < 5; x++) {
      C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x++) {
      const p = (x + 4) % 5, q = (x + 1) % 5;
      const [rl, rh] = rot(C[2 * q], C[2 * q + 1], 1);
      const dLo = C[2 * p] ^ rl, dHi = C[2 * p + 1] ^ rh;
      for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= dLo; s[2 * (x + y) + 1] ^= dHi; }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const i = x + 5 * y, j = y + 5 * ((2 * x + 3 * y) % 5);
        const [l, h] = rot(s[2 * i], s[2 * i + 1], R[i]);
        B[2 * j] = l; B[2 * j + 1] = h;
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        const i = x + y, a = (x + 1) % 5 + y, b = (x + 2) % 5 + y;
        s[2 * i] = B[2 * i] ^ (~B[2 * a] & B[2 * b]);
        s[2 * i + 1] = B[2 * i + 1] ^ (~B[2 * a + 1] & B[2 * b + 1]);
      }
    }
    s[0] ^= rcLo; s[1] ^= rcHi;
  }
}

export function keccak256(bytes) {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Uint32Array(50);
  const dv = new DataView(padded.buffer);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 4; i++) s[i] ^= dv.getUint32(off + 4 * i, true);
    keccakF(s);
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(4 * i, s[i], true);
  return out;
}

export const utf8 = (str) => new TextEncoder().encode(str);
export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
