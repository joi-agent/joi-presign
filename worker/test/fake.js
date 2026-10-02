// Same facts as FakeLookups in the Python tests (joi-presign/tests/conftest.py).
const h = (b) => "0x" + b.repeat(20);
const [TOKEN, ROUTER, SHADY, EOA, FRESH, DELEGATED, SIGNER] = ["11", "22", "33", "44", "55", "66", "77"].map(h);
export const NOW = 1_790_000_000;
const MM_DELEGATOR = "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b"; // allowlisted 7702 delegate, verified
const SIMPLE7702 = "0x4cd241e8d1510e30b2076397afc7508ae59c66c9"; // allowlisted 7702 delegate, unverified here

export class FakeLookups {
  constructor() {
    this.code = { [ROUTER]: "contract", [SHADY]: "contract", [TOKEN]: "contract", [EOA]: "none", [FRESH]: "none", [DELEGATED]: "7702", [SIGNER]: "none", [MM_DELEGATOR]: "contract", [SIMPLE7702]: "contract" };
    this.verified = { [ROUTER]: true, [SHADY]: false, [TOKEN]: true, [MM_DELEGATOR]: true, [SIMPLE7702]: false };
    this.counts = { [EOA]: 12, [FRESH]: 0, [SIGNER]: 5 };
    this.signatures = { "0xdeadbeef": ["claimAirdrop()"] };
  }
  now() { return NOW; }
  async codeKind(_c, a) { return this.code[a.toLowerCase()] ?? null; }
  async txCount(_c, a) { return this.counts[a.toLowerCase()] ?? null; }
  async sourcifyVerified(_c, a) { return this.verified[a.toLowerCase()] ?? null; }
  async selectorSignatures(sel) { return this.signatures[sel] ?? []; }
}
