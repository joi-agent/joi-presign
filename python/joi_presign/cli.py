"""joi-presign check <file.json|-> --chain base [--json] [--offline]. Exit: 0 LOW, 10 MEDIUM, 20 HIGH, 2 bad input."""
import argparse
import json
import sys

from .core import CHAINS, analyze
from .net import NetLookups


class OfflineLookups:
    def now(self):
        import time
        return int(time.time())

    def code_kind(self, chain_id, addr):
        return None

    def tx_count(self, chain_id, addr):
        return None

    def sourcify_verified(self, chain_id, addr):
        return None

    def selector_signatures(self, sel):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="joi-presign", description="Risk-check what a wallet is about to sign.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="analyze a transaction, typed data or sign request (JSON)")
    c.add_argument("file", help="path to a JSON file, or - for stdin")
    c.add_argument("--chain", default="ethereum", choices=sorted(CHAINS))
    c.add_argument("--json", action="store_true", help="print the raw report as JSON")
    c.add_argument("--offline", action="store_true", help="no network lookups (decoding only)")
    a = ap.parse_args(argv)

    raw = sys.stdin.read() if a.file == "-" else open(a.file).read()
    try:
        payload = json.loads(raw)
    except ValueError as e:
        print(f"error: not valid JSON: {e}", file=sys.stderr)
        return 2
    lookups = OfflineLookups() if a.offline else NetLookups()
    report = analyze(payload, CHAINS[a.chain], lookups)
    if a.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"RISK: {report['risk']}  ({report['kind']} on {a.chain})")
        for f in sorted(report["findings"], key=lambda f: -["INFO", "LOW", "MEDIUM", "HIGH"].index(f["severity"])):
            print(f"  [{f['severity']}] {f['code']}: {f['message']}")
        if not report["findings"]:
            print("  no findings")
    return {"LOW": 0, "MEDIUM": 10, "HIGH": 20}[report["risk"]]


if __name__ == "__main__":
    sys.exit(main())
