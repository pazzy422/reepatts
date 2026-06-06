#!/usr/bin/env python3
"""
reepatts/_render.py — internal helper that takes a JSON blob on stdin and renders
the reentrancy report in the requested format. Called by scan.sh.

Usage:
  python3 scripts/_render.py < contract=<addr> network=<net> chain_id=<id> net_label=<lbl> explorer=<url> explorer_link=<url> bytecode_size=<int> overall_score=<int> min_severity=<int> format=<md|json|txt> < matched.json

The matched JSON is read from stdin (single JSON object).
All other key=value pairs come from CLI args.
"""
import sys, os, json

# parse CLI args
KVS = {}
for arg in sys.argv[1:]:
    if "=" in arg:
        k, v = arg.split("=", 1)
        KVS[k] = v

# read matched JSON from stdin
matched = json.load(sys.stdin)
findings = matched.get("findings", [])

bytecode_size = int(KVS.get("bytecode_size", "0"))
contract = KVS["contract"]
net_label = KVS["net_label"]
explorer_link = KVS["explorer_link"]
min_severity = int(KVS.get("min_severity", "0"))
fmt = KVS.get("format", "md")

# Filter
findings = [f for f in findings if f["severity"] >= min_severity]
overall = max([f["severity"] for f in findings], default=0)

# Load selectors
selectors = {}
try:
    with open(os.path.join(os.path.dirname(__file__), "..", "references", "selectors.json")) as fp:
        selectors = json.load(fp)["selectors"]
except Exception:
    pass


def lookup_selector(off, bc_hex):
    """Find the PUSH4 selector in the 64 bytes before the SSTORE opcode offset."""
    if not bc_hex.startswith("0x"):
        return None
    raw = bytes.fromhex(bc_hex[2:])
    if off <= 0 or off >= len(raw):
        return None
    start = max(0, off - 5)
    for j in range(start - 1, max(0, start - 64) - 1, -1):
        if raw[j] == 0x63 and j + 4 < len(raw):
            return "0x" + raw[j + 1:j + 5].hex()
    return None


# Bytecode hex comes in via env var (set by scan.sh before piping)
bc_hex = os.environ.get("REEPATTS_BYTECODE_HEX", "")
for f in findings:
    sel = lookup_selector(f["sstore_offset"], bc_hex)
    f["function_selector"] = sel or "(unknown)"
    f["function_signature"] = selectors.get(sel, "(unknown)") if sel else "(unknown)"


def sev_label(s):
    if s <= 30: return "LOW"
    if s <= 60: return "MEDIUM"
    if s <= 80: return "HIGH"
    return "CRITICAL"


def hexoff(off):
    return "0x" + format(off, "x")


if fmt == "json":
    out = {
        "contract": contract,
        "network": KVS.get("network"),
        "chain_id": int(KVS.get("chain_id", "0")),
        "net_label": net_label,
        "explorer_link": explorer_link,
        "bytecode_size": bytecode_size,
        "overall_score": overall,
        "min_severity": min_severity,
        "format": fmt,
        "findings": findings,
    }
    print(json.dumps(out, indent=2))
elif fmt == "txt":
    print("reepatts — Reentrancy report")
    print(f"  Contract:    {contract}")
    print(f"  Network:     {net_label}")
    print(f"  Bytecode:    {bytecode_size:,} bytes")
    print(f"  Overall:     {overall} / 100 ({sev_label(overall)})")
    print(f"  Findings:    {len(findings)}")
    print()
    for f in findings:
        print(f"  #{f['id']} — {f['pattern']}")
        print(f"    severity:  {f['severity']} / 100")
        print(f"    offset:    {hexoff(f['sstore_offset'])}")
        print(f"    function:  {f.get('function_selector','(unknown)')} {f.get('function_signature','(unknown)')}")
        print()
else:  # md
    print("# reepatts — Reentrancy report")
    print()
    print(f"**Contract:** [{contract}]({explorer_link})")
    print(f"**Network:** {net_label}")
    print(f"**Bytecode size:** {bytecode_size:,} bytes")
    print()
    label = sev_label(overall)
    print(f"## Overall score: {overall} / 100 ({label} RISK)")
    print()
    print(f"## Findings ({len(findings)})")
    print()
    if not findings:
        print("_No reentrancy patterns detected above severity threshold._")
    else:
        for f in findings:
            print(f"### Finding #{f['id']} — pattern: `{f['pattern']}`")
            print()
            print(f"- Severity: **{f['severity']} / 100**")
            print(f"- SSTORE offset: `{hexoff(f['sstore_offset'])}`")
            print(f"- Function selector: `{f.get('function_selector','(unknown)')}` ({f.get('function_signature','unknown')})")
            print(f"- Call opcode: `{f.get('call_opcode','?')}`")
            print()
            print("**Evidence:**")
            print()
            print(f"- SLOAD at `{hexoff(f['sload_offset'])}`")
            print(f"- CALL-family at `{hexoff(f['call_offset'])}`")
            if "sload2_offset" in f:
                print(f"- SLOAD (2nd) at `{hexoff(f['sload2_offset'])}`")
            print(f"- SSTORE at `{hexoff(f['sstore_offset'])}`")
            if f.get("cross_function"):
                print("- ⚠️ Cross-function pattern")
            print()
            print("**Recommended fix:** apply OpenZeppelin's `ReentrancyGuard` (or `nonReentrant` modifier) to this function, follow the checks-effects-interactions pattern, or add a `nonReentrant` storage guard before the external call.")
            print()
    print("---")
    print()
    print(f"Generated by [reepatts](https://github.com/pazzy422/reepatts) on {net_label}.")
