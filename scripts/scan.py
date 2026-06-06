#!/usr/bin/env python3
"""
reepatts/scan.py — Reentrancy pattern scanner for deployed EVM bytecode.
Run on Pharos Atlantic Testnet or Pacific Mainnet.

Usage:
  python3 scripts/scan.py 0xCONTRACT [--network mainnet|atlantic-testnet] [--format md|json|txt] [--min-severity 0-100]
  python3 scripts/scan.py --demo    # scan a known public mainnet contract
  python3 scripts/scan.py --self    # scan the contract that called this script (default 0x0)

Requires:
  pip install web3
"""
import argparse
import json
import os
import sys
from pathlib import Path

# EVM opcode constants
SLOAD, SSTORE = 0x54, 0x55
CALL, CALLCODE, DELEGATECALL, STATICCALL = 0xf1, 0xf2, 0xf4, 0xfa
JUMPDEST, JUMPI = 0x5b, 0x57
STOP, RETURN, REVERT = 0x00, 0xf3, 0xfd

CALL_OPCODES = {CALL, CALLCODE, DELEGATECALL, STATICCALL}
GUARD_SLOTS = {0x4f10, 0x6d10, 0x3659}  # OpenZeppelin ReentrancyGuard

NETWORKS = {
    "mainnet": {
        "chainId": 1672,
        "rpcUrl": "https://rpc.pharos.xyz",
        "displayName": "Pharos Pacific Ocean Mainnet",
        "explorer": "https://www.pharosscan.xyz",
    },
    "atlantic-testnet": {
        "chainId": 688689,
        "rpcUrl": "https://atlantic.dplabs-internal.com",
        "displayName": "Pharos Atlantic Testnet",
        "explorer": "https://atlantic.pharosscan.xyz",
    },
}


def load_selectors():
    p = Path(__file__).parent.parent / "references" / "selectors.json"
    try:
        with open(p) as fp:
            return json.load(fp)["selectors"]
    except Exception:
        return {}


def fetch_bytecode(contract, rpc_url, retries=3):
    """Fetch the deployed bytecode of a contract via eth_getCode."""
    import urllib.request

    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [contract, "latest"],
        "id": 1,
    }).encode()
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                rpc_url, data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            if "error" in data:
                raise RuntimeError(f"RPC error: {data['error']}")
            result = data.get("result", "")
            if not result or result == "0x":
                raise RuntimeError("contract has no deployed code (or address is an EOA)")
            return result
        except Exception as e:
            last_err = e
    raise RuntimeError(f"failed to fetch bytecode after {retries} attempts: {last_err}")


def _iter_opcodes(raw):
    """Yield (offset, opcode) skipping over PUSH-data bytes so 0x00 in PUSH payloads is not misread as STOP."""
    i = 0
    while i < len(raw):
        op = raw[i]
        yield i, op
        # PUSH1..PUSH32
        if 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1


def find_basic_blocks(raw):
    """Return a list of (start, end) inclusive index ranges for each function-like basic block.
    Properly skips PUSH-data so we don't false-match 0x00 (STOP) inside PUSH payloads.
    """
    op_list = [(off, op) for off, op in _iter_opcodes(raw)]
    jumdests = [off for off, op in op_list if op == JUMPDEST]
    func_end_opcodes = {STOP, RETURN, REVERT, JUMPI}
    func_ends = [off for off, op in op_list if op in func_end_opcodes]
    blocks = []
    for j in jumdests:
        ends = [fe for fe in func_ends if fe > j]
        if ends:
            blocks.append((j, min(ends)))
    return blocks


def is_guarded(start, end, raw):
    """True if [start, end] contains a SSTORE pushing to a known ReentrancyGuard slot."""
    for i in range(start, min(end + 1, len(raw))):
        if raw[i] != SSTORE:
            continue
        for j in range(max(0, i - 32), i):
            op = raw[j]
            if 0x60 <= op <= 0x7f:  # PUSH1..PUSH32
                n = op - 0x5f
                if j + n < len(raw):
                    slot_bytes = raw[j + 1:j + 1 + n]
                    try:
                        slot = int.from_bytes(slot_bytes, "big")
                        if slot in GUARD_SLOTS:
                            return True
                    except Exception:
                        pass
    return False


def same_block(off_a, off_b, blocks):
    for s, e in blocks:
        if s <= off_a <= e and s <= off_b <= e:
            return True
    return False


def find_function_selector(off, raw):
    """Look backwards from the SSTORE opcode for a PUSH4 (0x63). Prefer the nearest non-slot PUSH4.
    Strategy: scan from off-5 (skipping the SSTORE's own 5-byte slot-push) backwards up to 64 bytes.
    Return the first PUSH4 found.
    """
    if off <= 0 or off >= len(raw):
        return None
    # Skip the SSTORE's slot-push: 5 bytes (PUSH4 + 4 data) ending at `off`.
    start = max(0, off - 5)
    # Walk backward from `off - 5` to find the first PUSH4 before the slot
    for j in range(start - 1, max(0, start - 64) - 1, -1):
        if raw[j] == 0x63 and j + 4 < len(raw):
            return "0x" + raw[j + 1:j + 5].hex()
    return None


def scan(bytecode_hex, selectors=None):
    """Run the 6-pattern matcher against the given bytecode and return a list of findings."""
    if selectors is None:
        selectors = {}
    assert bytecode_hex.startswith("0x")
    raw = bytes.fromhex(bytecode_hex[2:])
    blocks = find_basic_blocks(raw)

    sloads  = [i for i, b in enumerate(raw) if b == SLOAD]
    calls   = [i for i, b in enumerate(raw) if b in CALL_OPCODES]
    sstores = [i for i, b in enumerate(raw) if b == SSTORE]

    findings = []
    fid = 0

    # ----- Pattern 1/2/3: SLOAD ... CALL-family ... SSTORE -----
    for s in sloads:
        for c in calls:
            if c <= s:
                continue
            if raw[c] == STATICCALL:
                continue
            if not same_block(s, c, blocks):
                continue
            for st in sstores:
                if st <= c:
                    continue
                if not same_block(s, st, blocks):
                    continue
                # determine pattern
                if raw[c] == CALL:
                    pattern, base = "SLOAD-CALL-SSTORE", 90
                elif raw[c] == CALLCODE:
                    pattern, base = "SLOAD-CALLCODE-SSTORE", 85
                elif raw[c] == DELEGATECALL:
                    pattern, base = "SLOAD-DELEGATECALL-SSTORE", 80
                else:
                    pattern, base = "SLOAD-CALL-SSTORE", 90

                sev = base
                cross = not same_block(c, st, blocks)
                if not same_block(c, st, blocks) and same_block(s, c, blocks):
                    sev += 15
                # Guard penalty if same block
                if same_block(s, st, blocks):
                    for s_, e_ in blocks:
                        if s_ <= s <= e_:
                            if is_guarded(s_, e_, raw):
                                sev -= 10
                            break
                sev = max(0, min(100, sev))
                fid += 1
                findings.append({
                    "id": fid,
                    "pattern": pattern,
                    "severity": sev,
                    "sload_offset": s,
                    "call_offset": c,
                    "sstore_offset": st,
                    "call_opcode": hex(raw[c]),
                    "cross_function": cross,
                })

    # ----- Pattern 4: SLOAD ... CALL ... SLOAD ... SSTORE -----
    for s1 in sloads:
        for c in calls:
            if c <= s1:
                continue
            if raw[c] == STATICCALL:
                continue
            if not same_block(s1, c, blocks):
                continue
            for s2 in sloads:
                if s2 <= c:
                    continue
                if not same_block(c, s2, blocks):
                    continue
                for st in sstores:
                    if st <= s2:
                        continue
                    if not same_block(s2, st, blocks):
                        continue
                    sev = 95
                    for s_, e_ in blocks:
                        if s_ <= s1 <= e_:
                            if is_guarded(s_, e_, raw):
                                sev -= 10
                            break
                    sev = max(0, min(100, sev))
                    fid += 1
                    findings.append({
                        "id": fid,
                        "pattern": "SLOAD-CALL-SLOAD-SSTORE",
                        "severity": sev,
                        "sload_offset": s1,
                        "call_offset": c,
                        "sload2_offset": s2,
                        "sstore_offset": st,
                        "call_opcode": hex(raw[c]),
                        "cross_function": False,
                    })

    # Dedupe
    seen, unique = set(), []
    for f in findings:
        key = (f["sload_offset"], f["call_offset"], f["sstore_offset"], f["pattern"])
        if key in seen:
            continue
        seen.add(key)
        # Annotate with function selector (best-effort)
        sel = find_function_selector(f["sstore_offset"], raw)
        f["function_selector"] = sel or "(unknown)"
        f["function_signature"] = selectors.get(sel, "(unknown)") if sel else "(unknown)"
        unique.append(f)
    findings = sorted(unique, key=lambda f: -f["severity"])
    return findings, len(raw)


def sev_label(s):
    if s <= 30:
        return "LOW"
    if s <= 60:
        return "MEDIUM"
    if s <= 80:
        return "HIGH"
    return "CRITICAL"


def render(data, fmt):
    if fmt == "json":
        return json.dumps(data, indent=2)
    if fmt == "txt":
        out = []
        out.append("reepatts — Reentrancy report")
        out.append(f"  Contract:    {data['contract']}")
        out.append(f"  Network:     {data['net_label']}")
        out.append(f"  Bytecode:    {data['bytecode_size']:,} bytes")
        out.append(f"  Overall:     {data['overall_score']} / 100 ({sev_label(data['overall_score'])})")
        out.append(f"  Findings:    {len(data['findings'])}")
        out.append("")
        for f in data["findings"]:
            out.append(f"  #{f['id']} — {f['pattern']}")
            out.append(f"    severity:  {f['severity']} / 100")
            out.append(f"    offset:    0x{f['sstore_offset']:x}")
            out.append(f"    function:  {f.get('function_selector','(unknown)')} {f.get('function_signature','(unknown)')}")
            out.append("")
        return "\n".join(out)
    # md
    out = []
    out.append("# reepatts — Reentrancy report")
    out.append("")
    out.append(f"**Contract:** [{data['contract']}]({data['explorer_link']})")
    out.append(f"**Network:** {data['net_label']}")
    out.append(f"**Bytecode size:** {data['bytecode_size']:,} bytes")
    out.append("")
    label = sev_label(data["overall_score"])
    out.append(f"## Overall score: {data['overall_score']} / 100 ({label} RISK)")
    out.append("")
    out.append(f"## Findings ({len(data['findings'])})")
    out.append("")
    if not data["findings"]:
        out.append("_No reentrancy patterns detected above severity threshold._")
    else:
        for f in data["findings"]:
            out.append(f"### Finding #{f['id']} — pattern: `{f['pattern']}`")
            out.append("")
            out.append(f"- Severity: **{f['severity']} / 100**")
            out.append(f"- SSTORE offset: `0x{f['sstore_offset']:x}`")
            out.append(f"- Function selector: `{f.get('function_selector','(unknown)')}` ({f.get('function_signature','unknown')})")
            out.append(f"- Call opcode: `{f.get('call_opcode','?')}`")
            out.append("")
            out.append("**Evidence:**")
            out.append("")
            out.append(f"- SLOAD at `0x{f['sload_offset']:x}`")
            out.append(f"- CALL-family at `0x{f['call_offset']:x}`")
            if "sload2_offset" in f:
                out.append(f"- SLOAD (2nd) at `0x{f['sload2_offset']:x}`")
            out.append(f"- SSTORE at `0x{f['sstore_offset']:x}`")
            if f.get("cross_function"):
                out.append("- ⚠️ Cross-function pattern")
            out.append("")
            out.append("**Recommended fix:** apply OpenZeppelin's `ReentrancyGuard` (or `nonReentrant` modifier) to this function, follow the checks-effects-interactions pattern, or add a `nonReentrant` storage guard before the external call.")
            out.append("")
    out.append("---")
    out.append("")
    out.append(f"Generated by [reepatts](https://github.com/pazzy422/reepatts) on {data['net_label']}.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="reepatts — Reentrancy pattern scanner for Pharos")
    ap.add_argument("contract", nargs="?", help="contract address (0x...)")
    ap.add_argument("--network", default="atlantic-testnet", choices=list(NETWORKS.keys()))
    ap.add_argument("--format", default="md", choices=["md", "json", "txt"])
    ap.add_argument("--min-severity", type=int, default=0)
    ap.add_argument("--demo", action="store_true", help="scan a real public mainnet contract")
    ap.add_argument("--self", action="store_true", help="alias for --demo (deprecated)")
    args = ap.parse_args()

    contract = args.contract
    if args.demo or args.self:
        # real public contract on Pharos Pacific Mainnet (USDC.e — Proxy pattern, will have findings)
        contract = "0x76c2ca2fd57a0c4d3a1ce16a6f2f3a6c6e8a2d4b"

    if not contract:
        ap.print_help()
        sys.exit(1)

    contract = contract.lower()
    if not (contract.startswith("0x") and len(contract) == 42):
        print(f"ERROR: contract must look like 0x + 40 hex chars, got: {contract}", file=sys.stderr)
        sys.exit(2)

    net = NETWORKS[args.network]
    print(f"[reepatts] fetching bytecode for {contract} on {net['displayName']}...", file=sys.stderr)
    try:
        bc = fetch_bytecode(contract, net["rpcUrl"])
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(3)

    print(f"[reepatts] scanning {len(bc) // 2 - 1} bytes...", file=sys.stderr)
    selectors = load_selectors()
    findings, bc_size = scan(bc, selectors=selectors)

    # Filter
    findings = [f for f in findings if f["severity"] >= args.min_severity]
    overall = max([f["severity"] for f in findings], default=0)

    data = {
        "contract": contract,
        "network": args.network,
        "chain_id": net["chainId"],
        "net_label": net["displayName"],
        "explorer_link": f"{net['explorer']}/address/{contract}",
        "bytecode_size": bc_size,
        "overall_score": overall,
        "min_severity": args.min_severity,
        "format": args.format,
        "findings": findings,
    }
    print(render(data, args.format))


if __name__ == "__main__":
    main()
