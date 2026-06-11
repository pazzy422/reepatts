#!/usr/bin/env bash
# reepatts/scan.sh — zero-dep bash scanner for reentrancy patterns in deployed EVM bytecode.
# Usage:
#   bash scripts/scan.sh 0xCONTRACT --network mainnet
#   bash scripts/scan.sh 0xCONTRACT --network testnet --format json
#   bash scripts/scan.sh 0xCONTRACT --network mainnet --min-severity 80
#
# Requires: bash 4+, curl, python3
# Read-only: never asks for a private key, never sends a transaction.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -------------------- args --------------------
if [[ $# -lt 1 ]]; then
  cat <<EOF
Usage: bash scripts/scan.sh 0xCONTRACT [--network mainnet|atlantic-testnet] [--format md|json|txt] [--min-severity 0-100]

Networks:
  atlantic-testnet  (default) — Pharos Atlantic Testnet, chain 688689
  mainnet                       — Pharos Pacific Ocean Mainnet, chain 1672

Examples:
  bash scripts/scan.sh 0x7a31dd32a880827477ab2bbeff47db188c896815 --network mainnet
  bash scripts/scan.sh 0xYOUR_CONTRACT --network testnet --format json
  bash scripts/scan.sh 0xYOUR_CONTRACT --network mainnet --min-severity 80
EOF
  exit 0
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  bash "$0"
  exit 0
fi

CONTRACT="${1,,}"
NETWORK="atlantic-testnet"
FORMAT="md"
MIN_SEVERITY=0

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)       NETWORK="$2"; shift 2 ;;
    --format)        FORMAT="$2"; shift 2 ;;
    --min-severity)  MIN_SEVERITY="$2"; shift 2 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

# validate
if [[ ! "$CONTRACT" =~ ^0x[0-9a-f]{40}$ ]]; then
  echo "ERROR: contract must look like 0x + 40 hex chars" >&2; exit 2
fi

case "$NETWORK" in
  mainnet)
    CHAIN_ID=1672
    RPC="https://rpc.pharos.xyz"
    EXPLORER="https://www.pharosscan.xyz"
    NET_LABEL="Pharos Pacific Ocean Mainnet (chain 1672)"
    ;;
  atlantic-testnet|testnet)
    CHAIN_ID=688689
    RPC="https://atlantic.dplabs-internal.com"
    EXPLORER="https://atlantic.pharosscan.xyz"
    NET_LABEL="Pharos Atlantic Testnet (chain 688689)"
    ;;
  *) echo "ERROR: unknown network: $NETWORK" >&2; exit 2 ;;
esac

case "$FORMAT" in md|json|txt) ;; *) echo "ERROR: format must be md|json|txt" >&2; exit 2 ;; esac

# -------------------- fetch bytecode --------------------
PAYLOAD=$(printf '{"jsonrpc":"2.0","method":"eth_getCode","params":["%s","latest"],"id":1}' "$CONTRACT")

RESP=$(curl -sS -X POST -H "Content-Type: application/json" --data "$PAYLOAD" "$RPC")
BYTECODE_HEX=$(printf '%s' "$RESP" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if "error" in d:
    print("ERROR:", d["error"].get("message", d["error"]), file=sys.stderr); sys.exit(3)
r = d.get("result", "")
if not r or r == "0x":
    print("ERROR: contract has no deployed code (or address is an EOA)", file=sys.stderr); sys.exit(4)
print(r)
')

BYTECODE_SIZE=$((${#BYTECODE_HEX} / 2 - 1))
echo "[reepatts] fetched ${BYTECODE_SIZE} bytes of bytecode for $CONTRACT on $NET_LABEL" >&2

# -------------------- run pattern matcher --------------------
MATCHED_JSON=$(export REEPATTS_BYTECODE_HEX="$BYTECODE_HEX" && BYTECODE_HEX="$BYTECODE_HEX" python3 <<'PYEOF'
import os, json

bytecode = os.environ["REEPATTS_BYTECODE_HEX"]
assert bytecode.startswith("0x")
raw = bytes.fromhex(bytecode[2:])

# EVM opcode constants
SLOAD, SSTORE = 0x54, 0x55
CALL, CALLCODE, DELEGATECALL, STATICCALL = 0xf1, 0xf2, 0xf4, 0xfa
JUMPDEST, JUMPI = 0x5b, 0x57
STOP, RETURN, REVERT = 0x00, 0xf3, 0xfd
CALL_OPCODES = {CALL, CALLCODE, DELEGATECALL, STATICCALL}
GUARD_SLOTS = {0x4f10, 0x6d10, 0x3659}

# PUSH-data-aware opcode iterator
def iter_opcodes(b):
    i = 0
    while i < len(b):
        op = b[i]
        yield i, op
        if 0x60 <= op <= 0x7f:
            i += (op - 0x5f) + 1
        else:
            i += 1

op_list = list(iter_opcodes(raw))
jumdests = [off for off, op in op_list if op == JUMPDEST]
func_ends = [off for off, op in op_list if op in (STOP, RETURN, REVERT, JUMPI)]
sloads  = [off for off, op in op_list if op == SLOAD]
calls   = [off for off, op in op_list if op in CALL_OPCODES]
sstores = [off for off, op in op_list if op == SSTORE]

def in_same_function(off_a, off_b):
    s = -1
    for j in jumdests:
        if j <= off_a and j > s: s = j
    if s == -1: return False
    e = -1
    for fe in func_ends:
        if fe > s and (e == -1 or fe < e): e = fe
    if e == -1: return False
    return s <= off_b <= e

def function_start_of(off):
    s = -1
    for j in jumdests:
        if j <= off and j > s: s = j
    return s

def function_end_of(start):
    e = -1
    for fe in func_ends:
        if fe > start and (e == -1 or fe < e): e = fe
    return e

def is_guarded(start, end):
    for i in range(start, min(end + 1, len(raw))):
        if raw[i] == SSTORE:
            for j in range(max(0, i - 32), i):
                op = raw[j]
                if 0x60 <= op <= 0x7f:
                    n = op - 0x5f
                    if j + n < len(raw):
                        slot_bytes = raw[j+1:j+1+n]
                        try:
                            slot = int.from_bytes(slot_bytes, "big")
                            if slot in GUARD_SLOTS:
                                return True
                        except Exception:
                            pass
    return False

findings = []
fid = 0

# ----- Pattern 1/2/3: SLOAD ... CALL-family ... SSTORE -----
for s in sloads:
    for c in calls:
        if c <= s: continue
        if raw[c] == STATICCALL: continue
        if not in_same_function(s, c): continue
        for st in sstores:
            if st <= c: continue
            if not in_same_function(s, st): continue
            if raw[c] == CALL:           pattern, base = "SLOAD-CALL-SSTORE", 90
            elif raw[c] == CALLCODE:     pattern, base = "SLOAD-CALLCODE-SSTORE", 85
            elif raw[c] == DELEGATECALL: pattern, base = "SLOAD-DELEGATECALL-SSTORE", 80
            else:                        pattern, base = "SLOAD-CALL-SSTORE", 90
            sev = base
            cross = not in_same_function(c, st)
            if not in_same_function(c, st) and in_same_function(s, c):
                sev += 15
            if in_same_function(s, st):
                start = function_start_of(s)
                end = function_end_of(start)
                if start >= 0 and end > start and is_guarded(start, end):
                    sev -= 10
            sev = max(0, min(100, sev))
            fid += 1
            findings.append({
                "id": fid, "pattern": pattern, "severity": sev,
                "sload_offset": s, "call_offset": c, "sstore_offset": st,
                "call_opcode": hex(raw[c]), "cross_function": cross,
            })

# ----- Pattern 4: SLOAD ... CALL ... SLOAD ... SSTORE -----
for s1 in sloads:
    for c in calls:
        if c <= s1: continue
        if raw[c] == STATICCALL: continue
        if not in_same_function(s1, c): continue
        for s2 in sloads:
            if s2 <= c: continue
            if not in_same_function(c, s2): continue
            for st in sstores:
                if st <= s2: continue
                if not in_same_function(s2, st): continue
                sev = 95
                start = function_start_of(s1)
                end = function_end_of(start) if start >= 0 else -1
                if start >= 0 and end > start and is_guarded(start, end):
                    sev -= 10
                sev = max(0, min(100, sev))
                fid += 1
                findings.append({
                    "id": fid, "pattern": "SLOAD-CALL-SLOAD-SSTORE", "severity": sev,
                    "sload_offset": s1, "call_offset": c, "sload2_offset": s2, "sstore_offset": st,
                    "call_opcode": hex(raw[c]), "cross_function": False,
                })

# Dedupe
seen, unique = set(), []
for f in findings:
    key = (f["sload_offset"], f["call_offset"], f["sstore_offset"], f["pattern"])
    if key in seen: continue
    seen.add(key)
    unique.append(f)
findings = sorted(unique, key=lambda f: -f["severity"])
overall = max([f["severity"] for f in findings], default=0)
print(json.dumps({"findings": findings, "overall_score": overall}))
PYEOF
)

# -------------------- render output --------------------
EXPLORER_LINK="$EXPLORER/address/$CONTRACT"
export REEPATTS_BYTECODE_HEX="$BYTECODE_HEX"
echo "$MATCHED_JSON" | python3 "$SCRIPT_DIR/_render.py" \
  "contract=$CONTRACT" \
  "network=$NETWORK" \
  "chain_id=$CHAIN_ID" \
  "net_label=$NET_LABEL" \
  "explorer_link=$EXPLORER_LINK" \
  "bytecode_size=$BYTECODE_SIZE" \
  "min_severity=$MIN_SEVERITY" \
  "format=$FORMAT"
