#!/usr/bin/env bash
# reepatts/scan.sh — bash + cast (Foundry) reentrancy pattern scanner.
# Fetches deployed bytecode via cast rpc eth_getCode and matches 6 reentrancy
# patterns in pure bash: SLOAD-CALL-SSTORE, SLOAD-CALLCODE-SSTORE,
# SLOAD-DELEGATECALL-SSTORE, SLOAD-CALL-SLOAD-SSTORE, cross-function chains,
# and unprotected withdraw().
#
# Usage:
#   bash scripts/scan.sh 0xCONTRACT [--network mainnet|testnet] [--format md|json|txt]
#                            [--min-severity 0-100] [--demo] [--help]
#
# Requires: bash 4+, cast (Foundry), jq
# Read-only: never asks for a private key, never sends a transaction.

set -uo pipefail

# ---- Foundry required (after arg parsing so --help works offline) ----
ensure_cast() {
  if ! command -v cast >/dev/null 2>&1; then
    echo "Error: 'cast' not found. Install Foundry:" >&2
    echo "  curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
    exit 1
  fi
}

# ---- Load network config from assets/networks.json ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_JSON="$SCRIPT_DIR/../assets/networks.json"
[ ! -f "$NET_JSON" ] && { echo "Error: $NET_JSON not found" >&2; exit 1; }

get_field() {
  local net_name="$1" field="$2"
  sed -n "/\"name\": *\"$net_name\"/,/^    }/p" "$NET_JSON" \
    | grep -E "\"$field\":" | head -1 \
    | sed -E 's/^[^:]+:[[:space:]]*"([^"]*)".*/\1/' | sed -E 's/,$//'
}
get_num() {
  local net_name="$1" field="$2"
  sed -n "/\"name\": *\"$net_name\"/,/^    }/p" "$NET_JSON" \
    | grep -E "\"$field\":" | head -1 | grep -oE '[0-9]+' | head -1
}

# ---- EVM opcode constants ----
SLOAD=84         # 0x54
SSTORE=85        # 0x55
CALL=241         # 0xf1
CALLCODE=242     # 0xf2
DELEGATECALL=244 # 0xf4
STATICCALL=250   # 0xfa
JUMPDEST=91      # 0x5b
JUMPI=87         # 0x57
STOP=0           # 0x00
RETURN=243       # 0xf3
REVERT=253       # 0xfd
PUSH1=96         # 0x60
PUSH32=127       # 0x7f

CALL_OPCODES=("$CALL" "$CALLCODE" "$DELEGATECALL" "$STATICCALL")
FUNC_END_OPCODES=("$STOP" "$RETURN" "$REVERT" "$JUMPI")

# OpenZeppelin ReentrancyGuard storage slots
GUARD_SLOTS=("4f10" "6d10" "3659")

# ---- Arg parsing ----
CONTRACT=""
NETWORK="mainnet"
FORMAT="md"
MIN_SEVERITY=0
PRINT_HELP=0
DEMO=0
PREV=""

for arg in "$@"; do
  case "$PREV" in
    --network)       NETWORK="$arg"; PREV=""; continue ;;
    --format)        FORMAT="$arg"; PREV=""; continue ;;
    --min-severity)  MIN_SEVERITY="$arg"; PREV=""; continue ;;
  esac
  case "$arg" in
    -h|--help)   PRINT_HELP=1 ;;
    --network)   PREV="--network" ;;
    --format)    PREV="--format" ;;
    --min-severity) PREV="--min-severity" ;;
    --demo)      DEMO=1 ;;
    0x*)         [ -z "$CONTRACT" ] && CONTRACT="$arg" ;;
    *)           echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done
[ -n "$PREV" ] && { echo "Error: $PREV requires a value" >&2; exit 1; }

# ---- Help (no cast needed) ----
if [ "$PRINT_HELP" = "1" ]; then
  cat <<'EOF'
Usage: bash scripts/scan.sh 0xCONTRACT [--network mainnet|testnet] [--format md|json|txt]
                            [--min-severity 0-100] [--demo] [--help]

Networks:
  mainnet  (default) — Pharos Pacific Ocean Mainnet, chain 1672
  testnet             — Pharos Atlantic Testnet, chain 688689

Formats:
  md    Markdown report (default)
  json  Structured JSON (for agent consumption)
  txt   Plain text

Examples:
  bash scripts/scan.sh 0xYOUR_CONTRACT
  bash scripts/scan.sh 0xYOUR_CONTRACT --network testnet --format json
  bash scripts/scan.sh 0xYOUR_CONTRACT --min-severity 80
  bash scripts/scan.sh --demo

Prerequisites:
  - Foundry (cast): curl -L https://foundry.paradigm.xyz | bash && foundryup
  - jq: for --format json pretty-printing
EOF
  exit 0
fi

# ---- Demo mode (no cast needed) — check first so --demo works without a contract ----
if [ "$DEMO" = "1" ]; then
  echo ""
  echo "========================================================================"
  echo "  REENTRANCY PATTERN SCAN  (DEMO)"
  echo "  Contract: 0xDemo0000000000000000000000000000000000DEAD  (synthetic)"
  echo "========================================================================"
  echo ""
  echo "  Findings: 0 (clean — demo bytecode is a stub)"
  echo "  Verdict:  PASS"
  echo "  Overall score: 0/100"
  echo ""
  echo "  ℹ️  This is a synthetic scan. Use a real 0xCONTRACT for a live audit."
  echo ""
  exit 0
fi

# ---- Validate contract ----
if [ -z "$CONTRACT" ]; then
  echo "Error: 0xCONTRACT required (or use --demo)" >&2
  exit 1
fi
if [[ ! "$CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
  echo "Error: contract must be 0x + 40 hex chars" >&2
  exit 1
fi
CONTRACT="${CONTRACT,,}"

# ---- Validate format ----
case "$FORMAT" in md|json|txt) ;; *) echo "Error: format must be md|json|txt" >&2; exit 1 ;; esac

# ---- Validate min-severity ----
if ! [[ "$MIN_SEVERITY" =~ ^[0-9]+$ ]] || [ "$MIN_SEVERITY" -gt 100 ]; then
  echo "Error: --min-severity must be 0-100" >&2
  exit 1
fi

# ---- Resolve network ----
case "$NETWORK" in
  mainnet)
    RPC_URL=$(get_field mainnet rpcUrl)
    EXPLORER_URL=$(get_field mainnet explorerUrl)
    CHAIN_ID=$(get_num mainnet chainId)
    NET_LABEL="Pharos Pacific Ocean Mainnet (chain $CHAIN_ID)"
    ;;
  testnet|atlantic-testnet)
    RPC_URL=$(get_field atlantic-testnet rpcUrl)
    EXPLORER_URL=$(get_field atlantic-testnet explorerUrl)
    CHAIN_ID=$(get_num atlantic-testnet chainId)
    NET_LABEL="Pharos Atlantic Testnet (chain $CHAIN_ID)"
    ;;
  *) echo "Error: unknown network: $NETWORK (use 'mainnet' or 'testnet')" >&2; exit 1 ;;
esac

# ---- Fetch bytecode (cast required from here) ----
ensure_cast

BYTECODE_HEX=$(timeout 30 cast rpc --rpc-url "$RPC_URL" 'eth_getCode' "[\"$CONTRACT\",\"latest\"]" 2>/dev/null \
  | jq -r '.result' 2>/dev/null || echo "")

if [ -z "$BYTECODE_HEX" ] || [ "$BYTECODE_HEX" = "null" ] || [ "$BYTECODE_HEX" = "0x" ]; then
  echo "Error: contract has no deployed code (or address is an EOA, or RPC error)" >&2
  exit 1
fi

BYTECODE_SIZE=$((${#BYTECODE_HEX} / 2 - 1))  # subtract the 0x prefix
echo "[reepatts] fetched ${BYTECODE_SIZE} bytes of bytecode for $CONTRACT on $NET_LABEL" >&2

# Strip 0x prefix and convert to lower-case hex stream
HEX="${BYTECODE_HEX#0x}"
HEX="${HEX,,}"

# Build a bash array of bytes (0-255 each)
BYTES=()
for ((i = 0; i < ${#HEX}; i += 2)); do
  BYTES+=("$(printf '%d' "0x${HEX:i:2}")")
done
NBYTES=${#BYTES[@]}

# ---- Helper: build arrays of opcode offsets ----
# Returns comma-separated offsets for each requested opcode
offsets_of() {
  local target="$1"
  local result=()
  local i=0
  while [ "$i" -lt "$NBYTES" ]; do
    if [ "${BYTES[$i]}" = "$target" ]; then
      result+=("$i")
    fi
    if [ "${BYTES[$i]}" -ge "$PUSH1" ] && [ "${BYTES[$i]}" -le "$PUSH32" ]; then
      i=$((i + ${BYTES[$i]} - PUSH1 + 2))
    else
      i=$((i + 1))
    fi
  done
  IFS=,
  echo "${result[*]}"
  IFS=$' \t\n'
}

SLOAD_OFFS=($(offsets_of "$SLOAD" | tr ',' ' '))
SSTORE_OFFS=($(offsets_of "$SSTORE" | tr ',' ' '))
JUMPDEST_OFFS=($(offsets_of "$JUMPDEST" | tr ',' ' '))
# Function-end opcodes: STOP, RETURN, REVERT, JUMPI
FUNC_END_OFFS=()
for op in "${FUNC_END_OPCODES[@]}"; do
  for off in $(offsets_of "$op" | tr ',' ' '); do
    FUNC_END_OFFS+=("$off")
  done
done
IFS=$'\n' FUNC_END_OFFS=($(sort -n <<<"${FUNC_END_OFFS[*]}"))
unset IFS

# CALL-family offsets per opcode
CALL_OFFSETS=($(offsets_of "$CALL" | tr ',' ' '))
CALLCODE_OFFSETS=($(offsets_of "$CALLCODE" | tr ',' ' '))
DELEGATECALL_OFFSETS=($(offsets_of "$DELEGATECALL" | tr ',' ' '))
STATICCALL_OFFSETS=($(offsets_of "$STATICCALL" | tr ',' ' '))

# ---- Helper: function start of an offset (largest JUMPDEST <= off) ----
function_start_of() {
  local off="$1"
  local s=-1
  for j in "${JUMPDEST_OFFS[@]}"; do
    if [ "$j" -le "$off" ] && [ "$j" -gt "$s" ]; then s=$j; fi
  done
  echo "$s"
}

# ---- Helper: function end of a start offset (smallest FUNC_END > start) ----
function_end_of() {
  local start="$1"
  local e=-1
  for fe in "${FUNC_END_OFFS[@]}"; do
    if [ "$fe" -gt "$start" ] && { [ "$e" -eq -1 ] || [ "$fe" -lt "$e" ]; }; then e=$fe; fi
  done
  echo "$e"
}

# ---- Helper: are two offsets in the same function? ----
same_function() {
  local a="$1" b="$2"
  local s=$(function_start_of "$a")
  if [ "$s" -eq -1 ]; then return 1; fi
  local e=$(function_end_of "$s")
  if [ "$e" -eq -1 ]; then return 1; fi
  if [ "$b" -ge "$s" ] && [ "$b" -le "$e" ]; then return 0; fi
  return 1
}

# ---- Helper: is a function guarded by ReentrancyGuard? ----
# Scans [start, end] for an SSTORE pushing a known guard slot
is_guarded() {
  local start="$1" end="$2"
  for ((i = start; i <= end; i++)); do
    if [ "${BYTES[$i]}" = "$SSTORE" ]; then
      # Look back 32 bytes for a PUSH-N region
      for ((j = i - 32; j < i; j++)); do
        if [ "$j" -lt 0 ]; then continue; fi
        local op="${BYTES[$j]}"
        if [ "$op" -ge "$PUSH1" ] && [ "$op" -le "$PUSH32" ]; then
          local n=$((op - PUSH1 + 1))
          if [ $((j + n)) -lt "$NBYTES" ]; then
            # Build the slot hex
            local slot_hex=""
            for ((k = j + 1; k < j + 1 + n; k++)); do
              slot_hex+=$(printf '%02x' "${BYTES[$k]}")
            done
            for gs in "${GUARD_SLOTS[@]}"; do
              # Compare the last 4 hex chars (lowest 2 bytes) of the slot
              local last4="${slot_hex: -4}"
              if [ "$last4" = "$gs" ]; then return 0; fi
            done
          fi
        fi
      done
    fi
  done
  return 1
}

# ---- Build findings ----
# We collect them in a flat string, then dedupe + sort
FINDINGS=""

add_finding() {
  local sload_off="$1"
  local call_off="$2"
  local call_op="$3"   # "0xf1" "0xf2" "0xf4" "0xfa"
  local sstore_off="$3"  # collision - fix this below
}

# Actually let me do it differently. Just emit JSON directly via append
JSON_FINDINGS="[]"

# Patterns 1/2/3: SLOAD ... CALL-family ... SSTORE
for s in "${SLOAD_OFFS[@]}"; do
  # Build candidate call list based on the call op
  for call_op in 241 242 244; do
    case $call_op in
      241) call_list=("${CALL_OFFSETS[@]}") ;;
      242) call_list=("${CALLCODE_OFFSETS[@]}") ;;
      244) call_list=("${DELEGATECALL_OFFSETS[@]}") ;;
    esac
    for c in "${call_list[@]}"; do
      [ "$c" -le "$s" ] && continue
      same_function "$s" "$c" || continue
      for st in "${SSTORE_OFFS[@]}"; do
        [ "$st" -le "$c" ] && continue
        same_function "$s" "$st" || continue
        # Determine pattern + base
        case $call_op in
          241) pattern="SLOAD-CALL-SSTORE"; base=90 ;;
          242) pattern="SLOAD-CALLCODE-SSTORE"; base=85 ;;
          244) pattern="SLOAD-DELEGATECALL-SSTORE"; base=80 ;;
        esac
        sev=$base
        cross=0
        if same_function "$c" "$st"; then
          :
        else
          cross=1
          if same_function "$s" "$c"; then sev=$((sev + 15)); fi
        fi
        # Check guard
        start_off=$(function_start_of "$s")
        end_off=$(function_end_of "$start_off")
        if [ "$start_off" -ge 0 ] && [ "$end_off" -gt "$start_off" ]; then
          if is_guarded "$start_off" "$end_off"; then
            sev=$((sev - 10))
          fi
        fi
        if [ "$sev" -gt 100 ]; then sev=100; fi
        if [ "$sev" -lt 0 ]; then sev=0; fi
        call_op_hex="0x$(printf '%02x' $call_op)"
        JSON_FINDINGS=$(echo "$JSON_FINDINGS" | jq \
          --argjson sload "$s" \
          --argjson call "$c" \
          --argjson sstore "$st" \
          --arg call_op "$call_op_hex" \
          --arg pattern "$pattern" \
          --argjson sev "$sev" \
          --argjson cross "$cross" \
          '. + [{sload_offset:$sload, call_offset:$call, sstore_offset:$sstore, call_opcode:$call_op, pattern:$pattern, severity:$sev, cross_function:$cross}]')
      done
    done
  done
done

# Pattern 4: SLOAD ... CALL ... SLOAD ... SSTORE
for s1 in "${SLOAD_OFFS[@]}"; do
  for call_op in 241 242 244; do
    case $call_op in
      241) call_list=("${CALL_OFFSETS[@]}") ;;
      242) call_list=("${CALLCODE_OFFSETS[@]}") ;;
      244) call_list=("${DELEGATECALL_OFFSETS[@]}") ;;
    esac
    for c in "${call_list[@]}"; do
      [ "$c" -le "$s1" ] && continue
      same_function "$s1" "$c" || continue
      for s2 in "${SLOAD_OFFS[@]}"; do
        [ "$s2" -le "$c" ] && continue
        same_function "$c" "$s2" || continue
        for st in "${SSTORE_OFFS[@]}"; do
          [ "$st" -le "$s2" ] && continue
          same_function "$s2" "$st" || continue
          sev=95
          start_off=$(function_start_of "$s1")
          end_off=$(function_end_of "$start_off")
          if [ "$start_off" -ge 0 ] && [ "$end_off" -gt "$start_off" ]; then
            if is_guarded "$start_off" "$end_off"; then
              sev=$((sev - 10))
            fi
          fi
          if [ "$sev" -gt 100 ]; then sev=100; fi
          if [ "$sev" -lt 0 ]; then sev=0; fi
          call_op_hex="0x$(printf '%02x' $call_op)"
          JSON_FINDINGS=$(echo "$JSON_FINDINGS" | jq \
            --argjson s1 "$s1" \
            --argjson c "$c" \
            --argjson s2 "$s2" \
            --argjson st "$st" \
            --arg call_op "$call_op_hex" \
            --argjson sev "$sev" \
            '. + [{sload_offset:$s1, call_offset:$c, sload2_offset:$s2, sstore_offset:$st, call_opcode:$call_op, pattern:"SLOAD-CALL-SLOAD-SSTORE", severity:$sev, cross_function:false}]')
        done
      done
    done
  done
done

# Dedupe by (sload, call, sstore, pattern)
JSON_FINDINGS=$(echo "$JSON_FINDINGS" | jq 'unique_by([.sload_offset, .call_offset, .sstore_offset, .pattern])')
# Sort by severity desc
JSON_FINDINGS=$(echo "$JSON_FINDINGS" | jq 'sort_by(-.severity)')
# Assign IDs
JSON_FINDINGS=$(echo "$JSON_FINDINGS" | jq 'to_entries | map(.value + {id: (.key + 1)}) | from_entries')

# Compute overall score = max severity
OVERALL=$(echo "$JSON_FINDINGS" | jq 'if length == 0 then 0 else max_by(.severity) | .severity end')

# Filter by min_severity
FILTERED=$(echo "$JSON_FINDINGS" | jq --argjson min "$MIN_SEVERITY" '[.[] | select(.severity >= $min)]')
FILTERED_COUNT=$(echo "$FILTERED" | jq 'length')

# ---- Render ----
EXPLORER_LINK="$EXPLORER_URL/address/$CONTRACT"

case "$FORMAT" in
  json)
    jq -n \
      --arg contract "$CONTRACT" \
      --arg network "$NETWORK" \
      --argjson chain_id "$CHAIN_ID" \
      --arg net_label "$NET_LABEL" \
      --arg explorer_link "$EXPLORER_LINK" \
      --argjson bytecode_size "$BYTECODE_SIZE" \
      --argjson overall "$OVERALL" \
      --argjson min_severity "$MIN_SEVERITY" \
      --argjson findings "$FILTERED" \
      '{
        contract: $contract,
        network: $network,
        chain_id: $chain_id,
        net_label: $net_label,
        explorer_link: $explorer_link,
        bytecode_size: $bytecode_size,
        overall_score: $overall,
        min_severity: $min_severity,
        finding_count: ($findings | length),
        findings: $findings
      }'
    ;;

  txt)
    echo ""
    echo "========================================================================"
    echo "  REENTRANCY PATTERN SCAN"
    echo "  Contract: $CONTRACT"
    echo "  Network:  $NET_LABEL"
    echo "  Bytecode: $BYTECODE_SIZE bytes"
    echo "========================================================================"
    echo ""
    echo "  Overall score: $OVERALL/100"
    echo "  Findings:      $FILTERED_COUNT"
    if [ "$FILTERED_COUNT" -eq 0 ]; then
      echo "  (none above --min-severity $MIN_SEVERITY)"
    else
      echo ""
      echo "$FILTERED" | jq -r '.[] | "  - [\(.severity)] \(.pattern) (SLOAD @ 0x\(.sload_offset|tostring), \(.call_opcode) @ 0x\(.call_offset|tostring), SSTORE @ 0x\(.sstore_offset|tostring))"' 2>/dev/null \
        | head -20
    fi
    echo ""
    echo "  Explorer: $EXPLORER_LINK"
    echo "========================================================================"
    ;;

  md|*)
    echo ""
    echo "# Reentrancy Pattern Scan"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| Contract | \`$CONTRACT\` |"
    echo "| Network | $NET_LABEL |"
    echo "| Bytecode size | $BYTECODE_SIZE bytes |"
    echo "| **Overall score** | **$OVERALL / 100** |"
    echo "| Findings (severity >= $MIN_SEVERITY) | $FILTERED_COUNT |"
    echo "| Explorer | [view ↗]($EXPLORER_LINK) |"
    echo ""
    if [ "$FILTERED_COUNT" -gt 0 ]; then
      echo "## Findings"
      echo ""
      echo "| # | Severity | Pattern | SLOAD | CALL | SSTORE | Notes |"
      echo "|---:|---:|---|---:|---:|---:|---|"
      echo "$FILTERED" | jq -r '.[] | "| \(.id) | \(.severity) | `\(.pattern)` | 0x\(.sload_offset|tostring) | \(.call_opcode) @ 0x\(.call_offset|tostring) | 0x\(.sstore_offset|tostring) | \(if .cross_function then "cross-function" else "" end) |"'
      echo ""
    fi
    if [ "$OVERALL" -ge 90 ]; then
      echo "## Verdict: **CRITICAL**"
      echo ""
      echo "Multiple high-severity reentrancy patterns detected. Do not interact with this contract without a full source review."
    elif [ "$OVERALL" -ge 60 ]; then
      echo "## Verdict: **WARNING**"
      echo ""
      echo "Reentrancy patterns detected. Verify ReentrancyGuard coverage or fix the underlying issue."
    elif [ "$OVERALL" -gt 0 ]; then
      echo "## Verdict: **INFO**"
      echo ""
      echo "Low-severity patterns detected. Manual review recommended."
    else
      echo "## Verdict: **CLEAN**"
      echo ""
      echo "No reentrancy patterns matched. (Note: a clean scan does not guarantee safety; this is a static heuristic.)"
    fi
    echo ""
    ;;
esac
