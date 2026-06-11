#!/usr/bin/env bash
# reepatts/scan_demo.sh — one-shot demo scan of a real public mainnet contract.
# Run with no arguments. Requires: bash, curl, python3.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Real public contract on Pharos Pacific Mainnet (a token with a Proxy pattern)
CONTRACT="0x76c2ca2fd57a0c4d3a1ce16a6f2f3a6c6e8a2d4b"

echo "==============================================="
echo " reepatts demo scan"
echo "==============================================="
echo " contract: $CONTRACT"
echo " network:  Pharos Pacific Ocean Mainnet (1672)"
echo " output:   Markdown, all severities"
echo "==============================================="
echo

bash "$SCRIPT_DIR/scan.sh" "$CONTRACT" --network mainnet --format md
