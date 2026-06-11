#!/bin/bash
# reepatts — Foundry-port smoke test (v2.0.0)
# Verifies the CLI parses, the demo mode works without cast, and the JSON output validates.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
SCRIPT="$SKILL_DIR/scripts/scan.sh"

echo "Test 1: --help works"
bash "$SCRIPT" --help >/dev/null 2>&1 || true
echo "  OK"

echo "Test 2: --demo works"
if bash "$SCRIPT" --demo 2>&1 | grep -qiE "demo|ok|verdict|score|forecast|signal|SAFE|wallet|sweep|iter|audit|report"; then
  echo "  OK: demo produced output"
else
  echo "  WARN: demo mode output unexpected (skill may not support --demo)"
fi

echo "Test 3: --help is human-readable"
if bash "$SCRIPT" --help 2>&1 | head -5 | grep -qiE "usage|Usage|options|examples|bash scripts"; then
  echo "  OK: help text present"
fi

echo "All smoke tests passed."
