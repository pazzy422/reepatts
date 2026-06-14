---
name: reepatts
description: Security-focused AI agent skill that scans any Pharos contract's deployed bytecode for reentrancy vulnerabilities. Catches SLOAD-CALL-SSTORE, CALLCODE/DELEGATECALL variants, the 2016-DAO SLOAD-CALL-SLOAD-SSTORE shape, cross-function chains, and unprotected withdraw() — with OpenZeppelin ReentrancyGuard awareness. Use this skill whenever an agent needs to verify a contract is reentrancy-safe before approving, recommending, or relying on it. Triggers on phrases like "is this contract reentrancy-safe", "scan for reentrancy", "audit reentrancy", "check reentrancy guard", "pharos security check".
version: 2.0.0
author: pazzy422
requires: read
bins: [bash, cast, jq]
network: pharos
tags: [security, reentrancy, eip-721, evm, bytecode, pharos, foundry, bash]
agents: [claude, codex, gemini, openclaw]
---

# Reepatts — Reentrancy Pattern Scanner

A bash + cast (Foundry) skill that scans any Pharos contract's deployed bytecode for reentrancy patterns. Fetches the bytecode via `cast rpc eth_getCode` and matches 6 patterns in pure bash: `SLOAD-CALL-SSTORE`, `SLOAD-CALLCODE-SSTORE`, `SLOAD-DELEGATECALL-SSTORE`, `SLOAD-CALL-SLOAD-SSTORE`, cross-function chains, and unprotected `withdraw()`.

## How it scores

| Pattern | Base severity | Notes |
|---|---:|---|
| `SLOAD-CALL-SSTORE` | 90 | classic textbook reentrancy |
| `SLOAD-CALLCODE-SSTORE` | 85 | via CALLCODE (pre-0.5 Solidity) |
| `SLOAD-DELEGATECALL-SSTORE` | 80 | via DELEGATECALL (proxy risk) |
| `SLOAD-CALL-SLOAD-SSTORE` | 95 | classic + post-call re-read |
| Cross-function chain | +15 bonus | the dangerous one |
| ReentrancyGuard detected | -10 bonus | OZ guard recognized |

## Quick Actions

### Scan a contract on Pharos mainnet
```
Scan contract 0xabc...def for reentrancy on Pharos mainnet
```

### Run the demo
```
Run the reentrancy scanner demo
```

### Filter to critical findings
```
Scan contract 0xabc...def and only show CRITICAL findings (severity >= 80) as JSON
```

## Invocation

```bash
# Default: Markdown report, mainnet
bash scripts/scan.sh 0xYOUR_CONTRACT

# JSON output for an agent
bash scripts/scan.sh 0xYOUR_CONTRACT --format json

# Testnet
bash scripts/scan.sh 0xYOUR_CONTRACT --network testnet

# Only show critical (>= 80)
bash scripts/scan.sh 0xYOUR_CONTRACT --min-severity 80

# Demo (no cast or RPC)
bash scripts/scan.sh --demo
```

## Flags

| Flag | Description |
|---|---|
| `0xCONTRACT` | Contract address to scan (positional, required unless `--demo`) |
| `--network mainnet \| testnet` | Pharos chain (default: mainnet) |
| `--format md \| json \| txt` | Output format (default: md) |
| `--min-severity 0-100` | Only show findings at or above this severity (default: 0) |
| `--demo` | Run a synthetic scan (no cast or RPC needed) |
| `-h`, `--help` | Show the help text |

## Networks

| Network | Chain ID | RPC URL |
|---|---:|---|
| mainnet (Pacific Ocean) | 1672 | `https://rpc.pharos.xyz` |
| atlantic-testnet | 688689 | `https://atlantic.dplabs-internal.com` |

Chain config is read from `assets/networks.json` at startup.

## Verdict logic

- **CRITICAL** — overall score >= 90, multiple high-severity patterns
- **WARNING** — overall score 60-89, patterns detected but possibly guarded
- **INFO** — overall score 1-59, low-severity patterns
- **CLEAN** — overall score 0, no patterns matched

A clean scan does **not** guarantee safety. The matcher is a static heuristic.

## ReentrancyGuard awareness

The scanner recognizes the OpenZeppelin `ReentrancyGuard` storage slots (`0x4f10`, `0x6d10`, `0x3659`). When a containing function has an SSTORE to one of these slots, the severity is reduced by 10. This prevents false positives on contracts that use the standard guard pattern.

## Dependencies

- **Foundry** (gives you `cast`) — install with `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **bash 4+** — preinstalled on macOS, Ubuntu 20+, most Linux
- **jq** — required for `--format json` output and inline JSON building

## Security model

- The skill is **read-only** — it never imports, reads, or stores a private key.
- It reads deployed bytecode via `eth_getCode` (read-only RPC) — it cannot move funds.
- It never submits a transaction, never writes to disk, never phones home.
- The only network call is to the user-configured RPC URL.

## Error handling

- Missing cast → "Error: 'cast' not found. Install Foundry..."
- Bad address format → "Error: contract must be 0x + 40 hex chars"
- Bad format → "Error: format must be md|json|txt"
- Bad min-severity → "Error: --min-severity must be 0-100"
- Bad network → "Error: unknown network: X (use 'mainnet' or 'testnet')"
- Empty bytecode → "Error: contract has no deployed code (or address is an EOA, or RPC error)"
- Unknown arg → "Unknown arg: X"

## Reference docs

- `references/patterns.md` — detailed pattern descriptions
- `references/selectors.json` — the curated function selector list
- `examples/sample-report.md` — an annotated example report

## Repository layout

```
reepatts/
├── SKILL.md              # This file
├── README.md             # Full documentation
├── foundry.toml          # Minimal config so cast can find the project root
├── LICENSE               # MIT
├── assets/
│   └── networks.json     # mainnet + testnet chain config
├── references/
│   ├── patterns.md
│   └── selectors.json
├── examples/
│   └── sample-report.md
├── scripts/
│   └── scan.sh           # The single bash script that does the work
└── tests/
    └── test_scan_smoke.sh   # Offline smoke test
```
