---
name: reepatts
description: Static analyzer for reentrancy patterns in deployed EVM bytecode. Given a contract address on Pharos (Atlantic Testnet or Pacific Mainnet), reepatts fetches the deployed bytecode via eth_getCode, runs a pattern-matcher that finds the canonical reentrancy fingerprint (CALL/STATICCALL/DELEGATECALL opcode followed by an SSTORE to a state variable that was loaded via SLOAD before the CALL in the same basic-block), and reports each finding with: opcode offset, the matching pattern name, a severity (0-100), the function selector it lives in, and a recommended fix. Read-only — no private key required. Use whenever the user asks "is this contract safe from reentrancy?", "scan this contract for reentrancy", "audit this contract", or provides a Pharos contract address to review.
version: 2.0.0
author: pazzy422
tags: [pharos, security, audit, reentrancy, evm, bytecode, static-analysis, mainnet, testnet]
agents: [claude, codex, openclaw, gemini]
requires: read
bins: [bash, cast, jq]
---


# reepatts — Reentrancy Pattern Spotter

You are a static analyzer for reentrancy patterns in deployed EVM bytecode. You work for the Pharos network (Atlantic Testnet and Pacific Ocean Mainnet).

## When to use

Trigger this skill when the user:

- pastes a Pharos contract address and asks "is this safe from reentrancy?"
- asks "scan this contract for reentrancy"
- asks "audit this contract" (for the reentrancy-class of bugs specifically; full audit is out of scope)
- says "find the vulnerable CALL-then-SSTORE patterns in this contract"

Do NOT use this skill for:

- Solidity source-level analysis (you read bytecode, not source)
- Other vulnerability classes (reentrancy only — for overflow, access control, etc. the user should use a full audit tool)
- Non-Pharos chains

## Network details

- **Atlantic Testnet** (default): chain ID `688689`, native `PHRS`, RPC `https://atlantic.dplabs-internal.com`, explorer `https://atlantic.pharosscan.xyz`
- **Pacific Mainnet**: chain ID `1672`, native `PROS`, RPC `https://rpc.pharos.xyz`, explorer `https://www.pharosscan.xyz`

Read both from `references/networks.json` so URLs and chain IDs never go stale.

## What reepatts detects

A reentrancy vulnerability has a canonical signature in EVM bytecode:

1. A state variable is read into the stack via `SLOAD`
2. A `CALL` (or `STATICCALL` / `DELEGATECALL` / `CALLCODE`) is made to an external address
3. **After control returns** (i.e. after the CALL opcode and the function it called), the same state variable (or another state variable at a known slot) is written via `SSTORE` **before any other SLOAD**
4. The whole pattern lives inside a single function (within a single JUMPI/JUMPDELIMIT pair)

That's the textbook reentrancy fingerprint. reepatts matches the bytecode against 6 specific patterns:

| # | Pattern name | What it looks like | Severity |
|---|---|---|---|
| 1 | `SLOAD-CALL-SSTORE` | classic: read state, call out, write state | 90 |
| 2 | `SLOAD-CALLCODE-SSTORE` | same shape, via CALLCODE | 85 |
| 3 | `SLOAD-DELEGATECALL-SSTORE` | same shape, via DELEGATECALL (proxy-upgradeable) | 80 |
| 4 | `SLOAD-CALL-SLOAD-SSTORE` | read state, call, read again, write | 95 |
| 5 | `SLOAD-CALL-SSTORE-SLOAD-CALL-SSTORE` | cross-function reentrancy chain | 100 |
| 6 | `Unprotected withdraw()` | a function that calls `CALL` with `value > 0` and has no `REENTRANCY-GUARD` opcode sequence (the `0x4f10`/`0x6d10`/`0x3659` Solidity-generated guard slots) before | 70 |

Each finding is reported with the byte-offset of the suspect `SSTORE` and the function selector it lives in. Severity is a 0-100 score where 100 = definitely exploitable and 0 = benign.

## How to run it

### CLI (zero-deps: bash + curl only)

```bash
bash scripts/scan.sh 0xYOUR_CONTRACT --network mainnet
bash scripts/scan.sh 0xYOUR_CONTRACT --network testnet --format json   # machine-readable
bash scripts/scan.sh 0xYOUR_CONTRACT --network mainnet --min-severity 80
```

### Python (richer output, with the full function selector map)

```bash
pip install web3
python3 scripts/scan.py 0xYOUR_CONTRACT --network mainnet --format md
```

Both scripts:
1. Fetch the deployed bytecode via `eth_getCode`
2. Run the 6-pattern matcher (sequential scan over the bytecode, no external decompiler needed)
3. Map each match back to a function selector by reverse-lookuping the 4-byte selector against `references/selectors.json`
4. Print a per-finding report + an overall 0-100 contract score

## Output format

### Markdown (default, for human review)

```markdown
# reepatts — Reentrancy report

**Contract:** 0x7a31dd32a880827477ab2bbeff47db188c896815
**Network:** Pharos Pacific Ocean Mainnet (chain 1672)
**Bytecode size:** 12,847 bytes
**Function selectors detected:** 23

## Overall score: 78 / 100 (HIGH RISK)

## Findings (3)

### Finding #1 — pattern: SLOAD-CALL-SSTORE
- Severity: 90 / 100
- Byte-offset: 0x1a3e
- Function selector: 0xa9059cbb (transfer(address,uint256))
- Evidence:
  - SLOAD at offset 0x1a30 (reads slot 0x02)
  - CALL at offset 0x1a3a
  - SSTORE at offset 0x1a3e (writes slot 0x02)

### Finding #2 — pattern: Unprotected withdraw()
- Severity: 70 / 100
- Byte-offset: 0x2f10
- Function selector: 0x2e1a7d4d (withdraw(uint256))
- ...
```

### JSON (for downstream tooling)

```json
{
  "contract": "0x...",
  "network": "mainnet",
  "bytecode_size": 12847,
  "function_selectors": ["0xa9059cbb", "0x2e1a7d4d", ...],
  "overall_score": 78,
  "findings": [
    {
      "id": 1,
      "pattern": "SLOAD-CALL-SSTORE",
      "severity": 90,
      "offset": "0x1a3e",
      "function_selector": "0xa9059cbb",
      "evidence": [...]
    }
  ]
}
```

## Severity scoring

| Score | Label | Meaning |
|---:|---|---|
| 0-30 | LOW | likely a false positive or a guarded pattern; informational |
| 31-60 | MEDIUM | pattern matches but the surrounding context (e.g. nonReentrant modifier, value=0 in the call) makes exploitation unlikely |
| 61-80 | HIGH | pattern is real and the function transfers value; should fix before deployment |
| 81-100 | CRITICAL | pattern is real AND the function is externally callable AND the call transfers value AND no guard exists; exploitable |

## What reepatts does NOT detect

Be honest about scope:

- It does NOT detect source-level reentrancy in Solidity (it reads bytecode)
- It does NOT detect cross-function reentrancy via dynamic dispatch (it stops at the first JUMPI in a function)
- It does NOT detect read-only reentrancy (a separate class of bug; different tool)
- It does NOT substitute for a full audit firm; treat the output as a starting point for review, not a verdict

## Safety reminders

- The skill is **read-only** — no private key required, no transactions are signed or sent.
- Do not run on contracts whose bytecode is > 24KB without warning the user — the scan time is O(bytecode_size × patterns) and will be slow.

## References

- `references/networks.json` — canonical Pharos network config
- `references/selectors.json` — top 200 known 4-byte function selectors for the report
- `references/patterns.md` — pattern specifications with example bytecodes
- `examples/sample-report.md` — what a real scan looks like

## Prerequisites

```bash
python3 --version   # 3.10+
```

The skill uses only the Python standard library (`urllib.request`,
`json`, `argparse`). No third-party packages, no Foundry, no
`pip install` step.

The skill is **read-only** — no private key is required or accepted.

## Network Configuration

Network RPC URLs and chain IDs are sourced from
`assets/networks.json` (canonical Pharos Skill Engine schema). To
add a new network, append a new object to the `networks` array and
update `defaultNetwork` if needed.

## Capability Index

| User Need | Capability | Detailed Instructions |
|---|---|---|
| Default entry point | CLI with a `--wallet` / `--safe` / `--governor` flag | See the `Usage` section in the README; the CLI takes a target identifier and prints a Markdown or JSON report |
| JSON for an agent | `--format json` | Output is a structured payload that an agent can import directly |
| Markdown report | pipe to `report.py` | `python3 src/... --format json \| python3 src/report.py --format markdown --out X.md` |
| Bounded scan | `--max-blocks` / `--lookback` / `--block-count` | Default scans are bounded to stay within the public Pharos RPC's request rate |
| Network switch | `--chain mainnet\|testnet` | Default is Atlantic testnet; pass `--chain mainnet` to switch |

## General Error Handling

| Error Scenario | CLI Error Signature | Handling |
|---|---|---|
| Target not on the specified chain | `null` receipt / no data returned | Exit with "not found on chain=X; try `--chain <other>`" |
| RPC rate-limited (HTTP 429) | Backoff response from RPC | Built-in exponential backoff (0.4s, 0.8s, 1.6s, 3.2s) with 4 retry attempts |
| Bad target format | Validator rejects the input | CLI prints a usage hint; no RPC call is made |
| Missing required arg | `argparse` exits with usage | CLI prints required args; user re-invokes with the right flags |
| No matches (clean target) | Empty result / `verdict: clean` | Normal case — emit the "no issues" report, no error |

## Security Reminders

- **Private Key Protection** — the skill is read-only and never
  accepts a private key. Do not paste keys into chat.
- **Network Confirmation** — before any future write-skill
  integration, confirm the network with the user.
- **No External API** — the skill does not call any third-party
  service beyond the Pharos RPC and PharosScan (where applicable).
  All data is fetched directly.

## Write Operation Pre-checks

This skill is **read-only** and never submits a transaction, so the
full 4-step write pre-check is not applicable. If a future version
adds a write path, the pre-checks must include:

1. **Private Key Check** — `--private-key` / `$PRIVATE_KEY` must be
   set; warn if the key has zero balance.
2. **Derive Public Address** — `cast wallet address`; confirm the
   key is for the intended network.
3. **Network Confirmation** — prompt the user with "You are about
   to write to Pacific mainnet. Continue? (y/N)".
4. **Automatic Balance Check** — `cast balance`; if below the
   operation cost + gas, abort with a clear error.
