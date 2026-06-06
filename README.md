# reepatts

A static analyzer for **reentrancy patterns in deployed EVM bytecode**, built for the [Pharos Network](https://pharos.xyz). Give it a contract address on Pharos Atlantic Testnet or Pacific Ocean Mainnet, and it returns a per-finding report of every suspicious `SLOAD-CALL-SSTORE` fingerprint in the bytecode — with the byte offset, the function selector, a severity (0-100), and a recommended fix.

Ships as a [Pharos Agent Center](https://www.pharos.xyz/agent-center) skill — drop it into Claude / Codex / OpenClaw and the agent can audit any Pharos contract on demand.

## What it detects

Six patterns, ordered by severity:

| # | Pattern | Severity | Notes |
|---|---|---:|---|
| 1 | `SLOAD-CALL-SSTORE` | 90 | classic textbook reentrancy |
| 2 | `SLOAD-CALLCODE-SSTORE` | 85 | via CALLCODE (pre-0.5 Solidity) |
| 3 | `SLOAD-DELEGATECALL-SSTORE` | 80 | via DELEGATECALL (proxy-upgradeable risk) |
| 4 | `SLOAD-CALL-SLOAD-SSTORE` | 95 | classic + post-call re-read |
| 5 | cross-function chain (SSTORE, CALL, SSTORE) | 100 | the dangerous one |
| 6 | `Unprotected withdraw()` | 70 | value-transferring CALL with no guard |

Each finding is reported with:
- Byte offset (decimal + hex) of the suspect `SSTORE`
- The function selector (4-byte hex) it lives in, reverse-looked against a known-functions table
- A 0-100 severity score
- The full evidence (each SLOAD/CALL/SSTORE offset + the slot it touches)

## Install

```bash
# Option A — git clone
git clone https://github.com/pazzy422/reepatts.git
cd reepatts
chmod +x scripts/scan.sh scripts/scan_demo.sh
pip install web3            # only for the Python version

# Option B — one-line via OpenClaw
npx skills add https://github.com/pazzy422/reepatts

# Or: install as a Pharos Agent Center / Claude Code / Codex / OpenClaw skill
mkdir -p ~/.pharos/skills
cp -r . ~/.pharos/skills/reepatts
```

## Quick start

### Zero-dependency (bash + curl only)

```bash
# Default: Markdown report, mainnet
bash scripts/scan.sh 0x7a31dd32a880827477ab2bbeff47db188c896815 --network mainnet

# Machine-readable JSON
bash scripts/scan.sh 0xYOUR_CONTRACT --network mainnet --format json

# Filter to only HIGH/CRITICAL findings
bash scripts/scan.sh 0xYOUR_CONTRACT --network testnet --min-severity 60
```

### Python (richer output)

```bash
pip install web3
python3 scripts/scan.py 0xYOUR_CONTRACT --network mainnet --format md
```

### Run the demo (no arguments needed)

```bash
bash scripts/scan_demo.sh
```

This scans a real public mainnet contract and prints a sample report.

### Verify the install

```bash
bash scripts/scan.sh --help
python3 scripts/scan.py --help
python3 tests/test_patterns.py
```

## Output formats

| Format | Use case |
|---|---|
| `md` (default) | Human-readable Markdown — pasteable into GitHub, Notion, Slack |
| `json` | Machine-readable — for downstream tooling (audit dashboards, CI gates) |
| `txt` | Plain text — for audit logs, terminal output |

## Output example

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
  - SLOAD at 0x1a30 (slot 0x02)
  - CALL at 0x1a3a
  - SSTORE at 0x1a3e (slot 0x02)

### Finding #2 — pattern: Unprotected withdraw()
- Severity: 70 / 100
- Byte-offset: 0x2f10
- Function selector: 0x2e1a7d4d (withdraw(uint256))
- ...
```

## Networks

| Network | Chain ID | Native | RPC | Explorer |
|---|---:|---|---|---|
| Pharos Atlantic Testnet | 688689 | PHRS | `https://atlantic.dplabs-internal.com` | https://atlantic.pharosscan.xyz |
| Pharos Pacific Ocean Mainnet | 1672 | PROS | `https://rpc.pharos.xyz` | https://www.pharosscan.xyz |

## Repository layout

```
.
├── README.md
├── SKILL.md                          # Agent-side description
├── references/
│   ├── networks.json                 # Canonical Pharos config
│   ├── selectors.json                # Known 4-byte function selectors
│   └── patterns.md                   # Pattern specifications + examples
├── scripts/
│   ├── scan.sh                       # Zero-dep bash scanner
│   ├── scan.py                       # Python scanner (richer output)
│   └── scan_demo.sh                  # One-shot demo with a real contract
├── tests/
│   ├── test_patterns.py              # Pattern-matcher unit tests
│   └── fixtures/                     # Sample bytecodes for testing
└── examples/
    └── sample-report.md              # Captured real-contract scan
```

## Requirements

### Runtime

| Tool | Version | Required by |
|---|---|---|
| `bash` | 4+ | `scripts/scan.sh` |
| `curl` | any | `scripts/scan.sh` (JSON-RPC) |
| `python3` | 3.8+ | `scripts/scan.py` |
| `cast` / `forge` | any | (optional) — only if you want to use the underlying Pharos Agent Kit directly |

### Python packages

```bash
pip install web3
```

### Network access

| Endpoint | Why | Fallback if blocked |
|---|---|---|
| `https://rpc.pharos.xyz` (mainnet) | fetch the deployed bytecode | none — the skill is read-only against the chain |
| `https://atlantic.dplabs-internal.com` (testnet) | same, for testnet | none |

## Framework compatibility

| Framework | Compatible? | How to use |
|---|---|---|
| Pharos Agent Center (official) | ✅ yes | drop `SKILL.md` into `~/.pharos/skills/reepatts/` |
| Claude Code | ✅ yes | drop `SKILL.md` into `~/.claude/skills/` |
| Codex | ✅ yes | drop `SKILL.md` into `~/.codex/skills/` |
| OpenClaw | ✅ yes | `npx skills add https://github.com/pazzy422/reepatts` |
| Raw CLI / cron | ✅ yes | `bash scripts/scan.sh 0x...` — no agent needed |
| Any agent that reads SKILL.md | ✅ yes | triggers on "audit", "reentrancy", "scan this contract" |

## Tests

```bash
python3 tests/test_patterns.py
# 6 pattern tests + 4 severity tests + 2 selector-lookup tests
```

## Honest scope

reepatts is a **starting point**, not a verdict. It catches the obvious textbook patterns but does NOT substitute for a full audit firm. Use it to triage contracts quickly, then hand off to a real audit for the ones that flag.

## License

MIT
