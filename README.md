# reepatts

A static analyzer for **reentrancy patterns in deployed EVM bytecode**, built for the [Pharos Network](https://pharos.xyz). Point it at a contract on Pharos Atlantic Testnet or Pacific Ocean Mainnet and it returns a per-finding report of every suspicious `SLOAD-CALL-SSTORE` fingerprint in the bytecode — byte offset, function selector, severity (0-100), and a recommended fix.

Six patterns matched: textbook `SLOAD-CALL-SSTORE`, `CALLCODE`/`DELEGATECALL` variants, the 2016-DAO shape `SLOAD-CALL-SLOAD-SSTORE`, cross-function chains, and unprotected `withdraw()`. The matcher is PUSH-data aware (no false-positive on slot bytes that happen to be `0x00`) and recognizes OpenZeppelin's `ReentrancyGuard` so guarded contracts don't false-flag.

Drop `SKILL.md` into your agent's skills directory and the agent can audit any Pharos contract on demand. Works with Claude Code, Codex, OpenClaw, and the Pharos Agent Center.

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

### 1. Install Foundry (the engine the skill is built on)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Verify with `cast --version`. This gives you `cast`, `forge`, `anvil`, and `chisel` on your `$PATH`. The skill uses `cast` for every RPC read.

### 2. Install jq (used to parse JSON)

```bash
# macOS
brew install jq
# Debian/Ubuntu/Termux
apt install -y jq
# Alpine
apk add jq
```

Verify with `jq --version`.

### 3. Get the skill

```bash
git clone https://github.com/pazzy422/reepatts
cd reepatts
chmod +x scripts/*.sh
```

That's it. No `pip install`, no `npm install`, no `forge build`, no compile. The skill is a bash script that uses `cast` (from Foundry) for every RPC read. The `assets/networks.json` file already knows the Pharos Pacific Mainnet and Atlantic Testnet endpoints.
## Quick test (try it in 30 seconds)

After the 3-step install above, run the demo mode (no private key, no RPC, no setup):

```bash
bash scripts/scan.sh 0xYOUR_CONTRACT
```

You should see a printed report. The demo uses synthetic data, so it works offline.

To run a real check on a Pharos transaction, wallet, or token, replace the placeholder:

```bash
bash scripts/scan.sh 0xYOUR_CONTRACT --network mainnet --format md
```

## Use in an AI agent (Claude Code / Codex / OpenClaw / Pharos Agent Center)

The skill ships with a `SKILL.md` that AI agents auto-load. Once installed in your agent, just ask in natural language — the agent will read `SKILL.md` and run the bash script for you.

```text
"Is this Pharos contract 0xabc... safe from reentrancy?"
```

The agent will run `bash scripts/scan.sh 0xYOUR_CONTRACT` (or the live command with the address you gave) and read the result back to you.

### Install in your agent

**Option A — Pharos Agent Center** (one-line install):

```bash
# from inside any agent that has the Pharos Agent Center CLI
pharos-skill install https://github.com/pazzy422/reepatts
```

**Option B — OpenClaw / Claude Code / Codex** (one-line via npm):

```bash
npx skills add https://github.com/pazzy422/reepatts
```

**Option C — Manual install** (drop into your agent's skills directory):

```bash
# Clone the skill
git clone https://github.com/pazzy422/reepatts
cd reepatts

# Claude Code: copy to ~/.claude/skills/
mkdir -p ~/.claude/skills/reepatts
cp -r . ~/.claude/skills/reepatts/

# Codex: copy to ~/.codex/skills/
mkdir -p ~/.codex/skills/reepatts
cp -r . ~/.codex/skills/reepatts/

# OpenClaw: copy to ~/.openclaw/skills/
mkdir -p ~/.openclaw/skills/reepatts
cp -r . ~/.openclaw/skills/reepatts/

# Then restart the agent — the skill will be auto-loaded.
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
| Pharos Agent Center | ✅ yes | `cp -r . ~/.pharos/skills/reepatts` (or symlink) |
| Claude Code | ✅ yes | `cp -r . ~/.claude/skills/reepatts` |
| Codex | ✅ yes | `cp -r . ~/.codex/skills/reepatts` |
| OpenClaw | ✅ yes | `npx skills add https://github.com/pazzy422/reepatts` |
| Raw CLI / cron | ✅ yes | `bash scripts/scan.sh 0x...` — no agent needed |
| Any agent that reads SKILL.md | ✅ yes | description front-matter triggers on "reentrancy", "scan", "audit" |

## Tests

```bash
python3 tests/test_patterns.py
# 6 pattern tests + 4 severity tests + 2 selector-lookup tests
```

## Honest scope

reepatts is a **starting point**, not a verdict. It catches the obvious textbook patterns but does NOT substitute for a full audit firm. Use it to triage contracts quickly, then hand off to a real audit for the ones that flag.

## License

MIT
