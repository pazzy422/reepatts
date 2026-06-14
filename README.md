# Reepatts — Reentrancy Pattern Scanner

> Static analyzer for reentrancy patterns in deployed EVM bytecode on Pharos. Catches SLOAD-CALL-SSTORE, CALLCODE / DELEGATECALL variants, cross-function chains, and unprotected withdraw().

[![foundry](https://img.shields.io/badge/built%20with-Foundry-orange)]()
[![bash](https://img.shields.io/badge/script-bash-blue)]()
[![license](https://img.shields.io/badge/license-MIT-green)]()
[![pharos](https://img.shields.io/badge/network-Pharos-blueviolet)]()
[![ai-agent](https://img.shields.io/badge/callable%20by-AI%20agent-purple)]()

## What it is

This is a **skill built for the Pharos network** — a self-contained, deterministic bash script that runs on top of the [Pharos](https://pharos.network) EVM chains. It is **not** an AI agent itself, and not a chatbot. It is a single bash script that:

- takes input from the caller via CLI flags,
- reads live bytecode from Pharos via `cast` (Foundry),
- runs its own pattern-matching in pure bash,
- prints a structured report (Markdown, JSON, or text) to stdout.

Fetches the contract's deployed bytecode via `cast rpc eth_getCode` and matches 6 reentrancy patterns in pure bash: `SLOAD-CALL-SSTORE` (textbook), `SLOAD-CALLCODE-SSTORE` (pre-0.5 Solidity), `SLOAD-DELEGATECALL-SSTORE` (proxy risk), `SLOAD-CALL-SLOAD-SSTORE` (post-call re-read), cross-function chains, and unprotected `withdraw()`. The matcher is PUSH-data-aware (no false-positives on slot bytes that happen to be `0x00`) and recognizes OpenZeppelin's `ReentrancyGuard` (storage slots `0x4f10` / `0x6d10` / `0x3659`) so guarded contracts don't false-flag. Each finding has a 0-100 severity, byte offsets, function selector, and a recommended fix path. Output as Markdown, JSON, or text. Bounded by `--min-severity`.

## What it detects

Six patterns, ordered by severity:

| # | Pattern | Base severity | Notes |
|---|---|---:|---|
| 1 | `SLOAD-CALL-SSTORE` | 90 | classic textbook reentrancy |
| 2 | `SLOAD-CALLCODE-SSTORE` | 85 | via CALLCODE (pre-0.5 Solidity) |
| 3 | `SLOAD-DELEGATECALL-SSTORE` | 80 | via DELEGATECALL (proxy-upgradeable risk) |
| 4 | `SLOAD-CALL-SLOAD-SSTORE` | 95 | classic + post-call re-read |
| 5 | cross-function chain (SSTORE, CALL, SSTORE) | +15 bonus | the dangerous one |
| 6 | ReentrancyGuard detected | -10 bonus | OZ guard recognized; not a true positive |

Each finding is reported with:
- Byte offset (decimal + hex) of the suspect `SLOAD`, `CALL`, and `SSTORE`
- The call opcode used (CALL / CALLCODE / DELEGATECALL / STATICCALL)
- A 0-100 severity score
- Whether the pattern crosses function boundaries
- Whether the containing function is protected by a known ReentrancyGuard

## Use it from an AI agent

This skill is designed to be **called by an AI agent** (a Claude Code / Codex / Cursor agent, the Pharos Agent Center, or any custom LLM agent). The agent reads `SKILL.md` to discover the skill's flags, fills them in based on the user's request, and runs the bash script in its sandbox. The agent's job is just to translate "is this contract reentrancy-safe?" into `bash scripts/scan.sh 0xADDR`.

Typical agent-side flow:

```text
User -> Agent: "Is this Pharos contract reentrancy-safe?"
Agent -> looks up SKILL.md for Reepatts — Reentrancy Pattern Scanner
Agent -> runs: bash scripts/scan.sh 0xCONTRACT
Agent -> reads the per-finding severity, presents the critical items to the user
```

The script prints structured output to stdout and human-readable progress to stderr, so the agent can parse the stdout cleanly (with `jq`) without being polluted by progress messages.

## Install

You need three things: **Foundry** (for `cast`), **jq** (for JSON pretty-printing), and **git** (to clone the repo).

```bash
# 1. Install Foundry (gives you cast, forge, anvil, chisel)
curl -L https://foundry.paradigm.xyz | bash
foundryup
# Reload your shell so the new commands are on PATH:
exec $SHELL
cast --version   # should print 1.x or higher

# 2. Install jq (required for --format json)
# macOS:   brew install jq
# Ubuntu:  sudo apt-get install -y jq
# Alpine:  apk add jq
jq --version

# 3. Clone this repo
git clone https://github.com/pazzy422/reepatts.git
cd reepatts
chmod +x scripts/*.sh tests/*.sh
```

## Quick test (30 seconds, no API keys needed)

```bash
bash scripts/scan.sh --demo
```

The demo runs offline and prints a synthetic report — no cast, no RPC.

## Usage

```bash
# Default: Markdown report, mainnet
bash scripts/scan.sh 0xYOUR_CONTRACT

# JSON output for an agent
bash scripts/scan.sh 0xYOUR_CONTRACT --format json

# Testnet
bash scripts/scan.sh 0xYOUR_CONTRACT --network testnet

# Only show CRITICAL/HIGH (>= 80)
bash scripts/scan.sh 0xYOUR_CONTRACT --min-severity 80

# Demo (no cast or RPC needed)
bash scripts/scan.sh --demo
```

### All flags

```
0xCONTRACT --network mainnet|testnet --format md|json|txt --min-severity 0-100 --demo --help
```

| Flag | Description |
|---|---|
| `0xCONTRACT` | Contract address to scan (positional, required unless `--demo`) |
| `--network mainnet \| testnet` | Pharos chain (default: mainnet) |
| `--format md \| json \| txt` | Output format (default: md) |
| `--min-severity 0-100` | Only show findings at or above this severity (default: 0 = all) |
| `--demo` | Run a synthetic scan (no cast or RPC needed) |
| `-h`, `--help` | Show the help text |

## Networks

The skill is built to run against the Pharos EVM chains. The chain config is stored in `assets/networks.json` and read at startup — no hardcoded URLs in the script.

| Network | Chain ID | RPC URL | Default |
|---|---:|---|:---:|
| mainnet (Pacific Ocean) | 1672 | `https://rpc.pharos.xyz` | ✓ |
| atlantic-testnet | 688689 | `https://atlantic.dplabs-internal.com` |  |

The script defaults to mainnet. Pass `--network testnet` to use the testnet instead. You can also override the RPC URL by editing `assets/networks.json`.

## Set it up in an AI agent

Three install paths for any AI agent that wants to call this skill.

### Path A — Pharos Agent Center (for the official Pharos LLM agent)

The Pharos Agent Center is the official agent runtime for the Pharos network. It reads `SKILL.md` from any skill repo to discover capabilities, dependencies, and required flags.

1. **Copy the skill into the Agent Center's skills directory:**
   ```bash
   cp -r scripts assets references examples SKILL.md README.md foundry.toml LICENSE \
     ~/.pharos/agent-center/skills/reepatts/
   ```

2. **Reload the Agent Center's skill registry:**
   ```bash
   pharos-agent reload-skills
   ```

3. **Invoke from the agent's chat UI:**
   ```text
   User: "Does this Pharos contract have reentrancy vulnerabilities?"
   Agent Center: loads Reepatts — Reentrancy Pattern Scanner, runs:
     bash ~/.pharos/agent-center/skills/reepatts/scripts/scan.sh 0xCONTRACT
   ```

### Path B — `npx skills add` (for Claude Code, Cursor, Codex, generic MCP agents)

```bash
npx skills add https://github.com/pazzy422/reepatts --skill reepatts
```

### Path C — Manual copy (any agent that reads `~/.claude/skills/`)

```bash
mkdir -p ~/.claude/skills/reepatts
cp -r scripts assets references examples SKILL.md README.md foundry.toml LICENSE ~/.claude/skills/reepatts/
```

### Path D — Direct invocation (shell agents, cron jobs, CI pipelines)

```bash
bash scripts/scan.sh 0xCONTRACT
```

### What the agent says to invoke this skill

| Caller says | Script invocation |
|---|---|
| Scan `0xabc...def` for reentrancy on Pharos mainnet | `bash scripts/scan.sh 0xabc...def` |
| Run the reentrancy scanner demo | `bash scripts/scan.sh --demo` |
| Scan and return only CRITICAL findings as JSON | `bash scripts/scan.sh 0xabc...def --min-severity 80 --format json` |
| "Run the demo" | `bash scripts/scan.sh --demo` |

## Security model

The skill is **read-only by design**:

- The script never imports, reads, or stores a private key.
- It reads deployed bytecode via `eth_getCode` (read-only RPC) — it cannot move funds.
- It never submits a transaction, never writes to disk, never phones home.
- The only network call is to the user-configured RPC URL.

A **clean scan does not guarantee safety**. The matcher is a static heuristic — it finds pattern matches in bytecode but cannot reason about control flow, storage layout, or cross-contract calls. Treat findings as "needs a human review", not as a verdict.

## Framework

| Layer | Tech | Purpose |
|---|---|---|
| Engine | **bash 4+** | Script host (single file per skill) |
| RPC client | **Foundry / cast** | Bytecode fetch via `cast rpc eth_getCode` |
| Bytecode analysis | **pure bash** | PUSH-data-aware opcode iteration, basic-block detection, pattern matching, guard-slot lookup — all in bash arrays + `printf '%d'` |
| Chain config | **JSON** (`assets/networks.json`) | Network endpoints + chain IDs |
| Data format | **JSON** | Output via `jq` for agent consumption |
| Runtime | Any POSIX shell, Foundry 1.0+ | Tested on Linux + macOS |

## Dependencies

**Required:**
- [Foundry](https://getfoundry.sh) (gives you `cast`)
- `bash` 4+ (preinstalled on macOS, Ubuntu 20+, most Linux)
- `jq` (for `--format json` output and inline JSON building)

**Optional:**
- `git` — only required if you're cloning the repo (you already have it)

## Tests

Each repo ships with a bash smoke test that verifies:
1. `--help` works (no cast required)
2. `--demo` works (no cast required)
3. No contract shows the usage hint
4. Bad address format is rejected
5. Bad format is rejected
6. Bad `--min-severity` is rejected
7. Bad network is rejected
8. The cast-missing error is clear (when cast is not installed)

```bash
bash tests/test_scan_smoke.sh
```

The test runs offline by default. If cast is installed, the live `eth_getCode` fetch will take a few seconds.

## Reference docs

- `references/patterns.md` — detailed description of each pattern with examples
- `references/selectors.json` — the curated list of 4-byte function selectors this scanner recognizes
- `examples/sample-report.md` — an annotated example of the text report

## Repository layout

```
reepatts/
├── SKILL.md              # Skill contract
├── README.md             # This file
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
│   └── scan.sh          # The single bash script that does the work
└── tests/
    └── test_scan_smoke.sh   # Offline smoke test
```

## License

MIT — see `LICENSE`.
