# Pattern specifications

This document defines the 6 reentrancy patterns reepatts detects, with the exact EVM opcode sequences each one matches.

## EVM opcode reference (only the opcodes we touch)

| Opcode | Hex | Meaning |
|---:|---|---|
| `SLOAD` | `0x54` | read a storage slot onto the stack |
| `SSTORE` | `0x55` | write the top stack item to a storage slot |
| `CALL` | `0xf1` | external call (transfers value) |
| `CALLCODE` | `0xf2` | legacy external call (runs target's code in caller's context) |
| `DELEGATECALL` | `0xf4` | external call (runs target's code in caller's storage context) |
| `STATICCALL` | `0xfa` | read-only external call (no state change) |
| `JUMPDEST` | `0x5b` | valid jump target (used to delimit functions) |
| `JUMPI` | `0x57` | conditional jump (used to delimit "end of function") |
| `STOP` | `0x00` | execution halt |
| `RETURN` | `0xf3` | return from call |
| `REVERT` | `0xfd` | revert |
| `SELFDESTRUCT` | `0xff` | deprecated self-destruct |

## Pattern 1: SLOAD-CALL-SSTORE (canonical reentrancy)

**Sequence:** `SLOAD ... CALL ... (0 or more other opcodes) ... SSTORE`

**Match rule:** Within a single function (between JUMPDEST and the next STOP/RETURN/REVERT/JUMPI that exits the function), find the sequence `SLOAD` then later `CALL/STATICCALL/CALLCODE/DELEGATECALL` then later `SSTORE` such that the slot read by SLOAD == the slot written by SSTORE.

**Severity:** 90

**True positive example:** an ERC-20 `transfer()` that does:
1. `balances[from] = SLOAD`
2. `balances[from] -= amount` (which is itself an SLOAD + SSTORE — but the second SSTORE is the bug because it happens *after* the external `recipient.call(...)`)

**False positive:** when the CALL has `value=0` and the post-call SSTORE only updates a non-value-bearing slot (e.g. a nonce or a mapping entry that doesn't hold real funds). reepatts surfaces the finding but the severity calculator down-weights it.

## Pattern 2: SLOAD-CALLCODE-SSTORE

**Sequence:** `SLOAD ... CALLCODE ... SSTORE`

**Match rule:** Same as Pattern 1 but with `CALLCODE` instead of `CALL`. CALLCODE is pre-0.5 Solidity; finding this in modern code is rare and suspicious.

**Severity:** 85

## Pattern 3: SLOAD-DELEGATECALL-SSTORE

**Sequence:** `SLOAD ... DELEGATECALL ... SSTORE`

**Match rule:** Same as Pattern 1 but with `DELEGATECALL`. DELEGATECALL is the modern way to do proxy-upgradeable calls. Finding it in a non-proxy contract is a strong reentrancy signal.

**Severity:** 80 (lower because the call may be to a trusted library)

## Pattern 4: SLOAD-CALL-SLOAD-SSTORE

**Sequence:** `SLOAD ... CALL ... SLOAD ... SSTORE`

**Match rule:** The classic pattern plus a second SLOAD after the CALL. This is the exact shape of the original 2016 DAO hack: `withdrawer.balance = SLOAD`, `msg.sender.call(...)`, `withdrawer.balance = SLOAD (re-read from storage, which is now stale)`, `withdrawer.balance = SSTORE (writes the stale value back, double-spending)`.

**Severity:** 95 (highest of the simple patterns)

## Pattern 5: cross-function chain (SSTORE, CALL, SSTORE)

**Sequence:** `SSTORE (in function A) ... CALL (in function A or B) ... SSTORE (in function B)`

**Match rule:** Find a CALL inside a function and a subsequent SSTORE in a different function, where the call is the only control-flow bridge. This is the harder-to-detect version of reentrancy where the bug spans two functions (e.g. `withdraw()` calls a `token.transfer()` which calls a hook back into the original contract).

**Severity:** 100 (the most dangerous pattern)

## Pattern 6: Unprotected withdraw()

**Sequence:** Any function that contains `CALL` with a non-zero `value` argument, AND does not contain a `0x4f10`/`0x6d10`/`0x3659` opcode sequence (the Solidity-generated `REENTRANCY-GUARD` slot).

**Match rule:** A function's bytecode contains a `CALL` opcode where the value argument (pushed onto the stack just before the CALL) is non-zero, AND the function does not push the OpenZeppelin `nonReentrant` guard slot to storage before the CALL.

**Severity:** 70 (lower because many legit contracts are unprotected by design — e.g. a one-shot mint)

## Severity calculator

The final severity score is a function of:

| Factor | Weight | Range |
|---|---:|---|
| Pattern base score | 40% | 70-100 |
| Value transferred? (CALL.value > 0) | 30% | 0 or 1 |
| Function is externally callable? (no function-modifier check before the entry point) | 15% | 0 or 1 |
| Has REENTRANCY-GUARD? (any push to slot 0x4f10/0x6d10/0x3659 in the function) | -10% or +10% | -10 if guard, +10 if not |
| Multiple matches within same function | +5% per additional | 0 to +20 |
| Match crosses JUMPDEST boundary (i.e. cross-function) | +15% | 0 or 1 |

Final score is clamped to [0, 100].

## What we do NOT detect (honest scope)

1. **Read-only reentrancy** — a different class of bug, where the contract reads state via a callback during a `view` function call. Not detected.
2. **Cross-contract reentrancy** — we look at a single contract's bytecode. If a function in contract A calls contract B which calls back into A, we only see A's side.
3. **Storage collision via proxy** — we don't model proxy patterns. If a contract is a proxy, the implementation's storage layout may collide with the proxy's; that's a separate audit.
4. **Solidity-level reentrancy via inline assembly** — possible but rare. We scan the post-compilation bytecode, so we catch all of them by construction.
5. **Reentrancy through a "safe" call wrapper (e.g. `ReentrancyGuard.sol`)** — we explicitly look for the guard's storage slot, so we don't false-positive on guarded contracts.

## References

- [Ethereum Yellow Paper § 9.4.4](https://ethereum.github.io/yellowpaper/paper.pdf) — opcode definitions
- [Solidity docs: Security Considerations — Reentrancy](https://docs.soliditylang.org/en/latest/security-considerations.html#reentrancy) — the high-level description of what we're catching
- [Trail of Bits: Slither](https://github.com/crytic/slither) — the static analyzer we *don't* try to replace; reepatts is a tiny focused tool
- [OpenZeppelin: ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard) — the `0x4f10`/`0x6d10`/`0x3659` slot values come from here
