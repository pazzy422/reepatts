#!/usr/bin/env python3
"""
reepatts/test_patterns.py — unit tests for the pattern matcher.
Run: python3 tests/test_patterns.py
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from scan import scan, find_basic_blocks, is_guarded, GUARD_SLOTS  # noqa


# ----- helpers: build tiny synthetic bytecodes -----

def SLOAD_slot(slot: int) -> bytes:
    """PUSH4 <slot> SLOAD (1+1+4+1 = 7 bytes)."""
    return bytes([0x63]) + slot.to_bytes(4, "big") + bytes([0x54])  # PUSH4 + 4 bytes + SLOAD

def PUSH1(v: int) -> bytes:
    return bytes([0x60, v])

def CALL_op(value: int = 1, opcode: int = 0xF1) -> bytes:
    """Build a full CALL-family stack: PUSH1 retSize PUSH1 retOff PUSH1 argSize PUSH1 argOff PUSH1 value PUSH1 addr CALL-family.
    Opcode 0xF1=CALL, 0xF2=CALLCODE, 0xF4=DELEGATECALL, 0xFA=STATICCALL.
    """
    return bytes([
        0x60, 0x00,        # retSize = 0
        0x60, 0x00,        # retOffset = 0
        0x60, 0x00,        # argSize = 0
        0x60, 0x00,        # argOffset = 0
        0x60, value,       # value
        0x60, 0x00,        # addr
        opcode,            # CALL-family
    ])

def SSTORE_slot(slot: int) -> bytes:
    return bytes([0x63]) + slot.to_bytes(4, "big") + bytes([0x55])

def JUMPDEST() -> bytes:
    return bytes([0x5b])

def RETURN() -> bytes:
    return bytes([0xf3])

def function_body(*parts: bytes) -> bytes:
    return JUMPDEST() + b"".join(parts) + RETURN()


# ----- tests -----

def test_pattern_1_sload_call_sstore():
    """SLOAD(slot=0x02) ... CALL ... SSTORE(slot=0x02) -> 1 finding, pattern SLOAD-CALL-SSTORE, severity 90."""
    bc = "0x" + function_body(
        SLOAD_slot(0x02),
        CALL_op(1),
        SSTORE_slot(0x02),
    ).hex()
    findings, _ = scan(bc)
    assert len(findings) == 1, f"expected 1 finding, got {len(findings)}"
    f = findings[0]
    assert f["pattern"] == "SLOAD-CALL-SSTORE"
    assert f["severity"] == 90, f"severity should be 90, got {f['severity']}"
    assert f["cross_function"] is False
    print("  ✓ test_pattern_1_sload_call_sstore")


def test_pattern_2_sload_callcode_sstore():
    bc = "0x" + function_body(
        SLOAD_slot(0x01),
        CALL_op(value=1, opcode=0xF2),  # CALLCODE
        SSTORE_slot(0x01),
    ).hex()
    findings, _ = scan(bc)
    assert any(f["pattern"] == "SLOAD-CALLCODE-SSTORE" and f["severity"] == 85 for f in findings), \
        f"missing CALLCODE pattern, got: {[f['pattern'] for f in findings]}"
    print("  ✓ test_pattern_2_sload_callcode_sstore")


def test_pattern_3_sload_delegatecall_sstore():
    bc = "0x" + function_body(
        SLOAD_slot(0x03),
        CALL_op(value=1, opcode=0xF4),  # DELEGATECALL
        SSTORE_slot(0x03),
    ).hex()
    findings, _ = scan(bc)
    assert any(f["pattern"] == "SLOAD-DELEGATECALL-SSTORE" and f["severity"] == 80 for f in findings)
    print("  ✓ test_pattern_3_sload_delegatecall_sstore")


def test_pattern_4_sload_call_sload_sstore():
    bc = "0x" + function_body(
        SLOAD_slot(0x04),
        CALL_op(value=0),
        SLOAD_slot(0x04),
        SSTORE_slot(0x04),
    ).hex()
    findings, _ = scan(bc)
    # Expect at least one SLOAD-CALL-SLOAD-SSTORE finding with severity 95
    assert any(f["pattern"] == "SLOAD-CALL-SLOAD-SSTORE" and f["severity"] == 95 for f in findings), \
        f"missing pattern 4, got: {[(f['pattern'], f['severity']) for f in findings]}"
    print("  ✓ test_pattern_4_sload_call_sload_sstore")


def test_staticcall_is_ignored():
    """STATICCALL is read-only, should not produce a finding."""
    bc = "0x" + function_body(
        SLOAD_slot(0x05),
        CALL_op(value=0, opcode=0xFA),  # STATICCALL
        SSTORE_slot(0x05),
    ).hex()
    findings, _ = scan(bc)
    assert len(findings) == 0, f"STATICCALL should not be flagged, got: {findings}"
    print("  ✓ test_staticcall_is_ignored")


def test_clean_contract_no_findings():
    """A contract that has SLOADs and SSTOREs but no CALL-family opcodes at all is clean."""
    bc = "0x" + function_body(
        SLOAD_slot(0x06),
        SSTORE_slot(0x06),
    ).hex()
    findings, _ = scan(bc)
    assert len(findings) == 0, f"no CALL-family should mean no findings, got: {findings}"
    print("  ✓ test_clean_contract_no_findings")


def test_reentrancy_guard_reduces_severity():
    """If a function pushes to slot 0x4f10 (ReentrancyGuard) before the CALL, severity drops by 10."""
    body = (
        SLOAD_slot(0x07)
        + bytes([0x63]) + (0x4f10).to_bytes(4, "big") + bytes([0x55])  # SSTORE(slot=0x4f10) — guard!
        + CALL_op(1)
        + SSTORE_slot(0x07)
    )
    bc = "0x" + function_body(body).hex()
    findings, _ = scan(bc)
    # All findings should have severity <= 80
    for f in findings:
        assert f["severity"] <= 80, f"guard should drop severity to <=80, got {f['severity']} for {f['pattern']}"
    print("  ✓ test_reentrancy_guard_reduces_severity")


def test_dedupes_duplicate_findings():
    """If the same (sload, call, sstore, pattern) triple is matched twice, we should return only one finding.
    Build a function with TWO identical SLOAD-CALL-SSTORE triples — the second one at a different offset.
    """
    # Same SLOAD and SSTORE (slot 0x08), two identical CALLs. Each SLOAD-CALL-SSTORE triple is distinct
    # by OFFSET, so they should be reported. But within the same offset-range, no duplicates.
    body = (
        SLOAD_slot(0x08) + CALL_op(1) + SSTORE_slot(0x08)
        + SLOAD_slot(0x08) + CALL_op(1) + SSTORE_slot(0x08)
    )
    bc = "0x" + function_body(body).hex()
    findings, _ = scan(bc)
    keys = [(f["sload_offset"], f["call_offset"], f["sstore_offset"], f["pattern"]) for f in findings]
    # Dedup: each (sload, call, sstore, pattern) key should appear at most once
    counts = {}
    for k in keys:
        counts[k] = counts.get(k, 0) + 1
    dups = {k: c for k, c in counts.items() if c > 1}
    assert not dups, f"duplicate findings present: {dups}"
    # Expect at least 2 findings (the two distinct SLOAD-CALL-SSTORE triples)
    assert len(findings) >= 2, f"expected at least 2 distinct findings, got {len(findings)}"
    print("  ✓ test_dedupes_duplicate_findings")


def test_function_selector_lookup():
    """find_function_selector should return the PUSH4 selector near the SSTORE opcode offset."""
    from scan import find_function_selector
    # Layout: JUMPDEST(1) + SLOAD_slot(6) + CALL_op(13) + PUSH4(5) + PUSH4-slot-of-SSTORE(5) + SSTORE(1) + RETURN(1)
    # The SSTORE opcode (0x55) is at offset 1+6+13+5+5 = 30.
    selector = bytes([0x63, 0xa9, 0x05, 0x9c, 0xbb])  # 0xa9059cbb
    sstore_push4 = bytes([0x63]) + (0x09).to_bytes(4, "big")  # 5 bytes (PUSH4 + slot 0x09)
    pre = JUMPDEST() + SLOAD_slot(0x09) + CALL_op(1) + selector + sstore_push4
    sstore_op_off = len(pre)  # the SSTORE opcode (0x55) is at this offset
    bc = pre + bytes([0x55]) + RETURN()
    assert bc[sstore_op_off] == 0x55, f"sanity: expected 0x55 at {sstore_op_off}, got 0x{bc[sstore_op_off]:02x}"
    sel = find_function_selector(sstore_op_off, bc)
    assert sel == "0xa9059cbb", f"expected 0xa9059cbb, got {sel}"
    print("  ✓ test_function_selector_lookup")


def test_severity_label_thresholds():
    from scan import sev_label
    assert sev_label(0)   == "LOW"
    assert sev_label(30)  == "LOW"
    assert sev_label(31)  == "MEDIUM"
    assert sev_label(60)  == "MEDIUM"
    assert sev_label(61)  == "HIGH"
    assert sev_label(80)  == "HIGH"
    assert sev_label(81)  == "CRITICAL"
    assert sev_label(100) == "CRITICAL"
    print("  ✓ test_severity_label_thresholds")


def test_basic_blocks_boundaries():
    """find_basic_blocks should partition the bytecode into function-like ranges."""
    from scan import STOP
    code = JUMPDEST() + SLOAD_slot(0x01) + RETURN() + bytes([STOP]) + JUMPDEST() + SLOAD_slot(0x02) + RETURN()
    blocks = find_basic_blocks(code)
    assert len(blocks) == 2, f"expected 2 blocks, got {len(blocks)}"
    assert blocks[0][0] == 0, f"first block should start at 0, got {blocks[0][0]}"
    print("  ✓ test_basic_blocks_boundaries")


# ----- runner -----

if __name__ == "__main__":
    tests = [
        test_pattern_1_sload_call_sstore,
        test_pattern_2_sload_callcode_sstore,
        test_pattern_3_sload_delegatecall_sstore,
        test_pattern_4_sload_call_sload_sstore,
        test_staticcall_is_ignored,
        test_clean_contract_no_findings,
        test_reentrancy_guard_reduces_severity,
        test_dedupes_duplicate_findings,
        test_function_selector_lookup,
        test_severity_label_thresholds,
        test_basic_blocks_boundaries,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {t.__name__} — {e}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {t.__name__} — EXCEPTION: {e}")
    print(f"\n{len(tests) - failed} test(s) passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
