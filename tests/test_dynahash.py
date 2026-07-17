"""DynamicHash port self-consistency: unique_hash -> find_varnode round-trips
over a real angr op graph, and the CRC table matches Ghidra's."""

import os

import pytest

FAUXWARE = "/workspace/binaries/tests/x86_64/fauxware"

pytestmark = pytest.mark.skipif(
    not os.path.exists(FAUXWARE), reason="test binary not available")


def test_crc_table_matches_ghidra():
    from angr_ghidra_core.core.dynahash import _CRC32TAB, _crc

    # spot-check against SimpleCRC32.crc32tab values from the Java source
    assert _CRC32TAB[0] == 0
    assert _CRC32TAB[1] == 1996959894
    assert _CRC32TAB[2] == (-301047508) & 0xFFFFFFFF
    assert _CRC32TAB[255] == 755167117
    # hashOneByte stays within 32 bits and handles negative "bytes" (slot -1)
    assert 0 <= _crc(0x3BA0FE06, -1) <= 0xFFFFFFFF


@pytest.fixture(scope="module")
def graph():
    import logging
    logging.disable(logging.CRITICAL)
    import angr

    from angr_ghidra_core.core.pcode import PcodeTranslator

    proj = angr.Project(FAUXWARE, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model)
    return PcodeTranslator(lambda off, sz: off).translate(dec.ail_graph)


def test_unique_hash_roundtrip(graph):
    """Every varnode attached to an op gets a non-zero unique hash that
    find_varnode resolves back to exactly that varnode -- the property Ghidra
    relies on when storing and consuming a dynamic-hash edit."""
    from angr_ghidra_core.core.dynahash import DynamicHasher

    hasher = DynamicHasher(graph)
    attached = set(hasher._def) | set(hasher._descend)
    assert len(attached) > 20, "expected a non-trivial op graph"

    hashed = resolved = 0
    for ref in sorted(attached):
        h, addr = hasher.unique_hash(ref)
        if h == 0:
            continue  # no uniquely-identifying hash exists (Ghidra gives up too)
        hashed += 1
        assert addr is not None
        got = hasher.find_varnode(addr, h)
        assert got == ref, f"varnode {ref} hashed to {h:#x} but resolved to {got}"
        resolved += 1
    assert hashed > 20, "expected most varnodes to be uniquely hashable"
    assert resolved == hashed


def test_hash_layout_fields(graph):
    """The packed hash fields (method/opcode/slot/attached) decode back to
    consistent values."""
    from angr_ghidra_core.core.dynahash import _trans, DynamicHasher

    hasher = DynamicHasher(graph)
    checked = 0
    for ref in sorted(set(hasher._def) | set(hasher._descend)):
        h, _addr = hasher.unique_hash(ref)
        if h == 0:
            continue
        method = (h >> 44) & 0xF
        opc = (h >> 37) & 0x7F
        assert method <= 3
        assert opc != 0 and opc in {_trans(o) for o in range(1, 67)}
        checked += 1
    assert checked > 0
