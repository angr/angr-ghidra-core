"""Whole-image cache: prober boundary handling, content hashing, and a
build-then-reload round trip through angrdb producing a decompilable project."""

import os

import pytest

from angr_ghidra_core.core.imagecache import (
    ImageCache,
    PAGE,
    image_hash,
    probe_image,
)

FAUXWARE = "/workspace/binaries/tests/x86_64/fauxware"

pytestmark = pytest.mark.skipif(
    not os.path.exists(FAUXWARE), reason="test binary not available")


def _pages(mapping):
    """A get_bytes(addr, size) backed by a dict of page_addr -> bytes."""
    def get_bytes(addr, size):
        return mapping.get(addr, None) if size == PAGE else mapping.get(addr, None)
    return get_bytes


def test_probe_stops_at_gaps_both_directions():
    base = 0x400000
    mapping = {base + i * PAGE: bytes([i]) * PAGE for i in range(3)}  # 3 contiguous pages
    entry = base + PAGE + 0x40
    got = probe_image(_pages(mapping), entry, max_size=1 << 20)
    assert got is not None
    gbase, content = got
    assert gbase == base
    assert len(content) == 3 * PAGE
    # a page below base and above the top are unmapped -> not included
    assert content[0] == 0 and content[-1] == 2


def test_probe_none_when_entry_unmapped():
    got = probe_image(lambda a, s: None, 0x400040, max_size=1 << 20)
    assert got is None


def test_probe_respects_max_size():
    base = 0x400000
    mapping = {base + i * PAGE: b"\x90" * PAGE for i in range(100)}
    entry = base
    got = probe_image(_pages(mapping), entry, max_size=4 * PAGE)
    assert got is not None
    _gbase, content = got
    assert len(content) <= 4 * PAGE


def test_short_page_ends_the_run():
    base = 0x400000
    mapping = {base: b"\x90" * PAGE, base + PAGE: b"\xcc" * (PAGE // 2)}
    got = probe_image(_pages(mapping), base + 0x10, max_size=1 << 20)
    assert got is not None
    _gbase, content = got
    # the short upper page is included, then the run stops
    assert len(content) == PAGE + PAGE // 2


def test_image_hash_is_content_addressed():
    a = image_hash(0x400000, b"abc")
    assert a == image_hash(0x400000, b"abc")
    assert a != image_hash(0x401000, b"abc")   # base is part of identity
    assert a != image_hash(0x400000, b"abd")   # content is part of identity


def test_build_reload_decompiles(tmp_path):
    """A cache built over real code bytes reloads from angrdb and yields a
    project whose functions decompile."""
    import angr

    with open(FAUXWARE, "rb") as fh:
        raw = fh.read()
    base = 0x400000
    # a page-aligned window of real .text-bearing bytes
    window = raw[:0x2000]
    mapping = {base + i * PAGE: window[i * PAGE:(i + 1) * PAGE] for i in range(2)}

    cache = ImageCache(cache_dir=str(tmp_path))
    got = cache.get(base + 0x600, _pages(mapping), "AMD64")
    assert got is not None
    proj, model = got
    assert len(list(proj.kb.functions)) > 0
    assert model is not None

    # a second get for the same image is served from the in-process cache
    got2 = cache.get(base + 0x600, _pages(mapping), "AMD64")
    assert got2[0] is proj

    # the angrdb file was written and reloads into a decompilable project
    adbs = list(tmp_path.glob("*.adb"))
    assert adbs, "expected an angrdb cache file"
    from angr.angrdb import AngrDB
    proj2 = AngrDB().load(str(adbs[0]))
    fn = max(proj2.kb.functions.values(), key=lambda f: f.size)
    dec = proj2.analyses.Decompiler(fn, cfg=proj2.kb.cfgs.get_most_accurate())
    assert dec.codegen is not None
