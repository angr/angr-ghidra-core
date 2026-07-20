"""Whole-image CFG cache for the angr-ghidra core.

Ghidra never tells the core where the binary is; the only view of program bytes
is the `getBytes(addr, size)` callback. For small programs it is far cheaper to
recover one CFG over the whole mapped image once and then decompile individual
functions straight out of it, than to re-run a scoped `load_shellcode` + CFG for
every `decompileAt`.

This module probes the readable image around a function entry (bounded by
`max_size`), identifies it by a content hash, and returns a cached
`(project, cfg_model)`. The CFG is persisted to disk with angrdb keyed by the
hash, so it survives across server restarts, and memoized in-process so repeated
requests in one session are free.

Scope/caveats:
  * We cover the *contiguous readable run* that contains the entry (probing stops
    at the first unmapped page in each direction). For typical small executables
    the code segment is one such run and contains the entry's sibling functions,
    which is what direct-decompile and callee-prototype recovery need. Programs
    whose run exceeds `max_size` fall back to the scoped path (return None).
  * The identity hash covers the probed code image, not the whole file; a data
    edit outside the run does not invalidate the cache.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile

log = logging.getLogger("angr_ghidra_core")

PAGE = 0x1000
DEFAULT_MAX_SIZE = 500 * 1024


def _default_cache_dir() -> str:
    env = os.environ.get("ANGR_GHIDRA_CACHE")
    if env:
        return env
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "angr-ghidra-core")


def probe_image(get_bytes, entry: int, max_size: int) -> tuple[int, bytes] | None:
    """Probe the contiguous readable run of pages containing `entry`.

    `get_bytes(addr, size)` returns the bytes or None (Ghidra fails the whole
    range if any byte is unmapped). Returns (base_addr, content) or None when the
    entry page is unreadable or the run would exceed `max_size`.
    """
    start = entry & ~(PAGE - 1)
    first = get_bytes(start, PAGE)
    if not first:
        return None
    pages: dict[int, bytes] = {start: first}
    total = len(first)

    # walk down, then up, stopping at the first unreadable/short page
    addr = start - PAGE
    while addr >= 0 and total + PAGE <= max_size:
        b = get_bytes(addr, PAGE)
        if not b or len(b) < PAGE:  # short read below start => gap; stop
            break
        pages[addr] = b
        total += len(b)
        addr -= PAGE

    addr = start + PAGE
    while total + PAGE <= max_size:
        b = get_bytes(addr, PAGE)
        if not b:
            break
        pages[addr] = b
        total += len(b)
        if len(b) < PAGE:  # end of mapping
            break
        addr += PAGE

    base = min(pages)
    content = b"".join(pages[a] for a in sorted(pages))
    if len(content) > max_size:
        return None
    return base, content


def image_hash(base: int, content: bytes) -> str:
    h = hashlib.sha256()
    h.update(base.to_bytes(8, "little"))
    h.update(content)
    return h.hexdigest()


class ImageCache:
    """Builds/loads and memoizes whole-image `(project, cfg_model)` by content
    hash. One instance per server (shared across protocol sessions)."""

    def __init__(self, get_bytes, angr_arch, *, cache_dir: str | None = None,
                 max_size: int = DEFAULT_MAX_SIZE):
        self._get_bytes = get_bytes
        self._arch = angr_arch
        self._max_size = max_size
        self._dir = cache_dir or _default_cache_dir()
        self._mem: dict[str, tuple] = {}       # hash -> (project, cfg_model)
        self._miss: set[int] = set()           # entries known too-big/unprobable

    def get(self, entry: int):
        """Return (project, cfg_model) for the image containing `entry`, or None
        to signal the caller should use the scoped path."""
        if entry in self._miss:
            return None
        probed = probe_image(self._get_bytes, entry, self._max_size)
        if probed is None:
            self._miss.add(entry)
            return None
        base, content = probed
        h = image_hash(base, content)
        if h in self._mem:
            return self._mem[h]
        try:
            result = self._load_or_build(h, base, content)
        except Exception:
            log.exception("whole-image CFG failed; falling back to scoped mode")
            self._miss.add(entry)
            return None
        self._mem[h] = result
        return result

    def _adb_path(self, h: str) -> str:
        return os.path.join(self._dir, f"{h}.adb")

    def _load_or_build(self, h: str, base: int, content: bytes):
        from angr.angrdb import AngrDB

        adb = self._adb_path(h)
        if os.path.exists(adb):
            try:
                proj = AngrDB().load(adb)
                model = proj.kb.cfgs.get_most_accurate()
                if model is not None:
                    log.debug("image cache hit %s", h[:12])
                    return proj, model
            except Exception:
                log.exception("angrdb load failed for %s; rebuilding", h[:12])

        os.makedirs(self._dir, exist_ok=True)
        proj, model, img_path = self._build(base, content)
        try:
            # angrdb re-reads the blob's backing file during dump, so it must
            # still exist here; the persisted db is self-contained afterwards
            AngrDB(proj).dump(adb)
        except Exception:
            log.exception("angrdb dump failed for %s (in-memory cache still used)", h[:12])
        finally:
            try:
                os.unlink(img_path)
            except OSError:
                pass
        return proj, model

    def _build(self, base: int, content: bytes):
        import angr

        # the blob backend wants a path; angrdb re-reads that path at dump time,
        # so keep the file until the dump completes (caller unlinks it)
        fd, path = tempfile.mkstemp(suffix=".img", dir=self._dir)
        os.write(fd, content)
        os.close(fd)
        proj = angr.Project(
            path,
            main_opts={"backend": "blob", "arch": self._arch, "base_addr": base},
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
        return proj, cfg.model, path
