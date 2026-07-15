"""Decode the model <function> of a decompileAt response into HighFunction-shaped
Python objects, mirroring what Ghidra's HighFunction.decode / LocalSymbolMap /
HighSymbol decoders build. Used to validate that a core's response is well-formed
without a running Ghidra.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .dump import Element


@dataclass
class Symbol:
    sym_id: int
    name: str
    category: int
    cat_index: int
    type_name: str
    type_id: int | None
    storage_space: object   # int space index or a special-space marker string
    storage_offset: int
    storage_size: int


@dataclass
class HighFunc:
    name: str
    entry_space: int
    entry_offset: int
    size: int
    return_type: str | None
    return_storage: tuple | None
    symbols: list[Symbol] = field(default_factory=list)

    @property
    def symbols_by_id(self) -> dict[int, Symbol]:
        return {s.sym_id: s for s in self.symbols}


def _addr_tuple(addr_el: Element):
    if addr_el is None:
        return None
    space = addr_el.attr("space")
    off = addr_el.attr("offset")
    size = addr_el.attr("size")
    if space is None and off is None:
        return None
    return (space, off, size)


def decode_high_function(fn: Element) -> HighFunc:
    """fn is the model <function> Element (from dump.parse_tree)."""
    addr = fn.first("addr")
    hf = HighFunc(
        name=fn.attr("name"),
        entry_space=addr.attr("space") if addr else None,
        entry_offset=addr.attr("offset") if addr else None,
        size=fn.attr("size"),
        return_type=None,
        return_storage=None,
    )

    proto = fn.first("prototype")
    if proto is not None:
        ret = proto.first("returnsym")
        if ret is not None:
            tref = ret.first("typeref") or ret.first("type")
            hf.return_type = tref.attr("name") if tref else None
            hf.return_storage = _addr_tuple(ret.first("addr"))

    localdb = fn.first("localdb")
    if localdb is not None:
        scope = localdb.first("scope")
        symlist = scope.first("symbollist") if scope else None
        if symlist is not None:
            for mapsym in symlist.find("mapsym"):
                hf.symbols.append(_decode_mapsym(mapsym))
    return hf


def _decode_mapsym(mapsym: Element) -> Symbol:
    sym_el = mapsym.first("symbol")
    tref = sym_el.first("typeref") or sym_el.first("type") if sym_el else None
    # the MappedEntry <addr> is the mapsym child after <symbol>
    addr_el = None
    for child in mapsym.children:
        if child.name == "addr":
            addr_el = child
            break
    space = addr_el.attr("space") if addr_el else None
    return Symbol(
        sym_id=sym_el.attr("id") if sym_el else None,
        name=sym_el.attr("name") if sym_el else None,
        category=sym_el.attr("cat", -1) if sym_el else -1,
        cat_index=sym_el.attr("index", -1) if sym_el else -1,
        type_name=tref.attr("name") if tref else None,
        type_id=tref.attr("id") if tref else None,
        storage_space=space,
        storage_offset=addr_el.attr("offset") if addr_el else None,
        storage_size=addr_el.attr("size") if addr_el else None,
    )


def collect_token_symrefs(markup: Element) -> list[int]:
    """All ATTRIB_SYMREF values appearing on variable tokens in the markup tree."""
    out: list[int] = []

    def walk(el: Element):
        sr = el.attr("symref")
        if sr is not None:
            out.append(sr)
        for c in el.children:
            walk(c)

    walk(markup)
    return out
