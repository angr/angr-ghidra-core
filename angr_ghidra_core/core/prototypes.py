"""Recover callee prototypes so angr's decompiler renders call arguments.

Primary source is Ghidra itself: the getMappedSymbols reply for a function carries
its prototype -- parameters appear in the localdb as symbols with category 0
(sorted by their index), and the return type in <prototype><returnsym>. This is
authoritative for the program being decompiled (libc, local, and user-edited
functions alike). angr's SIM_LIBRARIES provides a fallback keyed by name.
"""

from __future__ import annotations

from ..ghidra_wire import ids
from ..ghidra_wire.dump import Element

# category values from HighSymbol (ATTRIB_CAT)
_CAT_PARAMETER = 0

_LIB_CACHE = None


def ghidra_type_to_sim(tel: Element | None, arch):
    """Map a Ghidra <type>/<typeref> element to an angr SimType."""
    from angr import sim_type as st

    if tel is None:
        return st.SimTypeBottom()
    meta = tel.attr("metatype")
    size = tel.attr("size") or 0
    if meta == "ptr":
        return st.SimTypePointer(st.SimTypeBottom())
    if meta == "bool":
        return st.SimTypeBool()
    if meta == "float":
        return st.SimTypeDouble() if size == 8 else st.SimTypeFloat()
    if meta == "void":
        return st.SimTypeBottom()
    if meta in ("int", "uint", "unknown", None):
        signed = meta != "uint"
        bits = (size or (arch.bytes if meta is None else 4)) * 8
        return st.SimTypeInt(signed=signed) if bits == 32 else st.SimTypeNum(bits, signed=signed)
    # struct / array / code / partial: approximate by width so the CC slots it
    return st.SimTypeNum((size or arch.bytes) * 8, signed=False)


def prototype_from_ghidra(fn_el: Element, arch):
    """Build a SimTypeFunction from a getMappedSymbols model <function> element,
    or None if it carries no <prototype>."""
    proto_el = fn_el.first("prototype")
    if proto_el is None:
        return None

    # parameters: localdb symbols with category 0, ordered by their index
    params = []
    localdb = fn_el.first("localdb")
    scope = localdb.first("scope") if localdb else None
    symlist = scope.first("symbollist") if scope else None
    if symlist is not None:
        collected = []
        for mapsym in symlist.find("mapsym"):
            sym = mapsym.first("symbol")
            if sym is None or sym.attr("cat") != _CAT_PARAMETER:
                continue
            tel = sym.first("type") or sym.first("typeref")
            collected.append((sym.attr("index", 0), tel))
        collected.sort(key=lambda t: t[0])
        params = [ghidra_type_to_sim(tel, arch) for _idx, tel in collected]

    ret = None
    rs = proto_el.first("returnsym")
    if rs is not None:
        ret = ghidra_type_to_sim(rs.first("type") or rs.first("typeref"), arch)

    from angr.sim_type import SimTypeBottom, SimTypeFunction

    variadic = bool(proto_el.attr("dotdotdot"))
    return SimTypeFunction(params, ret or SimTypeBottom(), variadic=variadic)


def prototype_from_libraries(name: str):
    """Look up a prototype by name in angr's library definitions (libc first)."""
    global _LIB_CACHE
    if _LIB_CACHE is None:
        from angr.procedures.definitions import SIM_LIBRARIES

        libc, other = [], []
        for libname, liblist in SIM_LIBRARIES.items():
            (libc if "libc" in libname else other).extend(liblist)
        _LIB_CACHE = libc + other
    for lib in _LIB_CACHE:
        try:
            if lib.has_prototype(name):
                return lib.get_prototype(name)
        except Exception:
            continue
    return None


def set_stub_prototype(stub, proto, arch) -> bool:
    """Set stub.prototype + calling_convention from an already-chosen prototype."""
    from angr.calling_conventions import default_cc

    if proto is None:
        return False
    try:
        stub.prototype = proto.with_arch(arch)
        cc_cls = default_cc(arch.name)
        if cc_cls is not None:
            stub.calling_convention = cc_cls(arch)
    except Exception:
        return False
    return True
