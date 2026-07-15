"""Parse the four registerProgram spec documents into the information the angr
core needs: address-space indices, the return register, and an angr arch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.etree import ElementTree as ET

# processor id (from the pspec/tspec) -> archinfo class name.
# Extend as more architectures are validated end-to-end.
_ARCH_BY_ENDIAN_BITS = {
    ("x86", False, 64): "ArchAMD64",
    ("x86", False, 32): "ArchX86",
}


@dataclass
class SpecInfo:
    space_ram: int
    space_register: int
    space_unique: int
    bigendian: bool
    return_register_name: str
    angr_arch: object
    coretype_ids: dict  # name -> id, parsed from the coretypes document


def _space_index(root: ET.Element, name: str) -> int | None:
    for spaces in root.iter("spaces"):
        for spc in spaces:
            if spc.get("name") == name:
                return int(spc.get("index"), 0)
    return None


def parse_specs(pspec: str, cspec: str, tspec: str, coretypes: str) -> SpecInfo:
    troot = ET.fromstring(tspec)
    bigendian = troot.get("bigendian", "false") == "true"

    space_ram = _space_index(troot, "ram")
    space_register = _space_index(troot, "register")
    space_unique = _space_index(troot, "unique")

    # default-space size in bits => pointer width
    bits = 64
    for spaces in troot.iter("spaces"):
        default = spaces.get("defaultspace")
        for spc in spaces:
            if spc.get("name") == default:
                bits = int(spc.get("size", "8")) * 8
    # tspec space sizes are in bytes for the *address* width; ram size attr is
    # the addressable size in bytes, so bits = size*8 already handled above.

    angr_arch = _resolve_arch(pspec, bigendian, bits)
    ret_name = _return_register_name(cspec)
    coretype_ids = _parse_coretypes(coretypes)

    return SpecInfo(
        space_ram=space_ram if space_ram is not None else 2,
        space_register=space_register if space_register is not None else 3,
        space_unique=space_unique if space_unique is not None else 4,
        bigendian=bigendian,
        return_register_name=ret_name,
        angr_arch=angr_arch,
        coretype_ids=coretype_ids,
    )


def _parse_coretypes(coretypes: str) -> dict:
    ids: dict[str, int] = {}
    try:
        root = ET.fromstring(coretypes)
    except ET.ParseError:
        return ids
    for t in root.iter("type"):
        name, tid = t.get("name"), t.get("id")
        if name and tid is not None:
            ids[name] = int(tid, 0)
    return ids


def _resolve_arch(pspec: str, bigendian: bool, bits: int):
    import archinfo

    # infer processor family from register names present in the pspec, else x86
    proc = "x86"
    cls_name = _ARCH_BY_ENDIAN_BITS.get((proc, bigendian, bits))
    if cls_name is None:
        # fall back to a sensible default by bit width
        cls_name = "ArchAMD64" if bits == 64 else "ArchX86"
    return getattr(archinfo, cls_name)()


def _return_register_name(cspec: str) -> str:
    """The canonical Ghidra register name for the default (integer) return value,
    from the cspec's default prototype <output>. Prefers the first non-float
    pentry (integer returns) over float registers. Resolved to storage later via
    getRegister."""
    try:
        croot = ET.fromstring(cspec)
    except ET.ParseError:
        return "RAX"
    fallback = None
    for proto in croot.iter("default_proto"):
        for out in proto.iter("output"):
            for pentry in out.iter("pentry"):
                reg = pentry.find("register")
                if reg is None or not reg.get("name"):
                    continue
                if fallback is None:
                    fallback = reg.get("name")
                if pentry.get("metatype") != "float":
                    return reg.get("name")
    return fallback or "RAX"
