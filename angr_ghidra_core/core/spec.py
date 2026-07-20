"""Parse the four registerProgram spec documents into the information the angr
core needs: address-space indices, the return register, and an angr arch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.etree import ElementTree as ET


@dataclass
class SpecInfo:
    space_ram: int
    space_register: int
    space_unique: int
    bigendian: bool
    return_register_name: str | None  # cspec named the return register (x86-style)
    angr_arch: object
    coretype_ids: dict  # name -> id, parsed from the coretypes document
    bits: int = 64      # pointer width from the tspec default space
    # some cspecs give the return register as a direct register-space address
    # (offset, size) instead of a name (ARM/MIPS/PPC normalized specs)
    return_register_addr: tuple[int, int] | None = None


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

    angr_arch = _resolve_arch(pspec, cspec, bigendian, bits)
    ret_name, ret_addr = _return_register(cspec)
    coretype_ids = _parse_coretypes(coretypes)

    return SpecInfo(
        space_ram=space_ram if space_ram is not None else 2,
        space_register=space_register if space_register is not None else 3,
        space_unique=space_unique if space_unique is not None else 4,
        bigendian=bigendian,
        return_register_name=ret_name,
        return_register_addr=ret_addr,
        angr_arch=angr_arch,
        coretype_ids=coretype_ids,
        bits=bits,
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


def _resolve_arch(pspec: str, cspec: str, bigendian: bool, bits: int):
    """Resolve the angr/archinfo arch from the register names Ghidra's spec
    documents mention. Ghidra never sends the language id, but each ISA has a
    characteristic set of register names in its processor/compiler specs; we
    fingerprint on those, combined with the endianness and pointer width from the
    tspec. Falls back to x86/amd64 by bit width for an unrecognised spec."""
    import archinfo

    regs = _register_names(pspec) | _register_names(cspec)
    ident = _arch_ident(regs, bits)
    endness = "Iend_BE" if bigendian else "Iend_LE"
    try:
        return archinfo.arch_from_id(ident, endness=endness, bits=bits)
    except Exception:
        return archinfo.ArchAMD64() if bits == 64 else archinfo.ArchX86()


def _register_names(spec_xml: str) -> set[str]:
    return {m.lower() for m in re.findall(r'register name="([^"]+)"', spec_xml)}


def _arch_ident(regs: set[str], bits: int) -> str:
    """Map a register-name fingerprint to an archinfo id. Order matters: test the
    most specific landmarks first."""
    if "rax" in regs:
        return "amd64"
    if "eax" in regs:
        return "x86"
    if "x0" in regs or "x30" in regs:        # aarch64 general regs
        return "aarch64"
    if "lr" in regs and "r0" in regs and "v0" not in regs:  # 32-bit ARM
        return "arm"
    if "v0" in regs and "a0" in regs:        # MIPS v0/a0/ra ABI
        return "mips64" if bits == 64 else "mips32"
    if "r3" in regs and "r31" in regs:       # PowerPC gpr file
        return "ppc64" if bits == 64 else "ppc32"
    return "amd64" if bits == 64 else "x86"


def _return_register(cspec: str) -> tuple[str | None, tuple[int, int] | None]:
    """Locate the default (integer) return value's storage from the cspec's
    default prototype <output>. Returns (name, None) when the pentry names a
    register (x86-style specs) -- resolved to storage later via getRegister --
    or (None, (offset, size)) when it gives a direct register-space address
    (ARM/MIPS/PPC normalized specs, which carry no register names). Prefers the
    first integer pentry over float ones. Falls back to the x86 RAX name."""
    try:
        croot = ET.fromstring(cspec)
    except ET.ParseError:
        return "RAX", None
    fallback_name = None
    fallback_addr = None
    for proto in croot.iter("default_proto"):
        for out in proto.iter("output"):
            for pentry in out.iter("pentry"):
                is_float = pentry.get("metatype") == "float" \
                    or pentry.get("storage") == "float"
                reg = pentry.find("register")
                if reg is not None and reg.get("name"):
                    if fallback_name is None:
                        fallback_name = reg.get("name")
                    if not is_float:
                        return reg.get("name"), None
                    continue
                addr = pentry.find("addr")
                if addr is not None and addr.get("space") == "register" \
                        and addr.get("offset") is not None:
                    off = int(addr.get("offset"), 0)
                    size = int(pentry.get("maxsize", "0") or "0", 0) or None
                    if fallback_addr is None and size:
                        fallback_addr = (off, size)
                    if not is_float and size:
                        return None, (off, size)
    if fallback_name is not None:
        return fallback_name, None
    if fallback_addr is not None:
        return None, fallback_addr
    return "RAX", None
