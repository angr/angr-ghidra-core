"""Map a loaded binary's architecture to the Ghidra spec documents the oracle
needs to stand in for Ghidra.

This is test-harness support, not part of the core: it lets the oracle drive the
core with the *right* pspec/cspec/tspec for any architecture, just as real
Ghidra would. The core itself never sees this -- it infers the arch from the
spec documents it receives (see core/spec.py).

Given the binary's CLE arch we derive a Ghidra language id, resolve its processor
and (gcc/default) compiler spec files from the processor's `.ldefs`, and read the
integer return register out of the compiler spec.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from xml.etree import ElementTree as ET

GHIDRA_ROOT = "/workspace/ghidra"

# CLE arch name -> (Ghidra processor prefix, language variant). Endianness and
# bit width come from the loaded object, so a single entry covers BE/LE variants.
_CLE_TO_LANG = {
    "AMD64": ("x86", "default"),
    "X86": ("x86", "default"),
    "ARMEL": ("ARM", "v7"),
    "ARMHF": ("ARM", "v7"),
    "ARMEB": ("ARM", "v7"),
    "AARCH64": ("AARCH64", "v8A"),
    "MIPS32": ("MIPS", "default"),
    "MIPS64": ("MIPS", "default"),
    "PPC32": ("PowerPC", "default"),
    "PPC64": ("PowerPC", "default"),
}


@dataclass
class ArchSpec:
    langid: str
    pspec_path: str
    cspec_path: str
    ptr_bytes: int
    bigendian: bool
    return_register: str


def spec_for_arch(arch) -> ArchSpec | None:
    """Build an ArchSpec for a CLE/archinfo arch, or None if unsupported."""
    entry = _CLE_TO_LANG.get(arch.name)
    if entry is None:
        return None
    proc, variant = entry
    bigendian = arch.memory_endness == "Iend_BE"
    langid = f"{proc}:{'BE' if bigendian else 'LE'}:{arch.bits}:{variant}"
    resolved = _resolve_ldefs(langid)
    if resolved is None:
        return None
    pspec_path, cspec_path = resolved
    return ArchSpec(
        langid=langid,
        pspec_path=pspec_path,
        cspec_path=cspec_path,
        ptr_bytes=arch.bytes,
        bigendian=bigendian,
        return_register=_return_register(cspec_path),
    )


def _resolve_ldefs(langid: str) -> tuple[str, str] | None:
    for ldef in glob.glob(f"{GHIDRA_ROOT}/Ghidra/Processors/*/data/languages/*.ldefs"):
        try:
            root = ET.parse(ldef).getroot()
        except ET.ParseError:
            continue
        for lang in root.iter("language"):
            if lang.get("id") != langid:
                continue
            d = os.path.dirname(ldef)
            pspec = os.path.join(d, lang.get("processorspec"))
            comps = {c.get("id"): c.get("spec") for c in lang.findall("compiler")}
            # Linux ELFs use the gcc/System V ABI; prefer it, then a plain
            # default, then whatever the language offers.
            spec = comps.get("gcc") or comps.get("default") or next(iter(comps.values()))
            return pspec, os.path.join(d, spec)
    return None


def _return_register(cspec_path: str) -> str:
    try:
        root = ET.parse(cspec_path).getroot()
    except (ET.ParseError, OSError):
        return "RAX"
    fallback = None
    for proto in root.iter("default_proto"):
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
