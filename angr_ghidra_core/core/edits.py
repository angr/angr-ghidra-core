"""Consume user edits (variable renames/retypes) committed to Ghidra's database.

When a user renames or retypes a variable in the GUI, Ghidra writes it to the DB
and re-decompiles. The edited variable comes back to the core inside the
function's localdb as a symbol with `namelock`/`typelock` set and a fixed storage
location. We match that storage to the angr variable and apply the override to
its *unified* variable (angr's display name comes from there), then regenerate
the C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ghidra_wire import ids
from ..ghidra_wire.packed import SpecialSpace

_U64 = 1 << 64


@dataclass
class UserEdit:
    name: str | None          # rename target (namelock), else None
    type_el: object | None    # <type>/<typeref> element (typelock), else None
    stack_offset: int | None  # signed stack offset, if stack storage
    reg_offset: int | None    # register-space offset, if register storage
    size: int


def parse_user_edits(fn_el) -> list[UserEdit]:
    """Extract user-locked symbols (renames/retypes) from a getMappedSymbols
    model <function> element."""
    edits: list[UserEdit] = []
    if fn_el is None:
        return edits
    localdb = fn_el.first("localdb")
    scope = localdb.first("scope") if localdb else None
    symlist = scope.first("symbollist") if scope else None
    if symlist is None:
        return edits
    for mapsym in symlist.find("mapsym"):
        sym = mapsym.first("symbol")
        if sym is None:
            continue
        namelock = bool(sym.attr("namelock"))
        typelock = bool(sym.attr("typelock"))
        if not (namelock or typelock):
            continue  # only honour user-locked edits
        addr_el = next((c for c in mapsym.children if c.name == "addr"), None)
        if addr_el is None:
            continue
        space = addr_el.attr("space")
        offset = addr_el.attr("offset") or 0
        size = addr_el.attr("size") or 0
        stack_off = reg_off = None
        if isinstance(space, SpecialSpace):  # stack special space
            stack_off = offset - _U64 if offset >= (_U64 >> 1) else offset
        elif isinstance(space, int):  # register (or ram) space index
            reg_off = offset
        tel = sym.first("type") or sym.first("typeref")
        edits.append(UserEdit(
            name=sym.attr("name") if namelock else None,
            type_el=tel if typelock else None,
            stack_offset=stack_off,
            reg_offset=reg_off,
            size=size,
        ))
    return edits


def apply_user_edits(codegen, edits, register_space, reg_name_to_angr, set_type) -> bool:
    """Apply edits to the codegen's unified variables. `reg_name_to_angr` maps a
    register-space offset+size to an angr (reg_offset, size); `set_type` applies a
    retype (may be a no-op). Returns True if anything changed."""
    from angr.sim_variable import SimRegisterVariable, SimStackVariable

    by_stack: dict[int, object] = {}
    by_reg: dict[tuple, object] = {}
    seen: set[int] = set()
    for _text, obj in codegen.cfunc.c_repr_chunks(indent=0):
        if type(obj).__name__ != "CVariable":
            continue
        uv = obj.unified_variable
        var = obj.variable
        if uv is None or id(uv) in seen:
            continue
        seen.add(id(uv))
        if isinstance(var, SimStackVariable):
            by_stack.setdefault(var.offset, uv)
        elif isinstance(var, SimRegisterVariable):
            by_reg.setdefault((var.reg, var.size), uv)

    changed = False
    for edit in edits:
        uv = None
        if edit.stack_offset is not None:
            uv = by_stack.get(edit.stack_offset)
        elif edit.reg_offset is not None:
            key = reg_name_to_angr(edit.reg_offset, edit.size)
            if key is not None:
                uv = by_reg.get(key)
        if uv is None:
            continue
        if edit.name:
            uv.name = edit.name
            uv.renamed = True
            changed = True
        if edit.type_el is not None and set_type(uv, edit.type_el):
            changed = True
    if changed:
        codegen.regenerate_text()
    return changed
