"""Consume user edits (variable renames/retypes) committed to Ghidra's database.

When a user renames or retypes a variable in the GUI, Ghidra writes it to the DB
and re-decompiles. The edited variable comes back to the core in the function's
localdb as a symbol with `namelock`/`typelock` set and a fixed storage location.
We match that storage to the angr variable and apply the override:

  * rename  -> set the *unified* variable's name (angr's display name), then
               regenerate the C text.
  * retype  -> set a manual (ground-truth) type on the variable_kb, then
               re-decompile (angr applies manual types during type inference).
"""

from __future__ import annotations

from dataclasses import dataclass

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
            continue  # dynamic-hash storage needs the p-code op graph; skip
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


def storage_to_unified(codegen, reg_to_angr):
    """Map each edit's storage to the codegen's unified variable.

    Returns two dicts: stack_offset -> unified var, and register-space
    (offset,size) -> unified var (via reg_to_angr, which maps a register-space
    offset+size to an angr (reg, size))."""
    from angr.sim_variable import SimRegisterVariable, SimStackVariable

    by_stack: dict[int, object] = {}
    by_reg_angr: dict[tuple, object] = {}
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
            by_reg_angr.setdefault((var.reg, var.size), uv)
    return by_stack, by_reg_angr


def _match(edit, by_stack, by_reg_angr, reg_to_angr):
    if edit.stack_offset is not None:
        return by_stack.get(edit.stack_offset)
    if edit.reg_offset is not None:
        key = reg_to_angr(edit.reg_offset, edit.size)
        if key is not None:
            return by_reg_angr.get(tuple(key))
    return None


def apply_retypes(codegen, edits, var_manager, reg_to_angr, ghidra_type_to_sim, arch) -> bool:
    """Set manual (ground-truth) types on the variable manager for typelocked
    edits. Returns True if any were set (caller must then re-decompile)."""
    by_stack, by_reg = storage_to_unified(codegen, reg_to_angr)
    changed = False
    for edit in edits:
        if edit.type_el is None:
            continue
        uv = _match(edit, by_stack, by_reg, reg_to_angr)
        if uv is None:
            continue
        ty = ghidra_type_to_sim(edit.type_el, arch)
        if ty is None:
            continue
        try:
            var_manager.set_variable_type(uv, ty.with_arch(arch), mark_manual=True,
                                          all_unified=True)
            changed = True
        except Exception:
            continue
    return changed


def apply_renames(codegen, edits, reg_to_angr) -> bool:
    """Set unified variable names for namelocked edits, then regenerate text."""
    by_stack, by_reg = storage_to_unified(codegen, reg_to_angr)
    changed = False
    for edit in edits:
        if not edit.name:
            continue
        uv = _match(edit, by_stack, by_reg, reg_to_angr)
        if uv is None:
            continue
        uv.name = edit.name
        uv.renamed = True
        changed = True
    if changed:
        codegen.regenerate_text()
    return changed
