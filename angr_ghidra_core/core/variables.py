"""Build Ghidra HighSymbol descriptions from angr's decompilation variables.

Each distinct SimVariable used in the generated C becomes a local symbol with a
stable id, a name matching the C text, a core datatype sized to its storage, and
a storage location (stack special-space offset or a register-space address).
Register storage is resolved through Ghidra's getRegister callback so the offset
matches Ghidra's register space (SLEIGH), not angr's VEX register offset.
"""

from __future__ import annotations

from dataclasses import dataclass

# storage kinds
STACK = "stack"
REGISTER = "register"

def undef_type_for_size(size: int) -> tuple[str, int]:
    """Return (coretype_name, type_size) for a storage of the given byte size.
    Ghidra's core types provide undefined1..undefined8 (including odd sizes);
    larger storages clamp to undefined8."""
    if 1 <= size <= 8:
        return f"undefined{size}", size
    if size > 8:
        return "undefined8", 8
    return "undefined1", 1


@dataclass
class VarSymbol:
    sym_id: int
    name: str
    category: int          # 0 = parameter, -1 = local
    cat_index: int         # parameter index, or -1
    type_name: str
    type_size: int
    storage_kind: str      # STACK or REGISTER
    # for STACK: offset is the (possibly negative) stack offset; space is the
    # stack special-space code (0). for REGISTER: space is the register space
    # index and offset is the SLEIGH register offset.
    space: int
    offset: int
    size: int
    # create-index of the representative varnode in <ast>/<varnodes> (identity
    # key that markup tokens reference via varref)
    varnode_ref: int = 0

    @property
    def high_class(self) -> str:
        return "p" if self.category == 0 else "l"


class VariableSymbolTable:
    """Collects the variables in a codegen result and assigns symbol ids."""

    def __init__(self, register_resolver, space_register: int):
        """register_resolver(name) -> (offset, size) in the Ghidra register space."""
        self._resolve_register = register_resolver
        self.space_register = space_register
        self.by_var_id: dict[int, VarSymbol] = {}
        self.symbols: list[VarSymbol] = []
        self._next_id = 0x1001
        self._next_ref = 0x200  # varnode create-index namespace (distinct from ids)

    def build(self, codegen, arch) -> None:
        from angr.sim_variable import SimRegisterVariable, SimStackVariable

        param_index = 0
        for _text, obj in codegen.cfunc.c_repr_chunks(indent=0):
            if type(obj).__name__ != "CVariable":
                continue
            var = obj.variable
            if var is None or id(var) in self.by_var_id:
                continue
            # display name comes from the unified variable (what tokens show, and
            # where renames land); fall back to the raw variable name
            uv = obj.unified_variable
            name = (getattr(uv, "name", None) if uv is not None else None) \
                or getattr(var, "name", None) or f"var_{len(self.symbols)}"
            ident = getattr(var, "ident", "") or ""
            is_param = isinstance(var, SimRegisterVariable) and ident.startswith("arg_")

            if isinstance(var, SimStackVariable):
                type_name, type_size = undef_type_for_size(var.size)
                sym = VarSymbol(
                    sym_id=self._alloc_id(), name=name,
                    category=-1, cat_index=-1,
                    type_name=type_name, type_size=type_size,
                    storage_kind=STACK, space=0, offset=var.offset, size=var.size,
                )
            elif isinstance(var, SimRegisterVariable):
                reg_name = arch.translate_register_name(var.reg, var.size)
                try:
                    off, size = self._resolve_register(reg_name.upper())
                except Exception:
                    continue  # register angr uses but Ghidra doesn't name; skip
                type_name, type_size = undef_type_for_size(var.size)
                cat = 0 if is_param else -1
                cidx = param_index if is_param else -1
                if is_param:
                    param_index += 1
                sym = VarSymbol(
                    sym_id=self._alloc_id(), name=name,
                    category=cat, cat_index=cidx,
                    type_name=type_name, type_size=type_size,
                    storage_kind=REGISTER, space=self.space_register,
                    offset=off, size=var.size,
                )
            else:
                continue  # skip globals/memory vars for now

            sym.varnode_ref = self._next_ref
            self._next_ref += 1
            self.by_var_id[id(var)] = sym
            self.symbols.append(sym)

    def symref_for(self, var) -> int | None:
        sym = self.by_var_id.get(id(var))
        return sym.sym_id if sym else None

    def _alloc_id(self) -> int:
        v = self._next_id
        self._next_id += 1
        return v
